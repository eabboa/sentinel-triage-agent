"""
Containment node: Isolates compromised devices and revokes user sessions.

Executes only if containment_approved is True.
Uses the entities (hostnames + internal_ips) to trigger MDE device isolation and
the entities (usernames) to revoke Entra ID (Azure AD) refresh tokens. Internal
IPs found during lateral movement detection are treated as additional isolation
targets, since MDE accepts both hostnames and IP addresses for device lookup.
Both actions run sequentially under the single human containment approval; all
API failures are captured as non-fatal errors in the errors list.
"""

import asyncio
import re

import structlog

from sentinel_api import (
    isolate_mde_device,
    resolve_mde_machine_id,
    revoke_entra_sessions,
)
from state import TriageState

logger = structlog.get_logger(__name__)

# Allow only safe hostname characters (letters, digits, hyphens, dots)
_SAFE_HOSTNAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,253}[a-zA-Z0-9]$")

# Entra ID's revokeSignInSessions accepts only a UPN (user@domain.tld) or an
# object-ID GUID. The identifier is interpolated into a Graph API URL path, so
# SAM names (DOMAIN\user), bare usernames, and anything carrying URL-unsafe
# characters (slashes, whitespace) are rejected before any request is made.
_UPN_PATTERN = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_GUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-" r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _validate_hostname(hostname: str) -> bool:
    """
    Rejects hostnames with path traversal, whitespace, or injection characters.

    Args:
        hostname: The hostname string to validate.

    Returns:
        True if the hostname is safe, False otherwise.
    """
    return bool(_SAFE_HOSTNAME_PATTERN.match(hostname)) and ".." not in hostname


def _validate_entra_user(identifier: str) -> bool:
    """
    Accepts only Entra UPNs or object-ID GUIDs as session-revocation targets.

    Bare usernames and SAM account names (DOMAIN\\user) are not valid Graph
    identifiers and are rejected — this also blocks URL-path injection via the
    revokeSignInSessions endpoint.

    Args:
        identifier: The candidate user identifier from extracted entities.

    Returns:
        True if the identifier is a safe UPN or GUID, False otherwise.
    """
    return bool(_UPN_PATTERN.match(identifier) or _GUID_PATTERN.match(identifier))


async def _isolate_target(target: str) -> str | None:
    """
    Resolves a hostname/IP to an MDE machine ID and isolates it.

    Args:
        target: The hostname or IP to isolate.

    Returns:
        An error string on failure, or None on success.
    """
    machine_id = await resolve_mde_machine_id(target)
    if machine_id is None:
        msg = f"MDE device not found for target {target}; skipping isolation"
        logger.warning(msg)
        return msg

    result = await isolate_mde_device(machine_id)
    if isinstance(result, dict):
        logger.info(f"Successfully isolated target {target} (machine_id={machine_id})")
    else:
        logger.warning(f"Unexpected result type for {target}: {type(result)}")
    return None


def _collect_isolation_targets(entities: dict, errors: list[str]) -> list[str]:
    """
    Builds the validated, deduplicated list of device isolation targets.

    Merges hostnames and internal IPs (lateral-movement candidates); unsafe
    targets are dropped and recorded in errors.

    Args:
        entities: The extracted entities dict.
        errors: The mutable error list to append rejections to.

    Returns:
        The validated isolation targets.
    """
    hostnames = entities.get("hostnames", []) or []
    internal_ips = entities.get("internal_ips", []) or []

    targets = []
    for target in dict.fromkeys(hostnames + internal_ips):
        if _validate_hostname(target):
            targets.append(target)
        else:
            msg = f"Rejected unsafe isolation target: {target!r}"
            logger.warning(msg)
            errors.append(msg)
    return targets


def _collect_revocation_targets(entities: dict, errors: list[str]) -> list[str]:
    """
    Builds the validated, deduplicated list of Entra session-revocation targets.

    Only UPNs and object-ID GUIDs are revocable; non-revocable identities (bare
    usernames, SAM names) are dropped and recorded in errors so the analyst can
    see what was skipped.

    Args:
        entities: The extracted entities dict.
        errors: The mutable error list to append rejections to.

    Returns:
        The validated revocation targets.
    """
    usernames = entities.get("usernames", []) or []

    targets = []
    for user in dict.fromkeys(usernames):
        if _validate_entra_user(user):
            targets.append(user)
        else:
            msg = f"Skipped non-revocable user identity (not a UPN/GUID): {user!r}"
            logger.warning(msg)
            errors.append(msg)
    return targets


async def containment_node(state: TriageState) -> dict:
    """
    Orchestrates active containment: isolates MDE devices and revokes user sessions.

    Only executes if containment_approved is True.
    Validates and resolves hostnames to MDE machine IDs before calling isolation,
    and validates user identities to UPNs/GUIDs before revoking Entra sessions.
    All API failures are appended to errors list without crashing the pipeline.

    Args:
        state: The current TriageState dictionary.

    Returns:
        A dictionary containing the state updates for errors.
    """
    logger.info("node_entry", node="containment")
    errors: list[str] = []

    # Guard clause: only execute if containment is approved
    if not state.get("containment_approved", False):
        logger.debug("Containment not approved; skipping containment_node")
        logger.info("node_exit", node="containment")
        return {"errors": errors}

    logger.info("Containment approved; proceeding with active containment")

    entities = state.get("entities", {}) or {}
    isolation_targets = _collect_isolation_targets(entities, errors)
    revocation_targets = _collect_revocation_targets(entities, errors)

    if not isolation_targets and not revocation_targets:
        logger.info(
            "No valid isolation or revocation targets found in entities; "
            "nothing to contain"
        )
        logger.info("node_exit", node="containment")
        return {"errors": errors}

    # ── Device isolation (MDE) ────────────────────────────────────────────────
    if isolation_targets:
        logger.info(
            f"Attempting to isolate {len(isolation_targets)} targets: "
            f"{isolation_targets}"
        )
        for target in isolation_targets:
            try:
                err = await _isolate_target(target)
                if err:
                    errors.append(err)
            except Exception as exc:
                error_msg = f"MDE isolation failed for {target}: {str(exc)}"
                logger.error("node_error", node="containment", exc_info=True)
                errors.append(error_msg)

    # ── Session revocation (Entra ID) ─────────────────────────────────────────
    if revocation_targets:
        logger.info(
            f"Attempting to revoke sessions for {len(revocation_targets)} users: "
            f"{revocation_targets}"
        )
        for user_id in revocation_targets:
            try:
                result = await revoke_entra_sessions(user_id)
                if isinstance(result, dict):
                    logger.info(
                        f"Successfully revoked Entra sessions for user {user_id}"
                    )
                else:
                    logger.warning(
                        f"Unexpected result type for {user_id}: {type(result)}"
                    )
            except Exception as exc:
                error_msg = f"Entra session revocation failed for {user_id}: {str(exc)}"
                logger.error("node_error", node="containment", exc_info=True)
                errors.append(error_msg)

    logger.info("node_exit", node="containment")
    return {"errors": errors}
