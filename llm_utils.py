"""
Utility module for shared LLM functions, deduplication of code.
"""
from google.genai.errors import APIError, ServerError
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception, wait_random

def _is_retryable_error(e: BaseException) -> bool:
    """
    Determines if an LLM provider error should be retried (e.g., 5xx or 429).

    Args:
        e: The exception caught during the LLM call.

    Returns:
        True if the error is retryable, False otherwise.
    """
    if isinstance(e, ServerError):
        return True
    if isinstance(e, APIError) and e.code == 429:
        return True
    return False

llm_retry = retry(
    wait=wait_exponential(multiplier=2, min=5, max=60) + wait_random(min=0, max=5),
    stop=stop_after_attempt(5),
    retry=retry_if_exception(_is_retryable_error),
    reraise=True
)