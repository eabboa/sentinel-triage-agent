"""
Utility module for shared LLM functions, deduplication of code.
"""
from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception, wait_random

def _is_retryable_error(e: Exception) -> bool:
    err_str = str(e).upper()
    return "429" in err_str or "503" in err_str or "RESOURCE_EXHAUSTED" in err_str or "UNAVAILABLE" in err_str

llm_retry = retry(
    wait=wait_exponential(multiplier=2, min=5, max=60) + wait_random(min=0, max=5),
    stop=stop_after_attempt(5),
    retry=retry_if_exception(_is_retryable_error),
    reraise=True
)