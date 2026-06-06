"""
Catch exception here, then validate in validate.py
We will have Sentinel, VT, AbuseIPDB, LLM exceptions.
This exceptions will capture and hold raw data. 
"""

class SentinelAlertValidationError(Exception):
    """Raised when data from the Microsoft Sentinel API fails validation."""
    
    def __init__(self, message: str, raw_data: object):
        """
        Initializes the SentinelAlertValidationError.

        Args:
            message: The error message describing the validation failure.
            raw_data: The raw, failing data object.

        Returns:
            None
        """
        # Call the parent class (Exception) constructor with the error message
        super().__init__(message)
        # Store the raw, failing data as an attribute on the exception object itself
        self.raw_data = raw_data


class VirusTotalResponseValidationError(Exception):
    """Raised when data from the VirusTotal API fails validation."""
    
    def __init__(self, message: str, raw_data: object):
        """
        Initializes the VirusTotalResponseValidationError.

        Args:
            message: The error message describing the validation failure.
            raw_data: The raw, failing data object.

        Returns:
            None
        """
        super().__init__(message)
        self.raw_data = raw_data

class AbuseIPDBResponseValidationError(Exception):
    """Raised when data from AbuseIPDB fails validation."""
    def __init__(self, message: str, raw_data: object):
        """
        Initializes the AbuseIPDBResponseValidationError.

        Args:
            message: The error message describing the validation failure.
            raw_data: The raw, failing data object.

        Returns:
            None
        """
        super().__init__(message)
        self.raw_data = raw_data

class LLMExtractionError(Exception):
    """Raised when an LLM invocation fails after retries (API/network/rate-limit)."""

    def __init__(self, message: str, original_error: BaseException):
        """
        Initializes the LLMExtractionError.

        Args:
            message: The error message describing the failure.
            original_error: The underlying exception that caused the failure.

        Returns:
            None
        """
        super().__init__(message)
        self.original_error = original_error


class LLMOutputValidationError(Exception):
    """Raised when the structured output from the LLM fails validation."""
    
    def __init__(self, message: str, raw_data: object):
        """
        Initializes the LLMOutputValidationError.

        Args:
            message: The error message describing the validation failure.
            raw_data: The raw, failing data object.

        Returns:
            None
        """
        super().__init__(message)
        self.raw_data = raw_data
