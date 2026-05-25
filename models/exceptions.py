"""
Catch exception here, then validate in validate.py
We will have Sentinel, VT, AbuseIPDB, LLM exceptions.
This exceptions will capture and hold raw data. 
"""

class SentinelAlertValidationError(Exception):
    """Raised when data from the Microsoft Sentinel API fails validation."""
    
    def __init__(self, message: str, raw_data: object):
        # Call the parent class (Exception) constructor with the error message
        super().__init__(message)
        # Store the raw, failing data as an attribute on the exception object itself
        self.raw_data = raw_data


class VirusTotalResponseValidationError(Exception):
    """Raised when data from the VirusTotal API fails validation."""
    
    def __init__(self, message: str, raw_data: object):
        super().__init__(message)
        self.raw_data = raw_data

class AbuseIPDBResponseValidationError(Exception):
    """Raised when data from AbuseIPDB fails validation."""
    def __init__(self, message: str, raw_data: object):
        super().__init__(message)
        self.raw_data = raw_data

class LLMOutputValidationError(Exception):
    """Raised when the structured output from the LLM fails validation."""
    
    def __init__(self, message: str, raw_data: object):
        super().__init__(message)
        self.raw_data = raw_data
