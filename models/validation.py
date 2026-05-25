from datetime import datetime
from typing import Literal, Any
from pydantic import BaseModel, Field, ConfigDict

"""
---EXAMPLE SENTINEL DATA---

{
  "id": "alert-123",
  "name": "Suspicious Login",
  "properties": {
    "alertDisplayName": "Suspicious Login from unfamiliar location",
    "severity": "High",
    "startTimeUtc": "2023-10-25T14:30:00Z",
    "endTimeUtc": "2023-10-25T14:35:00Z",
    "entities": [
      { "type": "ip", "address": "1.2.3.4" }
    ]
  }
}

We will use nested models to look inside child fields.

"""


class AlertProperties(BaseModel):
    """

    """ 
    alertDisplayName: str
    severity: Literal["High", "Medium", "Low", "Informational"]
    startTimeUtc: datetime
    endTimeUtc: datetime
    entities: list[dict[str, Any]] = Field(default_factory=list)

class SentinelAlert(BaseModel):
    properties: AlertProperties

"""
--- EXAMPLE VIRUSTOTAL DATA ---

{
  "data": {
    "attributes": {
      "last_analysis_stats": {
        "harmless": 50,
        "type-unsupported": 12,
        "suspicious": 2,
        "confirmed-timeout": 0,
        "timeout": 0,
        "failure": 0,
        "malicious": 8,
        "undetected": 15
      }
    }
  }
}

"""

class VTAnalysisStats(BaseModel): ## starting from the innermost
    malicious: int
    suspicious: int
    model_config = ConfigDict(extra="ignore")

class VTAttributes(BaseModel):
    last_analysis_stats: VTAnalysisStats
    model_config = ConfigDict(extra="ignore")

class VTData(BaseModel):
    attributes: VTAttributes
    model_config = ConfigDict(extra="ignore")

class VirusTotalResponse(BaseModel):
    data: VTData
    model_config = ConfigDict(extra="ignore")


"""
--- EXAMPLE ABUSEIPDB DATA ---

{
  "data": {
    "ipAddress": "118.25.6.39",
    "abuseConfidenceScore": 100,
    "countryCode": "CN",
    "usageType": "Data Center/Web Hosting/Transit",
    "isp": "Tencent Cloud Computing (Beijing) Co. Ltd",
    "totalReports": 1,
    "lastReportedAt": "2018-12-20T20:55:14+00:00",
    "reports": [
      {
        "reportedAt": "2018-12-20T20:55:14+00:00",
        "comment": "Invalid user...",
        "categories": [18, 22]
      }
    ]
  }
}

"""

class AbuseIPDBData(BaseModel):
    totalReports: int
    abuseConfidenceScore: int
    countryCode: str | None = None
    isp: str | None = None
    usageType: str | None = None

    model_config = ConfigDict(extra="ignore")

class AbuseIPDBResponse(BaseModel):
    data: AbuseIPDBData

    model_config = ConfigDict(extra="ignore")