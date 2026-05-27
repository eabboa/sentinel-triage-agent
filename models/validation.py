from datetime import datetime
from typing import Literal, Optional
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
    "status": "New",
    "title": "Suspicious Login",
    "description": "User logged in from an unfamiliar IP address.",
    "tactics": [
      "InitialAccess",
      "CredentialAccess"
    ],
    "entities": [
      {
        "type": "ip",
        "address": "1.2.3.4"
      },
      {
        "type": "url",
        "url": "http://evil.com/login"
      }
    ],
    "providerAlertId": "12345-67890",
    "vendorName": "Microsoft",
    "productName": "Azure Active Directory Identity Protection"
  }
}

"""

class SentinelEntity(BaseModel):
  type: str
  model_config = ConfigDict(extra="allow")

class AlertProperties(BaseModel):
    alertDisplayName: str
    severity: Literal["High", "Medium", "Low", "Informational"]
    startTimeUtc: datetime
    endTimeUtc: datetime
    entities: list[SentinelEntity] = Field(default_factory=list)

class SentinelAlert(BaseModel):
    properties: AlertProperties

"""
--- EXAMPLE VIRUSTOTAL DATA ---

{
  "data": {
    "id": "abc123def456...",
    "type": "url",
    "attributes": {
      "last_analysis_stats": {
        "malicious": 6,
        "suspicious": 2,
        "undetected": 60,
        "harmless": 20,
        "timeout": 0
      },
      "last_analysis_date": 1698244500,
      "reputation": -15
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
    "ipAddress": "1.2.3.4",
    "isPublic": true,
    "ipVersion": 4,
    "isWhitelisted": false,
    "abuseConfidenceScore": 85,
    "countryCode": "CN",
    "usageType": "Data Center/Web Hosting/Transit",
    "isp": "Some ISP Ltd",
    "domain": "someisp.com",
    "hostnames": [],
    "totalReports": 12,
    "numDistinctUsers": 5,
    "lastReportedAt": "2023-10-25T14:35:00+00:00"
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


"""
--- EXAMPLE LLM RESPONSE ---

{
  "classification": "TruePositive",
  "is_true_positive": true,
  "triage_summary": "User authenticated from a known-malicious IP (1.2.3.4) flagged by AbuseIPDB (confidence 85%) and VirusTotal (6 malicious detections). The IP originates from a Chinese data-center ISP with no prior association to the organisation. Login occurred outside business hours.",
  "mitre_analysis": "Initial access via valid account credentials from an anomalous location, consistent with credential stuffing or purchased credential use.",
  "mitre_techniques": [
    {
      "technique_id": "T1078",
      "name": "Valid Accounts",
      "confidence": 90,
      "tactic": "InitialAccess"
    },
    {
      "technique_id": "T1110",
      "name": "Brute Force",
      "confidence": 55,
      "tactic": "CredentialAccess"
    }
  ],
  "confidence": 85,
  "recommended_action": "Reset the affected user's credentials, block source IP 1.2.3.4 at the perimeter, and review sign-in logs for lateral movement."
}

"""

class MitreTechnique(BaseModel):
    technique_id: str
    name: str
    confidence: int
    tactic: Optional[str] = None


class AnalystVerdict(BaseModel):
    classification: Literal["TruePositive", "FalsePositive", "BenignPositive"]
    is_true_positive: bool
    triage_summary: str
    mitre_analysis: str
    mitre_techniques: list[MitreTechnique]
    confidence: int
    recommended_action: str