# SF Recon Engine - Backend API Specification

## Overview
This document outlines all backend API endpoints, data structures, and requirements needed to support the SF Recon Engine frontend application.

---

## Table of Contents
1. [Authentication](#authentication)
2. [Dashboard Page](#dashboard-page)
3. [Asset Inventory Page](#asset-inventory-page)
4. [New Scan Page](#new-scan-page)
5. [System Status](#system-status)
6. [Real-time Updates](#real-time-updates)
7. [Data Models](#data-models)

---

## Authentication

### User Session
**Endpoint:** `GET /api/auth/session`
**Description:** Get current user session information
**Response:**
```json
{
  "user": {
    "id": "string",
    "email": "string",
    "name": "string",
    "role": "admin" | "viewer" | "operator",
    "avatar": "string (url)",
    "organizationId": "string"
  },
  "permissions": ["string"],
  "sessionExpiry": "ISO8601 timestamp"
}
```

---

## Dashboard Page

### 1. Dashboard Metrics
**Endpoint:** `GET /api/dashboard/metrics`
**Description:** Get overview metrics for dashboard cards
**Response:**
```json
{
  "totalAssets": {
    "value": 1247,
    "change": {
      "percentage": 12,
      "direction": "increase" | "decrease" | "neutral",
      "timeframe": "last month"
    }
  },
  "criticalFindings": {
    "value": 23,
    "change": {
      "percentage": -8,
      "direction": "decrease",
      "timeframe": "last week"
    }
  },
  "riskScore": {
    "value": 7.2,
    "maxValue": 10,
    "change": {
      "value": 0.3,
      "direction": "increase",
      "timeframe": "last scan"
    }
  },
  "lastScan": {
    "timestamp": "ISO8601 timestamp",
    "relativeTime": "2 hours ago",
    "nextScan": {
      "timestamp": "ISO8601 timestamp",
      "relativeTime": "In 4 hours"
    }
  }
}
```

### 2. Risk Score Trend
**Endpoint:** `GET /api/dashboard/risk-trend`
**Description:** Get historical risk score data for chart
**Query Parameters:**
- `timeframe`: "7d" | "30d" | "90d" | "1y" (default: "30d")
- `granularity`: "daily" | "weekly" | "monthly"

**Response:**
```json
{
  "data": [
    {
      "date": "ISO8601 timestamp",
      "dateLabel": "Jan 1",
      "score": 6.8
    },
    {
      "date": "ISO8601 timestamp",
      "dateLabel": "Jan 5",
      "score": 7.0
    }
    // ... more data points
  ],
  "timeframe": "30d",
  "granularity": "daily"
}
```

### 3. Finding Distribution
**Endpoint:** `GET /api/dashboard/findings-distribution`
**Description:** Get count of findings by severity level
**Response:**
```json
{
  "distribution": [
    {
      "severity": "critical",
      "count": 23,
      "color": "#ef4444"
    },
    {
      "severity": "high",
      "count": 47,
      "color": "#f97316"
    },
    {
      "severity": "medium",
      "count": 89,
      "color": "#eab308"
    },
    {
      "severity": "low",
      "count": 156,
      "color": "#22c55e"
    }
  ],
  "total": 315
}
```

### 4. Recent Scans
**Endpoint:** `GET /api/scans/recent`
**Description:** Get list of recent scan activities
**Query Parameters:**
- `limit`: number (default: 10, max: 50)
- `offset`: number (default: 0)

**Response:**
```json
{
  "scans": [
    {
      "id": "string (uuid)",
      "target": "acme-corp.com",
      "type": "full_scan" | "quick_scan" | "network_scan" | "subdomain_scan" | "custom_scan",
      "typeLabel": "Full Scan",
      "status": "completed" | "in_progress" | "failed" | "pending" | "cancelled",
      "findings": 23,
      "startedAt": "ISO8601 timestamp",
      "completedAt": "ISO8601 timestamp",
      "duration": 7200,
      "relativeTime": "2 hours ago"
    }
    // ... more scans
  ],
  "total": 100,
  "limit": 10,
  "offset": 0
}
```

---

## Asset Inventory Page

### 1. Assets List
**Endpoint:** `GET /api/assets`
**Description:** Get paginated list of all discovered assets
**Query Parameters:**
- `page`: number (default: 1)
- `limit`: number (default: 10, max: 100)
- `filter`: "all" | "domains" | "ips" | "cloud" | "webapps"
- `search`: string (search query)
- `riskLevel`: "critical" | "high" | "medium" | "low" (can be multiple)
- `status`: "active" | "inactive"
- `sortBy`: "asset" | "risk" | "findings" | "lastScan"
- `sortOrder`: "asc" | "desc"

**Response:**
```json
{
  "assets": [
    {
      "id": "string (uuid)",
      "asset": "acme-corp.com",
      "type": "domain" | "ip_address" | "cloud_resource" | "web_app",
      "typeLabel": "Domain",
      "riskLevel": "critical" | "high" | "medium" | "low",
      "findings": 23,
      "lastScan": {
        "timestamp": "ISO8601 timestamp",
        "relativeTime": "2 hours ago",
        "scanId": "string (uuid)"
      },
      "status": "active" | "inactive",
      "metadata": {
        "ipAddress": "203.0.113.45",
        "cloudProvider": "aws" | "azure" | "gcp",
        "region": "us-east-1",
        "tags": ["production", "external"]
      },
      "createdAt": "ISO8601 timestamp",
      "updatedAt": "ISO8601 timestamp"
    }
    // ... more assets
  ],
  "pagination": {
    "total": 1247,
    "page": 1,
    "limit": 10,
    "totalPages": 125
  },
  "filters": {
    "applied": {
      "filter": "all",
      "search": "",
      "riskLevel": [],
      "status": null
    }
  }
}
```

### 2. Asset Stats
**Endpoint:** `GET /api/assets/stats`
**Description:** Get aggregate statistics for assets
**Response:**
```json
{
  "total": 1247,
  "active": 1203,
  "inactive": 44,
  "atRisk": 23,
  "byType": {
    "domains": 523,
    "ipAddresses": 312,
    "cloudResources": 189,
    "webApps": 223
  },
  "byRisk": {
    "critical": 23,
    "high": 89,
    "medium": 234,
    "low": 901
  }
}
```

### 3. Asset Details
**Endpoint:** `GET /api/assets/{assetId}`
**Description:** Get detailed information about a specific asset
**Response:**
```json
{
  "id": "string (uuid)",
  "asset": "acme-corp.com",
  "type": "domain",
  "typeLabel": "Domain",
  "riskLevel": "high",
  "riskScore": 7.5,
  "findings": 23,
  "status": "active",
  "discoveryDate": "ISO8601 timestamp",
  "lastScan": {
    "timestamp": "ISO8601 timestamp",
    "scanId": "string (uuid)",
    "duration": 3600
  },
  "scanHistory": [
    {
      "scanId": "string (uuid)",
      "timestamp": "ISO8601 timestamp",
      "type": "full_scan",
      "findings": 23,
      "riskScore": 7.5
    }
  ],
  "findings": [
    {
      "id": "string (uuid)",
      "severity": "critical",
      "title": "Exposed Admin Panel",
      "description": "Administrative interface accessible without authentication",
      "category": "access_control",
      "cvss": 9.8,
      "cve": "CVE-2024-1234",
      "discoveredAt": "ISO8601 timestamp",
      "status": "open" | "investigating" | "mitigated" | "false_positive"
    }
  ],
  "metadata": {
    "ipAddress": "203.0.113.45",
    "ports": [80, 443, 8080],
    "technologies": ["nginx", "wordpress", "php"],
    "certificates": [
      {
        "issuer": "Let's Encrypt",
        "validFrom": "ISO8601 timestamp",
        "validTo": "ISO8601 timestamp",
        "subject": "acme-corp.com"
      }
    ],
    "dns": {
      "a": ["203.0.113.45"],
      "aaaa": ["2001:db8::1"],
      "mx": ["mail.acme-corp.com"],
      "txt": ["v=spf1 include:_spf.google.com ~all"]
    }
  },
  "tags": ["production", "external", "critical-asset"],
  "notes": "string",
  "assignedTo": {
    "userId": "string (uuid)",
    "userName": "John Doe",
    "email": "john@example.com"
  }
}
```

### 4. Trigger Asset Scan
**Endpoint:** `POST /api/assets/{assetId}/scan`
**Description:** Trigger a new scan for specific asset
**Request Body:**
```json
{
  "scanType": "full_scan" | "quick_scan",
  "priority": "low" | "normal" | "high",
  "options": {
    "portScanning": true,
    "sslAnalysis": true,
    "vulnerabilityAssessment": true
  }
}
```
**Response:**
```json
{
  "scanId": "string (uuid)",
  "status": "queued",
  "estimatedDuration": 3600,
  "queuePosition": 3,
  "message": "Scan queued successfully"
}
```

### 5. Export Assets
**Endpoint:** `GET /api/assets/export`
**Description:** Export assets list in various formats
**Query Parameters:**
- `format`: "csv" | "json" | "xlsx" | "pdf"
- `filter`: same as assets list endpoint
- `fields`: array of field names to include

**Response:** File download (Content-Type based on format)

---

## New Scan Page

### 1. Create New Scan
**Endpoint:** `POST /api/scans`
**Description:** Create and configure a new scan
**Request Body:**
```json
{
  "targets": [
    "acme-corp.com",
    "203.0.113.0/24",
    "*.acme-corp.com"
  ],
  "scanType": "full_scan" | "quick_scan" | "custom_scan",
  "options": {
    "portScanning": true,
    "sslAnalysis": true,
    "dnsEnumeration": true,
    "subdomainDiscovery": true,
    "technologyDetection": true,
    "vulnerabilityAssessment": false,
    "screenshotCapture": false
  },
  "schedule": {
    "type": "immediate" | "scheduled",
    "scheduledAt": "ISO8601 timestamp"
  },
  "notifications": {
    "emailOnCompletion": true,
    "notifyOnCriticalFindings": true,
    "slackWebhook": "https://hooks.slack.com/services/...",
    "customWebhook": "https://api.example.com/webhook"
  },
  "priority": "low" | "normal" | "high",
  "name": "string (optional)",
  "description": "string (optional)",
  "tags": ["string"]
}
```
**Response:**
```json
{
  "scanId": "string (uuid)",
  "status": "queued" | "scheduled",
  "estimatedStartTime": "ISO8601 timestamp",
  "estimatedDuration": 7200,
  "queuePosition": 5,
  "targetCount": 3,
  "message": "Scan created successfully"
}
```

### 2. Scan Templates
**Endpoint:** `GET /api/scans/templates`
**Description:** Get pre-configured scan templates
**Response:**
```json
{
  "templates": [
    {
      "id": "string (uuid)",
      "name": "Full Security Audit",
      "description": "Comprehensive scan with all options enabled",
      "scanType": "full_scan",
      "options": {
        "portScanning": true,
        "sslAnalysis": true,
        "dnsEnumeration": true,
        "subdomainDiscovery": true,
        "technologyDetection": true,
        "vulnerabilityAssessment": true,
        "screenshotCapture": true
      },
      "estimatedDuration": 14400,
      "isDefault": false
    }
  ]
}
```

### 3. Validate Targets
**Endpoint:** `POST /api/scans/validate-targets`
**Description:** Validate scan targets before creating scan
**Request Body:**
```json
{
  "targets": [
    "acme-corp.com",
    "203.0.113.0/24",
    "invalid-target"
  ]
}
```
**Response:**
```json
{
  "valid": [
    {
      "target": "acme-corp.com",
      "type": "domain",
      "resolved": true,
      "ipAddress": "203.0.113.45"
    },
    {
      "target": "203.0.113.0/24",
      "type": "cidr",
      "ipCount": 256
    }
  ],
  "invalid": [
    {
      "target": "invalid-target",
      "reason": "Invalid domain format",
      "suggestion": null
    }
  ],
  "summary": {
    "totalTargets": 3,
    "validTargets": 2,
    "invalidTargets": 1
  }
}
```

### 4. Scan Options Config
**Endpoint:** `GET /api/scans/options`
**Description:** Get available scan options and their descriptions
**Response:**
```json
{
  "options": [
    {
      "key": "portScanning",
      "label": "Port Scanning",
      "description": "Scan for open ports and running services",
      "estimatedTime": 600,
      "requiresElevatedPermissions": false,
      "defaultEnabled": true,
      "category": "network"
    },
    {
      "key": "vulnerabilityAssessment",
      "label": "Vulnerability Assessment",
      "description": "Check for known vulnerabilities (CVEs)",
      "estimatedTime": 3600,
      "requiresElevatedPermissions": false,
      "defaultEnabled": false,
      "category": "security"
    }
  ],
  "categories": [
    {
      "id": "network",
      "label": "Network Analysis",
      "description": "Network-level reconnaissance"
    },
    {
      "id": "security",
      "label": "Security Testing",
      "description": "Vulnerability and security checks"
    }
  ]
}
```

---

## System Status

### 1. System Health
**Endpoint:** `GET /api/system/health`
**Description:** Get overall system health status
**Response:**
```json
{
  "status": "operational" | "degraded" | "down",
  "services": {
    "scanner": {
      "status": "operational",
      "uptime": 99.99,
      "activeScans": 3,
      "queuedScans": 12
    },
    "database": {
      "status": "operational",
      "responseTime": 45,
      "connections": 23
    },
    "api": {
      "status": "operational",
      "responseTime": 120,
      "requestsPerMinute": 1234
    }
  },
  "lastUpdated": "ISO8601 timestamp"
}
```

### 2. Scan Queue Status
**Endpoint:** `GET /api/scans/queue`
**Description:** Get current scan queue information
**Response:**
```json
{
  "activeScans": 3,
  "queuedScans": 12,
  "completedToday": 45,
  "averageWaitTime": 300,
  "estimatedQueueClearTime": "ISO8601 timestamp",
  "queue": [
    {
      "scanId": "string (uuid)",
      "position": 1,
      "target": "example.com",
      "scanType": "full_scan",
      "priority": "high",
      "estimatedStartTime": "ISO8601 timestamp",
      "submittedBy": "John Doe",
      "submittedAt": "ISO8601 timestamp"
    }
  ]
}
```

---

## Scan Management

### 1. Get Scan Details
**Endpoint:** `GET /api/scans/{scanId}`
**Description:** Get detailed information about a specific scan
**Response:**
```json
{
  "id": "string (uuid)",
  "target": "acme-corp.com",
  "targets": ["acme-corp.com", "*.acme-corp.com"],
  "scanType": "full_scan",
  "status": "completed" | "in_progress" | "failed" | "pending" | "cancelled",
  "progress": 75,
  "startedAt": "ISO8601 timestamp",
  "completedAt": "ISO8601 timestamp",
  "duration": 7200,
  "findings": {
    "total": 23,
    "critical": 2,
    "high": 5,
    "medium": 8,
    "low": 8
  },
  "assetsDiscovered": 15,
  "options": {
    "portScanning": true,
    "sslAnalysis": true
  },
  "createdBy": {
    "userId": "string (uuid)",
    "userName": "John Doe",
    "email": "john@example.com"
  },
  "logs": [
    {
      "timestamp": "ISO8601 timestamp",
      "level": "info" | "warning" | "error",
      "message": "Starting port scan on 203.0.113.45"
    }
  ],
  "results": {
    "summary": "string",
    "detailedReport": "url to full report"
  }
}
```

### 2. Cancel Scan
**Endpoint:** `POST /api/scans/{scanId}/cancel`
**Description:** Cancel a running or queued scan
**Response:**
```json
{
  "scanId": "string (uuid)",
  "status": "cancelled",
  "message": "Scan cancelled successfully",
  "timestamp": "ISO8601 timestamp"
}
```

### 3. Retry Failed Scan
**Endpoint:** `POST /api/scans/{scanId}/retry`
**Description:** Retry a failed scan
**Response:**
```json
{
  "newScanId": "string (uuid)",
  "status": "queued",
  "message": "Scan retried successfully"
}
```

---

## Findings Management

### 1. Get Findings
**Endpoint:** `GET /api/findings`
**Description:** Get paginated list of security findings
**Query Parameters:**
- `page`: number
- `limit`: number
- `severity`: "critical" | "high" | "medium" | "low"
- `status`: "open" | "investigating" | "mitigated" | "false_positive"
- `assetId`: string (uuid)
- `scanId`: string (uuid)
- `category`: string
- `sortBy`: "severity" | "discoveredAt" | "cvss"
- `sortOrder`: "asc" | "desc"

**Response:**
```json
{
  "findings": [
    {
      "id": "string (uuid)",
      "severity": "critical",
      "title": "SQL Injection Vulnerability",
      "description": "SQL injection found in login form",
      "category": "injection",
      "cvss": 9.8,
      "cve": "CVE-2024-1234",
      "asset": {
        "id": "string (uuid)",
        "name": "app.acme-corp.com",
        "type": "domain"
      },
      "scan": {
        "id": "string (uuid)",
        "timestamp": "ISO8601 timestamp"
      },
      "status": "open",
      "discoveredAt": "ISO8601 timestamp",
      "updatedAt": "ISO8601 timestamp",
      "assignedTo": {
        "userId": "string (uuid)",
        "userName": "Jane Doe"
      },
      "proof": {
        "url": "https://app.acme-corp.com/login",
        "method": "POST",
        "payload": "admin' OR '1'='1",
        "screenshot": "url to screenshot"
      },
      "remediation": {
        "recommendation": "Use parameterized queries",
        "references": ["https://owasp.org/..."],
        "estimatedEffort": "4 hours"
      }
    }
  ],
  "pagination": {
    "total": 315,
    "page": 1,
    "limit": 20,
    "totalPages": 16
  }
}
```

### 2. Update Finding Status
**Endpoint:** `PATCH /api/findings/{findingId}`
**Description:** Update finding status and details
**Request Body:**
```json
{
  "status": "open" | "investigating" | "mitigated" | "false_positive",
  "assignedTo": "string (userId)",
  "notes": "string",
  "tags": ["string"]
}
```
**Response:**
```json
{
  "id": "string (uuid)",
  "status": "investigating",
  "updatedAt": "ISO8601 timestamp",
  "message": "Finding updated successfully"
}
```

---

## Notifications

### 1. Get Notifications
**Endpoint:** `GET /api/notifications`
**Description:** Get user notifications
**Query Parameters:**
- `unreadOnly`: boolean
- `limit`: number
- `offset`: number

**Response:**
```json
{
  "notifications": [
    {
      "id": "string (uuid)",
      "type": "scan_completed" | "critical_finding" | "scan_failed" | "system_alert",
      "title": "Scan Completed",
      "message": "Full scan of acme-corp.com completed with 23 findings",
      "severity": "info" | "warning" | "error",
      "read": false,
      "timestamp": "ISO8601 timestamp",
      "relatedEntity": {
        "type": "scan" | "asset" | "finding",
        "id": "string (uuid)"
      },
      "actionUrl": "/scans/abc-123"
    }
  ],
  "unreadCount": 5,
  "total": 50
}
```

### 2. Mark Notification as Read
**Endpoint:** `POST /api/notifications/{notificationId}/read`
**Response:**
```json
{
  "id": "string (uuid)",
  "read": true,
  "timestamp": "ISO8601 timestamp"
}
```

---

## Real-time Updates

### WebSocket Connection
**Endpoint:** `ws://api.example.com/ws`
**Description:** WebSocket connection for real-time updates
**Authentication:** JWT token in connection params or header

**Events to Subscribe:**
- `scan.progress` - Scan progress updates
- `scan.completed` - Scan completion
- `scan.failed` - Scan failure
- `finding.new` - New finding discovered
- `asset.updated` - Asset information updated
- `system.status` - System status changes

**Event Format:**
```json
{
  "event": "scan.progress",
  "timestamp": "ISO8601 timestamp",
  "data": {
    "scanId": "string (uuid)",
    "progress": 45,
    "currentPhase": "port_scanning",
    "message": "Scanning ports 1-1000"
  }
}
```

---

## Data Models

### Asset Type Enum
- `domain`
- `ip_address`
- `cloud_resource`
- `web_app`
- `api_endpoint`
- `mobile_app`

### Scan Type Enum
- `full_scan`
- `quick_scan`
- `network_scan`
- `subdomain_scan`
- `custom_scan`

### Scan Status Enum
- `pending`
- `queued`
- `in_progress`
- `completed`
- `failed`
- `cancelled`

### Risk Level Enum
- `critical`
- `high`
- `medium`
- `low`
- `info`

### Finding Category Enum
- `injection`
- `broken_authentication`
- `sensitive_data_exposure`
- `xml_external_entities`
- `broken_access_control`
- `security_misconfiguration`
- `xss`
- `insecure_deserialization`
- `vulnerable_components`
- `insufficient_logging`
- `network_security`
- `ssl_tls_issues`

---

## Error Responses

All endpoints should return consistent error responses:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request parameters",
    "details": [
      {
        "field": "targets",
        "message": "At least one target is required"
      }
    ],
    "timestamp": "ISO8601 timestamp",
    "requestId": "string (uuid)"
  }
}
```

### HTTP Status Codes
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `409` - Conflict
- `422` - Unprocessable Entity
- `429` - Too Many Requests
- `500` - Internal Server Error
- `503` - Service Unavailable

### Error Codes
- `VALIDATION_ERROR` - Invalid input data
- `AUTHENTICATION_REQUIRED` - User not authenticated
- `INSUFFICIENT_PERMISSIONS` - User lacks required permissions
- `RESOURCE_NOT_FOUND` - Requested resource doesn't exist
- `RATE_LIMIT_EXCEEDED` - Too many requests
- `SCAN_LIMIT_REACHED` - Maximum concurrent scans reached
- `INVALID_TARGET` - Target format is invalid
- `TARGET_BLOCKED` - Target is in blocklist
- `SCAN_IN_PROGRESS` - Scan already running for target
- `INTERNAL_ERROR` - Server error

---

## Rate Limiting

**Headers:**
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640000000
```

**Limits:**
- API calls: 100 requests per minute per user
- Scan creation: 10 scans per hour per user
- Export operations: 5 exports per hour per user

---

## Pagination

All paginated endpoints use consistent pagination format:

**Query Parameters:**
- `page`: number (1-indexed)
- `limit`: number (default: 20, max: 100)

**Response:**
```json
{
  "data": [...],
  "pagination": {
    "total": 1247,
    "page": 1,
    "limit": 20,
    "totalPages": 63,
    "hasNext": true,
    "hasPrev": false
  }
}
```

---

## Sorting and Filtering

**Query Parameters:**
- `sortBy`: field name
- `sortOrder`: "asc" | "desc"
- `filter[fieldName]`: filter value

**Example:**
```
GET /api/assets?sortBy=riskLevel&sortOrder=desc&filter[type]=domain&filter[status]=active
```

---

## Date/Time Format

All timestamps use **ISO 8601** format in UTC:
```
2026-03-09T14:30:00.000Z
```

---

## Authentication

**Method:** JWT Bearer Token

**Header:**
```
Authorization: Bearer <token>
```

**Token Refresh:**
**Endpoint:** `POST /api/auth/refresh`
**Request Body:**
```json
{
  "refreshToken": "string"
}
```
**Response:**
```json
{
  "accessToken": "string",
  "refreshToken": "string",
  "expiresIn": 3600
}
```

---

## Additional Features

### 1. Bulk Operations
**Endpoint:** `POST /api/assets/bulk-action`
**Request Body:**
```json
{
  "assetIds": ["uuid1", "uuid2", "uuid3"],
  "action": "scan" | "delete" | "tag" | "assign",
  "parameters": {
    "scanType": "quick_scan",
    "tags": ["production"],
    "assignTo": "userId"
  }
}
```

### 2. Search
**Endpoint:** `GET /api/search`
**Query Parameters:**
- `q`: search query
- `type`: "assets" | "scans" | "findings" | "all"
- `limit`: number

**Response:**
```json
{
  "results": {
    "assets": [...],
    "scans": [...],
    "findings": [...]
  },
  "total": 45,
  "query": "acme-corp"
}
```

### 3. Reports
**Endpoint:** `GET /api/reports/{reportType}`
**Report Types:**
- `executive-summary`
- `detailed-findings`
- `compliance-report`
- `trend-analysis`

**Query Parameters:**
- `format`: "pdf" | "html" | "json"
- `dateFrom`: ISO8601
- `dateTo`: ISO8601
- `assetIds`: array of uuids

---

## Summary Checklist

### Dashboard Page Needs:
- ✅ Metrics (total assets, critical findings, risk score, last scan)
- ✅ Risk trend data (30 days)
- ✅ Finding distribution by severity
- ✅ Recent scans list (10 items)

### Asset Inventory Page Needs:
- ✅ Paginated assets list with filters
- ✅ Asset statistics (total, active, inactive, at risk)
- ✅ Asset type counts
- ✅ Search functionality
- ✅ Export capability
- ✅ Individual asset details
- ✅ Trigger scan for specific asset

### New Scan Page Needs:
- ✅ Create new scan endpoint
- ✅ Scan templates/presets
- ✅ Target validation
- ✅ Available scan options configuration
- ✅ Schedule options

### General Requirements:
- ✅ User authentication & session
- ✅ System health status
- ✅ Real-time updates (WebSocket)
- ✅ Notifications
- ✅ Error handling
- ✅ Rate limiting
- ✅ Pagination & sorting
- ✅ Search functionality

---

**Document Version:** 1.0  
**Last Updated:** March 9, 2026  
**Frontend Application:** SF Recon Engine Dashboard
