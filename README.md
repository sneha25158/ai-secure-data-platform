## Problem Statement

Log files often contain sensitive information such as passwords, API keys, and user data.
If exposed, this can lead to serious security vulnerabilities.

## Solution

I built an AI Secure Data Intelligence Platform that analyzes logs, detects sensitive data,
and generates risk insights to help developers identify and fix security issues quickly.

## My Approach

I designed the system as a modular pipeline:

- Parser → Converts raw logs into structured lines
- Detector → Identifies sensitive data using pattern matching
- Risk Engine → Calculates risk score and generates insights

This design ensures separation of concerns and makes each component independently testable and scalable.

## Key Features

- Log file upload and raw text analysis
- Detection of sensitive data (passwords, API keys, emails)
- Risk scoring and classification
- AI-style insights for security improvement
- Clean and simple UI for interaction

---

## Project Structure

```
secure-intel/
├── backend/
│   ├── package.json
│   └── src/
│       ├── server.js           ← Express entry point
│       ├── parser/index.js     ← Line parser
│       ├── detector/index.js   ← Regex-based detection engine
│       ├── risk/index.js       ← Risk scoring + insights generator
│       └── controller/index.js ← Pipeline orchestrator
├── frontend/
│   └── index.html              ← Single-page UI
├── sample-test.log             ← Example log file for testing
└── README.md
```

---

## Setup & Run

### Prerequisites

- Node.js >= 16

### Install dependencies

```bash
cd backend
npm install
```

### Start the server

```bash
npm start
```

The server starts at **http://localhost:3000**  
Frontend is served automatically at **http://localhost:3000**

---

## API Usage

### Endpoint: `POST /analyze`

#### Option A — Text input (form-data)

```bash
curl -X POST http://localhost:3000/analyze \
  -F "text=2024-01-15 ERROR Login failed for user: admin
2024-01-15 ERROR Login failed for user: admin
2024-01-15 ERROR Login failed for user: admin
2024-01-15 DEBUG password=SuperSecret123
2024-01-15 DEBUG api_key=sk-abc123xyz"
```

#### Option B — File upload

```bash
curl -X POST http://localhost:3000/analyze \
  -F "file=@sample-test.log"
```

#### Option C — JSON body

```bash
curl -X POST http://localhost:3000/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "ERROR Login failed\nDEBUG password=secret123"}'
```

---

## Example Output

```json
{
  "summary": "Detected 9 security findings in log data including 2 critical issues and 2 high-severity issues. Overall risk level: HIGH.",
  "content_type": "logs",
  "findings": [
    { "type": "email", "risk": "low", "line": 2 },
    { "type": "password", "risk": "critical", "line": 3 },
    { "type": "email", "risk": "low", "line": 4 },
    { "type": "api_key", "risk": "high", "line": 9 },
    { "type": "stack_trace", "risk": "medium", "line": 11 },
 
  ]
  "risk_score": 134,
  "risk_level": "high",
  "action": "masked",
  "insights": [
    "⚠️ Sensitive credentials are exposed in plain text within logs.",
    "🔑 API keys detected in logs — rotate them immediately to prevent unauthorized access.",
    "📛 Error stack traces reveal internal system structure — suppress in production environments.",
    "📧 Email addresses found in logs — review data retention and privacy compliance."
  ]
}
```

---

## Detection Capabilities

| Detection Type | Risk Level | Pattern                                |
| -------------- | ---------- | -------------------------------------- |
| Password       | Critical   | `password=...` / `password:...`        |
| API Key        | High       | `api_key=...` / `sk-...`               |
| Stack Trace    | Medium     | Exception / Error / Traceback keywords |
| Email Address  | Low        | Standard email regex                   |

---

## Risk Score Logic

| Risk     | Points per finding |
| -------- | ------------------ |
| Critical | 40                 |
| High     | 20                 |
| Medium   | 10                 |
| Low      | 2                  |

| Total Score | Risk Level |
| ----------- | ---------- |
| ≥ 40        | high       |
| ≥ 15        | medium     |
| < 15        | low        |

## Project Setup (Step-by-step)

1. Clone the repository
2. Navigate to backend folder  
   cd backend

3. Install dependencies  
   npm install

4. Start the server  
   npm start

5. Open browser  
   http://localhost:3000
