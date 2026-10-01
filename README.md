# Linux Privilege Escalation Detection Toolkit

Detects Linux privilege-escalation-related **misconfigurations**. It does **not** execute exploits.
Each finding has evidence, severity (INFO/LOW/MEDIUM/HIGH/CRITICAL) and a recommendation.

## Project Description

This is a **detection-only** Linux security auditing toolkit designed for authorized security assessments in controlled environments. It identifies common misconfigurations that could lead to privilege escalation but does **not** perform any exploitation.

## Architecture

### Local/Kali Mode (Full Scanner)
```
Kali Linux
    ↓
Python Security Scanner (main.py)
    ↓
Scanner Modules (modules/)
    ↓
Analysis Engine
    ↓
Security Findings
    ↓
Reports (reports/)
```

### Deployed/Demo Mode (Safe API)
```
Browser/API Client
    ↓
Flask Backend (app.py)
    ↓
Safe predefined scanner/demo functions
    ↓
JSON/Report Response
```

## Modules
- **system_info**: user, UID, groups, OS, kernel, architecture
- **suid_scan**: SUID/SGID files (normal vs risky vs unrecognised)
- **permission_scan**: world-writable files/directories, `/etc/passwd` & `/etc/shadow` permission
  checks, and home-directory permission checks
- **sudo_scan**: risky `sudo -l` rules (NOPASSWD, ALL, shell-capable commands)
- **service_scan**: systemd services running as root with a world/group-writable executable,
  plus insecure PATH variables (`.`, empty entries, world-writable PATH directories)
- **cron_scan**: root cron jobs (`/etc/crontab`, `/etc/cron.d`, `/etc/cron.*`, and per-user
  `crontab -l`) that point to a world- or group-writable script
- **kernel_scan**: kernel version vs a local CVE reference list, plus a basic end-of-life
  version check (see Limitations below)
- **capability_scan**: dangerous file capabilities via `getcap`

Detection rules for suid_scan, capability_scan, and kernel_scan live in `config/signatures.json`,
so you can tune or extend them without touching code.

## Requirements

### Local/Kali Mode
- Debian/Ubuntu/Kali with Python 3
- For capabilities: `sudo apt install libcap2-bin`

### Backend/Deployed Mode
- Python 3.11+
- Flask 3.0.0
- Gunicorn 21.2.0

## Local Setup (Kali Linux)

### Run the Full Scanner
```bash
cd linux-privesc-toolkit
python3 main.py
```

Reports are written to `reports/report.txt`, `reports/report.json`, and `reports/report.html`
(open the HTML file in a browser for a styled, color-coded view).

### Run the Demo
```bash
./demo.sh
```

## Backend Setup (Local Development)

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Run Flask Development Server
```bash
python app.py
```

The API will be available at `http://localhost:5000`

### Run with Gunicorn (Production Mode)
```bash
gunicorn app:app --bind 0.0.0.0:5000
```

## Deployment (Render)

### Prerequisites
1. Create a [Render](https://render.com) account
2. Push your code to GitHub/GitLab

### Deploy Steps

1. **Connect Repository**
   - Go to Render Dashboard
   - Click "New +" → "Web Service"
   - Connect your repository

2. **Configure Service**
   - **Name**: `linux-privesc-toolkit`
   - **Environment**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT`

3. **Deploy**
   - Click "Create Web Service"
   - Render will automatically deploy using `render.yaml` if present

4. **Verify Deployment**
   - Once deployed, visit: `https://your-app-name.onrender.com/health`
   - You should see: `{"status": "healthy", ...}`

### Environment Variables
No environment variables are required for basic deployment. Render automatically provides:
- `PORT`: The port to bind to (handled automatically by Gunicorn command)

Optional environment variables:
- `RENDER`: Set to `true` to force demo mode (automatically set by Render)

## API Documentation

### Base URL
- **Local**: `http://localhost:5000`
- **Deployed**: `https://your-app-name.onrender.com`

### Endpoints

#### 1. Health Check
```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "Linux Privilege Escalation Automation Toolkit",
  "timestamp": "2026-10-01T12:00:00.000000",
  "mode": "demo"
}
```

#### 2. API Information
```http
GET /api/info
```

**Response:**
```json
{
  "success": true,
  "service": "Linux Privilege Escalation Detection Toolkit",
  "description": "Detection-only security auditing toolkit...",
  "version": "1.0.0",
  "mode": "demo",
  "scanner_available": true,
  "modules": ["system_info", "suid_scan", ...],
  "security_notice": "This toolkit is for authorized security auditing only..."
}
```

#### 3. Run Security Scan
```http
POST /api/scan
Content-Type: application/json

{
  "type": "full"
}
```

**Parameters:**
- `type` (optional): `"full"` or `"quick"` (default: `"full"`)

**Response:**
```json
{
  "success": true,
  "timestamp": "2026-10-01T12:00:00.000000",
  "mode": "demo",
  "scan_type": "full",
  "summary": {
    "INFO": 3,
    "MEDIUM": 1
  },
  "findings": [
    {
      "title": "Finding title",
      "evidence": "Evidence details",
      "severity": "INFO",
      "recommendation": "Recommended action"
    }
  ],
  "total_findings": 4
}
```

#### 4. Get Scan Report
```http
GET /api/report?format=json
```

**Parameters:**
- `format` (optional): `"json"`, `"txt"`, or `"html"` (default: `"json"`)

**Response (JSON):**
```json
{
  "success": true,
  "generated": "2026-10-01T12:00:00.000000",
  "summary": {...},
  "findings": [...]
}
```

**Response (TXT):**
Plain text report

**Response (HTML):**
Styled HTML report

### Error Responses

All endpoints return consistent error responses:

```json
{
  "success": false,
  "error": "Error description"
}
```

Common HTTP status codes:
- `200`: Success
- `400`: Bad request (invalid parameters)
- `404`: Endpoint not found
- `500`: Internal server error

## Security Notice

⚠️ **IMPORTANT**: This toolkit is designed for **authorized security auditing** and **controlled environments only**.

### What This Toolkit Does:
- ✅ Detects security misconfigurations
- ✅ Identifies potential privilege escalation vectors
- ✅ Provides remediation recommendations
- ✅ Generates detailed security reports

### What This Toolkit Does NOT Do:
- ❌ Execute privilege escalation exploits
- ❌ Perform arbitrary command execution
- ❌ Modify system configurations
- ❌ Create backdoors or reverse shells
- ❌ Exploit vulnerabilities

### Safe Deployment Mode

When deployed on Render (or similar platforms), the toolkit runs in **DEMO MODE**:
- Returns controlled demonstration data
- Does NOT execute system commands
- Does NOT access sensitive system files
- Provides API functionality demonstration only

For **real security audits**, deploy locally on Kali Linux where you have proper authorization and control.

### Legal Disclaimer

Only use this toolkit on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal. The authors are not responsible for misuse of this tool.

## Limitations / Future Scope

- `kernel_cves` in `config/signatures.json` is a small static list for demonstration, not a
  live feed. A production version should query a maintained source such as the NVD API.
- `service_scan` reads unit files directly rather than querying a running systemd, so it works
  the same whether or not systemd is actually managing services on the host.
- No remediation is performed automatically; every finding only suggests a fix.
- Deployed/Demo mode has limited functionality for security reasons.
- Possible next steps: multi-host scanning over SSH, a report diff between scans, and an
  optional (confirmation-gated) auto-remediation mode.

## Testing

### Test Local Scanner
```bash
python3 main.py
```

### Test Backend Locally
```bash
# Terminal 1: Start server
python app.py

# Terminal 2: Test endpoints
curl http://localhost:5000/health
curl http://localhost:5000/api/info
curl -X POST http://localhost:5000/api/scan -H "Content-Type: application/json" -d '{"type":"full"}'
curl http://localhost:5000/api/report?format=json
```

### Test Deployed API
```bash
# Replace with your Render URL
export API_URL="https://your-app-name.onrender.com"

curl $API_URL/health
curl $API_URL/api/info
curl -X POST $API_URL/api/scan -H "Content-Type: application/json" -d '{"type":"full"}'
curl "$API_URL/api/report?format=json"
```

## File Structure

```
linux-privesc-toolkit/
├── app.py                    # Flask backend entry point
├── main.py                   # CLI scanner entry point
├── requirements.txt          # Python dependencies
├── render.yaml              # Render deployment config
├── README.md                # This file
├── demo.sh                  # Demo script
├── config/
│   └── signatures.json      # Detection rules
├── modules/
│   ├── __init__.py
│   ├── system_info.py       # System information scanner
│   ├── suid_scan.py         # SUID/SGID scanner
│   ├── permission_scan.py   # Permission scanner
│   ├── sudo_scan.py         # Sudo rules scanner
│   ├── cron_scan.py         # Cron jobs scanner
│   ├── service_scan.py      # Systemd services scanner
│   ├── kernel_scan.py       # Kernel CVE scanner
│   ├── capability_scan.py   # Capabilities scanner
│   ├── report_html.py       # HTML report generator
│   └── config_loader.py     # Config loader utility
├── reports/                 # Generated reports (local mode)
└── screenshots/             # Screenshots (optional)
```

## Contributing

This is a security auditing tool. Contributions should:
- Maintain the detection-only philosophy
- Not add exploitation capabilities
- Include proper documentation
- Follow secure coding practices

## License

[Specify your license here]

## Support

For issues, questions, or contributions, please open an issue on the project repository.
