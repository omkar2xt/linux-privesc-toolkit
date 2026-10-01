"""Flask backend for Linux Privilege Escalation Detection Toolkit.
Provides safe HTTP API access to the scanner modules.
"""
import json
import logging
import os
import platform
import sys
from datetime import datetime

from flask import Flask, jsonify, request, render_template

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Detect if we're in a deployed environment (Render, Heroku, etc.)
# vs local Kali Linux
IS_DEPLOYED = os.environ.get('RENDER', False) or os.environ.get('DYNO', False)
IS_KALI = os.path.exists('/etc/os-release') and 'kali' in open('/etc/os-release').read().lower() if os.path.exists('/etc/os-release') else False

# Import scanner modules only if we're in a safe environment
# On Render (Linux but not Kali), we'll run in demo mode
SCANNER_AVAILABLE = False
MODULES = []

try:
    from modules import (
        system_info, suid_scan, permission_scan, sudo_scan, capability_scan,
        cron_scan, service_scan, kernel_scan, report_html,
    )
    MODULES = [
        system_info, suid_scan, permission_scan, sudo_scan, service_scan,
        cron_scan, kernel_scan, capability_scan,
    ]
    SCANNER_AVAILABLE = True
    logger.info("Scanner modules loaded successfully")
except Exception as e:
    logger.warning(f"Scanner modules not available: {e}")
    SCANNER_AVAILABLE = False

ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def get_demo_findings():
    """Return safe demo findings for deployed environments."""
    return [
        {
            "title": "Demo Mode - Limited Functionality",
            "evidence": "This is a demonstration deployment. The full scanner requires Kali Linux with appropriate permissions.",
            "severity": "INFO",
            "recommendation": "Deploy locally on Kali Linux for complete security auditing capabilities."
        },
        {
            "title": "System Information (Demo)",
            "evidence": f"Platform: {platform.system()} {platform.release()}\nArchitecture: {platform.machine()}\nPython: {sys.version.split()[0]}",
            "severity": "INFO",
            "recommendation": "This is sanitized demo data. Full system enumeration requires local deployment."
        },
        {
            "title": "Scanner Status",
            "evidence": "Backend API is operational. Scanner modules are in demo mode for security.",
            "severity": "INFO",
            "recommendation": "For production security audits, deploy on authorized Kali Linux systems."
        }
    ]


def run_scan_modules():
    """Execute all scanner modules safely."""
    findings = []

    if not SCANNER_AVAILABLE or IS_DEPLOYED:
        logger.info("Running in demo mode")
        return get_demo_findings()

    logger.info("Starting full scanner modules")
    for module in MODULES:
        name = module.__name__.split(".")[-1]
        try:
            logger.info(f"Running module: {name}")
            findings.extend(module.scan())
        except Exception as exc:
            logger.error(f"Module {name} failed: {exc}")
            findings.append({
                "title": f"Module error: {name}",
                "evidence": "Module temporarily unavailable",
                "severity": "INFO",
                "recommendation": "Check module configuration."
            })

    findings.sort(key=lambda f: ORDER.get(f["severity"], 999))
    logger.info(f"Scan completed with {len(findings)} findings")
    return findings


@app.route('/')
def index():
    """Serve the dashboard HTML page."""
    return render_template('index.html')


@app.route('/health')
def health():
    """Health check endpoint for Render."""
    return jsonify({
        "status": "healthy",
        "service": "Linux Privilege Escalation Automation Toolkit",
        "timestamp": datetime.now().isoformat(),
        "mode": "demo" if IS_DEPLOYED else "local"
    })


@app.route('/api/info')
def info():
    """API information endpoint."""
    return jsonify({
        "success": True,
        "service": "Linux Privilege Escalation Detection Toolkit",
        "description": "Detection-only security auditing toolkit for Linux privilege escalation misconfigurations",
        "version": "1.0.0",
        "mode": "demo" if IS_DEPLOYED else "local",
        "scanner_available": SCANNER_AVAILABLE,
        "modules": [
            "system_info",
            "suid_scan",
            "permission_scan",
            "sudo_scan",
            "cron_scan",
            "service_scan",
            "kernel_scan",
            "capability_scan"
        ],
        "security_notice": "This toolkit is for authorized security auditing only. No exploitation is performed."
    })


@app.route('/api/scan', methods=['POST'])
def scan():
    """Execute security scan (predefined modules only, no arbitrary commands)."""
    try:
        logger.info("Scan request received")
        
        # Optional: Get scan type from request (for future extensibility)
        data = request.get_json(silent=True) or {}
        scan_type = data.get('type', 'full')
        
        # Only allow predefined scan types - no arbitrary input
        if scan_type not in ['full', 'quick']:
            return jsonify({
                "success": False,
                "error": "Invalid scan type. Only 'full' and 'quick' are supported."
            }), 400
        
        findings = run_scan_modules()
        
        # Calculate summary
        counts = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        
        response = {
            "success": True,
            "timestamp": datetime.now().isoformat(),
            "mode": "demo" if IS_DEPLOYED else "local",
            "scan_type": scan_type,
            "summary": counts,
            "findings": findings,
            "total_findings": len(findings)
        }
        
        logger.info(f"Scan completed successfully: {len(findings)} findings")
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Scan error: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": "Scanner temporarily unavailable"
        }), 500


@app.route('/api/report')
def report():
    """Get the latest scan report in various formats."""
    try:
        format_type = request.args.get('format', 'json').lower()
        
        if format_type not in ['json', 'txt', 'html']:
            return jsonify({
                "success": False,
                "error": "Invalid format. Supported: json, txt, html"
            }), 400
        
        # Run a fresh scan for the report
        findings = run_scan_modules()
        
        counts = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        
        if format_type == 'json':
            return jsonify({
                "success": True,
                "generated": datetime.now().isoformat(),
                "summary": counts,
                "findings": findings
            })
        
        elif format_type == 'txt':
            lines = [f"REPORT generated {datetime.now():%Y-%m-%d %H:%M:%S}", "=" * 60,
                    "SUMMARY: " + ", ".join(f"{k}={counts[k]}" for k in ORDER if k in counts),
                    "=" * 60]
            for f in findings:
                lines += [f"\n[{f['severity']}] {f['title']}",
                         f"Evidence:\n{f['evidence']}",
                         f"Recommendation: {f['recommendation']}"]
            return "\n".join(lines), 200, {'Content-Type': 'text/plain'}
        
        elif format_type == 'html':
            if SCANNER_AVAILABLE and not IS_DEPLOYED:
                html_content = report_html.build(findings, counts)
            else:
                # Simple HTML for demo mode
                html_content = f"""<!DOCTYPE html>
<html><head><title>Demo Report</title></head>
<body><h1>Demo Mode Report</h1>
<p>Full HTML reports require local deployment on Kali Linux.</p>
<p>Total findings: {len(findings)}</p>
</body></html>"""
            return html_content, 200, {'Content-Type': 'text/html'}
        
    except Exception as e:
        logger.error(f"Report generation error: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": "Report generation failed"
        }), 500


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({
        "success": False,
        "error": "Endpoint not found"
    }), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logger.error(f"Internal error: {error}")
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500


if __name__ == '__main__':
    # This is for local development only
    # Production uses Gunicorn (see render.yaml)
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
