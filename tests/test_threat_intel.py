import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.threat_intel as ti
from core import ip_reputation
from core.risk_engine import compute_connection_risk


def test_local_ip_threat_summary():
    result = ti.lookup_ip_threat("192.168.1.50")
    assert result["is_malicious"] is False
    assert result["source"] == "local"
    assert result["abuse_score"] == 0


def test_unified_threat_confirms_malicious_from_virus_total():
    orig_abuse = ip_reputation.lookup_abuse_ip
    orig_vt = ti.lookup_virustotal
    orig_otx = ti.lookup_otx
    ip_reputation.lookup_abuse_ip = lambda ip, timeout=3.0: {
        "abuse_score": 0, "abuse_category": None, "is_malicious": False, "source": "none"
    }
    ti.lookup_virustotal = lambda ip, timeout=3.0: {
        "vt_score": 2, "vt_malicious": True, "source": "VirusTotal"
    }
    ti.lookup_otx = lambda ip, timeout=3.0: {
        "otx_pulse": 0, "otx_general": False, "source": "none"
    }
    try:
        result = ti.lookup_ip_threat("8.8.8.8")
        assert result["is_malicious"] is True
        assert "VirusTotal" in result["malicious_sources"]
    finally:
        ip_reputation.lookup_abuse_ip = orig_abuse
        ti.lookup_virustotal = orig_vt
        ti.lookup_otx = orig_otx


def test_risk_engine_incorporates_vt_signal():
    connection = {
        "remote_ip": "8.8.8.8",
        "status": "ESTABLISHED",
        "is_private": False,
        "process_name": "chrome.exe",
    }
    threat = {
        "abuse_score": 0,
        "is_malicious": False,
        "vt_score": 2,
        "otx_pulse": 0,
        "malicious_sources": [],
        "source": "none",
    }
    risk = compute_connection_risk(connection, threat)
    # 5 puntos por IP pública + 15 por señales de amenaza detectadas
    assert risk["risk_score"] >= 5
    assert any("Threat Intelligence" in r for r in risk["risk_reasons"])
