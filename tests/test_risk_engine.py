import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.risk_engine import compute_connection_risk, get_risk_level


def test_local_connection_is_low_risk():
    connection = {
        "remote_ip": "192.168.1.50",
        "status": "ESTABLISHED",
        "is_private": True,
        "process_name": "chrome.exe",
    }
    risk = compute_connection_risk(connection, {"abuse_score": 0, "is_malicious": False, "source": "local"})
    assert risk["risk_score"] == 0
    assert risk["risk_level"] == "LOW"
    assert risk["threat_malicious"] is False


def test_malicious_ip_is_critical():
    connection = {
        "remote_ip": "8.8.8.8",
        "status": "ESTABLISHED",
        "is_private": False,
        "process_name": "chrome.exe",
    }
    threat = {"abuse_score": 0, "is_malicious": True, "source": "AbuseIPDB"}
    risk = compute_connection_risk(connection, threat)
    assert risk["risk_score"] >= 60
    assert risk["risk_level"] == "CRITICAL"
    assert risk["threat_malicious"] is True
    assert len(risk["risk_reasons"]) > 0


def test_high_abuse_score_increases_risk():
    connection = {
        "remote_ip": "203.0.113.10",
        "status": "ESTABLISHED",
        "is_private": False,
        "process_name": "svchost.exe",
    }
    threat = {"abuse_score": 80, "is_malicious": True, "source": "AbuseIPDB"}
    risk = compute_connection_risk(connection, threat)
    assert risk["risk_score"] >= 60
    assert risk["risk_level"] in ("HIGH", "CRITICAL")


def test_exposed_listening_service_on_public_ip():
    connection = {
        "remote_ip": "203.0.113.10",
        "status": "LISTEN",
        "is_private": False,
        "process_name": "httpd.exe",
    }
    risk = compute_connection_risk(connection, {"abuse_score": 0, "is_malicious": False, "source": "local"})
    assert risk["risk_score"] >= 15  # 5 por IP pública + 15 por LISTEN


def test_risky_process_adds_score():
    connection = {
        "remote_ip": "192.168.1.50",
        "status": "ESTABLISHED",
        "is_private": True,
        "process_name": "powershell.exe",
    }
    risk = compute_connection_risk(connection, {"abuse_score": 0, "is_malicious": False, "source": "local"})
    assert risk["risk_score"] > 0
    assert any("riesgo" in r.lower() or "sospechoso" in r.lower() for r in risk["risk_reasons"])


def test_get_risk_level_boundaries():
    assert get_risk_level(0) == "LOW"
    assert get_risk_level(24) == "LOW"
    assert get_risk_level(25) == "MEDIUM"
    assert get_risk_level(49) == "MEDIUM"
    assert get_risk_level(50) == "HIGH"
    assert get_risk_level(74) == "HIGH"
    assert get_risk_level(75) == "CRITICAL"
    assert get_risk_level(100) == "CRITICAL"
