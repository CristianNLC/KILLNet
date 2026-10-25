import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.evidence_exporter import export_audit_to_pdf, get_forensic_summary


def test_export_pdf_requires_connections():
    ok, msg = export_audit_to_pdf([], r"C:\Users\JULIAN\AppData\Local\Temp\opencode\KILLNet_empty.pdf")
    assert ok is False
    assert "conexiones" in msg.lower()


def test_forensic_summary_counts():
    connections = [
        {"risk_level": "CRITICAL"},
        {"risk_level": "HIGH"},
        {"risk_level": "LOW"},
        {"risk_level": "MEDIUM"},
        {"risk_level": None},
    ]
    summary = get_forensic_summary(connections)
    assert summary["total"] == 5
    assert summary["critical"] == 1
    assert summary["high"] == 1
    assert summary["medium"] == 1
    # 'LOW' y None se normalizan al nivel LOW
    assert summary["low"] == 2
