import json
import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional
from analyzer.models import RiskReport

DB_PATH = Path(__file__).parent / "devsecops.db"


def get_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_name TEXT NOT NULL,
                scan_timestamp TEXT NOT NULL,
                overall_risk_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                total_dependencies INTEGER NOT NULL,
                vulnerable_dependencies_count INTEGER NOT NULL,
                critical_count INTEGER NOT NULL,
                high_count INTEGER NOT NULL,
                medium_count INTEGER NOT NULL,
                low_count INTEGER NOT NULL,
                quality_gate_passed INTEGER NOT NULL,
                report_json TEXT NOT NULL
            )
        """)
        conn.commit()


def save_scan_record(report: RiskReport) -> int:
    init_db()
    report_dict = report.to_dict()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (
                target_name, scan_timestamp, overall_risk_score, risk_level,
                total_dependencies, vulnerable_dependencies_count,
                critical_count, high_count, medium_count, low_count,
                quality_gate_passed, report_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report.target_path,
            report.scan_timestamp,
            report.overall_risk_score,
            report.risk_level,
            report.total_dependencies,
            report.vulnerable_dependencies_count,
            report.severity_counts.get("CRITICAL", 0),
            report.severity_counts.get("HIGH", 0),
            report.severity_counts.get("MEDIUM", 0),
            report.severity_counts.get("LOW", 0),
            1 if report.quality_gate_passed else 0,
            json.dumps(report_dict)
        ))
        conn.commit()
        return cursor.lastrowid


def get_all_scans(limit: int = 50) -> List[Dict[str, Any]]:
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, target_name, scan_timestamp, overall_risk_score, risk_level,
                   total_dependencies, vulnerable_dependencies_count,
                   critical_count, high_count, medium_count, low_count, quality_gate_passed
            FROM scans ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        if row:
            res = dict(row)
            res["report"] = json.loads(res["report_json"])
            return res
        return None


def get_analytics_summary() -> Dict[str, Any]:
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                COUNT(*) as total_scans,
                AVG(overall_risk_score) as avg_risk_score,
                SUM(critical_count) as total_critical,
                SUM(high_count) as total_high,
                SUM(medium_count) as total_medium,
                SUM(low_count) as total_low,
                SUM(CASE WHEN quality_gate_passed = 1 THEN 1 ELSE 0 END) as passed_scans,
                SUM(CASE WHEN quality_gate_passed = 0 THEN 1 ELSE 0 END) as failed_scans
            FROM scans
        """)
        row = cursor.fetchone()
        stats = dict(row) if row else {}

        # Fetch recent 10 risk scores for trend chart
        cursor.execute("SELECT id, scan_timestamp, overall_risk_score, target_name FROM scans ORDER BY id ASC LIMIT 15")
        trend_rows = cursor.fetchall()
        trend = [dict(r) for r in trend_rows]

        return {
            "total_scans": stats.get("total_scans") or 0,
            "avg_risk_score": round(stats.get("avg_risk_score") or 0.0, 1),
            "total_critical": stats.get("total_critical") or 0,
            "total_high": stats.get("total_high") or 0,
            "total_medium": stats.get("total_medium") or 0,
            "total_low": stats.get("total_low") or 0,
            "passed_scans": stats.get("passed_scans") or 0,
            "failed_scans": stats.get("failed_scans") or 0,
            "trend": trend,
        }
