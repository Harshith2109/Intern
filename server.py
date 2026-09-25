import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from analyzer.parsers import find_and_parse
from analyzer.scanners import ScanManager
from analyzer.scoring import RiskEngine
from analyzer.reporters import HTMLReporter, JSONReporter, SARIFReporter
from analyzer.github import GitHubFetcher
import db

app = FastAPI(
    title="DevSecOps Dependency Risk Analyzer API",
    description="REST API & Dashboard Server for Dependency Vulnerability Scanning & Risk Engine",
    version="1.0.0"
)

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Database
db.init_db()

# Mount Web Dashboard Frontend Assets
WEB_DIR = Path(__file__).parent / "web"
WEB_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


class GitHubScanRequest(BaseModel):
    url: str
    branch: Optional[str] = "main"
    token: Optional[str] = None
    threshold: Optional[float] = 70.0


@app.get("/", response_class=HTMLResponse)
def read_root():
    index_path = WEB_DIR / "index.html"
    if index_path.exists():
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>DevSecOps Dependency Risk Analyzer API is running.</h1><p>Frontend template initializing...</p>")


@app.post("/api/scan/file")
async def scan_file(
    file: UploadFile = File(...),
    threshold: float = Form(70.0),
    fail_on_critical: bool = Form(True)
):
    """Scan an uploaded dependency manifest file (requirements.txt, package.json, pom.xml)."""
    temp_dir = Path(tempfile.mkdtemp(prefix="devsecops_upload_"))
    try:
        file_path = temp_dir / file.filename
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        dependencies = find_and_parse(file_path)
        if not dependencies:
            raise HTTPException(status_code=400, detail=f"No supported dependencies found in file '{file.filename}'.")

        scanner = ScanManager()
        analyses = scanner.scan_dependencies(dependencies)

        risk_engine = RiskEngine(risk_threshold=threshold, fail_on_critical=fail_on_critical)
        report = risk_engine.evaluate(file.filename, analyses)

        scan_id = db.save_scan_record(report)
        result = report.to_dict()
        result["scan_id"] = scan_id

        return JSONResponse(content=result)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.post("/api/scan/github")
def scan_github(req: GitHubScanRequest):
    """Scan a remote public or private GitHub repository."""
    fetcher = GitHubFetcher()
    try:
        temp_dir = fetcher.fetch_repo_manifests(req.url, branch=req.branch, token=req.token)
        dependencies = find_and_parse(temp_dir)
        if not dependencies:
            raise HTTPException(status_code=400, detail=f"No dependency manifests found in GitHub repo: {req.url}")

        scanner = ScanManager()
        analyses = scanner.scan_dependencies(dependencies)

        risk_engine = RiskEngine(risk_threshold=req.threshold or 70.0)
        report = risk_engine.evaluate(req.url, analyses)

        scan_id = db.save_scan_record(report)
        result = report.to_dict()
        result["scan_id"] = scan_id

        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scans")
def list_scans(limit: int = 50):
    """Get list of past scans."""
    return db.get_all_scans(limit=limit)


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int):
    """Get full scan details by ID."""
    record = db.get_scan_by_id(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")
    return record


@app.get("/api/scans/{scan_id}/export/{export_format}")
def export_scan_report(scan_id: int, export_format: str):
    """Export scan report in HTML, JSON, or SARIF format."""
    record = db.get_scan_by_id(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")

    report_dict = record["report"]
    # Reconstruct temporary RiskReport object for exporter compatibility
    temp_dir = Path(tempfile.mkdtemp(prefix="devsecops_export_"))

    export_format = export_format.lower()
    if export_format == "json":
        json_file = temp_dir / f"scan_{scan_id}_report.json"
        with open(json_file, "w", encoding="utf-8") as f:
            f.write(record["report_json"])
        return FileResponse(json_file, media_type="application/json", filename=f"scan_{scan_id}_report.json")

    elif export_format == "html":
        # Import HTMLReporter directly
        from analyzer.models import RiskReport, DependencyAnalysis, Dependency, Vulnerability, Severity
        report_obj = _dict_to_risk_report(report_dict)
        html_file = temp_dir / f"scan_{scan_id}_report.html"
        HTMLReporter().export(report_obj, str(html_file))
        return FileResponse(html_file, media_type="text/html", filename=f"scan_{scan_id}_report.html")

    elif export_format == "sarif":
        report_obj = _dict_to_risk_report(report_dict)
        sarif_file = temp_dir / f"scan_{scan_id}_report.sarif"
        SARIFReporter().export(report_obj, str(sarif_file))
        return FileResponse(sarif_file, media_type="application/json", filename=f"scan_{scan_id}_report.sarif")

    elif export_format in ["cyclonedx", "sbom"]:
        from analyzer.reporters import CycloneDXReporter
        report_obj = _dict_to_risk_report(report_dict)
        cyclonedx_file = temp_dir / f"scan_{scan_id}_cyclonedx.json"
        CycloneDXReporter().export(report_obj, str(cyclonedx_file))
        return FileResponse(cyclonedx_file, media_type="application/json", filename=f"scan_{scan_id}_cyclonedx.json")

    else:
        raise HTTPException(status_code=400, detail="Invalid export format. Choose html, json, sarif, or cyclonedx.")


@app.post("/api/scans/{scan_id}/push-dependency-track")
def push_to_dependency_track(scan_id: int, server_url: str = Form(...), api_key: str = Form(...), project_id: str = Form(...)):
    """Pushes CycloneDX SBOM directly to OWASP Dependency-Track instance."""
    record = db.get_scan_by_id(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")

    import requests
    from analyzer.reporters import CycloneDXReporter

    report_obj = _dict_to_risk_report(record["report"])
    temp_dir = Path(tempfile.mkdtemp(prefix="devsecops_dtrack_"))
    sbom_file = temp_dir / "sbom.json"
    CycloneDXReporter().export(report_obj, str(sbom_file))

    try:
        with open(sbom_file, "r", encoding="utf-8") as f:
            sbom_json = f.read()

        import base64
        b64_bom = base64.b64encode(sbom_json.encode("utf-8")).decode("utf-8")

        payload = {
            "project": project_id,
            "bom": b64_bom
        }

        headers = {
            "X-Api-Key": api_key,
            "Content-Type": "application/json"
        }

        target_endpoint = f"{server_url.rstrip('/')}/api/v1/bom"
        resp = requests.put(target_endpoint, json=payload, headers=headers, timeout=10)

        if resp.status_code in [200, 201, 202]:
            return {"status": "success", "message": "Successfully uploaded SBOM to OWASP Dependency-Track"}
        else:
            raise HTTPException(status_code=resp.status_code, detail=f"OWASP Dependency-Track response: {resp.text}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)



@app.get("/api/analytics")
def get_analytics():
    """Get aggregate security analytics for dashboard charts."""
    return db.get_analytics_summary()


def _dict_to_risk_report(d: dict):
    from analyzer.models import RiskReport, DependencyAnalysis, Dependency, Vulnerability, Severity
    deps = []
    for item in d.get("dependencies", []):
        dep_data = item.get("dependency", {})
        dep = Dependency(
            name=dep_data.get("name", ""),
            version=dep_data.get("version", ""),
            ecosystem=dep_data.get("ecosystem", ""),
            is_direct=dep_data.get("is_direct", True),
            file_origin=dep_data.get("file_origin", "")
        )
        vulns = []
        for v in item.get("vulnerabilities", []):
            sev_str = v.get("severity", "UNKNOWN")
            sev_enum = getattr(Severity, sev_str, Severity.MEDIUM)
            vulns.append(Vulnerability(
                vuln_id=v.get("vuln_id", ""),
                summary=v.get("summary", ""),
                severity=sev_enum,
                cvss_score=v.get("cvss_score", 0.0),
                epss_score=v.get("epss_score", 0.0),
                fixed_version=v.get("fixed_version"),
                source=v.get("source", "OSV DB")
            ))
        deps.append(DependencyAnalysis(dependency=dep, vulnerabilities=vulns))

    return RiskReport(
        target_path=d.get("target_path", ""),
        scan_timestamp=d.get("scan_timestamp", ""),
        dependencies=deps,
        overall_risk_score=d.get("overall_risk_score", 0.0),
        risk_level=d.get("risk_level", "LOW"),
        total_dependencies=d.get("total_dependencies", 0),
        vulnerable_dependencies_count=d.get("vulnerable_dependencies_count", 0),
        severity_counts=d.get("severity_counts", {}),
        quality_gate_passed=d.get("quality_gate_passed", True),
        remediation_recommendations=d.get("remediation_recommendations", [])
    )
