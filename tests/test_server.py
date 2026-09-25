from fastapi.testclient import TestClient
from server import app

client = TestClient(app)


def test_api_analytics_endpoint():
    response = client.get("/api/analytics")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "avg_risk_score" in data
    assert "trend" in data


def test_api_scans_list_endpoint():
    response = client.get("/api/scans")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_api_file_upload_scan(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("urllib3==1.26.4\n", encoding="utf-8")

    with open(req_file, "rb") as f:
        response = client.post(
            "/api/scan/file",
            files={"file": ("requirements.txt", f, "text/plain")}
        )

    assert response.status_code == 200
    data = response.json()
    assert "overall_risk_score" in data
    assert "scan_id" in data
    assert data["total_dependencies"] == 1
