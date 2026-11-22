from fastapi.testclient import TestClient

from api.main import API_VERSION, app

client = TestClient(app)


def test_health_returns_ok():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "ai-powered-soc-lab", "version": API_VERSION}


def test_health_rejects_other_methods():
    response = client.post("/health")
    assert response.status_code == 405


def test_unknown_route_returns_404():
    assert client.get("/does-not-exist").status_code == 404


def test_openapi_schema_documents_health():
    schema = client.get("/openapi.json").json()
    assert schema["info"]["version"] == API_VERSION
    assert "/health" in schema["paths"]
