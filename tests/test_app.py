import pytest

from app import SECURITY_HEADERS, create_app


@pytest.fixture()
def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def test_index_returns_metadata(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.get_json()["name"] == "SecureShip Demo API"


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_security_headers_present(client):
    response = client.get("/")
    for header, value in SECURITY_HEADERS.items():
        assert response.headers[header] == value


def test_greet_accepts_valid_name(client):
    response = client.get("/api/greet", query_string={"name": "Ada"})
    assert response.status_code == 200
    assert "Ada" in response.get_json()["greeting"]


@pytest.mark.parametrize("name", ["<script>alert(1)</script>", "a" * 51, "'; DROP TABLE users;--"])
def test_greet_rejects_malicious_input(client, name):
    response = client.get("/api/greet", query_string={"name": name})
    assert response.status_code == 400


def test_unknown_route_returns_json_404(client):
    response = client.get("/does-not-exist")
    assert response.status_code == 404
    assert response.get_json() == {"error": "Not found"}
