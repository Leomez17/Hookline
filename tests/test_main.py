from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_endpoint():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_cors_preflight_is_allowed_for_check_endpoint():
    # The browser extension (and anything else poking this API from a
    # different origin, e.g. a browser console on a different port) relies
    # on this preflight succeeding with a permissive Access-Control-Allow-*
    # response — see the comment above app.add_middleware(CORSMiddleware...)
    # in app/main.py for why allow_origins=["*"] is acceptable here.
    resp = client.options(
        "/check",
        headers={
            "Origin": "chrome-extension://fakeextensionid",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == "*"


def test_cors_header_present_on_actual_response():
    resp = client.get("/health", headers={"Origin": "http://example.com"})
    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == "*"
