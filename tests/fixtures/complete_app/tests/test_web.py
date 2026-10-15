from svc.web import app


def test_hello():
    assert app.test_client().get("/").status_code == 200
