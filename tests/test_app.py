import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["AES256_KEY_HEX"] = "a" * 64
os.environ["SECRET_KEY"] = "test-only-secret"
from app import app, db, User, login_attempts

def test_injection_auth_encryption_and_headers():
    app.config["TESTING"] = True
    login_attempts.clear()
    with app.app_context():
        db.session.query(User).delete()
        db.session.commit()
    with app.test_client() as c:
        r = c.post("/api/register", json={"username": "alice", "password": "strongpassword123", "note": "private"})
        assert r.status_code == 201
        assert r.headers["X-Frame-Options"] == "DENY"
        assert c.post("/api/register", json={"username": "alice", "password": "strongpassword123"}).status_code == 409
        assert c.post("/api/register", json={"username": "a'", "password": "strongpassword123"}).status_code == 400
        assert c.post("/api/login", json={"username": "alice' OR 1=1 --", "password": "x"}).status_code == 401
        assert c.get("/api/note").status_code == 403
        cap = c.post("/api/login", json={"username": "alice", "password": "strongpassword123"}).json["capability"]
        assert c.get("/api/note", headers={"X-Capability": "wrong"}).status_code == 403
        assert c.get("/api/note", headers={"X-Capability": cap}).json["note"] == "private"
        with app.app_context():
            assert b"private" not in db.session.query(User).first().encrypted_note
        assert c.post("/api/logout").status_code == 200
        assert c.get("/api/note", headers={"X-Capability": cap}).status_code == 403

def test_login_throttling():
    login_attempts.clear()
    with app.test_client() as c:
        for _ in range(8):
            assert c.post("/api/login", json={"username": "missing", "password": "wrong"}).status_code == 401
        assert c.post("/api/login", json={"username": "missing", "password": "wrong"}).status_code == 429
