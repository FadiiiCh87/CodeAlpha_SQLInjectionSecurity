# SQL Injection Defense and Encrypted Notes

CodeAlpha Cloud Computing Internship project.

Flask security demo using SQLAlchemy ORM, password hashing, AES-256-GCM encryption and session plus capability-token authorization.

## Local setup

```bash
python -m venv .venv
# Activate the virtual environment
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000.

## Tests

```bash
python -m pytest -q
```

## Configuration

Before running, set AES256_KEY_HEX to a secure 64-character hex key. Set a persistent SECRET_KEY. Configure HTTPS and COOKIE_SECURE=1 for production.

## Files

- `app.py`: Flask backend
- `templates/index.html`: frontend
- `static/style.css`: UI
- `tests/test_app.py`: tests
- `requirements.txt`: dependencies
- `Procfile`: Gunicorn startup

## Scope

Educational prototype. Deployment and production security review have not been completed.
