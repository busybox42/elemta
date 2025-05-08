import pytest
import time
import smtplib
import requests

SMTP_HOST = 'localhost'
SMTP_PORT = 2525
API_URL = 'http://localhost:8081'
METRICS_URL = 'http://localhost:8080/metrics'

@pytest.fixture(scope='session', autouse=True)
def wait_for_services():
    # Wait for SMTP, API, and metrics endpoints to be up
    for _ in range(60):
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=2) as s:
                s.noop()
            requests.get(f'{API_URL}/health', timeout=2)
            requests.get(METRICS_URL, timeout=2)
            return
        except Exception:
            time.sleep(1)
    pytest.exit('Services did not become healthy in time', returncode=1)

@pytest.fixture
def smtp_host():
    return SMTP_HOST

@pytest.fixture
def smtp_port():
    return SMTP_PORT

@pytest.fixture
def api_url():
    return API_URL

@pytest.fixture
def metrics_url():
    return METRICS_URL 