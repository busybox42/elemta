import requests
import pytest

def test_api_health(api_url):
    r = requests.get(f'{api_url}/health', timeout=2)
    assert r.status_code == 200
    assert 'ok' in r.text.lower()

def test_metrics(metrics_url):
    r = requests.get(metrics_url, timeout=2)
    assert r.status_code == 200
    assert 'elemta_connections_total' in r.text 