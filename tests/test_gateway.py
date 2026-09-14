from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def analyze(payload):
    return client.post('/api/gateway/analyze', json=payload)

def test_health():
    r = client.get('/api/health')
    assert r.status_code == 200
    assert r.json()['status'] == 'ok'

def test_bola_is_blocked():
    r = analyze({
        'method': 'GET', 'path': '/api/users/1002', 'user_id': '1001',
        'role': 'user', 'token': 'demo-token', 'client_type': 'human',
        'source_ip': '192.0.2.10', 'body': {}
    })
    assert r.status_code == 200
    data = r.json()
    assert data['decision'] == 'BLOCK'
    assert any(f['code'] == 'BOLA' for f in data['findings'])

def test_ai_sensitive_action_challenges():
    r = analyze({
        'method': 'POST', 'path': '/api/transfer', 'user_id': '1001',
        'role': 'admin', 'token': 'demo-token', 'client_type': 'ai-agent',
        'source_ip': '192.0.2.11', 'body': {'amount': 50000}
    })
    assert r.status_code == 200
    data = r.json()
    assert data['decision'] in {'CHALLENGE', 'BLOCK'}
    assert any(f['code'] == 'AI_SENSITIVE_ACTION' for f in data['findings'])

def test_ssrf_is_blocked():
    r = analyze({
        'method': 'POST', 'path': '/api/fetch', 'user_id': '1001',
        'role': 'user', 'token': 'demo-token', 'client_type': 'human',
        'source_ip': '192.0.2.12', 'body': {'url': 'http://169.254.169.254/latest/meta-data/'}
    })
    data = r.json()
    assert data['decision'] == 'BLOCK'
    assert any(f['code'] == 'SSRF' for f in data['findings'])

def test_safe_request_allowed():
    r = analyze({
        'method': 'GET', 'path': '/api/users/1001', 'user_id': '1001',
        'role': 'user', 'token': 'demo-token', 'client_type': 'human',
        'source_ip': '192.0.2.13', 'body': {}
    })
    assert r.json()['decision'] == 'ALLOW'
