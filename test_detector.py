from detector import analyze_url

def test_safe():
    r=analyze_url("https://www.google.com")
    assert r["status"]=="ok"
    assert r["score"] < 30

def test_suspicious():
    r=analyze_url("http://192.168.1.10@evil.example/login")
    assert r["status"]=="ok"
    assert r["score"] >= 40

def test_features_present():
    r=analyze_url("https://example.com")
    assert "rule_score" in r
    assert "model_score" in r
    assert "confidence" in r

def test_empty():
    assert analyze_url("")["status"]=="error"
