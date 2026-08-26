from app.signals.url_signals import extract_url_features


def signal_names(findings):
    return {f["signal"] for f in findings}


def test_clean_url_has_no_findings():
    findings = extract_url_features("https://github.com/Leomez17")
    assert findings == []


def test_ip_literal_and_http_flagged():
    findings = extract_url_features("http://192.168.1.5/login")
    names = signal_names(findings)
    assert "ip-literal-host" in names
    assert "no-tls" in names


def test_typosquat_domain_flagged():
    findings = extract_url_features("https://paypa1-secure-login.top/verify")
    names = signal_names(findings)
    assert "typosquat" in names or "brand-impersonation" in names
    assert "suspicious-tld" in names


def test_userinfo_hiding_real_host():
    findings = extract_url_features("http://paypal.com@evil-host.ru/login")
    names = signal_names(findings)
    assert "userinfo-in-url" in names


def test_url_shortener_flagged():
    findings = extract_url_features("https://bit.ly/3xample")
    names = signal_names(findings)
    assert "url-shortener" in names


def test_scheme_less_url_still_parses():
    findings = extract_url_features("bit.ly/3xample")
    names = signal_names(findings)
    assert "url-shortener" in names
