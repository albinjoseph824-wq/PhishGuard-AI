import ipaddress
import math
import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = {
    "login","signin","verify","verification","account","secure","security",
    "update","password","confirm","bank","wallet","payment","invoice",
    "recover","unlock","bonus","free","gift","claim","alert"
}
SHORTENERS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd",
    "buff.ly","cutt.ly","shorturl.at"
}

def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def entropy(text):
    if not text:
        return 0.0
    return -sum((text.count(c)/len(text))*math.log2(text.count(c)/len(text))
                for c in set(text))

def extract_features(url, parsed, host):
    lower = url.lower()
    return {
        "url_length": len(url),
        "host_length": len(host),
        "subdomains": max(0, host.count(".") - 1),
        "hyphens": host.count("-"),
        "digits": sum(c.isdigit() for c in host),
        "special_chars": len(re.findall(r"[^a-zA-Z0-9.\-:/]", url)),
        "at_symbol": int("@" in url),
        "ip_host": int(is_ip(host)),
        "https": int(parsed.scheme == "https"),
        "encoded": int(bool(re.search(r"%[0-9a-fA-F]{2}", url))),
        "shortener": int(host in SHORTENERS),
        "suspicious_words": sum(1 for w in SUSPICIOUS_WORDS if w in lower),
        "entropy": round(entropy(host), 2),
    }

def rule_score(f):
    score = 0
    if f["url_length"] > 100: score += 15
    if f["url_length"] > 180: score += 8
    if f["at_symbol"]: score += 25
    if f["ip_host"]: score += 25
    if not f["https"]: score += 10
    if f["subdomains"] >= 3: score += 10
    if f["hyphens"] >= 1: score += 5
    if f["shortener"]: score += 15
    if f["encoded"]: score += 5
    if f["digits"] >= 6: score += 5
    if f["special_chars"] >= 3: score += 5
    if f["entropy"] > 4.1: score += 5
    score += min(25, f["suspicious_words"] * 5)
    return min(score, 100)

def local_model_score(f):
    # Transparent lightweight logistic-style model.
    # V4 can replace this with a trained scikit-learn model and a labeled dataset.
    z = -3.2
    z += min(f["url_length"], 220) * 0.008
    z += f["subdomains"] * 0.24
    z += f["hyphens"] * 0.20
    z += min(f["digits"], 18) * 0.045
    z += f["at_symbol"] * 1.55
    z += f["ip_host"] * 1.60
    z += (1 - f["https"]) * 0.60
    z += f["encoded"] * 0.38
    z += f["shortener"] * 0.72
    z += min(f["suspicious_words"], 5) * 0.40
    z += min(f["special_chars"], 8) * 0.08
    z += max(0, f["entropy"] - 3.5) * 0.34
    probability = 1 / (1 + math.exp(-z))
    return round(probability * 100)

def analyze_url(url):
    if not url:
        return {"status":"error","message":"Please enter a URL."}

    candidate = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else "https://" + url
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return {"status":"error","message":"Invalid URL format."}

    if not host:
        return {"status":"error","message":"Could not identify a domain."}

    f = extract_features(candidate, parsed, host)
    rules = rule_score(f)
    model = local_model_score(f)
    final = round(rules * 0.65 + model * 0.35)

    findings = []
    def add(severity, text):
        findings.append({"severity":severity,"text":text})

    if f["ip_host"]: add("high","The host is an IP address instead of a normal domain.")
    if f["at_symbol"]: add("high","The URL contains @, which can hide the real destination.")
    if not f["https"]: add("medium","The URL does not use HTTPS.")
    if f["shortener"]: add("medium","A URL shortener hides the final destination.")
    if f["subdomains"] >= 3: add("medium","The hostname contains many subdomain levels.")
    if f["url_length"] > 100: add("medium","The URL is unusually long.")
    if f["suspicious_words"]:
        matched = sorted(w for w in SUSPICIOUS_WORDS if w in candidate.lower())
        add("medium","Security-sensitive terms: " + ", ".join(matched[:6]) + ".")
    if f["encoded"]: add("low","URL-encoded characters are present.")
    if f["entropy"] > 4.1: add("low","The domain has relatively high character randomness.")
    if not findings: add("low","No obvious phishing indicators were detected.")

    if final >= 60:
        label, level = "Potential Phishing", "high"
    elif final >= 30:
        label, level = "Suspicious", "medium"
    else:
        label, level = "Likely Safe", "low"

    confidence = min(99, max(51, round(55 + abs(model - 50) * 0.8)))

    return {
        "status":"ok",
        "url":url,
        "domain":host,
        "score":final,
        "label":label,
        "level":level,
        "rule_score":rules,
        "model_score":model,
        "confidence":confidence,
        "features":f,
        "findings":findings,
        "explanation":(
            f"The result combines a transparent rule score of {rules}/100 "
            f"with a local statistical model score of {model}/100. "
            f"The combined risk is {final}/100."
        ),
        "disclaimer":(
            "Educational defensive tool. A low score does not guarantee that a URL is safe. "
            "PhishGuard analyzes URL text and does not open the submitted website."
        )
    }
