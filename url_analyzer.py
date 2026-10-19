
from urllib.parse import urlparse

def analyze_url(url):
    parsed = urlparse(url)

    domain = parsed.hostname or ""
    path = parsed.path

    suspicious_words = [
        "login", "verify", "secure",
        "update", "password", "account"
    ]

    found_words = [
        word for word in suspicious_words
        if word in url.lower()
    ]

    result = {
        "url": url,
        "domain": domain,
        "path": path,
        "uses_https": parsed.scheme == "https",
        "suspicious_keywords": found_words,
        "keyword_count": len(found_words)
    }

    return result


# Safe example: reserved .test domain
sample_url = "https://account-verify.example.test/login"

print(analyze_url(sample_url))
