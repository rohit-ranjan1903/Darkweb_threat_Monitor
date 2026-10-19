import re

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
except ImportError:          # keyword extraction is optional
    TfidfVectorizer = None

EMAIL = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
RE_CRED = re.compile(rf"({EMAIL})\s*[:|;]\s*(\S+)")          # email:password
RE_EMAIL = re.compile(EMAIL)
RE_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_HASH = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{64}\b")

# category -> (weight, keywords)
CATEGORIES = {
    "leaked_credentials": (30, ["combo", "combolist", "leak", "leaked", "dump", "database", "breach",
                                "credentials", "logins", "stealer log", "fullz"]),
    "exploit": (35, ["0day", "zero-day", "zero day", "exploit", "rce", "remote code execution",
                     "poc", "privilege escalation", "vulnerability"]),
    "network_access": (40, ["vpn access", "rdp", "shell access", "webshell", "initial access",
                            "citrix", "admin panel", "domain admin"]),
    "ransomware_extortion": (40, ["ransomware", "ransom", "extortion", "data leak site", "encrypted"]),
    "malware": (25, ["malware", "stealer", "rat", "botnet", "loader", "crypter"]),
}
LEVELS = [(80, "CRITICAL"), (55, "HIGH"), (30, "MEDIUM"), (0, "LOW")]


def mask_email(email: str) -> str:
    user, _, domain = email.partition("@")
    return f"{user[:2]}{'*' * max(len(user) - 2, 1)}@{domain}"


def redact(text: str) -> str:
    """Replace every email:password pair with masked-email:[REDACTED]."""
    return RE_CRED.sub(lambda m: f"{mask_email(m.group(1))}:[REDACTED]", text)


def extract_iocs(text: str) -> dict:
    # Passwords are NEVER stored; only masked emails + a count.
    creds = RE_CRED.findall(text)
    return {
        "credential_pairs": len(creds),
        "masked_emails": sorted({mask_email(e) for e, _ in creds}),
        "cves": sorted({c.upper() for c in RE_CVE.findall(text)}),
        "ips": sorted(set(RE_IP.findall(text))),
        "hashes": len(RE_HASH.findall(text)),
        "email_domains": sorted({e.split("@")[1].lower() for e in RE_EMAIL.findall(text)}),
    }


def analyze_post(post: dict, watchlist: dict) -> dict:
    text = f"{post['title']}\n{post['body']}"
    low = text.lower()
    iocs = extract_iocs(text)

    score, cats = 0, []
    for name, (weight, words) in CATEGORIES.items():
        if any(w in low for w in words):
            cats.append(name)
            score += weight

    hits = [d for d in watchlist.get("domains", []) if d.lower() in low]
    hits += [k for k in watchlist.get("keywords", []) if k.lower() in low]
    hits = sorted(set(hits))
    if hits:
        score += 40                      # organization-specific threat = big boost
    if iocs["credential_pairs"] >= 10:
        score += 10

    score = min(score, 100)
    level = next(label for limit, label in LEVELS if score >= limit)
    snippet = redact(post["body"])[:200]

    clean = {k: v for k, v in post.items() if k != "body"}   # never keep the raw body
    return {**clean, "categories": cats, "watchlist_hits": hits, "iocs": iocs,
            "risk_score": score, "risk_level": level, "snippet": snippet}


def top_keywords(texts, n=6):
    """TF-IDF: words that are distinctive for this post compared with the others."""
    if not TfidfVectorizer or len(texts) < 2:
        return [[] for _ in texts]
    vec = TfidfVectorizer(stop_words="english", token_pattern=r"[A-Za-z][A-Za-z0-9\-]{2,}")
    matrix = vec.fit_transform(texts)
    names = vec.get_feature_names_out()
    result = []
    for row in matrix:
        arr = row.toarray()[0]
        idx = arr.argsort()[::-1][:n]
        result.append([names[i] for i in idx if arr[i] > 0])
    return result
