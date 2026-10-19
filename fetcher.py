
from pathlib import Path

import requests

TOR_PROXY = "socks5h://127.0.0.1:9050"   # Tor service. Tor Browser uses port 9150 instead.
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0"


def tor_session(proxy: str = TOR_PROXY) -> requests.Session:
    s = requests.Session()
    # socks5h = DNS is resolved inside Tor too (required for .onion addresses)
    s.proxies.update({"http": proxy, "https": proxy})
    s.headers["User-Agent"] = USER_AGENT
    return s


def check_tor(session: requests.Session) -> bool:
    """Ask the Tor Project whether our traffic really exits through Tor."""
    try:
        r = session.get("https://check.torproject.org/api/ip", timeout=30)
        return bool(r.json().get("IsTor"))
    except Exception:
        return False


def fetch_url(session: requests.Session, url: str, timeout: int = 60) -> str:
    r = session.get(url, timeout=timeout)
    r.raise_for_status()
    return r.text


def load_local_pages(folder: str):
    """Yield (source_name, html) for each .html file in a folder (offline demo / testing)."""
    for path in sorted(Path(folder).glob("*.html")):
        yield path.name, path.read_text(encoding="utf-8", errors="ignore")
