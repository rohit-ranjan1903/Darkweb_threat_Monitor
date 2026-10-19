"""SQLite storage with de-duplication, so repeated scans don't create repeated alerts."""
import hashlib
import json
import sqlite3
from datetime import datetime, timezone

SCHEMA = """CREATE TABLE IF NOT EXISTS alerts(
    id INTEGER PRIMARY KEY AUTOINCREMENT, fingerprint TEXT UNIQUE, found_at TEXT,
    source TEXT, title TEXT, author TEXT, post_date TEXT, risk_score INTEGER, risk_level TEXT,
    categories TEXT, watchlist_hits TEXT, keywords TEXT, iocs TEXT, snippet TEXT)"""


class Store:
    def __init__(self, path="threats.db"):
        self.db = sqlite3.connect(path)
        self.db.execute(SCHEMA)

    def save(self, a: dict) -> bool:
        fp = hashlib.sha256(f"{a['source']}|{a['title']}|{a['snippet']}".encode()).hexdigest()
        try:
            self.db.execute(
                "INSERT INTO alerts(fingerprint,found_at,source,title,author,post_date,risk_score,"
                "risk_level,categories,watchlist_hits,keywords,iocs,snippet) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (fp, datetime.now(timezone.utc).isoformat(timespec="seconds"), a["source"], a["title"],
                 a["author"], a["date"], a["risk_score"], a["risk_level"], json.dumps(a["categories"]),
                 json.dumps(a["watchlist_hits"]), json.dumps(a.get("keywords", [])),
                 json.dumps(a["iocs"]), a["snippet"]))
            self.db.commit()
            return True
        except sqlite3.IntegrityError:
            return False       # already stored
