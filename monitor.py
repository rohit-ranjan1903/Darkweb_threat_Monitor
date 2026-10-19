
import argparse
import json
from pathlib import Path

from analyzer import analyze_post, redact, top_keywords
from fetcher import check_tor, fetch_url, load_local_pages, tor_session
from parser import parse_posts
from storage import Store

ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def collect(args):
    """Return list of (source, html) pages."""
    if args.sample:
        return list(load_local_pages("sample_data"))
    session = tor_session(args.proxy)
    if not check_tor(session):
        raise SystemExit("Tor is not reachable. Start Tor first (see README).")
    print("[+] Connected through Tor")
    urls = list(args.url or [])
    if args.urls_file:
        urls += [u.strip() for u in Path(args.urls_file).read_text().splitlines() if u.strip()]
    pages = []
    for u in urls:
        try:
            pages.append((u, fetch_url(session, u)))
            print(f"[+] fetched {u}")
        except Exception as e:
            print(f"[!] failed {u}: {e}")
    return pages


def main():
    p = argparse.ArgumentParser(description="Dark Web Threat Monitoring System")
    p.add_argument("--sample", action="store_true", help="analyze local sample_data/ (offline)")
    p.add_argument("--url", action="append", help="page to fetch through Tor (repeatable)")
    p.add_argument("--urls-file", help="text file with one URL per line")
    p.add_argument("--proxy", default="socks5h://127.0.0.1:9050")
    p.add_argument("--watchlist", default="watchlist.json")
    p.add_argument("--min-level", default="LOW", choices=ORDER)
    args = p.parse_args()
    if not (args.sample or args.url or args.urls_file):
        p.error("give --sample, --url or --urls-file")

    watchlist = json.loads(Path(args.watchlist).read_text())
    posts = [post for src, html in collect(args) for post in parse_posts(html, src)]
    if not posts:
        raise SystemExit("No posts found (check the selectors in parser.py).")

    alerts = [analyze_post(x, watchlist) for x in posts]
    for a, kw in zip(alerts, top_keywords([redact(f"{x['title']} {x['body']}") for x in posts])):
        a["keywords"] = kw

    store, shown, new = Store(), [], 0
    for a in sorted(alerts, key=lambda x: -x["risk_score"]):
        new += store.save(a)
        if ORDER.index(a["risk_level"]) >= ORDER.index(args.min_level):
            shown.append(a)

    print(f"\nAnalyzed {len(posts)} posts - {new} new alerts stored in threats.db\n")
    for a in shown:
        print(f"[{a['risk_level']:8}] score={a['risk_score']:3}  {a['title']}")
        print(f"           source={a['source']}  author={a['author']}")
        print(f"           categories={a['categories']}  org_hits={a['watchlist_hits']}")
        i = a["iocs"]
        print(f"           creds={i['credential_pairs']} masked={i['masked_emails'][:2]} cves={i['cves']}")
        print(f"           keywords={a['keywords']}\n")

    Path("reports").mkdir(exist_ok=True)
    Path("reports/latest.json").write_text(json.dumps(shown, indent=2))
    print("Report saved to reports/latest.json")


if __name__ == "__main__":
    main()
