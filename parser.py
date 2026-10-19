
from bs4 import BeautifulSoup

SELECTORS = {
    "post": "div.post",
    "title": ".title",
    "author": ".author",
    "date": ".date",
    "body": ".body",
}


def parse_posts(html: str, source: str, selectors: dict = SELECTORS):
    soup = BeautifulSoup(html, "html.parser")

    def text(node, css):
        el = node.select_one(css)
        return el.get_text(" ", strip=True) if el else ""

    posts = []
    for node in soup.select(selectors["post"]):
        posts.append({
            "source": source,
            "title": text(node, selectors["title"]),
            "author": text(node, selectors["author"]),
            "date": text(node, selectors["date"]),
            "body": node.select_one(selectors["body"]).get_text("\n", strip=True)
                    if node.select_one(selectors["body"]) else "",
        })
    return posts
