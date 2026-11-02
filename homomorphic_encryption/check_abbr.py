"""List abbreviations in a page whose full term never appears in the visible text before
(or at) the first use of the abbreviation. Usage: python3 check_abbr.py html/primer/p7_lattices_and_lwe.html (after python3 build_html.py)"""
import html
import re
import sys

src = open(sys.argv[1], encoding="utf-8").read()
body = src.split("<article>", 1)[-1].split("</article>", 1)[0]
abbrs = re.findall(r'<abbr title="([^"]+)">([^<]+)</abbr>', body)
text = html.unescape(re.sub(r"<[^>]+>", " ", body))
raw = re.sub(r"\s+", " ", text)
text = raw.lower()
seen, problems = set(), []
for title, short in abbrs:
    if short in seen:
        continue
    seen.add(short)
    # match the abbreviation case-sensitively, as the tooltips do, so "she" is not SHE
    first = re.search(r"(?<![A-Za-z])" + re.escape(short) + r"(?![A-Za-z])", raw)
    upto = text[: first.end() + 200] if first else text
    # the spelled-out term is the part of the title before any "(" or ":" note
    main = re.split(r"[(:]", html.unescape(title))[0]
    words = [w for w in re.findall(r"[a-z]+", main.lower()) if len(w) > 3][:3]
    if not all(w in upto for w in words):
        problems.append(f"{short:10s} '{title}' is not spelled out before its first use")
print("\n".join(problems) if problems else f"All {len(seen)} abbreviations are spelled out at first use.")
