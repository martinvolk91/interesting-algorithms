"""Build an HTML version of these notes into html/, with math rendered by KaTeX.

    python3 build_html.py        # then open html/index.html

Needs only Python-Markdown and Pygments. Math ($...$ and $$...$$) is lifted out before
Markdown runs, so underscores and asterisks inside formulas can't turn into emphasis, and is
put back as \\( \\) / \\[ \\] for KaTeX to render in the browser (KaTeX loads from a CDN, so
formulas need an internet connection; everything else works offline).
"""
import html
import re
from pathlib import Path

import markdown
from pygments.formatters import HtmlFormatter

ROOT = Path(__file__).parent
OUT = ROOT / "html"
PAGES = [                                   # navigation order
    "README.md",
    "01_introduction.md", "02_math_foundations.md", "03_how_it_works.md", "04_schemes.md",
    "05_core_techniques.md", "06_security.md", "07_state_of_the_art_2026.md",
    "08_ecosystem_and_applications.md", "09_glossary_and_reading_list.md",
    "deep_dives/ckks.md", "deep_dives/ckks_ind_cpa_d.md", "deep_dives/tfhe.md",
    "deep_dives/bfv_pir.md", "deep_dives/threshold_fhe.md", "deep_dives/hardware.md",
]
KATEX = "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist"
RENDER_MATH = """<script>
function renderMath() {
  renderMathInElement(document.body, {
    delimiters: [{left: "\\\\[", right: "\\\\]", display: true}, {left: "\\\\(", right: "\\\\)", display: false}],
    throwOnError: false});
  // rendering changes the layout, so jump to the #section again once it is done
  const target = location.hash && document.getElementById(decodeURIComponent(location.hash.slice(1)));
  if (target) target.scrollIntoView();
}
</script>"""
LIST_ITEM = re.compile(r"^\s*([-*+]|\d+\.)\s")
PLACEHOLDER = "MATHPLACEHOLDER{}END"


# ---------------------------------------------------------------- Markdown clean-up
def normalize_blocks(text):
    """Python-Markdown is stricter than GitHub: nested lists need 4-space indents, and lists,
    tables, fences and quotes need a blank line before them. Strikethrough isn't supported."""
    out, in_fence = [], False
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            if not in_fence and out and out[-1].strip():
                out.append("")
            in_fence = not in_fence
            out.append(line)
            continue
        if in_fence:
            out.append(line)
            continue
        if re.match(r"^ {1,3}([-*+]|\d+\.)\s", line):
            line = "    " + line.lstrip(" ")                  # 1-3 space nesting -> 4-space
        prev = out[-1] if out else ""
        starts_block = LIST_ITEM.match(line) or line.startswith("|") or line.startswith(">")
        prev_is_text = prev.strip() and not LIST_ITEM.match(prev) and not prev.startswith(("|", ">", " "))
        if starts_block and prev_is_text and not line.startswith(" "):
            out.append("")
        out.append(re.sub(r"~~(.+?)~~", r"<del>\1</del>", line))
    return "\n".join(out)


def extract_math(text):
    """Replace math with placeholders, skipping code fences and inline code. Returns the new
    text and the placeholder -> HTML table. `\\$` stays a literal dollar sign."""
    store, out, i, n = {}, [], 0, len(text)

    def keep(html_snippet):
        key = PLACEHOLDER.format(len(store))
        store[key] = html_snippet
        out.append(key)

    while i < n:
        at_line_start = i == 0 or text[i - 1] == "\n"
        if at_line_start and text.startswith("```", i):          # fenced code: copy verbatim
            end = text.find("\n```", i + 3)
            end = n if end < 0 else text.find("\n", end + 4)
            end = n if end < 0 else end
            out.append(text[i:end])
            i = end
        elif text[i] == "`":                                       # inline code span
            run = len(text[i:]) - len(text[i:].lstrip("`"))
            end = text.find("`" * run, i + run)
            end = i + run if end < 0 else end + run
            out.append(text[i:end])
            i = end
        elif text.startswith("\\$", i):
            keep("$")
            i += 2
        elif text.startswith("$$", i):
            end = text.find("$$", i + 2)
            if end < 0:
                out.append(text[i:])
                break
            keep("\\[" + html.escape(text[i + 2:end].strip()) + "\\]")
            i = end + 2
        elif text[i] == "$" and i + 1 < n and not text[i + 1].isspace():
            j = i + 1
            while j < n:
                if text[j] == "$" and text[j - 1] != "\\" and not text[j - 1].isspace() \
                        and not (j + 1 < n and text[j + 1].isdigit()):
                    break
                if text.startswith("\n\n", j):
                    j = n
                    break
                j += 1
            if j < n:
                keep("\\(" + html.escape(text[i + 1:j]) + "\\)")
                i = j + 1
            else:
                out.append("$")
                i += 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out), store


def github_slug(value, separator):
    """Heading ids the way GitHub makes them, so the notes' #anchors keep working."""
    value = re.sub(r"[^\w\- ]", "", value.strip().lower())
    return value.replace(" ", separator)


# ---------------------------------------------------------------- HTML post-processing
def restore_math(body, store):
    for key, snippet in store.items():
        if snippet.startswith("\\["):
            body = body.replace(f"<p>{key}</p>", f'<div class="math-display">{snippet}</div>')
        body = body.replace(key, snippet)
    return body


def rewrite_links(body):
    """.md links -> .html (README.md -> index.html); other relative links gain one ../
    because html/ mirrors the source tree one level down."""
    def fix(m):
        href = m.group(1)
        if re.match(r"^([a-z]+:|#|//)", href):
            return m.group(0)
        path, _, frag = href.partition("#")
        if path.endswith(".md"):
            path = re.sub(r"(^|/)README\.md$", r"\1index.html", path)
            path = path[:-3] + ".html" if path.endswith(".md") else path
        else:
            path = "../" + path
        return f'href="{path}{"#" + frag if frag else ""}"'
    return re.sub(r'href="([^"]*)"', fix, body)


def wrap_tables(body):
    return body.replace("<table>", '<div class="table-wrap"><table>').replace("</table>", "</table></div>")


# ---------------------------------------------------------------- page assembly
def out_path(page):
    return OUT / ("index.html" if page == "README.md" else page[:-3] + ".html")


def rel(from_page, to_page):
    depth = from_page.count("/")
    target = out_path(to_page).relative_to(OUT).as_posix()
    return "../" * depth + target


def title_of(page):
    first = next(l for l in (ROOT / page).read_text().splitlines() if l.startswith("# "))
    return re.sub(r"[*`$]", "", first[2:]).strip()


def nav(page, titles):
    items = []
    for p in PAGES:
        if p == "deep_dives/ckks.md":
            items.append('<li class="nav-group">Deep dives</li>')
        cls = ' class="current"' if p == page else ""
        label = "Overview" if p == "README.md" else titles[p]
        items.append(f'<li{cls}><a href="{rel(page, p)}">{html.escape(label)}</a></li>')
    return "\n".join(items)


def render(page, titles):
    text = normalize_blocks((ROOT / page).read_text())
    text, store = extract_math(text)
    md = markdown.Markdown(
        extensions=["tables", "fenced_code", "codehilite", "toc", "sane_lists"],
        extension_configs={
            "codehilite": {"guess_lang": False, "css_class": "highlight"},
            "toc": {"slugify": github_slug, "permalink": "#", "permalink_title": "Link to this section",
                    "toc_depth": "2-3"},
        })
    body = wrap_tables(rewrite_links(restore_math(md.convert(text), store)))
    toc = restore_math(md.toc, store)
    idx = PAGES.index(page)
    prev_link = f'<a href="{rel(page, PAGES[idx - 1])}">← {html.escape(titles[PAGES[idx - 1]])}</a>' if idx else "<span></span>"
    next_link = f'<a href="{rel(page, PAGES[idx + 1])}">{html.escape(titles[PAGES[idx + 1]])} →</a>' if idx + 1 < len(PAGES) else "<span></span>"
    css = "../" * page.count("/") + "assets/style.css"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(titles[page])}</title>
<link rel="stylesheet" href="{KATEX}/katex.min.css">
<link rel="stylesheet" href="{css}">
{RENDER_MATH}
<script defer src="{KATEX}/katex.min.js"></script>
<script defer src="{KATEX}/contrib/auto-render.min.js" onload="renderMath()"></script>
</head>
<body>
<nav class="sidebar">
<a class="brand" href="{rel(page, 'README.md')}">Homomorphic Encryption</a>
<ul>
{nav(page, titles)}
</ul>
</nav>
<main>
<details class="page-toc"><summary>On this page</summary>{toc}</details>
<article>
{body}
</article>
<footer class="pager">{prev_link}{next_link}</footer>
</main>
</body>
</html>
"""


STYLE = """
:root { --bg: #ffffff; --fg: #1f2328; --muted: #59636e; --line: #d1d9e0; --soft: #f6f8fa;
        --accent: #0969da; --nav-bg: #f6f8fa; --code-bg: #f6f8fa; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --line: #3d444d; --soft: #151b23;
          --accent: #4493f8; --nav-bg: #010409; --code-bg: #151b23; }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--bg); color: var(--fg); display: flex; min-height: 100vh;
       font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.sidebar { width: 270px; flex-shrink: 0; background: var(--nav-bg); border-right: 1px solid var(--line);
           padding: 20px 14px; position: sticky; top: 0; height: 100vh; overflow-y: auto; font-size: 14px; }
.sidebar .brand { display: block; font-weight: 700; color: var(--fg); margin: 0 6px 12px; font-size: 15px; }
.sidebar ul { list-style: none; margin: 0; padding: 0; }
.sidebar li a { display: block; padding: 4px 8px; border-radius: 6px; color: var(--fg); }
.sidebar li a:hover { background: var(--soft); text-decoration: none; }
.sidebar li.current a { background: var(--accent); color: #fff; }
.sidebar .nav-group { margin: 14px 8px 4px; color: var(--muted); font-size: 12px; font-weight: 600;
                      text-transform: uppercase; letter-spacing: .04em; }
main { flex: 1; min-width: 0; padding: 28px 40px 60px; max-width: 980px; }
article { overflow-wrap: break-word; }
h1, h2, h3, h4 { line-height: 1.25; margin: 1.6em 0 .6em; }
h1 { font-size: 2em; margin-top: .4em; }
h2 { font-size: 1.5em; padding-bottom: .3em; border-bottom: 1px solid var(--line); }
h3 { font-size: 1.2em; }
.headerlink { margin-left: .4em; opacity: 0; font-weight: 400; }
h1:hover .headerlink, h2:hover .headerlink, h3:hover .headerlink, h4:hover .headerlink { opacity: .6; }
hr { border: 0; border-top: 1px solid var(--line); margin: 2em 0; }
code { font: .88em/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background: var(--code-bg);
       padding: .15em .35em; border-radius: 5px; }
pre { background: var(--code-bg); border: 1px solid var(--line); border-radius: 8px; padding: 14px 16px;
      overflow-x: auto; line-height: 1.45; }
pre code { background: none; padding: 0; font-size: .85em; }
.highlight { background: none; }
blockquote { margin: 1em 0; padding: .4em 1em; border-left: 4px solid var(--accent); background: var(--soft);
             border-radius: 0 8px 8px 0; color: var(--fg); }
blockquote p { margin: .4em 0; }
.table-wrap { overflow-x: auto; margin: 1em 0; }
table { border-collapse: collapse; font-size: .93em; }
th, td { border: 1px solid var(--line); padding: 6px 12px; vertical-align: top; }
th { background: var(--soft); text-align: left; }
.math-display { overflow-x: auto; overflow-y: hidden; margin: 1em 0; }
.katex-display { overflow-x: auto; overflow-y: hidden; }
.page-toc { border: 1px solid var(--line); border-radius: 8px; padding: 8px 14px; margin-bottom: 8px;
            font-size: 14px; background: var(--soft); }
.page-toc summary { cursor: pointer; color: var(--muted); font-weight: 600; }
.page-toc ul { margin: 6px 0; padding-left: 18px; }
.pager { display: flex; justify-content: space-between; gap: 16px; margin-top: 48px; padding-top: 16px;
         border-top: 1px solid var(--line); font-size: 14px; }
@media (max-width: 860px) {
  body { display: block; }
  .sidebar { position: static; width: auto; height: auto; border-right: 0; border-bottom: 1px solid var(--line); }
  .sidebar ul { display: flex; flex-wrap: wrap; gap: 2px; }
  .sidebar .nav-group { width: 100%; }
  main { padding: 20px 16px 48px; }
}
"""


def build():
    titles = {p: title_of(p) for p in PAGES}
    (OUT / "assets").mkdir(parents=True, exist_ok=True)
    light = HtmlFormatter(style="friendly").get_style_defs(".highlight")
    dark = HtmlFormatter(style="github-dark").get_style_defs(".highlight")
    (OUT / "assets" / "style.css").write_text(
        STYLE + light + "\n@media (prefers-color-scheme: dark) {\n" + dark + "\n}\n")
    for page in PAGES:
        target = out_path(page)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render(page, titles))
        print("wrote", target.relative_to(ROOT))


if __name__ == "__main__":
    build()
