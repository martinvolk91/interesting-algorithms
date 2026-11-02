"""Render figures in headless Chrome: report JavaScript errors and save screenshots.

    python3 build_html.py
    python3 check_figures.py p7-decryption-wheel p7-lattice-basis   # figures by name
    python3 check_figures.py primer/p7_lattices_and_lwe.md           # every figure on a page
    python3 check_figures.py --out /tmp/shots ...                    # default: ./figure-shots

Each figure is put alone on a page with the site's styles, then shot at desktop width in light
and dark mode and at phone width: <out>/<name>-light.png, -dark.png, -phone.png. Pages given as
.md files are also loaded whole, to catch errors from figures clashing with each other.
"""
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).parent
HTML = ROOT / "html"
PREVIEW = HTML / "_preview"
MARKER = re.compile(r"^<!-- figure: ([a-z0-9][a-z0-9-]*)( replaces the code block below)? -->[ \t]*$", re.M)
KATEX = "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist"
SHELL = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="{katex}/katex.min.css">
<link rel="stylesheet" href="../assets/style.css"><link rel="stylesheet" href="../assets/figures.css">
<script src="../assets/charts.js"></script>
<script defer src="{katex}/katex.min.js"></script>
<script defer src="{katex}/contrib/auto-render.min.js"
  onload="renderMathInElement(document.body, {{delimiters: [{{left: '\\\\[', right: '\\\\]', display: true}},
  {{left: '\\\\(', right: '\\\\)', display: false}}], throwOnError: false}})"></script>
</head><body><main><article>
{figure}
</article></main></body></html>
"""
SHOTS = [("light", "--window-size=1020,1100", []),
         ("dark", "--window-size=1020,1100", ["--blink-settings=preferredColorScheme=0"]),
         ("phone", "--window-size=390,1400", [])]


def chrome(*args):
    with tempfile.TemporaryDirectory() as profile:
        return subprocess.run(
            ["google-chrome", "--headless=new", "--disable-gpu", "--no-sandbox", "--hide-scrollbars",
             "--virtual-time-budget=5000", f"--user-data-dir={profile}", *args],
            capture_output=True, text=True, timeout=120)


def console_errors(url):
    run = chrome("--enable-logging=stderr", "--v=0", "--dump-dom", url)
    return [l for l in run.stderr.splitlines() if "CONSOLE" in l or "Uncaught" in l]


def main(argv):
    out = Path("figure-shots")
    if "--out" in argv:
        i = argv.index("--out")
        out = Path(argv[i + 1])
        argv = argv[:i] + argv[i + 2:]
    names, pages = [], []
    for arg in argv:
        if arg.endswith(".md"):
            pages.append(arg)
            names += [m.group(1) for m in MARKER.finditer((ROOT / arg).read_text())]
        else:
            names.append(arg)
    if not names:
        sys.exit(__doc__)
    out.mkdir(parents=True, exist_ok=True)
    PREVIEW.mkdir(exist_ok=True)
    jobs, checks = [], []
    for name in names:
        source = ROOT / "figures" / f"{name}.html"
        if not source.exists():
            sys.exit(f"no figures/{name}.html")
        page = PREVIEW / f"{name}.html"
        page.write_text(SHELL.format(katex=KATEX, figure=source.read_text()))
        url = page.resolve().as_uri()
        checks.append((name, url))
        for mode, size, extra in SHOTS:
            jobs.append((size, *extra, f"--screenshot={(out / f'{name}-{mode}.png').resolve()}", url))
    for page in pages:
        target = HTML / Path(page).with_suffix(".html")
        if page.endswith("README.md"):
            target = HTML / "index.html"
        checks.append((page, target.resolve().as_uri()))
    with ThreadPoolExecutor(8) as pool:
        errors = list(pool.map(lambda c: (c[0], console_errors(c[1])), checks))
        list(pool.map(lambda j: chrome(*j), jobs))
    shutil.rmtree(PREVIEW, ignore_errors=True)
    bad = [(what, errs) for what, errs in errors if errs]
    for what, errs in bad:
        print(f"ERRORS in {what}:\n  " + "\n  ".join(errs))
    if not bad:
        print(f"No JavaScript errors in {len(checks)} check(s).")
    print(f"Saved {len(jobs)} screenshots to {out}/ (<name>-light|dark|phone.png)")


if __name__ == "__main__":
    main(sys.argv[1:])
