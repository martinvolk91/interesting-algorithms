# Figures

The HTML version of these notes has interactive figures and drawn diagrams. The Markdown stays
the source of the text; each figure lives here as its own file, and `build_html.py` puts it into
the generated page.

## Adding a figure

1. In the Markdown, put a marker on a line of its own, with a blank line above and below, right
   after the paragraph the figure illustrates:

   ```markdown
   <!-- figure: p7-decryption-wheel -->
   ```

   GitHub hides the comment, so the Markdown reads exactly as before. To redraw an ASCII diagram,
   use `<!-- figure: n03-sector-wheel replaces the code block below -->` directly above its
   fenced block: the HTML shows the figure instead, GitHub still shows the ASCII.

2. Write `figures/<name>.html`. Names start with the page's prefix: `p1-` … `p9-` for the
   primer, `n01-` … `n09-` for chapters 01–09, `dd-ckks-`, `dd-tfhe-`, `dd-pir-`,
   `dd-threshold-`, `dd-hw-`, `dd-cpad-` for the deep dives.

3. `python3 build_html.py`, then `python3 check_figures.py --out <dir> <page.md>` and look at
   the screenshots (light, dark, phone width).

## Interactive figure

```html
<figure class="widget" id="w-p7-decryption-wheel">
  <p class="widget-title">The decryption wheel</p>
  <p class="widget-hint">Drag the noise up until the dot lands in the wrong sector.</p>
  <div class="controls"></div>                        <!-- controls go ABOVE charts -->
  <div class="widget-grid">                           <!-- optional: panels side by side -->
    <div><p class="panel-title">Left panel</p><div class="c-left"></div></div>
    <div><p class="panel-title">Right panel</p><div class="c-right"></div></div>
  </div>
  <div class="readout"></div>                         <!-- DS.stats / DS.table output -->
  <figcaption>What the reader should notice, in one or two sentences.</figcaption>
</figure>
<script>
(() => {                      // always wrap: several figures share one page
  const root = '#w-p7-decryption-wheel';
  const ui = DS.controls(root + ' .controls', () => { left.update(); readout(); });
  const noise = ui.slider({ label: 'Noise', min: 0, max: 40, step: 1, value: 5 });
  const left = DS.chart(root + ' .c-left', { x: { domain: [0, 1] }, y: { domain: [0, 1] }, draw(c) { … } });
  function readout() { DS.stats(root + ' .readout', [{ label: 'Decrypts to', value: '1', tone: 'good' }]); }
  readout();
})();
</script>
```

- The element id is `w-<name>`, and every selector is scoped to it.
- Every figure teaches one point better than prose: one or two controls, an obvious thing to try
  (say it in `widget-hint`), and a default state that already shows the point.
- Use the chapter's own numbers (P7's q = 97, t = 4, Δ = 24; P8's N = 16, t = 16, q = 2^60 …).
  Every number shown must be computed, and the default view must agree with the chapter text.
- Seed randomness: `DS.random(seed)`. A "Resample" button may change the seed.
- Math: KaTeX renders `\( … \)` and `\[ … \]` in the static HTML of a figure (title, hint,
  caption, panel titles). Text the script writes at run time is not re-rendered, so use plain
  Unicode there: Δ, σ, ≈, ⌊x⌉, ·, ×, ², ₁.
- Precompute heavy work once, outside `draw()`, which runs on every slider tick.
- Widths are fluid. Charts redraw themselves on resize; any custom SVG uses a `viewBox`.
- Don't edit `charts.js` or `figures.css`. If the kit lacks something, draw plain SVG inside
  your own figure's script.

### The chart kit (`charts.js`, global `DS`, from data-science-learn)

```js
const ui = DS.controls(sel, onChange);
const t  = ui.slider({ label: 'Threshold', min: 0, max: 1, step: 0.01, value: 0.5, format: v => v.toFixed(2) });
const lr = ui.slider({ label: 'Rate', min: 0.001, max: 1, value: 0.1, log: true });           // log slider
const n  = ui.slider({ label: 'Size', values: [100, 300, 1000, 3000], value: 1000 });         // fixed list
const v  = ui.choice({ label: 'Show', options: ['ROC', 'PR'], value: 'ROC' });                // segmented buttons
const s  = ui.select({ label: 'Dataset', options: [{ value: 'a', label: 'Fraud' }] });
const on = ui.toggle({ label: 'Show line', value: true });
ui.button({ label: 'Resample', onClick: () => { seed++; } });                                 // onChange fires after
// read current values with t.value, v.value, on.value …

const chart = DS.chart(sel, {
  x: { domain: [0, 1], label: 'x' },     // type: 'linear' (default) | 'log' | 'band' (categories)
  y: { domain: [0, 60], label: 'y' },    // format: v => …, ticks: 5, tickValues: [...]
  height: 260,                           // px (default 300); or equal: true for equal x/y units
  draw(c) {                              // runs on every update() and on resize
    c.domain({ y: [0, max], yLabel: 'Count' });          // change domains/labels BEFORE drawing marks
    c.histogram(values, { range: [0, 1], bins: 25, series: 1 });
    c.line([[x, y], …], { series: 2, label: 'Positives' });   // label → crosshair tooltip
    c.fn(x => Math.exp(-x), { series: 3, label: 'e^-x', n: 200 });
    c.area(pts, { series: 1 });  c.area(upper, { lower: lowerPts, series: 1 });
    c.scatter(points, { series: 1, r: 4, tip: p => `x ${p.x}` });   // [[x,y]] or [{x,y,series,tip}]
    c.bars([{ x: 'A', y: 3, tip: 'A: 3' }], { series: 1 });
    c.point(x, y, { series: 2, label: 'you are here' });
    c.vline(x, { label: 'threshold', series: 'ink' });  c.hline(0.5, { dash: true, label: 'chance' });
    c.segment(0, 0, 1, 1, { series: 'muted', dash: true, thin: true });
    c.arrow(x0, y0, x1, y1, { series: 'ink', label: 'gradient' });
    c.polygon([[0,0],[1,0],[1,1]], { series: 3 });
    c.text(x, y, 'label', { anchor: 'middle', dy: -8, cls: 'ink strong' });
    c.heatmap((x, y) => f(x, y), { nx: 60, ny: 40 });    // diverging: true for ± data
    c.contour((x, y) => f(x, y), { levels: [0.1, 0.5, 1] });
    c.errorbars([{ x: 1, lo: 0.2, hi: 0.6, y: 0.4 }], { series: 1 });
    c.legend([{ label: 'A', series: 1, kind: 'rect' }, { label: 'B', series: 2 }]);
  },
});
chart.onPointer({ click(x, y) { …; chart.update(); } });   // or drag(x, y) for draggable points

DS.stats(sel, [{ label: 'Noise budget', value: '12 bits', note: '…', tone: 'good' | 'bad' }]);
DS.table(sel, { columns: ['', 'A', 'B'], rows: [[{ text: 'Row', th: true }, '1', '2']] });
const R = DS.random(42);  R.uniform(); R.normal(mu, sd); R.int(n); R.shuffle(arr);
DS.math: linspace, range, sum, mean, variance, sd, quantile, clamp, sigmoid, erf, normalPdf, normalCdf, …
DS.fmt(v[, digits]) → number with a real minus sign;  DS.pct(0.123) → "12.3%"
```

Read `charts.js` itself for the exact options; the data-science-learn chapters
(`~/Projects/data-science-learn/chapters/*.html`, the `<script>` at the bottom of each) have
dozens of worked examples.

- **Colours** are series numbers 1–8: 1 blue, 2 orange, 3 aqua, 4 yellow, 5 pink, 6 green,
  7 violet, 8 red, plus `'muted'`, `'ink'`, `'good'`, `'bad'`. Series 1 is the main thing, 2 the
  contrast; `'good'`/`'bad'` for decrypts correctly / fails. Keep a meaning fixed within a page.
  At most 3–4 series per chart; a legend for two or more. Never colour text with a series colour.

## Static diagram

For a picture with nothing to drag (a circuit, a data flow, a pipeline), write inline SVG:

```html
<figure class="diagram" id="d-p6-chain-vs-tree">
  <svg viewBox="0 0 720 240" role="img" aria-label="…">
    <rect … fill="none" stroke="var(--line-strong)"/>
    <path … stroke="var(--series-1)"/>
    <text x="…" y="…">Label</text>              <!-- text is currentColor (the page ink) -->
  </svg>
  <figcaption>…</figcaption>
</figure>
```

Use `viewBox` (never a fixed pixel width), `currentColor` and the CSS variables
(`var(--series-1)` … `var(--series-8)`, `var(--line)`, `var(--line-strong)`, `var(--muted)`,
`var(--soft)`, `var(--bg)`), so it works in dark mode. Keep text at 12–14 px in viewBox units
and check the phone screenshot: a 720-wide viewBox shrinks to about half on a phone.
