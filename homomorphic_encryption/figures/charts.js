/* DS: a small SVG chart kit for the book's interactive figures (no dependencies).

   const fig = DS.chart('#el', {
     x: { domain: [0, 1], label: 'False positive rate' },     // type: 'linear' | 'log' | 'band'
     y: { domain: [0, 1], label: 'True positive rate' },
     height: 300,                 // px; or equal: true for equal x/y units
     draw(c) { c.line(points, { series: 1, label: 'ROC' }); },
   });
   const ui = DS.controls('#el-controls', () => fig.update());
   const t = ui.slider({ label: 'Threshold', min: 0, max: 1, step: 0.01, value: 0.5 });
   // read t.value inside draw()

   Colors are CSS classes (series 1–8, 'muted', 'ink', 'good', 'bad'), so the theme toggle
   restyles every chart without a redraw. Charts re-render themselves when their width changes. */
(function () {
  'use strict';
  const NS = 'http://www.w3.org/2000/svg';

  // ---------------------------------------------------------------- small helpers
  function svgEl(tag, attrs, parent) {
    const e = document.createElementNS(NS, tag);
    if (attrs) for (const k in attrs) if (attrs[k] !== undefined && attrs[k] !== null) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function htmlEl(tag, cls, parent, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    if (parent) parent.appendChild(e);
    return e;
  }
  function resolve(t) {
    const e = typeof t === 'string' ? document.querySelector(t) : t;
    if (!e) throw new Error('DS: element not found: ' + t);
    return e;
  }
  function seriesClass(s, kind) {          // kind 's' = stroke, 'f' = fill
    if (s === undefined || s === null) s = 1;
    return kind + s;
  }
  const r2 = v => Math.round(v * 100) / 100;

  // ---------------------------------------------------------------- number formatting
  const MINUS = '−';
  function fmt(v, digits) {
    if (v === null || v === undefined || Number.isNaN(v)) return '–';
    if (!isFinite(v)) return v > 0 ? '∞' : MINUS + '∞';
    let s;
    if (digits !== undefined) s = v.toFixed(digits);
    else {
      const a = Math.abs(v);
      if (a === 0) s = '0';
      else if (a >= 1e9) s = trim((v / 1e9).toFixed(1)) + 'B';
      else if (a >= 1e6) s = trim((v / 1e6).toFixed(1)) + 'M';
      else if (a >= 1e4) s = trim((v / 1e3).toFixed(0)) + 'K';
      else if (a >= 1000) s = trim((v / 1e3).toFixed(1)) + 'K';
      else if (a >= 100) s = v.toFixed(0);
      else if (a >= 10) s = trim(v.toFixed(1));
      else if (a >= 1) s = trim(v.toFixed(2));
      else if (a >= 0.001) s = trim(v.toFixed(3));
      else s = v.toExponential(1);
    }
    return s.replace('-', MINUS);
  }
  function trim(s) { return s.indexOf('.') >= 0 ? s.replace(/0+$/, '').replace(/\.$/, '') : s; }
  function pct(v, digits) { return fmt(v * 100, digits === undefined ? 1 : digits) + '%'; }

  function niceStep(span, n) {
    const raw = span / Math.max(1, n);
    const p = Math.pow(10, Math.floor(Math.log10(raw)));
    const f = raw / p;
    return (f < 1.5 ? 1 : f < 3 ? 2 : f < 7 ? 5 : 10) * p;
  }
  function linearTicks(lo, hi, n) {
    if (hi === lo) return { values: [lo], step: 1 };
    const step = niceStep(Math.abs(hi - lo), n);
    const a = Math.min(lo, hi), b = Math.max(lo, hi);
    const out = [];
    for (let v = Math.ceil(a / step - 1e-9) * step; v <= b + step * 1e-9; v += step) out.push(+v.toPrecision(12));
    return { values: out, step };
  }
  function stepFormat(step) {
    const d = Math.max(0, Math.min(6, -Math.floor(Math.log10(step) + 1e-9)));
    return v => {
      const a = Math.abs(v);
      if (a >= 1e4) return fmt(v);
      return (Math.abs(v) < step / 1e6 ? 0 : v).toFixed(d).replace('-', MINUS);
    };
  }

  // ---------------------------------------------------------------- scales
  function makeScale(spec, range) {
    const type = spec.type || 'linear';
    if (type === 'band') {
      const dom = spec.domain, n = dom.length, pad = spec.padding === undefined ? 0.3 : spec.padding;
      const step = (range[1] - range[0]) / n;
      const f = v => range[0] + step * (dom.indexOf(v) + 0.5);
      Object.assign(f, { type, domain: dom, range, step, bandwidth: Math.abs(step) * (1 - pad), invert: px => dom[Math.max(0, Math.min(n - 1, Math.floor((px - range[0]) / step)))] });
      return f;
    }
    const [d0, d1] = spec.domain;
    if (type === 'log') {
      const l0 = Math.log10(d0), l1 = Math.log10(d1);
      const k = (range[1] - range[0]) / (l1 - l0);
      const f = v => range[0] + (Math.log10(v) - l0) * k;
      Object.assign(f, { type, domain: spec.domain, range, invert: px => Math.pow(10, l0 + (px - range[0]) / k) });
      return f;
    }
    const k = (range[1] - range[0]) / ((d1 - d0) || 1);
    const f = v => range[0] + (v - d0) * k;
    Object.assign(f, { type, domain: spec.domain, range, invert: px => d0 + (px - range[0]) / k, k });
    return f;
  }
  function scaleTicks(scale, spec, pixels) {
    if (scale.type === 'band') return scale.domain.map(v => ({ v, label: spec.format ? spec.format(v) : String(v) }));
    if (scale.type === 'log') {
      const out = [];
      const lo = Math.floor(Math.log10(scale.domain[0]) + 1e-9), hi = Math.ceil(Math.log10(scale.domain[1]) - 1e-9);
      for (let e = lo; e <= hi; e++) {
        const v = Math.pow(10, e);
        if (v >= scale.domain[0] * (1 - 1e-9) && v <= scale.domain[1] * (1 + 1e-9)) out.push({ v, label: spec.format ? spec.format(v) : fmt(v) });
      }
      return out;
    }
    const n = spec.ticks || Math.max(2, Math.round(pixels / 80));
    const t = Array.isArray(spec.tickValues) ? { values: spec.tickValues, step: 1 } : linearTicks(scale.domain[0], scale.domain[1], n);
    const f = spec.format || stepFormat(t.step);
    return t.values.map(v => ({ v, label: f(v) }));
  }

  // ---------------------------------------------------------------- the chart
  let uid = 0;
  class Chart {
    constructor(target, opts) {
      this.o = Object.assign({ height: 300 }, opts);
      this.o.x = Object.assign({ domain: [0, 1] }, this.o.x);
      this.o.y = Object.assign({ domain: [0, 1] }, this.o.y);
      this.id = 'dsc' + (++uid);
      this.host = resolve(target);
      this.root = htmlEl('div', 'ds-chart', this.host);
      this.legendEl = htmlEl('div', 'ds-legend', this.root);
      this.wrap = htmlEl('div', 'ds-svgwrap', this.root);
      this.svg = svgEl('svg', { class: 'ds-svg', role: 'img', tabindex: 0 }, this.wrap);
      if (this.o.ariaLabel) this.svg.setAttribute('aria-label', this.o.ariaLabel);
      this.tip = htmlEl('div', 'ds-tip', this.wrap);
      this.tip.setAttribute('aria-hidden', 'true');
      this._domain = { x: this.o.x.domain.slice(), y: this.o.y.domain.slice() };
      this._bindPointer();
      this._lastW = 0;
      if ('ResizeObserver' in window) {
        this._ro = new ResizeObserver(() => {
          const w = this.wrap.clientWidth;
          if (w && Math.abs(w - this._lastW) > 2) this.update();
        });
        this._ro.observe(this.wrap);
      }
      this.update();
    }

    /* Change axis domains and/or labels: c.domain({ x: [0, 5], yLabel: 'Loss' }).
       Call before drawing marks (e.g. at the top of draw()). */
    domain(d) {
      if (d.x) this._domain.x = d.x.slice();
      if (d.y) this._domain.y = d.y.slice();
      if (d.xLabel !== undefined) this.o.x.label = d.xLabel;
      if (d.yLabel !== undefined) this.o.y.label = d.yLabel;
      this._layout();
      return this;
    }

    _layout() {
      const W = Math.max(240, this.wrap.clientWidth || 640);
      const ox = this.o.x, oy = this.o.y;
      const m = Object.assign({ t: 12, r: 16, b: ox.label ? 46 : 28, l: oy.label ? 60 : 46 }, this.o.margin);
      const mo = this.o.margin || {};
      if (ox.hidden && mo.b === undefined) m.b = Math.min(m.b, 12);
      if (oy.hidden && mo.l === undefined) m.l = Math.min(m.l, 12);
      let H = typeof this.o.height === 'function' ? this.o.height(W) : this.o.height;
      if (this.o.equal && ox.type !== 'band') {
        const xs = this._domain.x[1] - this._domain.x[0], ys = this._domain.y[1] - this._domain.y[0];
        H = (W - m.l - m.r) * ys / xs + m.t + m.b;
        const maxH = this.o.maxHeight || 460;
        if (H > maxH) {                        // too tall: widen the x-range to keep units equal
          H = maxH;
          const need = (W - m.l - m.r) * ys / (H - m.t - m.b);
          const c = (this._domain.x[0] + this._domain.x[1]) / 2;
          this._domain.x = [c - need / 2, c + need / 2];
        }
        const minH = this.o.minHeight || 240;
        if (H < minH) {                        // too short (phones): widen the y-range instead
          H = minH;
          const need = (H - m.t - m.b) * xs / (W - m.l - m.r);
          const c = (this._domain.y[0] + this._domain.y[1]) / 2;
          this._domain.y = [c - need / 2, c + need / 2];
        }
      }
      this.W = W; this.H = Math.round(H); this.m = m;
      this.x = makeScale(Object.assign({}, ox, { domain: this._domain.x }), [m.l, W - m.r]);
      this.y = makeScale(Object.assign({}, oy, { domain: this._domain.y }), [this.H - m.b, m.t]);
      this.svg.setAttribute('width', W);
      this.svg.setAttribute('height', this.H);
      this.svg.setAttribute('viewBox', `0 0 ${W} ${this.H}`);
    }

    /* Redraw everything: axes, then the draw() callback. Call this from slider handlers. */
    update() {
      this._domain = { x: this.o.x.domain.slice(), y: this.o.y.domain.slice() };
      this._layout();
      this._lastW = this.wrap.clientWidth;
      while (this.svg.firstChild) this.svg.removeChild(this.svg.firstChild);
      this.gAxes = svgEl('g', null, this.svg);
      this.gData = svgEl('g', null, this.svg);
      this.gHover = svgEl('g', { 'pointer-events': 'none' }, this.svg);
      this._axesDone = false;
      this._clipId = null;                     // the old <defs> was just removed with everything else
      this._lines = []; this._points = [];
      this._hideTip();
      if (this.o.draw) this.o.draw(this);
      this._axes();
      return this;
    }

    // -------------------------------------------------------------- axes and grid
    _axes() {
      if (this._axesDone) return;
      this._axesDone = true;
      const g = this.gAxes, { m, W, H } = this, ox = this.o.x, oy = this.o.y;
      while (g.firstChild) g.removeChild(g.firstChild);
      const grid = svgEl('g', { class: 'grid' }, g), axis = svgEl('g', { class: 'axis' }, g);
      const x0 = m.l, x1 = W - m.r, y0 = H - m.b, y1 = m.t;
      if (!oy.hidden) {
        for (const t of scaleTicks(this.y, oy, y0 - y1)) {
          const py = this.y(t.v);
          if (py < y1 - 0.5 || py > y0 + 0.5) continue;
          if (oy.grid !== false) svgEl('line', { x1: x0, x2: x1, y1: py, y2: py }, grid);
          svgEl('text', { x: x0 - 8, y: py, 'text-anchor': 'end', 'dominant-baseline': 'middle' }, axis).textContent = t.label;
        }
        if (oy.label) {
          const t = svgEl('text', { class: 'axis-label', transform: `translate(${14},${(y0 + y1) / 2}) rotate(-90)`, 'text-anchor': 'middle' }, axis);
          t.textContent = oy.label;
        }
      }
      if (!ox.hidden) {
        const ticks = scaleTicks(this.x, ox, x1 - x0);
        for (const t of ticks) {
          const px = this.x(t.v);
          if (px < x0 - 0.5 || px > x1 + 0.5) continue;
          if (ox.grid === true) svgEl('line', { x1: px, x2: px, y1: y0, y2: y1 }, grid);
          svgEl('line', { x1: px, x2: px, y1: y0, y2: y0 + 4 }, axis);
          svgEl('text', { x: px, y: y0 + 17, 'text-anchor': 'middle' }, axis).textContent = t.label;
        }
        if (ox.label) svgEl('text', { class: 'axis-label', x: (x0 + x1) / 2, y: H - 6, 'text-anchor': 'middle' }, axis).textContent = ox.label;
      }
      // baseline: at y = 0 when it is in range, else at the bottom
      const yd = this._domain.y;
      let by = y0;
      if (this.y.type === 'linear' && yd[0] < 0 && yd[1] > 0 && oy.baseline !== 'bottom') by = this.y(0);
      if (!ox.hidden) svgEl('line', { x1: x0, x2: x1, y1: by, y2: by }, axis);
      if (this.o.y.axisLine) svgEl('line', { x1: x0, x2: x0, y1: y0, y2: y1 }, axis);
      if (this.o.x.zeroLine && this.x.type === 'linear' && this._domain.x[0] < 0 && this._domain.x[1] > 0)
        svgEl('line', { x1: this.x(0), x2: this.x(0), y1: y0, y2: y1 }, axis);
    }

    _clip() {
      if (this._clipId) return `url(#${this._clipId})`;
      this._clipId = this.id + '-clip' + (++uid);
      const defs = svgEl('defs', null, this.gData);
      const cp = svgEl('clipPath', { id: this._clipId }, defs);
      svgEl('rect', { x: this.m.l, y: this.m.t - 1, width: this.W - this.m.l - this.m.r, height: this.H - this.m.t - this.m.b + 2 }, cp);
      return `url(#${this._clipId})`;
    }
    _pathD(pts) {
      let d = '', pen = false;
      for (const p of pts) {
        const X = this.x(p[0]), Y = this.y(p[1]);
        if (!isFinite(X) || !isFinite(Y)) { pen = false; continue; }
        d += (pen ? 'L' : 'M') + r2(X) + ',' + r2(Y);
        pen = true;
      }
      return d;
    }

    // -------------------------------------------------------------- marks
    /* pts: [[x, y], ...]. o: series, label (enables tooltip + legend), dash, thin, thick,
       hover (default true when labelled), format (tooltip value formatter) */
    line(pts, o = {}) {
      this._axes();
      const cls = ['ln', seriesClass(o.series, 's')];
      if (o.dash) cls.push('dash');
      if (o.thin) cls.push('thin');
      if (o.thick) cls.push('thick');
      const p = svgEl('path', { d: this._pathD(pts), class: cls.join(' '), 'clip-path': o.clip === false ? null : this._clip() }, this.gData);
      if (o.label && o.hover !== false) this._lines.push({ pts, o });
      return p;
    }
    /* A function plot: fn(x) sampled n times across the x-domain (or o.from..o.to). */
    fn(f, o = {}) {
      const a = o.from !== undefined ? o.from : this._domain.x[0], b = o.to !== undefined ? o.to : this._domain.x[1];
      const n = o.n || 200, pts = [];
      for (let i = 0; i <= n; i++) { const x = a + (b - a) * i / n; pts.push([x, f(x)]); }
      return this.line(pts, o);
    }
    /* Shaded area between the curve and y0 (default 0), or between two curves with o.lower. */
    area(pts, o = {}) {
      this._axes();
      const lower = o.lower || pts.map(p => [p[0], o.y0 !== undefined ? o.y0 : Math.max(this._domain.y[0], Math.min(0, this._domain.y[1]))]);
      const d = this._pathD(pts) + 'L' + this._pathD(lower.slice().reverse()).slice(1) + 'Z';
      return svgEl('path', { d, class: 'wash ' + (o.strong ? 'strong ' : '') + seriesClass(o.series, 'f'), 'clip-path': this._clip() }, this.gData);
    }
    /* Polygon in data coordinates. o.fill (wash), o.stroke (outline), o.series */
    polygon(pts, o = {}) {
      this._axes();
      const d = this._pathD(pts) + 'Z';
      const g = svgEl('g', null, this.gData);
      if (o.fill !== false) svgEl('path', { d, class: 'wash ' + (o.strong ? 'strong ' : '') + seriesClass(o.series, 'f') }, g);
      if (o.stroke !== false) svgEl('path', { d, class: 'ln ' + (o.dash ? 'dash ' : '') + (o.thin ? 'thin ' : '') + seriesClass(o.series, 's') }, g);
      return g;
    }
    /* pts: [[x, y], ...] or [{x, y, series, label, tip}]. o: series, r, tip(p) → string|rows */
    scatter(pts, o = {}) {
      this._axes();
      const g = svgEl('g', { 'clip-path': o.clip === false ? null : this._clip() }, this.gData);
      const r = o.r || 4;
      for (const raw of pts) {
        const p = Array.isArray(raw) ? { x: raw[0], y: raw[1] } : raw;
        const X = this.x(p.x), Y = this.y(p.y);
        if (!isFinite(X) || !isFinite(Y)) continue;
        const c = svgEl('circle', { cx: r2(X), cy: r2(Y), r: p.r || r, class: 'dot ' + (r < 3.5 ? 'small ' : '') + seriesClass(p.series || o.series, 'f') }, g);
        if (o.opacity) c.setAttribute('fill-opacity', o.opacity);
        if (o.tip || p.tip || p.label) this._points.push({ X, Y, p, o, node: c });
      }
      return g;
    }
    /* A single highlighted marker, optional text label next to it. */
    point(x, y, o = {}) {
      this._axes();
      const X = this.x(x), Y = this.y(y);
      const c = svgEl('circle', { cx: r2(X), cy: r2(Y), r: o.r || 5.5, class: 'dot ' + seriesClass(o.series, 'f') }, this.gData);
      if (o.label) this.text(x, y, o.label, Object.assign({ dx: 9, dy: -8, cls: 'ink strong' }, o.labelOpts));
      if (o.tip) this._points.push({ X, Y, p: { x, y }, o, node: c });
      return c;
    }
    /* items: [{x, y, series, label, tip}] where x is a band category or a number (with o.width in data units).
       Bars grow from o.base (default 0) with a 4px rounded data-end. */
    bars(items, o = {}) {
      this._axes();
      const g = svgEl('g', null, this.gData);
      const base = o.base || 0;
      for (const it of items) {
        let cx, w;
        if (this.x.type === 'band') { cx = this.x(it.x); w = Math.min(o.maxWidth || 28, this.x.bandwidth); }
        else {
          const half = (it.width || o.width || 1) / 2;
          const a = this.x(it.x - half), b = this.x(it.x + half);
          cx = (a + b) / 2; w = Math.max(1, Math.abs(b - a) - (o.gap === undefined ? 2 : o.gap));
        }
        const yb = this.y(base), yv = this.y(it.y);
        const node = svgEl('path', { d: roundedBar(cx - w / 2, w, yb, yv, Math.min(4, w / 2)), class: 'bar ' + seriesClass(it.series || o.series, 'f') }, g);
        if (o.opacity || it.opacity) node.setAttribute('fill-opacity', it.opacity || o.opacity);
        if (o.tip || it.tip || it.label !== undefined) this._points.push({ X: cx, Y: Math.min(yb, yv), p: it, o, node, bar: { x0: cx - w / 2, x1: cx + w / 2, y0: Math.min(yb, yv), y1: Math.max(yb, yv) } });
      }
      return g;
    }
    /* Histogram of raw values. o: bins (count) or edges, range [lo, hi], density, series, tip.
       Returns the bin table [{x0, x1, count, y}] so the caller can label or reuse it. */
    histogram(values, o = {}) {
      const lo = o.range ? o.range[0] : Math.min(...values), hi = o.range ? o.range[1] : Math.max(...values);
      const edges = o.edges || DS.math.linspace(lo, hi, (o.bins || 20) + 1);
      const bins = [];
      for (let i = 0; i < edges.length - 1; i++) bins.push({ x0: edges[i], x1: edges[i + 1], count: 0 });
      for (const v of values) {
        if (v < edges[0] || v > edges[edges.length - 1]) continue;
        let i = Math.min(bins.length - 1, Math.floor((v - edges[0]) / (edges[1] - edges[0])));
        if (o.edges) { i = bins.findIndex(b => v >= b.x0 && v < b.x1); if (i < 0) i = bins.length - 1; }
        bins[i].count++;
      }
      const n = values.length;
      for (const b of bins) b.y = o.density ? b.count / (n * (b.x1 - b.x0)) : b.count;
      if (o.draw !== false) {
        this.bars(bins.map(b => ({ x: (b.x0 + b.x1) / 2, width: b.x1 - b.x0, y: b.y, series: o.series,
          tip: o.tip ? o.tip(b) : `${fmt(b.x0)} to ${fmt(b.x1)}: ${b.count}` })), { series: o.series, opacity: o.opacity, gap: o.gap });
      }
      return bins;
    }
    /* Error bars: items [{x, lo, hi, y?, tip}] — a vertical interval with caps, and a dot at y if given. */
    errorbars(items, o = {}) {
      this._axes();
      const g = svgEl('g', null, this.gData);
      const cap = o.cap === undefined ? 5 : o.cap;
      for (const it of items) {
        const X = this.x(it.x), Y0 = this.y(it.lo), Y1 = this.y(it.hi);
        const cls = 'ln thin ' + seriesClass(it.series || o.series, 's');
        svgEl('line', { x1: X, x2: X, y1: Y0, y2: Y1, class: cls }, g);
        svgEl('line', { x1: X - cap, x2: X + cap, y1: Y0, y2: Y0, class: cls }, g);
        svgEl('line', { x1: X - cap, x2: X + cap, y1: Y1, y2: Y1, class: cls }, g);
        let node = null;
        if (it.y !== undefined) node = svgEl('circle', { cx: X, cy: this.y(it.y), r: o.r || 4, class: 'dot ' + seriesClass(it.series || o.series, 'f') }, g);
        if (it.tip || o.tip) this._points.push({ X, Y: it.y !== undefined ? this.y(it.y) : (Y0 + Y1) / 2, p: it, o, node: node || { getAttribute: () => 4 } });
      }
      return g;
    }
    /* Reference lines. o: label, series (default muted), dash, labelPos ('top'|'bottom'), at (for hline: 'left'|'right') */
    vline(x, o = {}) {
      this._axes();
      const X = this.x(x);
      if (!isFinite(X)) return null;
      const cls = 'ln thin ' + (o.dash ? 'dash ' : '') + seriesClass(o.series === undefined ? 'muted' : o.series, 's');
      const l = svgEl('line', { x1: X, x2: X, y1: this.m.t, y2: this.H - this.m.b, class: cls }, this.gData);
      if (o.label) {
        const right = X > this.W - this.m.r - 80;
        const t = svgEl('text', { x: X + (right ? -5 : 5), y: o.labelPos === 'bottom' ? this.H - this.m.b - 6 : this.m.t + 11,
          'text-anchor': right ? 'end' : 'start', class: 'ink2' }, this.gData);
        t.textContent = o.label;
      }
      return l;
    }
    hline(y, o = {}) {
      this._axes();
      const Y = this.y(y);
      if (!isFinite(Y)) return null;
      const cls = 'ln thin ' + (o.dash ? 'dash ' : '') + seriesClass(o.series === undefined ? 'muted' : o.series, 's');
      const l = svgEl('line', { x1: this.m.l, x2: this.W - this.m.r, y1: Y, y2: Y, class: cls }, this.gData);
      if (o.label) {
        const left = o.at === 'left';
        const t = svgEl('text', { x: left ? this.m.l + 5 : this.W - this.m.r - 5, y: Y - 5, 'text-anchor': left ? 'start' : 'end', class: 'ink2' }, this.gData);
        t.textContent = o.label;
      }
      return l;
    }
    /* Line segment and arrow in data coordinates. */
    segment(x0, y0, x1, y1, o = {}) {
      this._axes();
      return svgEl('line', { x1: this.x(x0), y1: this.y(y0), x2: this.x(x1), y2: this.y(y1),
        class: 'ln ' + (o.dash ? 'dash ' : '') + (o.thin ? 'thin ' : '') + seriesClass(o.series, 's') }, this.gData);
    }
    arrow(x0, y0, x1, y1, o = {}) {
      this._axes();
      const X0 = this.x(x0), Y0 = this.y(y0), X1 = this.x(x1), Y1 = this.y(y1);
      const len = Math.hypot(X1 - X0, Y1 - Y0);
      const g = svgEl('g', null, this.gData);
      if (len < 1) return g;
      const ux = (X1 - X0) / len, uy = (Y1 - Y0) / len, h = Math.min(o.head || 9, len * 0.6), w = h * 0.55;
      const bx = X1 - ux * h, by = Y1 - uy * h;
      svgEl('line', { x1: X0, y1: Y0, x2: bx, y2: by, class: 'ln ' + (o.thin ? 'thin ' : '') + seriesClass(o.series, 's') }, g);
      svgEl('path', { d: `M${r2(X1)},${r2(Y1)}L${r2(bx - uy * w)},${r2(by + ux * w)}L${r2(bx + uy * w)},${r2(by - ux * w)}Z`, class: seriesClass(o.series, 'f') }, g);
      if (o.label) this.text(x1, y1, o.label, Object.assign({ dx: ux * 10 + (ux >= 0 ? 4 : -4), dy: uy * 10 - 4, anchor: ux >= 0 ? 'start' : 'end', cls: 'ink strong' }, o.labelOpts));
      return g;
    }
    /* Text at data coordinates; o: anchor, dx, dy, cls ('ink', 'ink2', 'strong', …), size */
    text(x, y, str, o = {}) {
      this._axes();
      const t = svgEl('text', { x: r2(this.x(x) + (o.dx || 0)), y: r2(this.y(y) + (o.dy || 0)), 'text-anchor': o.anchor || 'start',
        'dominant-baseline': o.baseline || 'auto', class: o.cls || 'ink2' }, this.gData);
      if (o.size) t.style.fontSize = o.size + 'px';
      t.textContent = str;
      return t;
    }
    /* Heat map of f(x, y) over the plot area, binned into a 9-step sequential (or diverging) ramp.
       o: nx, ny (cells), range [lo, hi] (auto otherwise), transform (e.g. Math.sqrt), diverging,
       full (use the whole ramp; by default only the light half, so contours and paths on top stay readable) */
    heatmap(f, o = {}) {
      this._axes();
      const nx = o.nx || 60, ny = o.ny || 40;
      const [xa, xb] = this._domain.x, [ya, yb] = this._domain.y;
      const vals = [];
      let lo = Infinity, hi = -Infinity;
      for (let j = 0; j < ny; j++) for (let i = 0; i < nx; i++) {
        const x = xa + (i + 0.5) * (xb - xa) / nx, y = ya + (j + 0.5) * (yb - ya) / ny;
        let v = f(x, y); if (o.transform) v = o.transform(v);
        vals.push(v); if (isFinite(v)) { lo = Math.min(lo, v); hi = Math.max(hi, v); }
      }
      if (o.range) [lo, hi] = o.range;
      const g = svgEl('g', { 'clip-path': this._clip() }, this.gData);
      const cw = (this.W - this.m.l - this.m.r) / nx, ch = (this.H - this.m.t - this.m.b) / ny;
      const divCls = ['dn4', 'dn3', 'dn2', 'dn1', 'd0', 'dp1', 'dp2', 'dp3', 'dp4'];
      const top = o.full ? 8 : 5;            // backgrounds stay light unless o.full
      for (let j = 0; j < ny; j++) for (let i = 0; i < nx; i++) {
        const v = vals[j * nx + i];
        if (!isFinite(v)) continue;
        let k;
        if (o.diverging) { const a = Math.max(Math.abs(lo), Math.abs(hi)) || 1; k = Math.round((v / a) * 4) + 4; }
        else k = Math.round(((v - lo) / ((hi - lo) || 1)) * top);
        k = Math.max(0, Math.min(8, k));
        svgEl('rect', { x: r2(this.m.l + i * cw), y: r2(this.H - this.m.b - (j + 1) * ch), width: r2(cw + 0.6), height: r2(ch + 0.6),
          class: 'cell ' + (o.diverging ? divCls[k] : 'q' + k) }, g);
      }
      return { lo, hi };
    }
    /* Contour lines of f(x, y) (marching squares). o: levels (array) or count, nx, ny, series (default muted), labels */
    contour(f, o = {}) {
      this._axes();
      const nx = o.nx || 70, ny = o.ny || 50;
      const [xa, xb] = this._domain.x, [ya, yb] = this._domain.y;
      const gx = i => xa + i * (xb - xa) / nx, gy = j => ya + j * (yb - ya) / ny;
      const v = [];
      let lo = Infinity, hi = -Infinity;
      for (let j = 0; j <= ny; j++) { const row = []; for (let i = 0; i <= nx; i++) { const z = f(gx(i), gy(j)); row.push(z); if (isFinite(z)) { lo = Math.min(lo, z); hi = Math.max(hi, z); } } v.push(row); }
      let levels = o.levels;
      if (!levels) { const n = o.count || 10; levels = []; for (let k = 1; k <= n; k++) levels.push(lo + (hi - lo) * Math.pow(k / (n + 1), o.power || 1)); }
      const g = svgEl('g', { 'clip-path': this._clip() }, this.gData);
      const cls = o.series ? 'ln thin ' + seriesClass(o.series, 's') : 'contour';
      for (const L of levels) {
        let d = '';
        for (let j = 0; j < ny; j++) for (let i = 0; i < nx; i++) {
          const a = v[j][i], b = v[j][i + 1], c = v[j + 1][i + 1], e = v[j + 1][i];
          const idx = (a > L ? 8 : 0) | (b > L ? 4 : 0) | (c > L ? 2 : 0) | (e > L ? 1 : 0);
          if (idx === 0 || idx === 15) continue;
          const lerp = (p, q) => (L - p) / ((q - p) || 1e-12);
          const pts = {
            B: [gx(i + lerp(a, b)), gy(j)], R: [gx(i + 1), gy(j + lerp(b, c))],
            T: [gx(i + lerp(e, c)), gy(j + 1)], Lf: [gx(i), gy(j + lerp(a, e))],
          };
          const segs = {
            1: [['Lf', 'T']], 2: [['T', 'R']], 3: [['Lf', 'R']], 4: [['B', 'R']], 5: [['Lf', 'B'], ['T', 'R']], 6: [['B', 'T']],
            7: [['Lf', 'B']], 8: [['Lf', 'B']], 9: [['B', 'T']], 10: [['Lf', 'T'], ['B', 'R']], 11: [['B', 'R']], 12: [['Lf', 'R']],
            13: [['T', 'R']], 14: [['Lf', 'T']],
          }[idx];
          for (const [p, q] of segs) {
            d += 'M' + r2(this.x(pts[p][0])) + ',' + r2(this.y(pts[p][1])) + 'L' + r2(this.x(pts[q][0])) + ',' + r2(this.y(pts[q][1]));
          }
        }
        if (d) svgEl('path', { d, class: cls }, g);
      }
      return levels;
    }

    /* Legend above the plot. items: [{label, series, kind: 'line'|'rect'|'dot'|'dash'}] */
    legend(items) {
      this.legendEl.textContent = '';
      for (const it of items) {
        const s = htmlEl('span', null, this.legendEl);
        const key = htmlEl('i', it.kind && it.kind !== 'line' ? it.kind : null, s);
        key.style.color = cssVarFor(it.series);
        s.appendChild(document.createTextNode(it.label));
      }
      return this;
    }

    /* Pointer events in data coordinates: { click(x, y), drag(x, y), move(x, y) }. */
    onPointer(h) {
      this._ptr = h;
      this.svg.style.cursor = h.click || h.drag ? 'crosshair' : '';
      this.svg.style.touchAction = h.drag ? 'none' : '';   // a drag chart keeps vertical swipes instead of scrolling the page
      return this;
    }

    // -------------------------------------------------------------- hover layer
    _bindPointer() {
      let dragging = false;
      const pos = ev => {
        const r = this.svg.getBoundingClientRect();
        return [ev.clientX - r.left, ev.clientY - r.top];
      };
      const inPlot = (px, py) => px >= this.m.l - 2 && px <= this.W - this.m.r + 2 && py >= this.m.t - 2 && py <= this.H - this.m.b + 2;
      this.svg.addEventListener('pointerdown', ev => {
        const [px, py] = pos(ev);
        if (!this._ptr || !inPlot(px, py)) return;
        const x = this.x.invert(px), y = this.y.invert(py);
        if (this._ptr.drag) { dragging = true; this.svg.setPointerCapture(ev.pointerId); this._ptr.drag(x, y); }
        if (this._ptr.click) this._ptr.click(x, y);
      });
      this.svg.addEventListener('pointerup', () => { dragging = false; });
      this.svg.addEventListener('pointercancel', () => { dragging = false; });
      this.svg.addEventListener('pointermove', ev => {
        const [px, py] = pos(ev);
        if (dragging && this._ptr && this._ptr.drag) { this._ptr.drag(this.x.invert(px), this.y.invert(py)); return; }
        if (this._ptr && this._ptr.move && inPlot(px, py)) this._ptr.move(this.x.invert(px), this.y.invert(py));
        this._hover(px, py);
      });
      this.svg.addEventListener('pointerleave', () => this._hideTip());
      this.svg.addEventListener('blur', () => this._hideTip());
      this.svg.addEventListener('keydown', ev => {
        if (!this._lines.length || (ev.key !== 'ArrowLeft' && ev.key !== 'ArrowRight')) return;
        ev.preventDefault();
        const xs = this._lines[0].pts.map(p => p[0]);
        this._kbd = Math.max(0, Math.min(xs.length - 1, (this._kbd === undefined ? 0 : this._kbd) + (ev.key === 'ArrowRight' ? 1 : -1)));
        this._crosshair(xs[this._kbd]);
      });
    }
    _hideTip() {
      this.tip.classList.remove('on');
      if (this.gHover) while (this.gHover.firstChild) this.gHover.removeChild(this.gHover.firstChild);
      if (this._hot) { this._hot.classList.remove('hot'); this._hot = null; }
    }
    _hover(px, py) {
      // 1. a point or bar under (or near) the pointer
      let best = null, bd = 24;
      for (const it of this._points) {
        let d;
        if (it.bar) {
          const b = it.bar;
          const dx = px < b.x0 ? b.x0 - px : px > b.x1 ? px - b.x1 : 0, dy = py < b.y0 ? b.y0 - py : py > b.y1 ? py - b.y1 : 0;
          d = Math.hypot(dx, dy) * 2;
        } else d = Math.hypot(it.X - px, it.Y - py);
        if (d < bd) { bd = d; best = it; }
      }
      if (best) {
        this._hideTip();
        const p = best.p, o = best.o;
        const content = (p.tip !== undefined ? p.tip : o.tip ? o.tip(p) : p.label !== undefined ? p.label : '');
        if (content === '' || content === null) return;
        if (best.node && best.bar) { best.node.classList.add('hot'); this._hot = best.node; }
        if (!best.bar) svgEl('circle', { cx: best.X, cy: best.Y, r: (+best.node.getAttribute('r') || 4) + 3, class: 'ln thin smuted' }, this.gHover);
        this._showTip(best.X, best.Y, content);
        return;
      }
      // 2. otherwise the crosshair over labelled lines
      if (!this._lines.length || px < this.m.l || px > this.W - this.m.r) { this._hideTip(); return; }
      this._crosshair(this.x.invert(px));
    }
    _crosshair(xv) {
      this._hideTip();
      const ref = this._lines[0].pts;
      let bi = 0, bd = Infinity;
      for (let i = 0; i < ref.length; i++) { const d = Math.abs(ref[i][0] - xv); if (d < bd) { bd = d; bi = i; } }
      const xs = ref[bi][0], X = this.x(xs);
      svgEl('line', { x1: X, x2: X, y1: this.m.t, y2: this.H - this.m.b, class: 'crosshair' }, this.gHover);
      const rows = [];
      for (const L of this._lines) {
        let yv = null, d = Infinity;
        for (const p of L.pts) { const dd = Math.abs(p[0] - xs); if (dd < d) { d = dd; yv = p[1]; } }
        if (yv === null || !isFinite(yv)) continue;
        const Y = this.y(yv);
        if (Y >= this.m.t - 1 && Y <= this.H - this.m.b + 1)
          svgEl('circle', { cx: X, cy: Y, r: 4, class: 'dot ' + seriesClass(L.o.series, 'f') }, this.gHover);
        rows.push({ value: L.o.format ? L.o.format(yv) : fmt(yv), label: L.o.label, series: L.o.series });
      }
      const head = (this.o.x.tipLabel ? this.o.x.tipLabel + ' ' : (this.o.x.label ? this.o.x.label + ' ' : 'x = ')) +
        (this.o.x.tipFormat ? this.o.x.tipFormat(xs) : fmt(xs));
      this._showTip(X, this.m.t + 10, { head, rows });
    }
    _showTip(X, Y, content) {
      const t = this.tip;
      t.textContent = '';
      if (typeof content === 'string') {
        content.split('\n').forEach((line, i) => htmlEl('div', i === 0 && content.includes('\n') ? 'h' : null, t, line));
      } else {
        if (content.head) htmlEl('div', 'h', t, content.head);
        for (const r of content.rows || []) {
          const row = htmlEl('div', 'r', t);
          if (r.series !== undefined) { const k = htmlEl('i', null, row); k.style.color = cssVarFor(r.series); }
          htmlEl('b', null, row, r.value);
          if (r.label) htmlEl('span', null, row, r.label);
        }
      }
      t.classList.add('on');
      const tw = t.offsetWidth, th = t.offsetHeight;
      let left = X + 14, top = Y - th - 10;
      if (left + tw > this.W) left = X - tw - 14;
      if (left < 0) left = 2;
      if (top < 0) top = Y + 14;
      t.style.left = left + 'px'; t.style.top = top + 'px';
    }
  }

  function roundedBar(x, w, yb, yv, rad) {
    const up = yv <= yb, h = Math.abs(yb - yv);
    const r = Math.min(rad, h);
    if (h < 0.5) return `M${r2(x)},${r2(yb)}h${r2(w)}`;
    if (up) return `M${r2(x)},${r2(yb)}V${r2(yv + r)}Q${r2(x)},${r2(yv)} ${r2(x + r)},${r2(yv)}H${r2(x + w - r)}Q${r2(x + w)},${r2(yv)} ${r2(x + w)},${r2(yv + r)}V${r2(yb)}Z`;
    return `M${r2(x)},${r2(yb)}V${r2(yv - r)}Q${r2(x)},${r2(yv)} ${r2(x + r)},${r2(yv)}H${r2(x + w - r)}Q${r2(x + w)},${r2(yv)} ${r2(x + w)},${r2(yv - r)}V${r2(yb)}Z`;
  }
  function cssVarFor(s) {
    if (s === 'muted') return 'var(--ink-muted)';
    if (s === 'ink') return 'var(--ink)';
    if (s === 'good') return 'var(--good)';
    if (s === 'bad') return 'var(--bad)';
    return `var(--series-${s || 1})`;
  }

  // ---------------------------------------------------------------- controls
  /* DS.controls(target, onChange) → builder. Every control calls onChange() when it changes. */
  function controls(target, onChange) {
    const host = resolve(target);
    const box = htmlEl('div', 'ds-controls', host);
    const fire = () => { if (onChange) onChange(); };
    let n = 0;
    function listSlider(o) {
      const wrap = htmlEl('div', 'ds-control', box);
      const id = 'dsctl' + (++uid) + '-' + (++n);
      const lab = htmlEl('label', null, wrap); lab.htmlFor = id;
      htmlEl('span', null, lab, o.label);
      const out = htmlEl('output', null, lab);
      const inp = htmlEl('input', null, wrap);
      inp.type = 'range'; inp.id = id; inp.min = 0; inp.max = o.values.length - 1; inp.step = 1;
      const near = v => { let b = 0; o.values.forEach((x, i) => { if (Math.abs(x - v) < Math.abs(o.values[b] - v)) b = i; }); return b; };
      inp.value = near(o.value !== undefined ? o.value : o.values[0]);
      const f = o.format || (v => fmt(v));
      const ctl = { el: wrap, input: inp, get value() { return o.values[+inp.value]; }, set(v) { inp.value = near(v); out.textContent = f(ctl.value); } };
      out.textContent = f(ctl.value);
      inp.addEventListener('input', () => { out.textContent = f(ctl.value); fire(); });
      return ctl;
    }
    const api = {
      el: box,
      /* {label, min, max, step, value, format(v) → string, log: true for a log-scaled slider}
         or {label, values: [0.001, 0.01, 0.1, 1], value} to snap to a fixed list */
      slider(o) {
        if (o.values) return listSlider(o);
        const wrap = htmlEl('div', 'ds-control', box);
        const id = 'dsctl' + (++uid) + '-' + (++n);
        const lab = htmlEl('label', null, wrap); lab.htmlFor = id;
        htmlEl('span', null, lab, o.label);
        const out = htmlEl('output', null, lab);
        const inp = htmlEl('input', null, wrap);
        inp.type = 'range'; inp.id = id;
        const toPos = v => o.log ? Math.log10(v) : v, fromPos = p => o.log ? Math.pow(10, p) : p;
        inp.min = toPos(o.min); inp.max = toPos(o.max); inp.step = o.log ? (toPos(o.max) - toPos(o.min)) / 200 : (o.step || (o.max - o.min) / 100);
        inp.value = toPos(o.value);
        const f = o.format || (v => fmt(v));
        const ctl = {
          el: wrap, input: inp,
          get value() { const v = fromPos(+inp.value); return o.step && !o.log ? Math.round(v / o.step) * o.step : v; },
          set(v) { inp.value = toPos(v); out.textContent = f(ctl.value); },
        };
        out.textContent = f(ctl.value);
        inp.addEventListener('input', () => { out.textContent = f(ctl.value); fire(); });
        return ctl;
      },
      /* {label, options: [{value, label}] or strings, value} → segmented buttons */
      choice(o) {
        const wrap = htmlEl('div', 'ds-control', box);
        htmlEl('label', null, wrap).appendChild(document.createTextNode(o.label || ''));
        const seg = htmlEl('div', 'ds-seg', wrap);
        seg.setAttribute('role', 'group');
        const opts = o.options.map(x => typeof x === 'object' ? x : { value: x, label: String(x) });
        let cur = o.value !== undefined ? o.value : opts[0].value;
        const btns = opts.map(op => {
          const b = htmlEl('button', null, seg, op.label); b.type = 'button';
          b.setAttribute('aria-pressed', String(op.value === cur));
          b.addEventListener('click', () => { cur = op.value; btns.forEach((bb, i) => bb.setAttribute('aria-pressed', String(opts[i].value === cur))); fire(); });
          return b;
        });
        return { el: wrap, get value() { return cur; }, set(v) { cur = v; btns.forEach((bb, i) => bb.setAttribute('aria-pressed', String(opts[i].value === cur))); } };
      },
      select(o) {
        const wrap = htmlEl('div', 'ds-control', box);
        const id = 'dsctl' + (++uid) + '-' + (++n);
        const lab = htmlEl('label', null, wrap, o.label); lab.htmlFor = id;
        const sel = htmlEl('select', null, wrap); sel.id = id;
        o.options.map(x => typeof x === 'object' ? x : { value: x, label: String(x) }).forEach(op => {
          const e = htmlEl('option', null, sel, op.label); e.value = op.value;
        });
        if (o.value !== undefined) sel.value = o.value;
        sel.addEventListener('change', fire);
        return { el: wrap, get value() { return sel.value; }, set(v) { sel.value = v; } };
      },
      toggle(o) {
        const wrap = htmlEl('div', 'ds-control inline', box);
        const lab = htmlEl('label', 'ds-check', wrap);
        const inp = htmlEl('input', null, lab); inp.type = 'checkbox'; inp.checked = !!o.value;
        lab.appendChild(document.createTextNode(o.label));
        inp.addEventListener('change', fire);
        return { el: wrap, get value() { return inp.checked; }, set(v) { inp.checked = !!v; } };
      },
      button(o) {
        const wrap = htmlEl('div', 'ds-control inline', box);
        const b = htmlEl('button', 'ds-btn', wrap, o.label); b.type = 'button';
        b.addEventListener('click', () => { if (o.onClick) o.onClick(); fire(); });
        return { el: wrap, button: b };
      },
    };
    return api;
  }

  /* DS.stats(target, [{label, value, note, tone: 'good'|'bad'}]) — a row of small number tiles. Call again to update. */
  function stats(target, items) {
    const host = resolve(target);
    let box = host.querySelector(':scope > .ds-stats');
    if (!box) box = htmlEl('div', 'ds-stats', host);
    box.textContent = '';
    for (const it of items) {
      const s = htmlEl('div', 'ds-stat' + (it.tone ? ' ' + it.tone : ''), box);
      htmlEl('div', 'l', s, it.label);
      htmlEl('div', 'v', s, it.value);
      if (it.note) htmlEl('div', 'n', s, it.note);
    }
    return box;
  }

  /* DS.table(target, {columns: [{label, num}], rows: [[...]], cls}) — a small table. Call again to update. */
  function table(target, spec) {
    const host = resolve(target);
    let t = host.querySelector('table.ds-table');
    if (!t) t = htmlEl('table', 'ds-table ' + (spec.cls || ''), htmlEl('div', 'table-wrap', host));
    t.textContent = '';
    if (spec.columns) {
      const tr = htmlEl('tr', null, htmlEl('thead', null, t));
      spec.columns.forEach(c => htmlEl('th', c.num ? 'num' : null, tr, c.label !== undefined ? c.label : c));
    }
    const tb = htmlEl('tbody', null, t);
    for (const row of spec.rows) {
      const tr = htmlEl('tr', row.cls || null, tb);
      (row.cells || row).forEach((cell, i) => {
        const num = spec.columns && spec.columns[i] && spec.columns[i].num;
        const c = typeof cell === 'object' && cell !== null ? cell : { text: cell };
        const td = htmlEl(c.th ? 'th' : 'td', [num ? 'num' : '', c.cls || ''].join(' ').trim() || null, tr, c.text);
        if (c.sub) htmlEl('small', null, td, c.sub);
      });
    }
    return t;
  }

  // ---------------------------------------------------------------- math and random numbers
  function erf(x) {                         // Abramowitz–Stegun 7.1.26, |error| < 1.5e-7
    const s = Math.sign(x); x = Math.abs(x);
    const t = 1 / (1 + 0.3275911 * x);
    const y = 1 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * Math.exp(-x * x);
    return s * y;
  }
  function normInv(p) {                     // Acklam's approximation
    if (p <= 0) return -Infinity; if (p >= 1) return Infinity;
    const a = [-39.69683028665376, 220.9460984245205, -275.9285104469687, 138.357751867269, -30.66479806614716, 2.506628277459239];
    const b = [-54.47609879822406, 161.5858368580409, -155.6989798598866, 66.80131188771972, -13.28068155288572];
    const c = [-0.007784894002430293, -0.3223964580411365, -2.400758277161838, -2.549732539343734, 4.374664141464968, 2.938163982698783];
    const d = [0.007784695709041462, 0.3224671290700398, 2.445134137142996, 3.754408661907416];
    const pl = 0.02425;
    let q, r;
    if (p < pl) { q = Math.sqrt(-2 * Math.log(p)); return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1); }
    if (p > 1 - pl) { q = Math.sqrt(-2 * Math.log(1 - p)); return -(((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1); }
    q = p - 0.5; r = q * q;
    return (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1);
  }
  const math = {
    linspace(a, b, n) { const out = []; for (let i = 0; i < n; i++) out.push(n === 1 ? a : a + (b - a) * i / (n - 1)); return out; },
    range(n) { return Array.from({ length: n }, (_, i) => i); },
    sum(a) { let s = 0; for (const v of a) s += v; return s; },
    mean(a) { return math.sum(a) / a.length; },
    variance(a) { const m = math.mean(a); let s = 0; for (const v of a) s += (v - m) * (v - m); return s / (a.length - 1); },
    sd(a) { return Math.sqrt(math.variance(a)); },
    quantile(a, q) { const s = a.slice().sort((x, y) => x - y); const i = (s.length - 1) * q, lo = Math.floor(i), hi = Math.ceil(i); return s[lo] + (s[hi] - s[lo]) * (i - lo); },
    clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); },
    sigmoid(z) { return 1 / (1 + Math.exp(-z)); },
    logit(p) { return Math.log(p / (1 - p)); },
    erf,
    normalPdf(x, mu = 0, sd = 1) { const z = (x - mu) / sd; return Math.exp(-0.5 * z * z) / (sd * Math.sqrt(2 * Math.PI)); },
    normalCdf(x, mu = 0, sd = 1) { return 0.5 * (1 + erf((x - mu) / (sd * Math.SQRT2))); },
    normalInv(p, mu = 0, sd = 1) { return mu + sd * normInv(p); },
    /* Gaussian kernel density estimate of values at points xs; bandwidth defaults to Silverman's rule. */
    kde(values, xs, bandwidth) {
      const n = values.length;
      const h = bandwidth || 1.06 * math.sd(values) * Math.pow(n, -0.2);
      return xs.map(x => { let s = 0; for (const v of values) { const z = (x - v) / h; s += Math.exp(-0.5 * z * z); } return [x, s / (n * h * Math.sqrt(2 * Math.PI))]; });
    },
    /* trapezoid area under points sorted by x */
    trapz(pts) { let s = 0; for (let i = 1; i < pts.length; i++) s += (pts[i][0] - pts[i - 1][0]) * (pts[i][1] + pts[i - 1][1]) / 2; return s; },
  };

  /* DS.random(seed): a reproducible generator, so the numbers in the text match the figures. */
  function random(seed) {
    let a = (seed === undefined ? 12345 : seed) >>> 0;
    const uniform = () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
    let spare = null;
    const normal = (mu = 0, sd = 1) => {
      if (spare !== null) { const s = spare; spare = null; return mu + sd * s; }
      let u = 0, v = 0; while (u === 0) u = uniform(); v = uniform();
      const r = Math.sqrt(-2 * Math.log(u)); spare = r * Math.sin(2 * Math.PI * v);
      return mu + sd * r * Math.cos(2 * Math.PI * v);
    };
    return {
      uniform, normal,
      int(n) { return Math.floor(uniform() * n); },
      bernoulli(p) { return uniform() < p ? 1 : 0; },
      beta(alpha, beta) { const x = gamma(alpha), y = gamma(beta); return x / (x + y); },
      choice(arr) { return arr[Math.floor(uniform() * arr.length)]; },
      shuffle(arr) { const b = arr.slice(); for (let i = b.length - 1; i > 0; i--) { const j = Math.floor(uniform() * (i + 1)); [b[i], b[j]] = [b[j], b[i]]; } return b; },
    };
    function gamma(k) {                     // Marsaglia–Tsang
      if (k < 1) return gamma(k + 1) * Math.pow(uniform(), 1 / k);
      const d = k - 1 / 3, c = 1 / Math.sqrt(9 * d);
      for (;;) { let x, v; do { x = normal(); v = 1 + c * x; } while (v <= 0); v = v * v * v; const u = uniform();
        if (u < 1 - 0.0331 * x ** 4 || Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) return d * v; }
    }
  }

  window.DS = { chart: (t, o) => new Chart(t, o), controls, stats, table, math, random, fmt, pct };
})();
