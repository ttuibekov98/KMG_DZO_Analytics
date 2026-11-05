'use strict';
/* =========================================================================
   ДЗО КМГ — приложение
   Вход → расшифровка data.bin (PBKDF2 + AES-GCM + gzip) → роутинг #раздел/дзо → рендер
   ========================================================================= */

/* ------------------------------------------------------------------ утилиты */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const isNum = v => typeof v === 'number' && isFinite(v);
const sum = a => a.reduce((s, v) => s + (isNum(v) ? v : 0), 0);
const NF = {};
function fmt(v, nd = 0) {
  if (!isNum(v)) return '—';
  const k = nd;
  NF[k] = NF[k] || new Intl.NumberFormat('ru-RU', { minimumFractionDigits: nd, maximumFractionDigits: nd });
  const s = NF[k].format(v);
  return s === '-0' ? '0' : s;
}
const fmtA = v => !isNum(v) ? '—' : Number.isInteger(v) ? fmt(v, 0) : Math.abs(v) >= 1000 ? fmt(v, 0) : Math.abs(v) >= 100 ? fmt(v, 1) : Math.abs(v) >= 10 ? fmt(v, 1) : fmt(v, 2);
function fmtS(v) { // компактно для осей
  if (!isNum(v)) return '';
  const a = Math.abs(v);
  if (a >= 1e9) return fmt(v / 1e9, a >= 1e10 ? 0 : 1) + ' млрд';
  if (a >= 1e6) return fmt(v / 1e6, a >= 1e7 ? 0 : 1) + ' млн';
  if (a >= 1e4) return fmt(v / 1e3, 0) + ' тыс.';
  return fmt(v, a < 10 && a % 1 ? 1 : 0);
}
const fmtMln = v => !isNum(v) ? '' : Math.abs(v) >= 1000 ? fmt(v / 1000, Math.abs(v) >= 1e5 ? 0 : 1) + ' млрд' : fmt(v, 0) + ' млн';
const pct = (v, nd = 1) => isNum(v) ? fmt(v * 100, nd) + '%' : '—';
const sign = (v, nd = 0) => !isNum(v) ? '—' : (v > 0 ? '+' : v < 0 ? '−' : '') + fmt(Math.abs(v), nd);
const ratio = (f, p) => isNum(f) && isNum(p) && p !== 0 ? f / p : null;
function deltaPill(f, p, inv = false, nd = 1) {
  const r = ratio(f, p);
  if (r === null) return '';
  const d = r - 1, good = inv ? d <= 0 : d >= 0;
  const cls = Math.abs(d) < 0.0005 ? 'neu' : good ? 'good' : 'bad';
  const arrow = d > 0 ? '▲' : d < 0 ? '▼' : '';
  return `<span class="delta ${cls}">${arrow} ${fmt(Math.abs(d) * 100, nd)}%</span>`;
}
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const MONTHS = ['январь', 'февраль', 'март', 'апрель', 'май', 'июнь', 'июль', 'август', 'сентябрь', 'октябрь', 'ноябрь', 'декабрь'];
const MON3 = ['янв', 'фев', 'мар', 'апр', 'май', 'июн', 'июл', 'авг', 'сен', 'окт', 'ноя', 'дек'];
const dLabel = iso => { const [y, m, d] = iso.split('-'); return `${d}.${m}.${y}`; };
const dShort = iso => { const [, m, d] = iso.split('-'); return `${+d} ${MON3[+m - 1]}`; };
const mLabel = ym => { const [y, m] = ym.split('-'); return `${MON3[+m - 1]} ${y.slice(2)}`; };
const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };

/* ------------------------------------------------------------------ вход */
const SS_KEY = 'dzo-pass';
async function decryptPayload(buf, password) {
  const bytes = new Uint8Array(buf);
  const salt = bytes.slice(0, 16), iv = bytes.slice(16, 28), ct = bytes.slice(28);
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: PAYLOAD.iter, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  let plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  if (PAYLOAD.gzip) {
    const stream = new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'));
    plain = await new Response(stream).arrayBuffer();
  }
  return JSON.parse(new TextDecoder().decode(plain));
}
let PAYLOAD_BUF = null;
async function loadPayload() {
  if (PAYLOAD_BUF) return PAYLOAD_BUF;
  if (location.protocol === 'file:') throw new Error('file');
  const res = await fetch(PAYLOAD.file, { cache: 'no-store' });
  if (!res.ok) throw new Error('nofile');
  PAYLOAD_BUF = await res.arrayBuffer();
  return PAYLOAD_BUF;
}
async function unlock(pw) {
  if (!window.crypto?.subtle) throw new Error('nocrypto');
  const buf = await loadPayload();
  const obj = await decryptPayload(buf, pw);
  DATA = obj.d;
}
function gateError(err) {
  const msg = $('#gateMsg'); msg.className = 'gate-msg';
  if (err?.message === 'file' || err?.message === 'nocrypto') msg.textContent = 'Откройте сайт по ссылке https:// (или через локальный сервер), а не как файл с диска.';
  else if (err?.message === 'nofile') msg.textContent = 'Файл data.bin не найден. Он должен лежать рядом с index.html.';
  else if (err?.name === 'OperationError') msg.textContent = 'Неверный пароль. Проверьте раскладку и Caps Lock.';
  else msg.textContent = 'Не удалось открыть данные: ' + (err?.message || err);
  const card = $('#gateForm'); card.classList.remove('shake'); void card.offsetWidth; card.classList.add('shake');
}
function initGate() {
  const form = $('#gateForm'), btn = $('#gateBtn'), pw = $('#pw');
  $('#pwShow').addEventListener('click', e => {
    const on = pw.type === 'password'; pw.type = on ? 'text' : 'password';
    e.currentTarget.setAttribute('aria-pressed', on); e.currentTarget.setAttribute('aria-label', on ? 'Скрыть пароль' : 'Показать пароль');
  });
  form.addEventListener('submit', async e => {
    e.preventDefault();
    btn.disabled = true; btn.querySelector('span').textContent = 'Проверяем…'; $('#gateMsg').textContent = '';
    try {
      await unlock(pw.value);
      if ($('#remember').checked) sessionStorage.setItem(SS_KEY, pw.value); else sessionStorage.removeItem(SS_KEY);
      $('#gateMsg').className = 'gate-msg ok'; $('#gateMsg').textContent = 'Готово';
      startApp();
    } catch (err) { gateError(err); }
    btn.disabled = false; btn.querySelector('span').textContent = 'Войти';
  });
  const saved = sessionStorage.getItem(SS_KEY);
  if (saved) {
    btn.disabled = true; btn.querySelector('span').textContent = 'Проверяем…';
    unlock(saved).then(startApp).catch(() => { sessionStorage.removeItem(SS_KEY); btn.disabled = false; btn.querySelector('span').textContent = 'Войти'; pw.focus(); });
  } else pw.focus();
}

/* ------------------------------------------------------------------ подсказка */
const TIP = { el: null };
function tipShow(html, x, y) {
  const t = TIP.el || (TIP.el = $('#tip'));
  t.innerHTML = html; t.style.opacity = 1;
  const r = t.getBoundingClientRect();
  let left = x + 14, top = y + 14;
  if (left + r.width > innerWidth - 8) left = x - r.width - 14;
  if (top + r.height > innerHeight - 8) top = y - r.height - 14;
  t.style.left = Math.max(8, left) + 'px'; t.style.top = Math.max(8, top) + 'px';
}
const tipHide = () => { if (TIP.el) TIP.el.style.opacity = 0; };
const tipRow = (name, val, color) => `<div class="r"><span><i class="sw" style="background:${color}"></i>${esc(name)}</span><b>${val}</b></div>`;

/* ------------------------------------------------------------------ графики (SVG) */
function niceScale(min, max, ticks = 5) {
  if (min === max) { max = min + 1; min = Math.min(0, min); }
  const span = max - min, step0 = span / ticks, mag = Math.pow(10, Math.floor(Math.log10(step0)));
  const step = [1, 2, 2.5, 5, 10].map(m => m * mag).find(s => span / s <= ticks) || 10 * mag;
  const lo = Math.floor(min / step) * step, hi = Math.ceil(max / step) * step;
  const out = []; for (let v = lo; v <= hi + step / 2; v += step) out.push(+v.toFixed(10));
  return { lo, hi, ticks: out };
}
const W = el => Math.max(280, Math.floor(el.clientWidth || el.parentElement?.clientWidth || 600));

/** Линейный / площадной график.
 *  opt: {labels, series:[{name,values,color,dash,area,width,fmt}], height, fmt, zero, tickEvery, tipTitle} */
function lineChart(el, opt) {
  const w = W(el), h = opt.height || 260, pl = 50, pr = 14, pt = 16, pb = 28;
  const n = opt.labels.length;
  const all = opt.series.flatMap(s => s.values.filter(isNum));
  if (!all.length) { el.innerHTML = '<div class="empty">Нет данных за выбранный период</div>'; return; }
  let mn = Math.min(...all), mx = Math.max(...all);
  if (opt.zero) mn = Math.min(0, mn);
  else { const pad = (mx - mn) * 0.12 || Math.abs(mx) * 0.05 || 1; const nonneg = mn >= 0; mn -= pad; mx += pad * 0.6; if (nonneg) mn = Math.max(0, mn); }
  const sc = niceScale(mn, mx, 4);
  const X = i => pl + (n <= 1 ? (w - pl - pr) / 2 : i * (w - pl - pr) / (n - 1));
  const Y = v => pt + (h - pt - pb) * (1 - (v - sc.lo) / (sc.hi - sc.lo));
  const f = opt.fmt || fmtS;
  let g = '';
  sc.ticks.forEach(t => { g += `<line class="gl" x1="${pl}" x2="${w - pr}" y1="${Y(t)}" y2="${Y(t)}"/><text x="${pl - 8}" y="${Y(t) + 4}" text-anchor="end">${f(t)}</text>`; });
  const every = opt.tickEvery || Math.max(1, Math.ceil(n / Math.max(2, Math.floor((w - pl) / 64))));
  opt.labels.forEach((l, i) => { if (i % every === 0 || i === n - 1 && n < 40) g += `<text x="${X(i)}" y="${h - 8}" text-anchor="middle">${esc(l)}</text>`; });
  const path = vals => { let d = '', pen = false; vals.forEach((v, i) => { if (isNum(v)) { d += (pen ? 'L' : 'M') + X(i).toFixed(1) + ' ' + Y(v).toFixed(1); pen = true; } else pen = false; }); return d; };
  const gid = 'g' + Math.random().toString(36).slice(2, 8);
  let defs = '', body = '';
  opt.series.forEach((s, k) => {
    if (s.area) {
      const idx = s.values.map((v, i) => isNum(v) ? i : -1).filter(i => i >= 0);
      if (idx.length > 1) {
        defs += `<linearGradient id="${gid}${k}" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="${s.color}" stop-opacity=".38"/><stop offset="1" stop-color="${s.color}" stop-opacity=".02"/></linearGradient>`;
        const base = Y(Math.max(sc.lo, Math.min(0, sc.hi)));
        body += `<path d="${path(s.values)} L${X(idx[idx.length - 1])} ${base} L${X(idx[0])} ${base}Z" fill="url(#${gid}${k})"/>`;
      }
    }
  });
  opt.series.forEach(s => {
    body += `<path d="${path(s.values)}" fill="none" stroke="${s.color}" stroke-width="${s.width || 2.2}" stroke-linejoin="round" stroke-linecap="round" ${s.dash ? `stroke-dasharray="${s.dash}"` : ''}/>`;
    if (s.dots && n <= 40) s.values.forEach((v, i) => { if (isNum(v)) body += `<circle cx="${X(i)}" cy="${Y(v)}" r="3.2" fill="${s.color}" stroke="var(--glass-hi)" stroke-width="1.5"/>`; });
    if (s.labels && n <= 16) s.values.forEach((v, i) => { if (isNum(v)) body += `<text class="lbl" x="${X(i)}" y="${Y(v) - 9}" text-anchor="middle">${(s.fmt || f)(v)}</text>`; });
  });
  el.innerHTML = `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="${esc(opt.aria || 'График')}"><defs>${defs}</defs>${g}${body}<line class="cur" x1="0" x2="0" y1="${pt}" y2="${h - pb}" stroke="var(--muted)" stroke-dasharray="3 3" opacity="0"/><rect x="${pl}" y="${pt}" width="${w - pl - pr}" height="${h - pt - pb}" fill="transparent"/></svg>`;
  const svg = el.firstChild, cur = svg.querySelector('.cur');
  svg.addEventListener('pointermove', e => {
    const r = svg.getBoundingClientRect(), x = (e.clientX - r.left) * (w / r.width);
    const i = Math.max(0, Math.min(n - 1, Math.round((x - pl) / ((w - pl - pr) / Math.max(1, n - 1)))));
    cur.setAttribute('x1', X(i)); cur.setAttribute('x2', X(i)); cur.setAttribute('opacity', .7);
    tipShow(`<b>${esc(opt.tipTitle ? opt.tipTitle(i) : opt.labels[i])}</b>` + opt.series.map(s => tipRow(s.name, (s.fmt || opt.tipFmt || fmtA)(s.values[i]), s.color)).join('') + (opt.tipExtra ? opt.tipExtra(i) : ''), e.clientX, e.clientY);
  });
  svg.addEventListener('pointerleave', () => { cur.setAttribute('opacity', 0); tipHide(); });
}

/** Столбцы (сгруппированные) + необязательная линия.  opt: {labels, bars:[{name,values,color,ghost}], line:{name,values,color}, height, fmt, labelsOn} */
function barChart(el, opt) {
  const w = W(el), h = opt.height || 260, pl = 50, pr = 12, pt = 18, pb = 28;
  const n = opt.labels.length, bars = opt.bars;
  const all = [...bars.flatMap(b => b.values), ...(opt.line ? opt.line.values : [])].filter(isNum);
  if (!all.length) { el.innerHTML = '<div class="empty">Нет данных</div>'; return; }
  const sc = niceScale(Math.min(0, ...all), Math.max(0, ...all), 4);
  const Y = v => pt + (h - pt - pb) * (1 - (v - sc.lo) / (sc.hi - sc.lo));
  const band = (w - pl - pr) / n, gw = band * (bars.length > 1 ? 0.72 : 0.56), bw = gw / bars.length;
  const X = i => pl + band * i + band / 2;
  const f = opt.fmt || fmtS;
  let g = '';
  sc.ticks.forEach(t => { g += `<line class="gl" x1="${pl}" x2="${w - pr}" y1="${Y(t)}" y2="${Y(t)}"/><text x="${pl - 8}" y="${Y(t) + 4}" text-anchor="end">${f(t)}</text>`; });
  const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor((w - pl) / 56))));
  opt.labels.forEach((l, i) => { if (i % every === 0) g += `<text x="${X(i)}" y="${h - 8}" text-anchor="middle">${esc(l)}</text>`; });
  let body = '';
  const z = Y(0);
  bars.forEach((b, k) => b.values.forEach((v, i) => {
    if (!isNum(v)) return;
    const x = X(i) - gw / 2 + k * bw + 1, y = Math.min(Y(v), z), hh = Math.max(1, Math.abs(Y(v) - z));
    const col = typeof b.color === 'function' ? b.color(v, i) : b.color;
    body += `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${Math.max(2, bw - 2).toFixed(1)}" height="${hh.toFixed(1)}" rx="${Math.min(5, bw / 3)}" fill="${col}" ${b.ghost ? 'fill-opacity=".35"' : ''}/>`;
    if (opt.labelsOn && n <= 12 && bars.length === 1) body += `<text class="lbl" x="${X(i)}" y="${(v >= 0 ? y - 6 : y + hh + 13).toFixed(1)}" text-anchor="middle">${f(v)}</text>`;
  }));
  if (opt.line) {
    let d = '', pen = false;
    opt.line.values.forEach((v, i) => { if (isNum(v)) { d += (pen ? 'L' : 'M') + X(i) + ' ' + Y(v); pen = true; } else pen = false; });
    body += `<path d="${d}" fill="none" stroke="${opt.line.color}" stroke-width="2.4" ${opt.line.dash ? `stroke-dasharray="${opt.line.dash}"` : ''}/>`;
    opt.line.values.forEach((v, i) => { if (isNum(v)) body += `<circle cx="${X(i)}" cy="${Y(v)}" r="3.5" fill="${opt.line.color}" stroke="var(--glass-hi)" stroke-width="1.5"/>`; });
  }
  el.innerHTML = `<svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="${esc(opt.aria || 'Диаграмма')}">${g}<line x1="${pl}" x2="${w - pr}" y1="${z}" y2="${z}" stroke="var(--line)"/>${body}<rect class="hit" x="${pl}" y="${pt}" width="${w - pl - pr}" height="${h - pt - pb}" fill="transparent"/></svg>`;
  const svg = el.firstChild;
  svg.addEventListener('pointermove', e => {
    const r = svg.getBoundingClientRect(), x = (e.clientX - r.left) * (w / r.width);
    const i = Math.max(0, Math.min(n - 1, Math.floor((x - pl) / band)));
    const rows = bars.map(b => tipRow(b.name, (opt.tipFmt || fmtA)(b.values[i]), typeof b.color === 'function' ? b.color(b.values[i], i) : b.color));
    if (opt.line) rows.push(tipRow(opt.line.name, (opt.tipFmt || fmtA)(opt.line.values[i]), opt.line.color));
    tipShow(`<b>${esc(opt.labels[i])}</b>${rows.join('')}`, e.clientX, e.clientY);
  });
  svg.addEventListener('pointerleave', tipHide);
}

/** Кольцевая диаграмма. items:[{name,v,color}] */
function donut(el, items, center, sub, fmtV = fmtA) {
  items = items.filter(i => isNum(i.v) && i.v > 0);
  const tot = sum(items.map(i => i.v));
  if (!tot) { el.innerHTML = '<div class="empty">Нет данных</div>'; return; }
  const S = 200, R = 84, r = 60, cx = 100, cy = 100;
  let a0 = -Math.PI / 2, arcs = '';
  items.forEach((it, k) => {
    const a1 = a0 + (it.v / tot) * Math.PI * 2 - 0.012;
    const large = a1 - a0 > Math.PI ? 1 : 0;
    const p = (a, rad) => `${(cx + rad * Math.cos(a)).toFixed(2)} ${(cy + rad * Math.sin(a)).toFixed(2)}`;
    arcs += `<path data-k="${k}" d="M${p(a0, R)} A${R} ${R} 0 ${large} 1 ${p(a1, R)} L${p(a1, r)} A${r} ${r} 0 ${large} 0 ${p(a0, r)}Z" fill="${it.color}"/>`;
    a0 = a1 + 0.012;
  });
  el.innerHTML = `<div class="ring-wrap"><svg viewBox="0 0 ${S} ${S}" width="180" height="180" style="flex:none">${arcs}
    <text x="100" y="98" text-anchor="middle" style="font:600 18px var(--display);fill:var(--ink)">${esc(typeof center === 'function' ? center(tot) : center ?? fmtS(tot))}</text>
    <text x="100" y="118" text-anchor="middle" style="font:11px var(--body);fill:var(--muted)">${esc(sub || '')}</text></svg>
    <div class="ring-legend">${items.map(it => `<div><i style="background:${it.color}"></i><span>${esc(it.name)}</span><b>${fmtV(it.v)} <span class="muted">· ${fmt(it.v / tot * 100, 0)}%</span></b></div>`).join('')}</div></div>`;
  const svg = el.querySelector('svg');
  svg.addEventListener('pointermove', e => { const k = e.target.dataset?.k; if (k == null) return tipHide(); const it = items[k]; tipShow(`<b>${esc(it.name)}</b>${tipRow('Значение', fmtV(it.v), it.color)}${tipRow('Доля', fmt(it.v / tot * 100, 1) + '%', it.color)}`, e.clientX, e.clientY); });
  svg.addEventListener('pointerleave', tipHide);
}

/** Мини-спарклайн (строка SVG) */
function spark(vals, color, plan) {
  const v = vals.filter(isNum); if (v.length < 2) return '';
  const all = [...v, ...(plan || []).filter(isNum)];
  const mn = Math.min(...all), mx = Math.max(...all), w = 200, h = 38;
  const X = i => i * w / (vals.length - 1), Y = x => h - 3 - (h - 6) * ((x - mn) / ((mx - mn) || 1));
  const p = arr => arr.map((x, i) => isNum(x) ? `${X(i).toFixed(1)},${Y(x).toFixed(1)}` : null).filter(Boolean).join(' ');
  const id = 's' + Math.random().toString(36).slice(2, 7);
  return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true"><defs><linearGradient id="${id}" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stop-color="${color}" stop-opacity=".35"/><stop offset="1" stop-color="${color}" stop-opacity="0"/></linearGradient></defs>
    ${plan ? `<polyline points="${p(plan)}" fill="none" stroke="var(--plan)" stroke-width="1.4" stroke-dasharray="3 3" vector-effect="non-scaling-stroke"/>` : ''}
    <polygon points="0,${h} ${p(vals)} ${X(vals.length - 1)},${h}" fill="url(#${id})"/>
    <polyline points="${p(vals)}" fill="none" stroke="${color}" stroke-width="2" vector-effect="non-scaling-stroke"/></svg>`;
}

/** Расходящиеся горизонтальные бары. items:[{name,v}] */
function hbars(items, fmtV = v => sign(v, 0), opts = {}) {
  const mx = Math.max(...items.map(i => Math.abs(i.v || 0)), 1);
  const pos = opts.positive;
  return `<div class="hb ${pos ? 'pos' : ''}">` + items.map(it => {
    const v = it.v || 0, wv = Math.abs(v) / mx * (pos ? 100 : 50);
    const left = pos ? 0 : v >= 0 ? 50 : 50 - wv;
    const col = it.color || (pos ? 'var(--c1)' : v >= 0 ? 'var(--good)' : 'var(--bad)');
    return `<div class="hb-row" title="${esc(it.name)}"><span class="hb-l">${esc(it.name)}</span><span class="hb-t"><i style="left:${left}%;width:${Math.max(.6, wv)}%;background:${col}"></i></span><span class="hb-v" style="color:${pos ? 'var(--ink)' : col}">${fmtV(v)}</span></div>`;
  }).join('') + '</div>';
}

/* ------------------------------------------------------------------ виджеты-строители */
const W_ = (cls, title, unit, body, sub) => `<section class="w ${cls}">${title ? `<div class="w-h"><div><h3>${esc(title)}</h3>${sub ? `<div class="w-sub">${sub}</div>` : ''}</div>${unit ? `<span class="u">${esc(unit)}</span>` : ''}</div>` : ''}${body}</section>`;
const KPI = (label, value, unit, sub, extra = '', cls = '') => `<div class="kpi glass ${cls}"><div class="l"><span>${esc(label)}</span>${unit ? `<span class="u">${esc(unit)}</span>` : ''}</div><div class="v">${value}</div>${sub ? `<div class="s">${sub}</div>` : ''}${extra}</div>`;
function trioKPI(label, unit, py, pp, fp, perLabel, inv = false, nd = 0, isPct = false) {
  const f = v => isPct ? pct(v, 0) : fmt(v, nd);
  const r = ratio(fp, pp);
  const w = r === null ? 0 : Math.min(100, Math.max(2, r * 100));
  const cls = r === null ? '' : (inv ? r <= 1 : r >= 1) ? 'over' : 'under';
  return `<div class="kpi glass wide"><div class="l"><span>${esc(label)}</span><span class="u">${esc(unit || '')}</span></div>
    <div class="trio"><div><div class="tl">План 2026</div><div class="tv">${f(py)}</div></div><div><div class="tl">План ${esc(perLabel)}</div><div class="tv">${f(pp)}</div></div><div><div class="tl">Факт ${esc(perLabel)}</div><div class="tv">${f(fp)}</div></div></div>
    <div class="bar ${cls}"><i style="width:${w}%"></i></div>
    <div class="s">${isPct ? (isNum(fp) && isNum(pp) ? `<span class="delta ${(fp - pp >= 0) !== inv ? 'good' : 'bad'}">${sign((fp - pp) * 100, 1)} п.п.</span>` : '') : deltaPill(fp, pp, inv)}<span>${isPct ? '' : 'к плану периода'}</span></div></div>`;
}
function chipsDZO(list, cur, attr = 'data-dzo', withSeg = true) {
  let out = '', seg = null;
  list.forEach(c => {
    const d = DATA.dzo[c];
    if (withSeg && d && d.seg !== seg) { seg = d.seg; out += `<span class="chip-sep">${seg}</span>`; }
    out += `<button class="chip" ${attr}="${esc(c)}" aria-pressed="${c === cur}" title="${esc(d ? d.name : c)}"><i class="dot" style="background:${colorOf(c)}"></i>${esc(c)}</button>`;
  });
  return `<div class="chips scroll" role="group" aria-label="ДЗО">${out}</div>`;
}
function seg(name, opts, cur) {
  return `<div class="seg" role="group" data-seg="${name}">${opts.map(([v, l]) => `<button type="button" data-v="${esc(v)}" aria-pressed="${String(v) === String(cur)}">${esc(l)}</button>`).join('')}</div>`;
}
function table(head, rows, cls = '') {
  return `<div class="tbl-wrap"><table class="t ${cls}"><thead>${head}</thead><tbody>${rows.join('')}</tbody></table></div>`;
}
const legend = items => `<div class="legend">${items.map(([n, c, dash]) => `<span><i class="${dash ? 'dash' : ''}" style="background:${c};color:${c}"></i>${esc(n)}</span>`).join('')}</div>`;
const tdNum = (v, nd = 0, colorize = false, inv = false) => {
  if (!isNum(v)) return '<td>—</td>';
  const cls = !colorize || Math.abs(v) < 1e-9 ? '' : (v > 0) !== inv ? 'pos' : 'neg';
  return `<td class="${cls}">${colorize ? sign(v, nd) : fmt(v, nd)}</td>`;
};

/* ------------------------------------------------------------------ цвета ДЗО */
const PALETTE = ['#0a5fb0', '#1aa3e8', '#14b8a6', '#f2a33a', '#e2557b', '#7a5cd6', '#2f7fd9', '#0e9a6c', '#d97a2b',
  '#4b5fd6', '#1394b8', '#c2447a', '#5d8f2f', '#9c6ade', '#e07b39', '#2b9ba3', '#6b7fa8', '#b8862a'];
const COLORS = {};
function colorOf(code) {
  if (!COLORS[code]) { const keys = Object.keys(DATA.dzo); const i = keys.indexOf(code); COLORS[code] = PALETTE[(i >= 0 ? i : Object.keys(COLORS).length) % PALETTE.length]; }
  return COLORS[code];
}
const mono = (c, size = '') => `<span class="mono ${size}" style="background:linear-gradient(140deg,${colorOf(c)},color-mix(in srgb,${colorOf(c)} 55%,#062a5a))"><span>${esc(c.length > 4 ? c.slice(0, 3) : c)}</span></span>`;

/* ------------------------------------------------------------------ состояние и роутинг */
const TABS = [['home', 'Обзор'], ['pass', 'Паспорт ДЗО'], ['oil', 'Нефть'], ['gas', 'Газ'], ['ops', 'Суточные данные'], ['otm', 'ОТМ'], ['fin', 'Финансы'], ['bud', 'Бюджеты']];
const S = {
  tab: 'home', dzo: 'ОМГ', oilSub: 'nk', nkGrp: 'D', nkRow: null, nkDay: null, nkDev: 'd',
  odFrom: null, odTo: null, plat: 0, platInd: 'fact', gasSec: '1', gasFrom: 2021, gasTo: 2026, gasEnt: 'ОМГ',
  opsDay: null, opsFund: 'Нефтедобывающий фонд', otmM: null, otmQ: '', otmOpen: new Set(), finM: null, finMode: 'ytd', budV: 'all'
};
const codeBySlug = s => Object.keys(DATA.dzo).find(c => DATA.dzo[c].slug === s);
function readHash() {
  const [t, s] = decodeURIComponent(location.hash.replace(/^#/, '')).split('/');
  S.tab = TABS.some(x => x[0] === t) ? t : 'home';
  const c = s && codeBySlug(s); if (c) S.dzo = c;
}
function writeHash(replace) {
  const slug = DATA.dzo[S.dzo]?.slug;
  const h = '#' + S.tab + (S.tab !== 'home' && S.tab !== 'gas' && slug ? '/' + slug : '');
  if (location.hash !== h) { replace ? history.replaceState(null, '', h) : history.pushState(null, '', h); }
}
function pickDZO(list) { if (!list.includes(S.dzo)) S.dzo = list[0]; return S.dzo; }
const ndoList = () => Object.keys(DATA.dzo).filter(c => DATA.dzo[c].seg === 'НДО');
const allList = () => Object.keys(DATA.dzo);
const ordered = keys => allList().filter(c => keys.includes(c));

/* ------------------------------------------------------------------ расчёты (единые для всех мест) */
const dayIndex = (startIso, iso) => Math.round((Date.parse(iso) - Date.parse(startIso)) / 864e5);
const sumRange = (a, i0, i1) => { let s = 0; for (let i = Math.max(0, i0); i <= i1 && i < a.length; i++) if (isNum(a[i])) s += a[i]; return s; };
function monthStart(dates, di) { const m = dates[di].slice(0, 7); let i = di; while (i > 0 && dates[i - 1].slice(0, 7) === m) i--; return i; }
/** Нефть по ДЗО (Добыча_нефти_2026): индекс последнего дня с фактом */
function odLast(code) { const f = DATA.oilDaily.dzo[code].fact; let i = f.length - 1; while (i > 0 && !isNum(f[i])) i--; return i; }
function odDate(i) { const d = new Date(Date.parse(DATA.oilDaily.start) + i * 864e5); return d.toISOString().slice(0, 10); }
/** Помесячные суммы ряда Добыча_нефти_2026 (тыс. т); незавершённый месяц факта — null */
function odMonthly(arr, upto) {
  const start = Date.parse(DATA.oilDaily.start), lastIso = odDate(upto);
  return [...Array(12).keys()].map(m => {
    const ym = `2026-${String(m + 1).padStart(2, '0')}`;
    if (upto < 366 && !monthDone(ym, lastIso)) return null;
    let v = 0, any = false;
    for (let i = 0; i <= upto && i < arr.length; i++) if (new Date(start + i * 864e5).getUTCMonth() === m && isNum(arr[i])) { v += arr[i]; any = true; }
    return any ? v / 1e3 : null;
  });
}
/** НК: показатели строки на дату */
function nkAt(row, di) {
  const N = DATA.nk, ms = monthStart(N.dates, di);
  return {
    dp: N.dp[row][di], df: N.df[row][di], sp: N.sp[row][di], sf: N.sf[row][di],
    mp: sumRange(N.dp[row], ms, di), mf: sumRange(N.df[row], ms, di), msp: sumRange(N.sp[row], ms, di), msf: sumRange(N.sf[row], ms, di),
    yp: sumRange(N.dp[row], 0, di), yf: sumRange(N.df[row], 0, di), ysp: sumRange(N.sp[row], 0, di), ysf: sumRange(N.sf[row], 0, di),
    py: N.py[row], pmon: (N.pm[N.dates[di].slice(0, 7)] || [])[row]
  };
}
const monthDone = (ym, lastIso) => { const [y, m] = ym.split('-').map(Number); return lastIso >= new Date(Date.UTC(y, m, 0)).toISOString().slice(0, 10); };
const nkRowIdx = name => DATA.nk.names.findIndex(n => n === name);
/** Финансы: источник и строки */
const finSrc = c => DATA.fin.dzo[c] ? DATA.fin : DATA.finNS.dzo[c] ? DATA.finNS : null;
const finRow = (c, ...keys) => { const src = finSrc(c); if (!src) return null; for (const k of keys) { const r = src.dzo[c].find(x => x.k === k); if (r) return r; } return null; };
function finMonths26(c) {
  const src = finSrc(c), rev = finRow(c, 'Выручка');
  return src.months.map((m, i) => [m, i]).filter(([m, i]) => m.startsWith('2026') && rev && isNum(rev.f[i])).map(x => x[1]);
}
function finVal(r, kind, mi, mode, months) {
  if (!r) return null;
  const arr = kind === 'p' ? r.p : r.f;
  if (mode === 'm' || r.t === 'Расчетный показатель' || r.u === '%') return arr[mi];
  const y = months[mi].slice(0, 4); let s = 0, any = false;
  for (let i = 0; i <= mi; i++) if (months[i].startsWith(y) && isNum(arr[i])) { s += arr[i]; any = true; }
  return any ? s : null;
}

/* ------------------------------------------------------------------ рендер */
const RENDER = {};
function render() {
  $('#tabs').innerHTML = TABS.map(([k, l]) => `<a class="tab" role="tab" href="#${k}" data-tab="${k}" aria-selected="${k === S.tab}">${l}</a>`).join('');
  tipHide();
  const v = $('#view');
  try { v.innerHTML = RENDER[S.tab](); (POST[S.tab] || (() => { }))(); }
  catch (err) { console.error(err); v.innerHTML = `<div class="w glass"><div class="empty">Не удалось построить раздел: ${esc(err.message)}</div></div>`; }
  $('.tab[aria-selected="true"]')?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
}
const POST = {};
const head = (title, sub, ctrls = '') => `<div class="sec-head"><div><h1>${esc(title)}</h1>${sub ? `<p>${sub}</p>` : ''}</div>${ctrls ? `<div class="ctrls">${ctrls}</div>` : ''}</div>`;

/* ====================== ОБЗОР ====================== */
RENDER.home = () => {
  const N = DATA.nk, di = N.dates.length - 1, t = nkAt(0, di);
  const op = nkRowIdx('Операционные активы, ВСЕГО'), lp = nkRowIdx('Крупные проекты, ВСЕГО');
  const o = nkAt(op, di), l = nkAt(lp, di);
  const r = ratio(t.yf, t.yp);
  const M = DATA.macro, mi = M.brent.f ? M.brent.f.length - 1 : -1;
  const hero = `<section class="hero glass">
    <div>
      <h2>Добыча нефти и конденсата с учётом доли КМГ, с начала года</h2>
      <p class="mega" data-count="${t.yf / 1e6}">${fmt(t.yf / 1e6, 2)}<small>млн т</small></p>
      <div class="hero-meta"><span>План <b>${fmt(t.yp / 1e6, 2)} млн т</b></span><span>Исполнение <b>${pct(r)}</b></span><span>Откл. <b>${sign((t.yf - t.yp) / 1e3, 0)} тыс. т</b></span></div>
      <div class="hero-sub">
        ${KPI('Сутки, ' + dShort(N.dates[di]), fmt(t.df, 0), 'т', `план ${fmt(t.dp, 0)} ${deltaPill(t.df, t.dp)}`, '', '')}
        ${KPI('С начала месяца', fmt(t.mf / 1e3, 1), 'тыс. т', `план ${fmt(t.mp / 1e3, 1)} ${deltaPill(t.mf, t.mp)}`)}
        ${KPI('Операционные активы', fmt(o.yf / 1e6, 2), 'млн т', `план ${fmt(o.yp / 1e6, 2)} ${deltaPill(o.yf, o.yp)}`)}
        ${KPI('Крупные проекты', fmt(l.yf / 1e6, 2), 'млн т', `план ${fmt(l.yp / 1e6, 2)} ${deltaPill(l.yf, l.yp)}`)}
      </div>
    </div>
    <div><div class="w-h"><div><h3>Помесячно, 2026</h3><div class="w-sub">с учётом доли КМГ, завершённые месяцы</div></div><span class="u">тыс. т</span></div>
      ${legend([['План', 'var(--plan)', 1], ['Факт', 'var(--fact)']])}<div class="chart" id="cHomeM"></div>
      ${mi >= 0 ? `<div class="chips mt"><span class="chip" style="cursor:default">Brent ${MON3[mi]}: <b>$${fmt(M.brent.f[mi], 2)}</b></span><span class="chip" style="cursor:default">Курс USD: <b>${fmt(M.rate.f[mi], 2)} ₸</b></span><span class="chip" style="cursor:default">План бюджета: $${fmt(M.brent.p[mi], 0)} / ${fmt(M.rate.p[mi], 0)} ₸</span></div>` : ''}
    </div></section>`;
  // отклонения операционных активов за сутки
  const opsRows = nkGroupOps('D');
  const dev = opsRows.map(i => ({ name: N.names[i].replace(' (доля)', ''), v: (N.df[i][di] ?? 0) - (N.dp[i][di] ?? 0) })).sort((a, b) => b.v - a.v);
  // плитки НДО
  const od = DATA.oilDaily, ndo = ndoList().filter(c => od.dzo[c]);
  const tilesN = ndo.map(c => {
    const s = od.dzo[c], li = odLast(c), f = sumRange(s.fact, 0, li), p = sumRange(s.plan, 0, li);
    const from = Math.max(0, li - 75);
    return `<button class="tile glass" data-go="pass" data-dzo="${esc(c)}"><div class="tile-top">${mono(c)}<div><div class="tile-n">${esc(DATA.dzo[c].name)}</div><div class="tile-s">Нефть с начала года</div></div></div>
      <div class="tile-m"><div><div class="big">${fmt(f / 1e3, 1)}</div><div class="lab">тыс. т · план ${fmt(p / 1e3, 1)}</div></div>${deltaPill(f, p)}</div>
      ${spark(s.fact.slice(from, li + 1), colorOf(c), s.plan.slice(from, li + 1))}</button>`;
  }).join('');
  const ns = allList().filter(c => DATA.dzo[c].seg === 'НС');
  const tilesS = ns.map(c => {
    const rev = finRow(c, 'Выручка'); let f = null, p = null, sp = '';
    if (rev) { const ms = finMonths26(c); f = sum(ms.map(i => rev.f[i])); p = sum(ms.map(i => rev.p[i])); sp = spark(rev.f.slice(-21), colorOf(c)); }
    const ps = DATA.pass[c] || {};
    return `<button class="tile glass" data-go="pass" data-dzo="${esc(c)}"><div class="tile-top">${mono(c)}<div><div class="tile-n">${esc(DATA.dzo[c].name)}</div><div class="tile-s">Выручка с начала 2026 г.</div></div></div>
      <div class="tile-m"><div><div class="big">${fmt(f, 0)}</div><div class="lab">млн тг · план ${fmt(p, 0)}</div></div>${deltaPill(f, p)}</div>${sp}</button>`;
  }).join('');
  return head('Обзор ДЗО', `Суточные данные на ${dLabel(N.dates[di])}. Нажмите на компанию, чтобы открыть её паспорт.`) +
    hero +
    `<div class="grid g-12 mt">
      ${W_('glass s-7', 'Отклонение суточной добычи от плана', 'т', hbars(dev), 'операционные активы, с учётом доли КМГ, ' + dShort(N.dates[di]))}
      ${W_('glass s-5', 'Структура добычи с начала года', 'тыс. т', '<div id="cHomeD"></div>', 'операционные активы, с учётом доли КМГ')}
    </div>
    <div class="grp-h"><h2>Нефтедобывающие (НДО)</h2><span>${ndo.length} компаний</span></div><div class="tiles">${tilesN}</div>
    <div class="grp-h"><h2>Нефтесервисные (НС)</h2><span>${ns.length} компаний</span></div><div class="tiles">${tilesS}</div>`;
};
function nkGroupOps(grp) {
  const N = DATA.nk, idx = N.names.map((_, i) => i).filter(i => N.grp[i] === grp);
  const s = idx.findIndex(i => /^Операционные активы/.test(N.names[i]));
  return s < 0 ? [] : idx.slice(s + 1).filter(i => !/^в т\.ч\./.test(N.names[i]));
}
POST.home = () => {
  const N = DATA.nk, di = N.dates.length - 1, months = Object.keys(N.pm).sort().filter(m => monthDone(m, N.dates[di]));
  const fact = months.map(m => { const ids = N.dates.map((d, i) => d.startsWith(m) ? i : -1).filter(i => i >= 0); return sum(ids.map(i => N.df[0][i])) / 1e3; });
  lineChart($('#cHomeM'), { labels: months.map(m => MON3[+m.slice(5) - 1]), height: 230, series: [
    { name: 'План', values: months.map(m => N.pm[m][0] / 1e3), color: 'var(--plan)', dash: '5 4', width: 2 },
    { name: 'Факт', values: fact, color: 'var(--fact)', area: true, dots: true }], tipTitle: i => MONTHS[+months[i].slice(5) - 1] + ' 2026', tipFmt: v => fmt(v, 1) + ' тыс. т' });
  const ops = nkGroupOps('D').filter(i => !/конденсат/i.test(N.names[i]) || /УОГ/.test(N.names[i]));
  const items = ops.map((i, k) => ({ name: N.names[i].replace(' (доля)', ''), v: sumRange(N.df[i], 0, di) / 1e3, color: PALETTE[k % PALETTE.length] }))
    .filter(x => x.v > 0 && !/Кольжан|ПКИ|Тургай|\*33/.test(x.name)).sort((a, b) => b.v - a.v);
  donut($('#cHomeD'), items, t => fmt(t / 1e3, 2), 'млн т', v => fmt(v, 0));
  const mega = $('.mega[data-count]');
  if (mega && !matchMedia('(prefers-reduced-motion: reduce)').matches && !S._counted) {
    S._counted = true; const target = +mega.dataset.count, small = mega.querySelector('small').outerHTML, t0 = performance.now();
    const step = t => { const k = Math.min(1, (t - t0) / 900), e = 1 - Math.pow(1 - k, 3); mega.innerHTML = fmt(target * e, 2) + small; if (k < 1) requestAnimationFrame(step); };
    requestAnimationFrame(step);
  }
};

/* ====================== ПАСПОРТ ====================== */
RENDER.pass = () => {
  const c = pickDZO(allList()), d = DATA.dzo[c], p = DATA.pass[c] || {};
  const share = isNum(p.share) ? `доля КМГ ${pct(p.share, p.share % 0.01 ? 1 : 0)}` : '';
  const top = head(d.name, `${d.seg === 'НДО' ? 'Нефтедобывающая' : 'Нефтесервисная'} организация${share ? ', ' + share : ''}.`, chipsDZO(allList(), c));
  return top + (d.seg === 'НДО' ? passNDO(c, p) : passNS(c, p));
};
function people(p, isNS) {
  const rows = [['Генеральный директор', [p.ceo, p.ceoTerm].filter(Boolean).join('\n')], ['Акционеры', p.holders], [isNS ? 'Наблюдательный совет' : 'Орган управления', (p.board || '').replace(/^(Совет директоров|Наблюдательный совет):\s*/, '')]];
  return `<dl class="people">${rows.filter(r => r[1]).map(([k, v]) => `<div class="person"><dt>${k}</dt><dd>${esc(v)}</dd></div>`).join('')}</dl>`;
}
function passNDO(c, p) {
  const k = p.kpi || {}, S7 = DATA.s7, rows = S7.rows[c] || [], per = S7.period.ytd;
  const g = n => rows.find(r => r.name === n);
  const kv = (o, nd = 0) => o ? (isNum(o.v) ? fmt(o.v, nd) : esc(o.t || '—')) : '—';
  const kpis = `<div class="kpis">
    ${KPI('Остаточные извлекаемые запасы', kv(k.reserves, k.reserves && k.reserves.v % 1 ? 1 : 0), 'млн т', 'нефть и конденсат', '', k.reserves && !isNum(k.reserves.v) ? 'text' : '')}
    ${KPI('Месторождений', kv(k.fields), 'шт.')}
    ${KPI('Действующий фонд скважин', kv(k.wells), 'шт.')}
    ${KPI('Штатная численность', kv(k.staff), 'чел.', 'утверждённая')}
    ${KPI('Несчастные случаи', kv(k.accidents), 'ед.', 'с начала года', '', isNum(k.accidents?.v) && k.accidents.v > 0 ? '' : '')}
  </div>`;
  const oil = g('Добыча нефти') || g('Добыча конденсата'), gas = g('Добыча газа'), np = g('Чистая прибыль'), ex = g('Доля экспорта'), lt = g('Лифтинг-затраты на тонну добычи');
  const trio = [
    np && trioKPI('Чистая прибыль', 'млн тг', np.bud, np.yp, np.yf, per),
    oil && trioKPI(oil.name, 'тыс. т', oil.bud, oil.yp, oil.yf, per),
    gas && trioKPI('Добыча газа', 'млн м³', gas.bud, gas.yp, gas.yf, per),
    ex && trioKPI('Доля экспорта', '', ex.bud, ex.yp, ex.yf, per, false, 0, true),
    lt && trioKPI('Лифтинг-затраты', 'тг/т', lt.bud, lt.yp, lt.yf, per, true),
  ].filter(Boolean).join('');
  const isP = r => r.u === '%';
  const trs = rows.map(r => {
    const md = isNum(r.mf) && isNum(r.mp) ? r.mf - r.mp : null, yd = isNum(r.yf) && isNum(r.yp) ? r.yf - r.yp : null;
    const inv = /Себестоимость|Лифтинг|Административ|Расходы/.test(r.name);
    const f = v => isP(r) ? pct(v, 1) : fmtA(v);
    const dv = v => !isNum(v) ? '—' : isP(r) ? sign(v * 100, 1) + ' п.п.' : sign(v, Math.abs(v) < 100 ? 1 : 0);
    const dc = v => !isNum(v) || Math.abs(v) < 1e-9 ? '' : (v > 0) !== inv ? 'pos' : 'neg';
    return `<tr><td class="code">${r.n ?? ''}</td><td class="l">${esc(r.name)}</td><td class="l muted">${esc(r.u || '')}</td><td>${f(r.bud)}</td><td>${f(r.mp)}</td><td>${f(r.mf)}</td><td class="${dc(md)}">${dv(md)}</td><td>${f(r.yp)}</td><td>${f(r.yf)}</td><td class="${dc(yd)}">${dv(yd)}</td><td>${isP(r) ? '' : pct(ratio(r.yf, r.yp), 1)}</td></tr>`;
  });
  const th = `<tr><th class="l">№</th><th class="l">Показатель</th><th class="l">ед.</th><th>Бюджет 2026</th><th>План ${esc(S7.period.month)}</th><th>Факт ${esc(S7.period.month)}</th><th>Откл.</th><th>План ${esc(per)}</th><th>Факт ${esc(per)}</th><th>Откл.</th><th>Исп.</th></tr>`;
  return `<div class="grid g-12"><div class="s-12">${kpis}</div></div>
    <div class="kpis mt">${trio}</div>
    <div class="grid g-12 mt">
      ${W_('glass s-7', 'О компании', '', `<p class="desc">${esc(p.desc || '')}</p>`)}
      ${W_('glass s-5', 'Управление', '', people(p, false))}
      ${DATA.oilDaily.dzo[c] ? W_('glass s-12', 'Добыча нефти по месяцам 2026', 'тыс. т', legend([['План', 'var(--plan)'], ['Факт', 'var(--fact)']]) + '<div class="chart" id="cPassOil"></div>', 'сумма суточных данных') : ''}
      ${W_('glass flat s-12', `Исполнение бюджета: ${S7.period.month}, ${per} 2026`, '', table(th, trs), 'данные на ' + dLabel(S7.period.asOf))}
    </div>`;
}
function passNS(c, p) {
  const ni = p.ni || {}, vk = p.vuk || {}, per = ni.per || vk.per || '';
  const trio = [
    isNum(ni.fp) || isNum(ni.py) ? trioKPI('Чистый доход (убыток)', 'млн тг', ni.py, ni.pp, ni.fp, per) : '',
    isNum(vk.py) || isNum(vk.fp) ? trioKPI(p.vukName || 'ВУК', 'млн тг', vk.py, vk.pp, vk.fp, vk.per || per) : '',
    ...(p.finFacts || []).map(f => KPI(f.name, fmt(f.v, 0), f.u, f.per ? 'на ' + esc(f.per) : '')),
    ...Object.entries(p.texts || {}).map(([k, v]) => KPI(k, esc(v), '', '', '', 'text')),
  ].filter(Boolean).join('');
  const prog = (p.prog || []).map(r => {
    const rr = ratio(r.fp, r.pp);
    return `<tr><td class="l">${esc(r.name)}</td><td class="l muted">${esc(r.u || '')}</td><td>${fmtA(r.py)}</td><td>${fmtA(r.pp)}</td><td>${fmtA(r.fp)}</td><td class="${rr === null ? '' : rr >= 1 ? 'pos' : 'neg'}">${pct(rr, 0)}</td><td style="min-width:120px"><div class="bar ${rr >= 1 ? 'over' : 'under'}" style="margin:0"><i style="width:${Math.min(100, (rr || 0) * 100)}%"></i></div></td></tr>`;
  });
  const years = [...new Set(Object.values(p.plan || {}).flatMap(o => Object.keys(o)))].sort();
  const planRows = Object.entries(p.plan || {}).map(([k, o]) => `<tr><td class="l">${esc(k)}</td>${years.map(y => `<td>${fmt(o[y], 0)}</td>`).join('')}</tr>`);
  return `<div class="kpis">${trio}</div>
    <div class="grid g-12 mt">
      ${prog.length ? W_('glass flat s-6', 'Производственная программа 2026', '', table(`<tr><th class="l">Показатель</th><th class="l">ед.</th><th>План 2026</th><th>План ${esc(per)}</th><th>Факт ${esc(per)}</th><th>Исп.</th><th></th></tr>`, prog)) : ''}
      ${years.length ? W_(`glass ${prog.length ? 's-6' : 's-12'}`, 'Финансовый план', 'млн тг', legend([['Выручка', 'var(--c2)'], ['Расходы', 'var(--c8)'], ['Чистая прибыль', 'var(--c4)']]) + '<div class="chart" id="cPassPlan"></div>') : ''}
      ${W_('glass s-7', 'О компании', '', `<p class="desc">${esc(p.desc || '')}</p>`)}
      ${W_('glass s-5', 'Управление', '', people(p, true))}
      ${(p.targets || []).length ? W_('glass s-12', 'Целевые ориентиры', '', `<div class="targets">${p.targets.map(t => `<div class="target"><div class="tn">${esc(t.name)} · к ${esc(t.h)}</div><div class="tv">${esc(t.val || '—')}${t.u && /^\s*[\d\s]+$/.test(t.val || '') ? ' ' + esc(t.u) : ''}</div></div>`).join('')}</div>`) : ''}
      ${planRows.length ? W_('glass flat s-12', 'Финансовый план по годам', 'млн тг', table(`<tr><th class="l">Показатель</th>${years.map(y => `<th>${y}</th>`).join('')}</tr>`, planRows)) : ''}
    </div>`;
}
POST.pass = () => {
  const c = S.dzo, p = DATA.pass[c] || {};
  if ($('#cPassOil')) {
    const s = DATA.oilDaily.dzo[c], li = odLast(c);
    barChart($('#cPassOil'), { labels: MON3, height: 230, bars: [{ name: 'План', values: odMonthly(s.plan, 999), color: 'var(--plan)' }, { name: 'Факт', values: odMonthly(s.fact, li), color: 'var(--fact)' }], tipFmt: v => fmt(v, 1) + ' тыс. т' });
  }
  if ($('#cPassPlan')) {
    const yrs = [...new Set(Object.values(p.plan).flatMap(o => Object.keys(o)))].sort(), g = k => yrs.map(y => (p.plan[k] || {})[y] ?? null);
    barChart($('#cPassPlan'), { labels: yrs, height: 240, bars: [{ name: 'Выручка', values: g('Выручка'), color: 'var(--c2)' }, { name: 'Расходы', values: g('Расходы'), color: 'var(--c8)' }], line: { name: 'Чистая прибыль', values: g('Чистая прибыль'), color: 'var(--c4)' }, fmt: fmtMln, tipFmt: v => fmt(v, 0) + ' млн тг' });
  }
};

/* ====================== НЕФТЬ ====================== */
const subtabs = (key, opts) => `<div class="subtabs" role="tablist">${opts.map(([v, l]) => `<button role="tab" data-sub="${key}" data-v="${v}" aria-selected="${S[key] === v}">${esc(l)}</button>`).join('')}</div>`;
RENDER.oil = () => {
  const st = subtabs('oilSub', [['nk', 'Сводка НК КМГ'], ['od', 'Суточная добыча по ДЗО'], ['pl', 'По платформам']]);
  if (S.oilSub === 'od') return oilOD(st);
  if (S.oilSub === 'pl') return oilPL(st);
  return oilNK(st);
};
function oilNK(st) {
  const N = DATA.nk, last = N.dates.length - 1;
  if (S.nkDay == null || S.nkDay > last) S.nkDay = last;
  const di = S.nkDay;
  const grpIdx = N.names.map((_, i) => i).filter(i => N.grp[i] === S.nkGrp);
  if (!grpIdx.includes(S.nkRow)) S.nkRow = grpIdx[0];
  const row = S.nkRow, a = nkAt(row, di), nm = N.names[row];
  const ctr = `<div class="range"><span class="rl">Дата</span><input type="range" min="0" max="${last}" value="${di}" data-k="nkDay" aria-label="Дата"><output>${dLabel(N.dates[di])}</output></div>` +
    seg('nkGrp', [['D', 'С учётом доли'], ['T', 'Общий']], S.nkGrp);
  const k3 = (title, f, p) => KPI(title, fmt(f, 0), 'т', `план ${fmt(p, 0)} <span class="delta ${f - p >= 0 ? 'good' : 'bad'}">${sign(f - p, 0)}</span>`);
  const big = v => v >= 1e6 ? fmt(v / 1e6, 2) + ' млн' : v >= 1e5 ? fmt(v / 1e3, 1) + ' тыс.' : fmt(v, 0);
  const k3b = (title, f, p) => KPI(title, big(f), 'т', `план ${big(p)} ${deltaPill(f, p)}`);
  const kp = `<div class="grid g-12">
    ${W_('glass s-6', 'Добыча', nm, `<div class="kpis k3">${k3('Сутки', a.df, a.dp)}${k3b('С начала месяца', a.mf, a.mp)}${k3b('С начала года', a.yf, a.yp)}</div>`)}
    ${W_('glass s-6', 'Сдача', nm, `<div class="kpis k3">${k3('Сутки', a.sf, a.sp)}${k3b('С начала месяца', a.msf, a.msp)}${k3b('С начала года', a.ysf, a.ysp)}</div>`)}
  </div>`;
  const ops = nkGroupOps(S.nkGrp);
  const devOf = i => { const b = nkAt(i, di); return S.nkDev === 'd' ? b.df - b.dp : S.nkDev === 'm' ? b.mf - b.mp : b.yf - b.yp; };
  const dev = ops.map(i => ({ name: N.names[i].replace(' (доля)', ''), v: devOf(i) })).sort((x, y) => y.v - x.v);
  const trs = grpIdx.map(i => {
    const b = nkAt(i, di), tot = /ВСЕГО|^Добыча нефти/.test(N.names[i]);
    return `<tr class="click ${tot ? 'lv1' : ''} ${i === row ? 'sel' : ''}" data-nkrow="${i}"><td class="l">${esc(N.names[i])}</td><td>${fmt(b.py, 0)}</td><td>${fmt(b.pmon, 0)}</td><td>${fmt(b.dp, 0)}</td><td>${fmt(b.df, 0)}</td>${tdNum(b.df - b.dp, 0, true)}<td>${fmt(b.mp, 0)}</td><td>${fmt(b.mf, 0)}</td>${tdNum(b.mf - b.mp, 0, true)}<td>${fmt(b.yp, 0)}</td><td>${fmt(b.yf, 0)}</td>${tdNum(b.yf - b.yp, 0, true)}</tr>`;
  });
  const th = `<tr><th class="l" rowspan="2">ДЗО / актив</th><th rowspan="2">План 2026</th><th rowspan="2">План месяца</th><th colspan="3">Сутки</th><th colspan="3">С начала месяца</th><th colspan="3">С начала года</th></tr>
    <tr><th>План</th><th>Факт</th><th>±</th><th>План</th><th>Факт</th><th>±</th><th>План</th><th>Факт</th><th>±</th></tr>`;
  return head('Нефть', `Суточная добыча и сдача нефти по активам КМГ, тонн. Нажмите на строку таблицы, чтобы показать её в карточках и на графике.`, ctr) + st + kp +
    `<div class="grid g-12 mt">
      ${W_('glass s-8', 'Добыча по месяцам', 'тыс. т', legend([['План', 'var(--plan)', 1], ['Факт', 'var(--fact)']]) + '<div class="chart" id="cNkM"></div>', esc(nm) + ', завершённые месяцы')}
      ${W_('glass s-4', 'Отклонения операционных активов', 'т', seg('nkDev', [['d', 'Сутки'], ['m', 'Месяц'], ['y', 'Год']], S.nkDev) + `<div class="mt">${hbars(dev)}</div>`)}
      ${W_('glass flat s-12', 'Исполнение добычи по активам', 'т', table(th, trs), 'на ' + dLabel(N.dates[di]))}
    </div>`;
}
POST.oil = () => {
  if (S.oilSub === 'nk') {
    const N = DATA.nk, row = S.nkRow, months = Object.keys(N.pm).sort().filter(m => monthDone(m, N.dates[S.nkDay]));
    const fact = months.map(m => { const ids = N.dates.map((d, i) => d.startsWith(m) && i <= S.nkDay ? i : -1).filter(i => i >= 0); return ids.length ? sum(ids.map(i => N.df[row][i])) / 1e3 : null; });
    if (!months.length) { $('#cNkM').innerHTML = '<div class="empty">Нет завершённых месяцев до выбранной даты</div>'; return; }
    lineChart($('#cNkM'), { labels: months.map(m => MON3[+m.slice(5) - 1]), height: 250, series: [
      { name: 'План', values: months.map(m => isNum(N.pm[m][row]) ? N.pm[m][row] / 1e3 : null), color: 'var(--plan)', dash: '5 4', labels: true, fmt: v => fmt(v, 0) },
      { name: 'Факт', values: fact, color: 'var(--fact)', area: true, dots: true }], tipFmt: v => fmt(v, 1) + ' тыс. т', tipTitle: i => MONTHS[+months[i].slice(5) - 1] });
  }
  if (S.oilSub === 'od') {
    const c = S.dzo, s = DATA.oilDaily.dzo[c], [a, b] = odRange();
    const lab = []; for (let i = a; i <= b; i++) lab.push(dShort(odDate(i)));
    lineChart($('#cOdD'), { labels: lab, height: 300, series: [
      { name: 'План', values: s.plan.slice(a, b + 1), color: 'var(--plan)', dash: '4 4', width: 2 },
      { name: 'Необходимый уровень', values: s.need.slice(a, b + 1), color: 'var(--need)', dash: '2 3', width: 1.6 },
      { name: 'Факт', values: s.fact.slice(a, b + 1), color: 'var(--fact)', area: true }], tipFmt: v => fmt(v, 0) + ' т', tipTitle: i => dLabel(odDate(a + i)) });
    const li = odLast(c), pf = odMonthly(s.plan, 999), ff = odMonthly(s.fact, li);
    barChart($('#cOdM'), { labels: MON3, height: 240, bars: [{ name: 'План', values: pf, color: 'var(--plan)' }, { name: 'Факт', values: ff, color: (v, i) => isNum(pf[i]) && v < pf[i] ? 'var(--bad)' : 'var(--fact)' }], tipFmt: v => fmt(v, 1) + ' тыс. т' });
  }
  if (S.oilSub === 'pl') {
    const P = DATA.plat.list[S.plat], ind = PLI.find(x => x[0] === S.platInd) || PLI[0], [a, b] = plRange();
    const lab = []; for (let i = a; i <= b; i++) lab.push(dShort(plDate(i)));
    const series = [];
    if (ind[0] === 'fact' && P.s.plan) series.push({ name: 'План', values: P.s.plan.slice(a, b + 1), color: 'var(--plan)', dash: '4 4', width: 2 });
    series.push({ name: ind[1], values: (P.s[ind[0]] || []).slice(a, b + 1), color: 'var(--fact)', area: true });
    lineChart($('#cPlD'), { labels: lab, height: 300, series, tipFmt: v => fmt(v, 0), tipTitle: i => dLabel(plDate(a + i)) });
  }
};
/* --- по ДЗО */
function odRange() {
  const c = S.dzo, li = odLast(c);
  let a = S.odFrom ? dayIndex(DATA.oilDaily.start, S.odFrom) : Math.max(0, li - 89);
  let b = S.odTo ? dayIndex(DATA.oilDaily.start, S.odTo) : li;
  a = Math.max(0, Math.min(a, DATA.oilDaily.dzo[c].fact.length - 1)); b = Math.max(a, Math.min(b, DATA.oilDaily.dzo[c].fact.length - 1));
  return [a, b];
}
function oilOD(st) {
  const list = ndoList().filter(c => DATA.oilDaily.dzo[c]), c = pickDZO(list), s = DATA.oilDaily.dzo[c];
  const [a, b] = odRange(), li = odLast(c), bf = Math.min(b, li);
  const pY = sum(s.plan), fY = sumRange(s.fact, 0, li), pP = sumRange(s.plan, a, bf), fP = sumRange(s.fact, a, bf);
  const ctr = chipsDZO(list, c, 'data-dzo', false) +
    `<div class="range"><span class="rl">с</span><input type="date" class="sel" style="padding:0 8px;background-image:none" data-k="odFrom" value="${odDate(a)}" min="${DATA.oilDaily.start}" max="${odDate(s.fact.length - 1)}"><span class="rl">по</span><input type="date" class="sel" style="padding:0 8px;background-image:none" data-k="odTo" value="${odDate(b)}" min="${DATA.oilDaily.start}" max="${odDate(s.fact.length - 1)}"></div>` +
    seg('odPreset', [['30', '30 дней'], ['90', '90 дней'], ['ytd', 'С начала года']], S.odPreset || '90');
  return head('Нефть', `Ежесуточная добыча ${esc(DATA.dzo[c].name)}: план, факт и уровень, необходимый для выполнения годового плана.`, ctr) + st +
    `<div class="kpis">
      ${KPI('План 2026', fmt(pY / 1e3, 1), 'тыс. т', 'годовой')}
      ${KPI('Факт с начала года', fmt(fY / 1e3, 1), 'тыс. т', `исполнение годового плана ${pct(fY / pY)}`, '', 'accent')}
      ${KPI('План за период', fmt(pP / 1e3, 1), 'тыс. т', `${dShort(odDate(a))} — ${dShort(odDate(bf))}`)}
      ${KPI('Факт за период', fmt(fP / 1e3, 1), 'тыс. т', deltaPill(fP, pP) + ' к плану')}
      ${KPI('Откл. за период', sign((fP - pP) / 1e3, 1), 'тыс. т', `в среднем ${sign((fP - pP) / Math.max(1, bf - a + 1), 0)} т/сут`)}
    </div>
    <div class="grid g-12 mt">
      ${W_('glass s-12', 'Добыча нефти ежесуточно', 'т/сут', legend([['План', 'var(--plan)', 1], ['Необходимый уровень', 'var(--need)', 1], ['Факт', 'var(--fact)']]) + '<div class="chart" id="cOdD"></div>')}
      ${W_('glass s-12', 'По месяцам', 'тыс. т', legend([['План', 'var(--plan)'], ['Факт', 'var(--fact)'], ['Факт ниже плана', 'var(--bad)']]) + '<div class="chart" id="cOdM"></div>')}
    </div>`;
}
/* --- платформы */
const PLI = [['fact', 'Факт добычи нефти, т'], ['sd', 'Сдача нефти, т'], ['liq', 'Добыча жидкости'], ['inj', 'Закачка'], ['dt_n', 'Простой, скв.'], ['dt_t', 'Простой, потери т'], ['dn_n', 'Снижение, скв.'], ['dn_t', 'Снижение, потери т'], ['fund', 'Действующий фонд'], ['bd', 'Бездействующий фонд']];
const plDate = i => new Date(Date.parse(DATA.plat.start) + i * 864e5).toISOString().slice(0, 10);
function plLast() { const f = DATA.plat.list[S.plat].s.fact || []; let i = f.length - 1; while (i > 0 && !isNum(f[i])) i--; return i; }
function plRange() { const li = plLast(); let a = S.odFrom ? dayIndex(DATA.plat.start, S.odFrom) : Math.max(0, li - 89); let b = S.odTo ? dayIndex(DATA.plat.start, S.odTo) : li; a = Math.max(0, Math.min(a, DATA.plat.n - 1)); b = Math.max(a, Math.min(b, DATA.plat.n - 1)); return [a, b]; }
function oilPL(st) {
  const L = DATA.plat.list; if (S.plat >= L.length) S.plat = 0;
  const P = L[S.plat], li = plLast(), [a, b] = plRange();
  let chips = '', g = null;
  L.forEach((p, i) => { if (p.dzo !== g) { g = p.dzo; chips += `<span class="chip-sep">${esc(g)}</span>`; } chips += `<button class="chip" data-plat="${i}" aria-pressed="${i === S.plat}"><i class="dot" style="background:${colorOf(p.dzo)}"></i>${esc(p.name)}</button>`; });
  const ctr = `<div class="chips scroll">${chips}</div><div class="range"><span class="rl">с</span><input type="date" class="sel" style="padding:0 8px;background-image:none" data-k="odFrom" value="${plDate(a)}"><span class="rl">по</span><input type="date" class="sel" style="padding:0 8px;background-image:none" data-k="odTo" value="${plDate(b)}"></div>`;
  const avail = PLI.filter(x => P.s[x[0]]);
  const at = (k, i) => (P.s[k] || [])[i];
  const months = [...new Set([...Array(li + 1).keys()].map(i => plDate(i).slice(0, 7)))];
  const isAvg = k => ['dt_n', 'dn_n', 'fund', 'bd', 'efund'].includes(k);
  const mAgg = (k, m) => { const ids = [...Array(li + 1).keys()].filter(i => plDate(i).startsWith(m)); const v = ids.map(i => at(k, i)).filter(isNum); return v.length ? (isAvg(k) ? sum(v) / v.length : sum(v)) : null; };
  const rows = [['plan', 'План добычи нефти, т'], ...PLI].filter(x => P.s[x[0]]).map(([k, l]) => `<tr><td class="l">${esc(l)}${isAvg(k) ? ' <span class="muted">(ср.)</span>' : ''}</td>${months.map(m => `<td>${fmt(mAgg(k, m), 0)}</td>`).join('')}</tr>`);
  const fP = sumRange(P.s.fact || [], a, Math.min(b, li)), pP = sumRange(P.s.plan || [], a, Math.min(b, li));
  return head('Нефть', `Производственные суточные показатели по платформам и НГДУ: ${esc(P.name)} (${esc(P.dzo)}).`, ctr) + st +
    `<div class="kpis">
      ${KPI('Факт добычи, сутки', fmt(at('fact', li), 0), 'т', `${dLabel(plDate(li))}, план ${fmt(at('plan', li), 0)} ${deltaPill(at('fact', li), at('plan', li))}`, '', 'accent')}
      ${KPI('Добыча за период', fmt(fP / 1e3, 1), 'тыс. т', `план ${fmt(pP / 1e3, 1)} ${deltaPill(fP, pP)}`)}
      ${KPI('Действующий фонд', fmt(at('fund', li), 0), 'скв.', isNum(at('bd', li)) ? `бездействующий ${fmt(at('bd', li), 0)}` : '')}
      ${KPI('Простой', fmt(at('dt_n', li), 0), 'скв.', `потери ${fmt(at('dt_t', li), 0)} т/сут`)}
      ${KPI('Снижение', fmt(at('dn_n', li), 0), 'скв.', `потери ${fmt(at('dn_t', li), 0)} т/сут`)}
    </div>
    <div class="grid g-12 mt">
      ${W_('glass s-12', 'Динамика показателя', '', seg('platInd', avail.map(x => [x[0], x[1]]), S.platInd) + '<div class="chart mt" id="cPlD"></div>')}
      ${W_('glass flat s-12', 'По месяцам', 'суммы, для фонда и количества — среднее', table(`<tr><th class="l">Показатель</th>${months.map(m => `<th>${MON3[+m.slice(5) - 1]}</th>`).join('')}</tr>`, rows))}
    </div>`;
}

/* ====================== ГАЗ ====================== */
RENDER.gas = () => {
  const G = DATA.gas, sec = +S.gasSec, rows = G.rows.filter(r => r.sec === sec);
  const yrs = G.years, a = Math.min(S.gasFrom, S.gasTo), b = Math.max(S.gasFrom, S.gasTo);
  const inR = y => +y >= a && +y <= b;
  const ents = rows.filter(r => r.code && /^\d\.\d\.\d+\.$/.test(r.code));
  if (!ents.some(r => r.name === S.gasEnt)) S.gasEnt = ents.find(r => r.code.includes('.2.'))?.name || ents[0].name;
  const ent = ents.find(r => r.name === S.gasEnt);
  const tot = r => { let f = 0, p = 0; Object.entries(r?.v || {}).forEach(([y, o]) => { if (inR(y) && isNum(o.f)) { f += o.f; p += o.p || 0; } }); return [f, p]; };
  const big = rows.find(r => r.code === `${sec}.1.`), opr = rows.find(r => r.code === `${sec}.2.`);
  const [bf, bp] = tot(big), [of, opp] = tot(opr), [ef, ep] = tot(ent);
  const nextY = '2027', e27 = ent?.v[nextY]?.fc, e26 = ent?.v['2026']?.p;
  const yopts = yrs.map(y => `<option value="${y}">${y}</option>`).join('');
  const ctr = seg('gasSec', [['1', 'С учётом доли КМГ'], ['2', '100%']], S.gasSec) +
    `<div class="range"><span class="rl">с</span><select class="sel" data-k="gasFrom">${yopts.replace(`value="${a}"`, `value="${a}" selected`)}</select><span class="rl">по</span><select class="sel" data-k="gasTo">${yopts.replace(`value="${b}"`, `value="${b}" selected`)}</select></div>`;
  const entChips = `<div class="chips scroll">${ents.map(r => `<button class="chip" data-gasent="${esc(r.name)}" aria-pressed="${r.name === S.gasEnt}">${esc(r.name)}</button>`).join('')}</div>`;
  const shown = yrs.filter(y => inR(y));
  const th = `<tr><th class="l" rowspan="2">Предприятие</th>${shown.map(y => `<th colspan="${y > 2025 ? 1 : 3}">${y}</th>`).join('')}</tr><tr>${shown.map(y => y > 2025 ? `<th>${y == 2026 ? 'План' : 'Прогноз'}</th>` : '<th>План</th><th>Факт</th><th>±</th>').join('')}</tr>`;
  const trs = rows.map(r => {
    const lv = !r.code ? 'lv3' : /^\d$/.test(r.code) || /^\d\.\d\.$/.test(r.code) ? 'lv1' : '';
    return `<tr class="${lv}"><td class="l">${esc(r.name)}</td>${shown.map(y => { const o = r.v[y] || {}; return y > 2025 ? `<td>${fmt(o.p ?? o.fc, 1)}</td>` : `<td>${fmt(o.p, 1)}</td><td>${fmt(o.f, 1)}</td>${tdNum(isNum(o.f) && isNum(o.p) ? o.f - o.p : null, 1, true)}`; }).join('')}</tr>`;
  });
  const per = `${a}–${Math.min(b, 2025)}`;
  return head('Газ', `Добыча газа по предприятиям: план, факт и отклонение за ${a}–${b} гг., млн м³. Факт есть до 2025 г., дальше план и прогноз.`, ctr) +
    `<div class="kpis">
      ${KPI('Крупные проекты', fmt(bf, 0), 'млн м³', `план ${fmt(bp, 0)} ${deltaPill(bf, bp)}`, '', 'accent')}
      ${KPI('Операционные активы', fmt(of, 0), 'млн м³', `план ${fmt(opp, 0)} ${deltaPill(of, opp)}`)}
      ${KPI(S.gasEnt, fmt(ef, 1), 'млн м³', `план ${fmt(ep, 1)} ${deltaPill(ef, ep)}`)}
      ${KPI(`Прогноз ${S.gasEnt} на 2027`, fmt(e27, 1), 'млн м³', isNum(e27) && isNum(e26) ? `к плану 2026 (${fmt(e26, 1)}) ${deltaPill(e27, e26)}` : '')}
    </div>
    <div class="note">Суммы фактов за ${per} гг.</div>
    <div class="grid g-12 mt">
      ${W_('glass s-7', 'Динамика добычи газа', 'млн м³', entChips + legend([['Факт', 'var(--fact)'], ['Прогноз', 'var(--c2)'], ['План', 'var(--c4)']]) + '<div class="chart" id="cGas"></div>', esc(S.gasEnt) + ', 2015–2030')}
      ${W_('glass s-5', 'Распределение добычи', 'млн м³', '<div id="cGasD"></div>', `операционные активы, факт ${per}`)}
      ${W_('glass flat s-12', 'Показатели по активам', 'млн м³', table(th, trs))}
    </div>`;
};
POST.gas = () => {
  const G = DATA.gas, sec = +S.gasSec, rows = G.rows.filter(r => r.sec === sec);
  const ent = rows.find(r => r.name === S.gasEnt), yrs = G.years;
  const vals = yrs.map(y => { const o = ent.v[y] || {}; return isNum(o.f) ? o.f : isNum(o.fc) ? o.fc : null; });
  barChart($('#cGas'), { labels: yrs.map(String), height: 260, bars: [{ name: 'Факт / прогноз', values: vals, color: (v, i) => isNum((ent.v[yrs[i]] || {}).f) ? 'var(--fact)' : 'var(--c2)' }], line: { name: 'План', values: yrs.map(y => (ent.v[y] || {}).p ?? null), color: 'var(--c4)' }, tipFmt: v => fmt(v, 1) + ' млн м³' });
  const a = Math.min(S.gasFrom, S.gasTo), b = Math.max(S.gasFrom, S.gasTo);
  const ops = rows.filter(r => r.code && new RegExp(`^${sec}\\.2\\.\\d+\\.$`).test(r.code));
  donut($('#cGasD'), ops.map((r, k) => ({ name: r.name, v: sum(Object.entries(r.v).filter(([y]) => +y >= a && +y <= b).map(([, o]) => o.f)), color: PALETTE[k % PALETTE.length] })).sort((x, y) => y.v - x.v), null, 'млн м³', v => fmt(v, 0));
};

/* ====================== СУТОЧНЫЕ ДАННЫЕ (DATA_КМГ) ====================== */
const OPS = { cache: {} };
function opsDay(i) {
  if (OPS.cache[i]) return OPS.cache[i];
  const O = DATA.ops, d = O.days[i], m = {};
  d.v.forEach(([k, e, v]) => { const ent = O.ents[e]; (m[ent] = m[ent] || {})[O.keys[k]] = v; });
  return (OPS.cache[i] = m);
}
const opsGet = (m, ent, re) => { const o = m[ent] || {}; const k = Object.keys(o).find(k => re.test(k)); return k ? o[k] : null; };
function opsPivot(m, block, ents) {
  const keys = [...new Set(ents.flatMap(e => Object.keys(m[e] || {})).filter(k => k.startsWith(block + '|')))].sort((x, y) => DATA.ops.keys.indexOf(x) - DATA.ops.keys.indexOf(y));
  return keys;
}
RENDER.ops = () => {
  const O = DATA.ops, n = O.days.length;
  if (S.opsDay == null) { // последний день с заполненным фондом скважин
    S.opsDay = n - 1;
    for (let i = n - 1; i >= 0; i--) { const m = opsDay(i); const v = Object.keys(m).filter(e => DATA.dzo[e]).map(e => opsGet(m, e, /^Фонд скважин\|Нефтедобывающий фонд\|Действующий/)); if (sum(v) > 0) { S.opsDay = i; break; } }
  }
  const di = S.opsDay, m = opsDay(di), date = O.days[di].d;
  const ents = O.ents.filter(e => DATA.dzo[e] && m[e]);
  const c = ents.includes(S.dzo) ? S.dzo : ents[0];
  const ctr = `<div class="range"><span class="rl">Дата</span><input type="range" min="0" max="${n - 1}" value="${di}" data-k="opsDay" aria-label="Дата"><output>${dLabel(date)}</output></div>` + chipsDZO(ents, c, 'data-dzo', false);
  // бригады
  const br = (sub, cat, per) => opsGet(m, c, new RegExp(`^Бригады\\|${sub}\\|[^|]*\\|${cat}\\|${per}\\|`));
  const brCard = sub => { const on = br(sub, 'Всего', 'На линии'), pl = br(sub, 'Всего', 'План'); const r = ratio(on, pl);
    return `<div class="kpi glass"><div class="l"><span>${sub}</span><span class="u">бригад</span></div><div class="v">${fmt(on, 0)}<span class="muted" style="font-size:.55em"> / ${fmt(pl, 0)}</span></div>
      <div class="bar ${r >= 1 ? 'over' : 'under'}"><i style="width:${Math.min(100, (r || 0) * 100)}%"></i></div>
      <div class="s"><span>подрядные ${fmt(br(sub, 'Подрядные', 'На линии'), 0)} / ${fmt(br(sub, 'Подрядные', 'План'), 0)}</span><span>собственные ${fmt(br(sub, 'Собственные', 'На линии'), 0)} / ${fmt(br(sub, 'Собственные', 'План'), 0)}</span></div></div>`; };
  const subs = ['Бурение', 'КРС', 'ПРС'];
  const allE = O.ents.filter(e => m[e]).sort((x, y) => (!DATA.dzo[x]) - (!DATA.dzo[y]));
  const brTh = `<tr><th class="l" rowspan="2">Предприятие</th>${subs.map(s => `<th colspan="2">${s}</th>`).join('')}</tr><tr>${subs.map(() => '<th>На линии</th><th>План</th>').join('')}</tr>`;
  const brTr = allE.map(e => `<tr class="${DATA.dzo[e] ? '' : 'lv1'} ${e === c ? 'sel' : ''}"><td class="l">${esc(e)}</td>${subs.map(s => { const on = opsGet(m, e, new RegExp(`^Бригады\\|${s}\\|[^|]*\\|Всего\\|На линии`)), pl = opsGet(m, e, new RegExp(`^Бригады\\|${s}\\|[^|]*\\|Всего\\|План`)); return `<td class="${isNum(on) && isNum(pl) && on < pl ? 'neg' : ''}">${fmt(on, 0)}</td><td>${fmt(pl, 0)}</td>`; }).join('')}</tr>`);
  // фонд
  const fundKeys = opsPivot(m, 'Фонд скважин|' + S.opsFund, allE);
  const cat = k => k.split('|')[2];
  const fTr = allE.filter(e => fundKeys.some(k => isNum((m[e] || {})[k]))).map(e => `<tr class="${DATA.dzo[e] ? '' : 'lv1'} ${e === c ? 'sel' : ''}"><td class="l">${esc(e)}</td>${fundKeys.map(k => `<td>${fmt((m[e] || {})[k], 0)}</td>`).join('')}</tr>`);
  // потери
  const loss = ents.map(e => ({ name: e, v: opsGet(m, e, /^Потери от простоя скважин\|\|Потери нефти\|\|С начала года/) || 0, color: colorOf(e) })).sort((x, y) => y.v - x.v);
  const lossNow = opsGet(m, c, /^Потери от простоя скважин\|\|Количество скважин\|\|На текущую дату/), lossM = opsGet(m, c, /^Потери от простоя скважин\|\|Потери нефти\|\|С начала месяца/), lossY = opsGet(m, c, /^Потери от простоя скважин\|\|Потери нефти\|\|С начала года/);
  // скважины
  const wl = sub => ents.map(e => { const pl = opsGet(m, e, new RegExp(`^Скважины\\|${sub}\\|[^|]*\\|\\|[Пп]лан 2026`)), f = opsGet(m, e, new RegExp(`^Скважины\\|${sub}\\|[^|]*\\|\\|Факт с начала года`)); return { e, pl, f }; }).filter(x => isNum(x.pl) || isNum(x.f));
  const wTr = sub => wl(sub).map(x => { const r = ratio(x.f, x.pl); return `<tr><td class="l">${esc(x.e)}</td><td>${fmt(x.pl, 0)}</td><td>${fmt(x.f, 0)}</td><td>${pct(r, 0)}</td><td style="min-width:110px"><div class="bar" style="margin:0"><i style="width:${Math.min(100, (r || 0) * 100)}%"></i></div></td></tr>`; });
  const wTh = '<tr><th class="l">Предприятие</th><th>План 2026</th><th>Факт с н. г.</th><th>Исп.</th><th></th></tr>';
  // произвольные блоки: МРП и ГТМ, аварийные отключения
  const pivotTable = block => {
    const ks = opsPivot(m, block, allE); if (!ks.length) return '<div class="empty">Нет данных на эту дату</div>';
    const lab = k => { const p = k.split('|'); return [p[1], p[1] && p[1].includes(p[2]) || (p[2] || '').includes(p[1] || '§') ? '' : p[2], p[4]].filter(Boolean).join(' · ') + (p[5] ? `, ${p[5]}` : ''); };
    const es = allE.filter(e => ks.some(k => isNum((m[e] || {})[k])));
    return table(`<tr><th class="l">Предприятие</th>${ks.map(k => `<th style="white-space:normal;min-width:110px">${esc(lab(k))}</th>`).join('')}</tr>`, es.map(e => `<tr class="${DATA.dzo[e] ? '' : 'lv1'}"><td class="l">${esc(e)}</td>${ks.map(k => `<td>${fmtA((m[e] || {})[k])}</td>`).join('')}</tr>`));
  };
  const water = opsGet(m, 'КБМ', /^Пресная вода\|.*\|Сутки/);
  return head('Суточные данные', `Бригады, фонд скважин, потери, ГТМ и аварийные отключения по ДЗО на ${dLabel(date)}.`, ctr) +
    `<div class="kpis">${subs.map(brCard).join('')}
      ${KPI('Потери от простоя', fmt(lossY, 0), 'т с н. г.', `${fmt(lossNow, 0)} скв. простаивают, с начала месяца ${fmt(lossM, 0)} т`)}
    </div>
    <div class="grid g-12 mt">
      ${W_('glass flat s-6', 'Бригады', 'на линии / план', table(brTh, brTr))}
      ${W_('glass s-6', 'Потери нефти от простоя скважин', 'т с начала года', hbars(loss, v => fmt(v, 0), { positive: true }))}
      ${W_('glass flat s-12', 'Фонд скважин', 'скв.', `<div style="padding:0 20px 10px">${seg('opsFund', [['Нефтедобывающий фонд', 'Нефтедобывающий'], ['Нагнетательный фонд', 'Нагнетательный']], S.opsFund)}</div>` + (fTr.length ? table(`<tr><th class="l">Предприятие</th>${fundKeys.map(k => `<th>${esc(cat(k))}</th>`).join('')}</tr>`, fTr) : '<div class="empty">На эту дату фонд не заполнен. Выберите другую дату.</div>'))}
      ${W_('glass flat s-6', 'Бурение скважин', 'скв.', table(wTh, wTr('Бурение скважин')))}
      ${W_('glass flat s-6', 'КРС', 'скв.', table(wTh, wTr('КРС')))}
      ${W_('glass flat s-12', 'МРП и ГТМ', '', pivotTable('МРП и ГТМ'))}
      ${W_('glass flat s-12', 'Аварийные отключения', '', pivotTable('Аварийные отключения'), isNum(water) ? `Выработка пресной воды ОЗПВ КБМ за сутки: ${fmt(water, 0)} м³` : '')}
    </div>`;
};

/* ====================== ОТМ ====================== */
RENDER.otm = () => {
  const T = DATA.otm, months = T.months;
  if (!months.includes(+S.otmM)) S.otmM = months[months.length - 1];
  const mo = +S.otmM, list = ordered(Object.keys(T.rows).filter(c => T.rows[c][mo]));
  const c = pickDZO(list), rows = T.rows[c][mo];
  const find = re => rows.find(r => re.test(r[1]));
  const ctr = seg('otmM', months.map(x => [String(x), MON3[x - 1]]), String(mo)) + chipsDZO(list, c, 'data-dzo', false);
  const k = (re, label, inv = false) => { const r = find(re); if (!r) return ''; const nd = Math.abs(r[5] ?? 0) < 100 ? 1 : 0;
    return KPI(label, fmt(r[5], nd), r[2], `план ${fmt(r[4], nd)} ${deltaPill(r[5], r[4], inv)}<span>с н. г. ${fmt(r[7], nd)} из ${fmt(r[6], nd)}</span>`); };
  const lvl = code => !code ? '' : /^\d+$/.test(code.replace(/\.$/, '')) ? 'lv1' : (code.match(/[.,]/g) || []).length >= 3 ? 'lv3' : '';
  const q = S.otmQ.trim().toLowerCase();
  const trs = [];
  rows.forEach((r, i) => {
    if (q && !r[1].toLowerCase().includes(q)) return;
    const md = isNum(r[5]) && isNum(r[4]) ? r[5] - r[4] : null, yd = isNum(r[7]) && isNum(r[6]) ? r[7] - r[6] : null, nd = 1;
    trs.push(`<tr class="${lvl(r[0])}"><td class="code">${esc(r[0] || '')}</td><td class="l">${esc(r[1])}</td><td class="l muted">${esc(r[2] || '')}</td><td>${fmt(r[3], nd)}</td><td>${fmt(r[4], nd)}</td><td>${fmt(r[5], nd)}</td>${tdNum(md, nd, true)}<td>${pct(ratio(r[5], r[4]), 1)}</td><td>${fmt(r[6], nd)}</td><td>${fmt(r[7], nd)}</td>${tdNum(yd, nd, true)}<td>${pct(ratio(r[7], r[6]), 1)}</td><td class="l" style="min-width:0">${r[8] ? `<button class="cm" data-cm="${i}" aria-expanded="${S.otmOpen.has(i)}">${S.otmOpen.has(i) ? 'Скрыть' : 'Комментарий'}</button>` : ''}</td></tr>`);
    if (r[8] && S.otmOpen.has(i)) trs.push(`<tr class="cmt"><td></td><td colspan="12">${esc(r[8])}</td></tr>`);
  });
  const th = `<tr><th class="l" rowspan="2">№</th><th class="l" rowspan="2">Показатель</th><th class="l" rowspan="2">ед.</th><th rowspan="2">План 2026</th><th colspan="4">${MONTHS[mo - 1]}</th><th colspan="4">С начала года</th><th rowspan="2"></th></tr><tr><th>План</th><th>Факт</th><th>±</th><th>%</th><th>План</th><th>Факт</th><th>±</th><th>%</th></tr>`;
  const gtm = rows.filter(r => r[2] === 'скв.' && /^\d+$/.test(String(r[0]).replace(/\.$/, '')) && isNum(r[6]) && r[6] > 0).map(r => ({ name: r[1], v: (r[7] || 0) / r[6] * 100, color: (r[7] || 0) >= r[6] ? 'var(--good)' : 'var(--c1)' }));
  return head('ОТМ', `Месячные показатели по основным технологическим мероприятиям, ${MONTHS[mo - 1]} 2026.`, ctr) +
    `<div class="kpis">${k(/^Объем добычи нефти$/, 'Добыча нефти')}${k(/^Суточная добыча нефти$/, 'Суточная добыча нефти')}${k(/^Действующий фонд добывающих/, 'Действующий фонд')}${k(/^Кол-во ГТМ/, 'Количество ГТМ')}${k(/^Обводненность/, 'Обводнённость', true)}</div>
    <div class="grid g-12 mt">
      ${W_('glass s-7', 'Добыча нефти по месяцам', 'тыс. т', legend([['План', 'var(--plan)'], ['Факт', 'var(--fact)']]) + '<div class="chart" id="cOtm"></div>')}
      ${W_('glass s-5', 'Мероприятия: исполнение с начала года', '% плана', gtm.length ? `<div style="max-height:330px;overflow:auto;padding-right:6px">${hbars(gtm, v => fmt(v, 0) + '%', { positive: true })}</div>` : '<div class="empty">Нет мероприятий с планом</div>')}
      ${W_('glass flat s-12', 'Показатели по активам', '', `<div style="padding:0 20px 12px"><input class="search" type="search" placeholder="Найти показатель" value="${esc(S.otmQ)}" data-k="otmQ" aria-label="Поиск показателя"></div>` + table(th, trs))}
    </div>`;
};
POST.otm = () => {
  const T = DATA.otm, c = S.dzo, ms = T.months;
  const v = ms.map(m => (T.rows[c][m] || []).find(r => r[1] === 'Объем добычи нефти'));
  barChart($('#cOtm'), { labels: ms.map(m => MON3[m - 1]), height: 240, bars: [{ name: 'План', values: v.map(r => r ? r[4] : null), color: 'var(--plan)' }, { name: 'Факт', values: v.map(r => r ? r[5] : null), color: 'var(--fact)' }], tipFmt: x => fmt(x, 1) + ' тыс. т' });
};

/* ====================== ФИНАНСЫ ====================== */
RENDER.fin = () => {
  const list = ordered([...Object.keys(DATA.fin.dzo), ...Object.keys(DATA.finNS.dzo)]);
  const c = pickDZO(list), src = finSrc(c), months = src.months, av = finMonths26(c);
  if (!av.includes(S.finM)) S.finM = av[av.length - 1];
  const mi = S.finM, mode = S.finMode, rows = src.dzo[c], isN = DATA.dzo[c].seg === 'НДО';
  const per = mode === 'ytd' ? `январь — ${MONTHS[+months[mi].slice(5) - 1]} 2026` : `${MONTHS[+months[mi].slice(5) - 1]} 2026`;
  const v = (r, k) => finVal(r, k, mi, mode, months);
  const kp = (label, keys, inv) => { const r = finRow(c, ...keys); if (!r) return ''; const f = v(r, 'f'), p = v(r, 'p');
    return KPI(label, fmt(f, 0), 'млн тг', `план ${fmt(p, 0)} ${deltaPill(f, p, inv)}`, `<div class="spark">${spark(r.f.slice(-24), 'var(--c2)')}</div>`); };
  const M = DATA.macro, mm = DATA.macro.months.indexOf(months[mi]);
  const macro = mm >= 0 ? `<div class="chips"><span class="chip" style="cursor:default">Курс $ ${fmt(M.rate.f[mm], 2)} ₸</span><span class="chip" style="cursor:default">Brent $${fmt(M.brent.f[mm], 2)}</span></div>` : '';
  const ctr = chipsDZO(list, c) + `<select class="sel" data-k="finM" aria-label="Месяц">${av.map(i => `<option value="${i}" ${i === mi ? 'selected' : ''}>${MONTHS[+months[i].slice(5) - 1]} 2026</option>`).join('')}</select>` + seg('finMode', [['ytd', 'С начала года'], ['m', 'За месяц']], mode);
  // ОПиУ
  const opiu = rows.filter(r => isN ? r.t === 'Для таблицы' : r.lvl >= 1).filter(r => isNum(v(r, 'f')) || isNum(v(r, 'p')));
  const inv = k => /Расход|Себестоим|КПН|ФОТ|Амортиз|РиУ|Энерг|СиМ|Налог|Транспорт|Охрана|Прочие|Лифтинг/.test(k) && !/доход/i.test(k);
  const trs = opiu.map(r => { const f = v(r, 'f'), p = v(r, 'p'), d = isNum(f) && isNum(p) ? f - p : null;
    return `<tr class="lv${r.lvl}"><td class="l">${esc(r.k)}</td><td>${fmt(p, 0)}</td><td>${fmt(f, 0)}</td>${tdNum(d, 0, true, inv(r.k))}<td>${pct(ratio(f, p), 0)}</td></tr>`; });
  const unit = rows.filter(r => r.t === 'Расчетный показатель').map(r => { const f = r.f[mi], p = r.p[mi]; return `<tr><td class="l">${esc(r.k)}</td><td>${fmt(p, 0)}</td><td>${fmt(f, 0)}</td>${tdNum(isNum(f) && isNum(p) ? f - p : null, 0, true, true)}</tr>`; });
  return head('Финансы', `${esc(DATA.dzo[c].name)}: доходы, расходы и денежный поток, ${per}, млн тг.`, ctr) +
    `<div class="kpis">${kp('Выручка', ['Выручка'])}${kp('Расходы', ['Расходы, всего'], true)}${kp('Чистый доход', ['ЧИСТЫЙ ДОХОД/(УБЫТОК)'])}${kp('Капвложения (КВЛ)', ['КВЛ', 'КВЛ, всего'])}${kp('Свободный ден. поток', ['СДП'])}${kp('EBITDA', ['EBITDA'])}</div>
    ${macro ? `<div class="mt">${macro}</div>` : ''}
    <div class="grid g-12 mt">
      ${W_('glass s-8', 'Выручка и расходы по месяцам', 'млн тг', legend([['Выручка, факт', 'var(--c1)'], ['Выручка, план', 'var(--c2)', 1], ['Расходы, факт', 'var(--c5)']]) + '<div class="chart" id="cFinM"></div>', '2024 — 2026')}
      ${W_('glass s-4', 'Чистый доход (убыток) по годам', 'млн тг', '<div class="chart" id="cFinY"></div>', '2026 — с начала года по выбранный месяц')}
      ${W_('glass s-6', 'Структура себестоимости', 'млн тг', '<div id="cFinC"></div>', per)}
      ${W_('glass s-6', isN ? 'Реализация нефти' : 'Структура выручки', isN ? 'тыс. т' : 'млн тг', '<div id="cFinR"></div>', per)}
      ${W_(`glass flat ${unit.length ? 's-8' : 's-12'}`, 'Сравнение план / факт по ОПиУ', 'млн тг', table('<tr><th class="l">Статья</th><th>План</th><th>Факт</th><th>±</th><th>Исп.</th></tr>', trs), per)}
      ${unit.length ? W_('glass flat s-4', 'Удельные показатели', 'тг/т', table('<tr><th class="l">Показатель</th><th>План</th><th>Факт</th><th>±</th></tr>', unit), MONTHS[+months[mi].slice(5) - 1] + ' 2026') : ''}
    </div>`;
};
POST.fin = () => {
  const c = S.dzo, src = finSrc(c), months = src.months, mi = S.finM, rows = src.dzo[c], isN = DATA.dzo[c].seg === 'НДО';
  const rev = finRow(c, 'Выручка'), exp = finRow(c, 'Расходы, всего'), ni = finRow(c, 'ЧИСТЫЙ ДОХОД/(УБЫТОК)');
  const upto = arr => arr.map((x, i) => i <= mi ? x : null);
  lineChart($('#cFinM'), { labels: months.map(mLabel), height: 260, series: [
    { name: 'Выручка, план', values: rev.p.map(x => isNum(x) ? x : null), color: 'var(--c2)', dash: '5 4', width: 2 },
    { name: 'Расходы, факт', values: upto(exp?.f || []), color: 'var(--c5)', width: 2 },
    { name: 'Выручка, факт', values: upto(rev.f), color: 'var(--c1)', area: true }], fmt: fmtMln, tipFmt: v => fmt(v, 0) + ' млн тг', tipTitle: i => MONTHS[+months[i].slice(5) - 1] + ' ' + months[i].slice(0, 4) });
  const yrs = ['2024', '2025', '2026'], yv = yrs.map(y => { let s = 0, any = false; months.forEach((m, i) => { if (m.startsWith(y) && i <= mi && isNum(ni?.f[i])) { s += ni.f[i]; any = true; } }); return any ? s : null; });
  barChart($('#cFinY'), { labels: yrs, height: 240, labelsOn: true, fmt: fmtMln, bars: [{ name: 'Чистый доход', values: yv, color: v => v >= 0 ? 'var(--good)' : 'var(--bad)' }], tipFmt: v => fmt(v, 0) + ' млн тг' });
  const ci = rows.findIndex(r => r.k === 'Себестоимость'); const kids = [];
  for (let i = ci + 1; ci >= 0 && i < rows.length; i++) { if (rows[i].lvl && rows[i].lvl < 3) break; if (rows[i].lvl === 3) kids.push(rows[i]); }
  const items = kids.map(r => ({ name: r.k, v: finVal(r, 'f', mi, S.finMode, months) })).filter(x => x.v > 0).sort((a, b) => b.v - a.v);
  const top = items.slice(0, 6), rest = sum(items.slice(6).map(x => x.v));
  if (rest > 0) top.push({ name: 'Прочие статьи', v: rest });
  donut($('#cFinC'), top.map((x, k) => ({ ...x, color: PALETTE[k % PALETTE.length] })), t => fmtMln(t).replace(/ (млрд|млн)$/, ''), sumUnit(sum(top.map(x => x.v))), v => fmt(v, 0));
  let r2;
  if (isN) r2 = [['Экспорт', 'Экспорт'], ['Внутренний рынок', 'Внут. Рынок']].map(([n, k], j) => ({ name: n, v: finVal(finRow(c, k), 'f', mi, S.finMode, months), color: j ? 'var(--c2)' : 'var(--c1)' }));
  else { const di = rows.findIndex(r => r.k === 'Доходы, всего'); r2 = rows.slice(0, Math.max(0, di)).filter(r => r.u === 'млн тг').map((r, k) => ({ name: r.k, v: finVal(r, 'f', mi, S.finMode, months), color: PALETTE[k % PALETTE.length] })); }
  donut($('#cFinR'), r2, isN ? null : t => fmtMln(t).replace(/ (млрд|млн)$/, ''), isN ? 'тыс. т' : sumUnit(sum(r2.map(x => x.v || 0))), v => fmt(v, 0));
};

const sumUnit = t => Math.abs(t) >= 1000 ? 'млрд тг' : 'млн тг';
/* ====================== БЮДЖЕТЫ ====================== */
RENDER.bud = () => {
  const B = DATA.budget, list = ordered(Object.keys(B.dzo)), c = pickDZO(list), rows = B.dzo[c], cols = B.cols;
  const find = re => rows.find(r => re.test(r.k));
  const ni = find(/^Чистый доход/i), isN = DATA.dzo[c].seg === 'НДО';
  const iU = 0, iE = 1, i27 = 2, i27m = 3;
  const cmp = (label, a, b, note) => { const va = ni?.v[a], vb = ni?.v[b]; const d = isNum(va) && isNum(vb) ? va - vb : null;
    return KPI(label, fmt(va, 0), 'млн тг', d === null ? '' : `<span class="delta ${d >= 0 ? 'good' : 'bad'}">${sign(d, 0)} (${sign(vb ? d / Math.abs(vb) * 100 : 0, 1)}%)</span><span>${note}</span>`); };
  const tileRow = find(isN ? /^Добыча нефти$/ : /^Выручка$/);
  const tiles = tileRow ? `<div class="kpis mt">${cols.filter((_, i) => i !== iE && i !== i27m).map(col => { const i = cols.indexOf(col); return KPI(col.replace(' утв', ''), fmt(tileRow.v[i], 0), isN ? 'тыс. т' : 'млн тг', esc(tileRow.k)); }).join('')}</div>` : '';
  const isHdr = r => !r.u && r.v.every(x => !isNum(x) || x === 0) && Number.isInteger(r.n);
  const trs = rows.filter(r => r.k).map(r => {
    if (isHdr(r)) return `<tr class="grp"><td class="code">${r.n ?? ''}</td><td class="l" colspan="${cols.length + 2}">${esc(r.k)}</td></tr>`;
    const p = r.u === '%', f = x => p ? pct(x, 1) : !isNum(x) ? '—' : Math.abs(x) < 100 && x % 1 ? fmt(x, 1) : fmt(x, 0);
    return `<tr class="${/^(Доходы, всего|Расходы, всего|Чистый доход|EBITDA|СДП|КВЛ)/i.test(r.k) ? 'lv1' : ''}"><td class="code">${r.n ?? ''}</td><td class="l">${esc(r.k)}</td><td class="l muted">${esc(r.u || '')}</td>${r.v.map(x => `<td>${f(x)}</td>`).join('')}</tr>`;
  });
  return head('Бюджеты', `${esc(DATA.dzo[c].name)}: утверждённый план 2026, оценка 6+6 и среднесрочный план до 2031 г.`, chipsDZO(list, c)) +
    `<div class="kpis">${cmp('План 2027 к утв. 2026', i27, iU, 'чистый доход')}${cmp('План 2027 к метрикам 2027', i27, i27m, 'чистый доход')}${cmp('Оценка 2026 (6+6) к утв. плану', iE, iU, 'чистый доход')}</div>${tiles}
    <div class="grid g-12 mt">
      ${W_('glass s-6', 'Чистый доход (убыток)', 'млн тг', '<div class="chart" id="cBudNi"></div>', 'утв. 2026 и план 2027–2031')}
      ${W_('glass s-6', 'Доходы и расходы', 'млн тг', legend([['Доходы, всего', 'var(--c1)'], ['Расходы, всего', 'var(--c8)']]) + '<div class="chart" id="cBudIE"></div>')}
      ${W_('glass flat s-12', 'Показатели бюджетов', '', table(`<tr><th class="l">№</th><th class="l">Статья</th><th class="l">ед.</th>${cols.map(x => `<th>${esc(x)}</th>`).join('')}</tr>`, trs))}
    </div>`;
};
POST.bud = () => {
  const B = DATA.budget, rows = B.dzo[S.dzo], cols = B.cols, idx = [0, 2, 4, 5, 6, 7];
  const ni = rows.find(r => /^Чистый доход/i.test(r.k)), inc = rows.find(r => /^Доходы, всего/i.test(r.k)), ex = rows.find(r => /^Расходы, всего/i.test(r.k));
  const lab = idx.map(i => cols[i].replace(' утв', ''));
  lineChart($('#cBudNi'), { labels: lab, height: 240, series: [{ name: 'Чистый доход', values: idx.map(i => ni?.v[i] ?? null), color: 'var(--c2)', area: true, dots: true, labels: true, fmt: v => fmt(v, 0) }], fmt: fmtMln, tipFmt: v => fmt(v, 0) + ' млн тг' });
  barChart($('#cBudIE'), { labels: lab, height: 240, bars: [{ name: 'Доходы, всего', values: idx.map(i => inc?.v[i] ?? null), color: 'var(--c1)' }, { name: 'Расходы, всего', values: idx.map(i => ex?.v[i] ?? null), color: 'var(--c8)' }], fmt: fmtMln, tipFmt: v => fmt(v, 0) + ' млн тг' });
};

/* ------------------------------------------------------------------ события */
function bindEvents() {
  const view = $('#view');
  view.addEventListener('click', e => {
    const t = e.target.closest('button, tr[data-nkrow]'); if (!t) return;
    if (t.dataset.go) { S.tab = t.dataset.go; S.dzo = t.dataset.dzo; writeHash(); render(); scrollTo({ top: 0, behavior: 'smooth' }); return; }
    if (t.dataset.dzo) { S.dzo = t.dataset.dzo; S.otmOpen.clear(); writeHash(true); render(); return; }
    if (t.dataset.sub) { S[t.dataset.sub] = t.dataset.v; render(); return; }
    if (t.dataset.plat != null) { S.plat = +t.dataset.plat; render(); return; }
    if (t.dataset.gasent) { S.gasEnt = t.dataset.gasent; render(); return; }
    if (t.dataset.nkrow) { S.nkRow = +t.dataset.nkrow; render(); return; }
    if (t.dataset.cm) { const i = +t.dataset.cm; S.otmOpen.has(i) ? S.otmOpen.delete(i) : S.otmOpen.add(i); render(); return; }
    const sg = t.closest('[data-seg]');
    if (sg && t.dataset.v != null) {
      const k = sg.dataset.seg, v = t.dataset.v;
      if (k === 'odPreset') {
        S.odPreset = v;
        const isPl = S.oilSub === 'pl', li = isPl ? plLast() : odLast(S.dzo), dt = isPl ? plDate : odDate;
        S.odTo = dt(li); S.odFrom = v === 'ytd' ? dt(0) : dt(Math.max(0, li - (+v - 1)));
      } else S[k] = v;
      if (k === 'otmM') S.otmOpen.clear();
      render();
    }
  });
  view.addEventListener('input', e => {
    const k = e.target.dataset.k; if (!k) return;
    if (k === 'otmQ') { S.otmQ = e.target.value; const pos = e.target.selectionStart; render(); const s = $('[data-k="otmQ"]'); s.focus(); s.setSelectionRange(pos, pos); return; }
    if (e.target.type === 'range') {
      S[k] = +e.target.value;
      const out = e.target.nextElementSibling;
      if (out) out.textContent = dLabel(k === 'nkDay' ? DATA.nk.dates[S[k]] : DATA.ops.days[S[k]].d);
      renderSoon();
    }
  });
  view.addEventListener('change', e => {
    const k = e.target.dataset.k; if (!k || e.target.type === 'range') return;
    if (k === 'finM' || k === 'gasFrom' || k === 'gasTo') S[k] = +e.target.value;
    else if (k === 'odFrom' || k === 'odTo') { S[k] = e.target.value || null; S.odPreset = null; }
    else S[k] = e.target.value;
    render();
  });
  addEventListener('hashchange', () => { readHash(); render(); });
  let lastW = innerWidth;
  addEventListener('resize', debounce(() => { if (Math.abs(innerWidth - lastW) > 30) { lastW = innerWidth; render(); } }, 200));
  $('#themeBtn').addEventListener('click', () => {
    const cur = document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    const nxt = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = nxt; try { localStorage.setItem('dzo-theme', nxt); } catch (e) { }
    render();
  });
  $('#logoutBtn').addEventListener('click', () => { sessionStorage.removeItem(SS_KEY); location.hash = ''; location.reload(); });
  $('#exportBtn').addEventListener('click', openExport);
  $('#doPdf').addEventListener('click', () => { $('#exportDlg').close(); setTimeout(() => print(), 150); });
  $('#doPptx').addEventListener('click', buildPptx);
}
const renderSoon = debounce(render, 120);

/* ------------------------------------------------------------------ выгрузка */
function openExport() {
  const box = $('#exportList');
  box.innerHTML = allList().map(c => `<label><input type="checkbox" value="${esc(c)}" ${c === S.dzo ? 'checked' : ''}> ${esc(c)} <span class="muted small">${esc(DATA.dzo[c].name)}</span></label>`).join('');
  $('#exportMsg').textContent = '';
  $('#exportDlg').showModal();
}
function loadScript(src) { return new Promise((ok, fail) => { const s = document.createElement('script'); s.src = src; s.onload = ok; s.onerror = fail; document.head.appendChild(s); }); }
async function buildPptx() {
  const sel = $$('#exportList input:checked').map(i => i.value);
  const msg = $('#exportMsg');
  if (!sel.length) { msg.textContent = 'Отметьте хотя бы одно ДЗО.'; return; }
  msg.textContent = 'Загружаем библиотеку и собираем слайды…';
  try {
    if (!window.PptxGenJS) {
      try { await loadScript('https://cdn.jsdelivr.net/npm/pptxgenjs@3.12.0/dist/pptxgen.bundle.js'); }
      catch (e) { await loadScript('https://cdnjs.cloudflare.com/ajax/libs/pptxgenjs/3.12.0/pptxgen.bundle.js'); }
    }
    const P = new PptxGenJS(); P.layout = 'LAYOUT_WIDE';
    const NAVY = '062A5A', BLUE = '0A5FB0', CY = '1AA3E8', INK = '0B1F3F', MUT = '6C7F9C';
    const per = DATA.s7.period;
    sel.forEach(c => {
      const d = DATA.dzo[c], p = DATA.pass[c] || {}, s = P.addSlide();
      s.background = { color: 'F3F7FC' };
      s.addShape(P.ShapeType.rect, { x: 0, y: 0, w: 13.33, h: 0.9, fill: { color: NAVY } });
      s.addText(`${d.name}`, { x: 0.4, y: 0.12, w: 9, h: 0.66, fontFace: 'Arial', fontSize: 24, bold: true, color: 'FFFFFF' });
      s.addText(d.seg === 'НДО' ? `Нефтедобывающая организация · данные ${per.ytd} 2026` : 'Нефтесервисная организация', { x: 8.4, y: 0.25, w: 4.6, h: 0.4, fontSize: 11, color: 'BFD8F5', align: 'right' });
      const box = (x, y, w, label, val, unit) => {
        s.addShape(P.ShapeType.roundRect, { x, y, w, h: 1.0, fill: { color: 'FFFFFF' }, line: { color: 'D6E3F2' }, rectRadius: 0.12 });
        s.addText(label, { x: x + 0.15, y: y + 0.08, w: w - 0.3, h: 0.3, fontSize: 10, color: MUT });
        s.addText([{ text: val, options: { fontSize: 20, bold: true, color: INK } }, { text: unit ? '  ' + unit : '', options: { fontSize: 10, color: MUT } }], { x: x + 0.15, y: y + 0.4, w: w - 0.3, h: 0.5 });
      };
      if (d.seg === 'НДО') {
        const k = p.kpi || {}; const kv = o => o ? (isNum(o.v) ? fmt(o.v, o.v % 1 ? 1 : 0) : (o.t || '—')) : '—';
        [['Остаточные запасы', kv(k.reserves), 'млн т'], ['Месторождений', kv(k.fields), ''], ['Действующий фонд', kv(k.wells), 'скв.'], ['Численность', kv(k.staff), 'чел.'], ['Несчастные случаи', kv(k.accidents), '']]
          .forEach((b, i) => box(0.4 + i * 2.52, 1.1, 2.4, ...b));
        const rows = (DATA.s7.rows[c] || []).filter(r => r.n <= 16 || r.name);
        const tb = [[{ text: 'Показатель', options: { bold: true, color: 'FFFFFF', fill: { color: BLUE } } }, ...['ед.', 'Бюджет 2026', `План ${per.ytd}`, `Факт ${per.ytd}`, 'Откл., %'].map(t => ({ text: t, options: { bold: true, color: 'FFFFFF', fill: { color: BLUE }, align: 'right' } }))]];
        rows.slice(0, 16).forEach(r => { const pc = r.u === '%'; const f = v => pc ? pct(v, 1) : fmtA(v); const rr = ratio(r.yf, r.yp);
          tb.push([r.name, { text: r.u || '', options: { color: MUT } }, { text: f(r.bud), options: { align: 'right' } }, { text: f(r.yp), options: { align: 'right' } }, { text: f(r.yf), options: { align: 'right', bold: true } }, { text: pc || rr === null ? '' : sign((rr - 1) * 100, 1) + '%', options: { align: 'right', color: rr === null ? INK : rr >= 1 ? '0E9A6C' : 'D93B3F' } }]); });
        s.addTable(tb, { x: 0.4, y: 2.3, w: 7.6, colW: [2.9, 0.8, 1.0, 1.0, 1.0, 0.9], fontSize: 8.5, color: INK, border: { type: 'solid', color: 'E1E9F3', pt: 0.5 }, rowH: 0.27 });
        const od = DATA.oilDaily.dzo[c];
        if (od) { const li = odLast(c), r1 = a => a.map(v => isNum(v) ? +v.toFixed(1) : 0);
          s.addChart(P.ChartType.bar, [{ name: 'План', labels: MON3, values: r1(odMonthly(od.plan, 999)) }, { name: 'Факт', labels: MON3, values: r1(odMonthly(od.fact, li)) }],
            { x: 8.2, y: 2.3, w: 4.8, h: 3.0, barGrouping: 'clustered', chartColors: ['9CC8EE', BLUE], showLegend: true, legendPos: 'b', legendFontSize: 9, catAxisLabelFontSize: 8, valAxisLabelFontSize: 8, showTitle: true, title: 'Добыча нефти, тыс. т', titleFontSize: 11, titleColor: INK }); }
        s.addText(p.desc || '', { x: 8.2, y: 5.45, w: 4.8, h: 1.8, fontSize: 9, color: INK, valign: 'top' });
      } else {
        const ni = p.ni || {}, vk = p.vuk || {};
        box(0.4, 1.1, 3.0, `Чистый доход, план 2026`, fmt(ni.py, 0), 'млн тг');
        box(3.55, 1.1, 3.0, `Чистый доход, факт ${ni.per || ''}`, fmt(ni.fp, 0), 'млн тг');
        box(6.7, 1.1, 3.0, `${p.vukName || 'ВУК'}, факт ${vk.per || ''}`, fmt(vk.fp, 0), 'млн тг');
        box(9.85, 1.1, 3.0, 'Численность', (p.texts?.['Численность'] || '—').split('\n')[0], '');
        const tb = [[{ text: 'Производственная программа', options: { bold: true, color: 'FFFFFF', fill: { color: BLUE } } }, ...['План 2026', 'План', 'Факт', 'Исп.'].map(t => ({ text: t, options: { bold: true, color: 'FFFFFF', fill: { color: BLUE }, align: 'right' } }))]];
        (p.prog || []).forEach(r => tb.push([r.name, { text: fmtA(r.py), options: { align: 'right' } }, { text: fmtA(r.pp), options: { align: 'right' } }, { text: fmtA(r.fp), options: { align: 'right', bold: true } }, { text: pct(ratio(r.fp, r.pp), 0), options: { align: 'right' } }]));
        if (tb.length > 1) s.addTable(tb, { x: 0.4, y: 2.35, w: 6.4, colW: [2.8, 0.9, 0.9, 0.9, 0.9], fontSize: 9, color: INK, border: { type: 'solid', color: 'E1E9F3', pt: 0.5 }, rowH: 0.3 });
        const yrs = [...new Set(Object.values(p.plan || {}).flatMap(o => Object.keys(o)))].sort();
        if (yrs.length) s.addChart(P.ChartType.bar, ['Выручка', 'Расходы', 'Чистая прибыль'].filter(k => p.plan[k]).map(k => ({ name: k, labels: yrs, values: yrs.map(y => p.plan[k][y] ?? 0) })),
          { x: 7.0, y: 2.35, w: 6.0, h: 3.0, barGrouping: 'clustered', chartColors: [CY, 'A9B9CC', 'F2A33A'], showLegend: true, legendPos: 'b', legendFontSize: 9, catAxisLabelFontSize: 8, valAxisLabelFontSize: 8, showTitle: true, title: 'Финансовый план, млн тг', titleFontSize: 11, titleColor: INK });
        s.addText(p.desc || '', { x: 0.4, y: 5.5, w: 12.5, h: 1.6, fontSize: 9.5, color: INK, valign: 'top' });
      }
      s.addText(`Источник: КМГ_Данные_PBI.xlsx · сформировано ${new Date().toLocaleDateString('ru-RU')}`, { x: 0.4, y: 7.1, w: 12.5, h: 0.3, fontSize: 8, color: MUT });
    });
    await P.writeFile({ fileName: `ДЗО_КМГ_${new Date().toISOString().slice(0, 10)}.pptx` });
    msg.textContent = `Готово: ${sel.length} слайд(ов).`;
  } catch (err) { console.error(err); msg.textContent = 'Не удалось собрать PPTX: проверьте доступ к cdn.jsdelivr.net или cdnjs.cloudflare.com.'; }
}

/* ------------------------------------------------------------------ старт */
function startApp() {
  document.body.classList.remove('locked');
  $('#app').hidden = false;
  $('#asof').textContent = 'Данные на ' + dLabel(DATA.meta.asOf);
  $('#built').textContent = 'Сборка ' + DATA.meta.built;
  readHash();
  if (!S._bound) { bindEvents(); S._bound = true; }
  render();
}
document.addEventListener('DOMContentLoaded', initGate);
