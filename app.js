/* Innovation idea board — client-side app.
   NOTE ON SECURITY: the site is authenticated upstream by Cloudflare Access (only the
   founders' emails can reach it). There is no client-side password gate. ideas.json is
   still fetchable by anyone who gets THROUGH Access, so keep the group's private founder
   descriptions out of it — those live in /analysis (never deployed). */

const $ = (s, el = document) => el.querySelector(s);
const state = { ideas: [], rubric: {}, votes: {}, voters: [], voter: "", sort: { key: "composite", asc: false }, trends: [], trendMeta: {}, trendSort: { key: "created", asc: false }, roles: [], roleMeta: {} };
let voteCbSeq = 0;

/* ---------- SHA-256 ----------
   Self-contained (works on file://, IP, localhost or https alike — no dependency on
   crypto.subtle, which only exists in a "secure context"). Used to match the Cloudflare
   Access identity email against the founder allow-list without storing plaintext emails. */
function sha256(ascii) {
  function rightRotate(value, amount) { return (value >>> amount) | (value << (32 - amount)); }
  var mathPow = Math.pow, maxWord = mathPow(2, 32), i, j, result = "", words = [];
  var asciiBitLength = ascii.length * 8;
  var hash = sha256.h = sha256.h || [];
  var k = sha256.k = sha256.k || [];
  var primeCounter = k.length, isComposite = {};
  for (var candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (i = 0; i < 313; i += candidate) { isComposite[i] = candidate; }
      hash[primeCounter] = (mathPow(candidate, .5) * maxWord) | 0;
      k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
    }
  }
  ascii += "\x80";
  while (ascii.length % 64 - 56) ascii += "\x00";
  for (i = 0; i < ascii.length; i++) {
    j = ascii.charCodeAt(i);
    if (j >> 8) return;
    words[i >> 2] |= j << ((3 - i) % 4) * 8;
  }
  words[words.length] = ((asciiBitLength / maxWord) | 0);
  words[words.length] = (asciiBitLength);
  for (j = 0; j < words.length;) {
    var w = words.slice(j, j += 16), oldHash = hash;
    hash = hash.slice(0, 8);
    for (i = 0; i < 64; i++) {
      var w15 = w[i - 15], w2 = w[i - 2], a = hash[0], e = hash[4];
      var temp1 = hash[7]
        + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25))
        + ((e & hash[5]) ^ ((~e) & hash[6])) + k[i]
        + (w[i] = (i < 16) ? w[i] : (
            w[i - 16]
            + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3))
            + w[i - 7]
            + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
          ) | 0);
      var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22))
        + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
    }
    for (i = 0; i < 8; i++) { hash[i] = (hash[i] + oldHash[i]) | 0; }
  }
  for (i = 0; i < 8; i++) {
    for (j = 3; j + 1; j--) {
      var b = (hash[i] >> (j * 8)) & 255;
      result += ((b < 16) ? 0 : "") + b.toString(16);
    }
  }
  return result;
}
const utf8 = s => unescape(encodeURIComponent(s));

/* ---------- Identity via Cloudflare Access ----------
   The site sits behind Cloudflare Access, which authenticates the visitor and exposes their
   identity at /cdn-cgi/access/get-identity. We map that email to a founder so the board knows
   "who am I" automatically — no name picker anywhere. Only SHA-256 hashes of the founder emails
   live here (this repo is public); the plaintext addresses never do. To add/rotate a founder:
   run  printf '%s' 'their.email@x.com' | shasum -a 256  and add the hash below (lowercase email). */
const VOTER_BY_EMAIL_HASH = {
  "3ee516e5ae18201a990b88185b40eeef130a5e8fce79186aba972352c0284e20": "Dave",
  "e58a8d5f0359593989194666cb9a81c867b9b5c981568c5ed3d222e7971ac98c": "Matt",
  "93a80fa8e4e00b8a6c2cf51661a14b822fb2a194c21fd99babd5d774ee58ee64": "Graeme",
  "1430fc986a4954158c76fa5a93e048d4d785a2d22b49558b093049f5726b91a5": "Rick",
  "2a11040687f87099b8ee6021aca51748083b23fe6a95589ad62a6c7b39ce2e8a": "Nik",
  "f2b8b429458d2d65ad504a3c09f380cb4ecc19d44562938a4b0455ddccfb2c44": "Kapil",
};
async function detectUser() {
  // Local-preview escape hatch (no Access in front): append ?as=Dave to the URL.
  const asParam = new URLSearchParams(location.search).get("as");
  if (asParam) { setVoter(asParam); return; }
  try {
    const id = await fetch("/cdn-cgi/access/get-identity", { credentials: "same-origin" })
      .then(r => r.ok ? r.json() : null);
    const email = id && (id.email || (id.identity && id.identity.email));
    if (email) {
      state.voterEmail = email;
      const name = VOTER_BY_EMAIL_HASH[sha256(utf8(email.trim().toLowerCase()))];
      if (name) { setVoter(name); return; }
    }
  } catch {}
  // Fallback (local dev / unrecognised login): last remembered name, if any.
  const remembered = localStorage.getItem("voterName");
  if (remembered) setVoter(remembered);
}
// Sign out = drop the Cloudflare Access session (bounces back to the login screen).
$("#signout").addEventListener("click", () => { location.href = "/cdn-cgi/access/logout"; });
boot();

/* ---------- Data + scoring ---------- */
async function boot() {
  await detectUser(); // resolve "who am I" from Cloudflare Access before first render
  const [ideasRes, cfgRes, trendsRes, rolesRes] = await Promise.all([
    fetch("ideas.json").then(r => r.json()),
    fetch("config.json").then(r => r.json()),
    // trends.json is optional — a missing/empty file just yields no trends.
    fetch("trends.json").then(r => r.ok ? r.json() : {}).catch(() => ({})),
    // roles.json is optional too — a missing/empty file just yields no team roles.
    fetch("roles.json").then(r => r.ok ? r.json() : {}).catch(() => ({})),
  ]);
  state.ideas = ideasRes.ideas || [];
  state.rubric = cfgRes.rubric || {};
  state.contactEmail = cfgRes.contactEmail || "";
  state.endpoint = cfgRes.endpoint || "";
  state.voters = cfgRes.voters || [];
  state.trends = (trendsRes && trendsRes.trends) || [];
  state.trendMeta = (trendsRes && trendsRes.meta) || {};
  state.roles = (rolesRes && rolesRes.roles) || [];
  state.roleMeta = (rolesRes && rolesRes.meta) || {};
  $("#brand-sub").textContent = (ideasRes.meta && ideasRes.meta.subtitle) || "";
  renderWhoAmI();
  route();
  loadVotes().then(route); // fill in live tallies without blocking first paint
}
window.addEventListener("hashchange", route);

/* ---------- Team voting ---------- */
// Single source of truth for "who am I" — used by the top picker, both forms, and voting.
function setVoter(name) {
  state.voter = name || "";
  localStorage.setItem("voterName", state.voter);
  renderWhoAmI();
}
// Show who Cloudflare Access says you are (replaces the old name picker).
function renderWhoAmI() {
  const el = $("#whoami");
  if (!el) return;
  el.textContent = state.voter ? `Signed in as ${state.voter}`
    : (state.voterEmail ? state.voterEmail : "");
}
// A fixed, read-only "your name" field — identity comes from Access, so there's nothing to pick.
// Renders a visible name plus a hidden input so existing form code can still read `.value`.
function voterFieldHtml(cls, attrs) {
  const n = state.voter || "";
  return `<span class="voter-fixed">${esc(n || "not recognised")}</span>` +
    `<input type="hidden" class="voter-select ${cls || ""}"${attrs || ""} value="${esc(n)}">`;
}
// Read live vote tallies from the Apps Script via JSONP (bypasses CORS on a static site).
function loadVotes() {
  return new Promise((resolve) => {
    if (!state.endpoint) { state.votes = {}; return resolve(); }
    const cb = "__votes_cb_" + (++voteCbSeq);
    let done = false;
    const s = document.createElement("script");
    const finish = (v) => { if (done) return; done = true; if (v) state.votes = v; try { s.remove(); } catch {} delete window[cb]; resolve(); };
    window[cb] = (data) => finish((data && data.votes) || {});
    s.onerror = () => finish({});
    s.src = `${state.endpoint}?action=votes&callback=${cb}&_=${Date.now()}`;
    document.body.appendChild(s);
    setTimeout(() => finish(null), 6000);
  });
}
function teamVotes(ideaId) {
  const arr = (state.votes && state.votes[ideaId]) || [];
  const valid = arr.filter(v => v.score > 0);
  const avg = valid.length ? valid.reduce((a, b) => a + b.score, 0) / valid.length : null;
  return { avg, count: valid.length, votes: arr };
}
// The team score for an idea stays hidden until the current voter has rated it (avoids anchoring).
function hasVoted(ideaId) {
  if (!state.voter) return false;
  const arr = (state.votes && state.votes[ideaId]) || [];
  return arr.some(v => v.name === state.voter && v.score > 0);
}
function upsertVote(ideaId, name, score, comment) {
  const arr = state.votes[ideaId] = state.votes[ideaId] || [];
  const existing = arr.find(v => v.name === name);
  if (existing) { existing.score = score; existing.comment = comment; }
  else { arr.push({ name, score, comment }); }
}
function teamCardHtml(idea) {
  const { avg, count, votes } = teamVotes(idea.id);
  const mine = votes.find(v => v.name === state.voter);
  const voted = hasVoted(idea.id);
  const summary = !voted
    ? `<p class="muted" style="margin:0 0 4px">🔒 Rate this idea below to reveal the team's score.</p>`
    : (count
      ? `<div class="vote-summary"><span class="composite team-score">${avg.toFixed(1)}</span><span class="muted">/ 10 · ${count} vote${count > 1 ? "s" : ""}</span></div>`
      : `<p class="muted" style="margin:0 0 4px">No team ratings yet.</p>`);
  const list = voted && votes.length
    ? `<div class="vote-list">${votes.map(v => `<div class="vote-row"><span class="vote-name">${esc(v.name)}</span><span class="score-pill ${scoreClass(v.score)}">${v.score}</span>${v.comment ? `<span class="vote-comment">${esc(v.comment)}</span>` : ""}</div>`).join("")}</div>`
    : "";
  const mineForm = state.voter
    ? `<form id="vote-form" class="vote-mine">
         <label>Your rating (as ${esc(state.voter)})</label>
         <div class="vote-slider"><input type="range" id="vote-score" min="1" max="10" step="1" value="${mine ? mine.score : 7}" /><output id="vote-val">${mine ? mine.score : 7}</output><span class="muted">/ 10</span></div>
         <textarea id="vote-comment" rows="2" placeholder="Why? (optional)">${esc(mine ? mine.comment : "")}</textarea>
         <div class="ans-actions"><button type="button" id="vote-save">${mine ? "Update my rating" : "Save my rating"}</button><span id="vote-note" class="muted"></span></div>
       </form>`
    : `<p class="muted" style="margin-bottom:0">Your login isn't recognised as a founder, so rating is disabled.</p>`;
  return `<div class="card"><h3>Team rating</h3>${summary}${list}${mineForm}</div>`;
}

function composite(idea) {
  let sum = 0, w = 0;
  for (const key in state.rubric) {
    const sc = idea.scores && idea.scores[key];
    if (!sc) continue;
    const weight = state.rubric[key].weight ?? 1;
    sum += sc.score * weight; w += weight;
  }
  return w ? sum / w : 0;
}
const scoreClass = v => v >= 7 ? "s-good" : v >= 5 ? "s-mid" : "s-bad";
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

/* ---------- Router ---------- */
function route() {
  const hash = location.hash;
  let page = "board";
  if (hash === "#/submit") { renderSubmit(); }
  else if (hash === "#/trends") { page = "trends"; renderTrends(); }
  else if (hash === "#/team") { page = "team"; renderTeam(); }
  else {
    const tm = hash.match(/^#\/trend\/(.+)$/);
    const im = hash.match(/^#\/idea\/(.+)$/);
    if (tm) {
      page = "trends";
      const t = state.trends.find(x => x.id === decodeURIComponent(tm[1]));
      t ? renderTrendDetail(t) : renderTrends();
    } else if (im) {
      const idea = state.ideas.find(i => i.id === decodeURIComponent(im[1]));
      idea ? renderDetail(idea) : renderList();
    } else {
      renderList();
    }
  }
  // highlight the active top-nav page link
  document.querySelectorAll(".nav-page").forEach(a => a.classList.toggle("active", a.dataset.match === page));
  window.scrollTo(0, 0);
}

/* ---------- List view ---------- */
function renderList() {
  const view = $("#view");
  if (!state.ideas.length) {
    view.innerHTML = `<div class="empty"><h2>No ideas yet</h2><p>Ideas will appear here once they're submitted and analysed.</p><p><a href="#/submit" class="btn-primary">+ Submit an idea</a></p></div>`;
    return;
  }
  const rows = state.ideas.map(i => ({ idea: i, composite: composite(i) }));
  const { key, asc } = state.sort;
  rows.sort((a, b) => {
    let av, bv;
    if (key === "composite") { av = a.composite; bv = b.composite; }
    else if (key === "team") { av = teamVotes(a.idea.id).avg ?? -1; bv = teamVotes(b.idea.id).avg ?? -1; }
    else { av = a.idea.scores?.[key]?.score ?? 0; bv = b.idea.scores?.[key]?.score ?? 0; }
    return asc ? av - bv : bv - av;
  });

  const cols = Object.keys(state.rubric); // all scorecard metrics
  const th = k => `<th data-key="${k}" class="num ${key === k ? "sorted " + (asc ? "asc" : "") : ""}" title="${esc(state.rubric[k]?.label || k)}">${esc(state.rubric[k]?.short || state.rubric[k]?.label || k)}</th>`;
  const thead = `<thead><tr>
        <th class="num">#</th>
        <th data-key="_title">Idea</th>
        <th data-key="composite" class="num ${key === "composite" ? "sorted " + (asc ? "asc" : "") : ""}">Composite</th>
        <th data-key="team" class="num ${key === "team" ? "sorted " + (asc ? "asc" : "") : ""}" title="Team rating (1–10 average)">Team</th>
        ${cols.map(th).join("")}
      </tr></thead>`;
  // Row renderer. `muted` = a discarded row (plain number, not keyed to a chart bubble).
  const rowHtml = ({ idea, composite: c }, num, muted) => `
          <tr data-id="${esc(idea.id)}">
            <td class="num">${muted ? `<span class="muted">${num}</span>` : `<span class="tm-leg-num" style="background:var(--team)">${num}</span>`}</td>
            <td class="idea-title">${esc(idea.title)}${idea.sample ? ' <span class="badge sample">sample</span>' : ""}
              <small>${esc(idea.oneLiner || "")}</small></td>
            <td class="num"><span class="composite">${c.toFixed(1)}</span></td>
            <td class="num">${hasVoted(idea.id)
              ? (teamVotes(idea.id).avg == null ? '<span class="muted">—</span>' : `<span class="composite team-score">${teamVotes(idea.id).avg.toFixed(1)}</span>`)
              : '<span class="vote-now">VOTE NOW</span>'}</td>
            ${cols.map(k => {
              const s = idea.scores?.[k]?.score;
              return `<td class="num">${s == null ? "—" : `<span class="score-pill ${scoreClass(s)}">${s}</span>`}</td>`;
            }).join("")}
          </tr>`;
  // Ideas stay on the board only with a composite of 5.0 OR ABOVE; the rest are shown as discarded.
  const kept = rows.filter(r => r.composite >= 5);
  const discarded = rows.filter(r => r.composite < 5);

  view.innerHTML = `
    <div class="list-head">
      <div><h2>Idea Board</h2><p class="muted">Ideas scoring <strong>5.0 or above</strong> stay on the board and are plotted below; lower-scoring ideas drop to <strong>Discarded</strong>. The chart plots each kept idea by <strong>attractiveness</strong> (higher up) against <strong>ease of entry</strong> (further right); <strong>bubble size</strong> is the team's average vote. Click any bubble or row for the full business case.</p></div>
      <a href="#/submit" class="btn-primary">+ Submit an idea</a>
    </div>
    ${quadrant(kept)}
    <h3 class="board-section" style="margin-top:22px">Ideas on the board <span class="muted">— composite 5.0 or above</span></h3>
    <div class="table-wrap"><table>
      ${thead}
      <tbody>
        ${kept.length ? kept.map((r, i) => rowHtml(r, i + 1, false)).join("") : `<tr><td colspan="${cols.length + 4}" class="muted" style="padding:14px">No ideas 5.0 or above yet.</td></tr>`}
      </tbody>
    </table></div>
    ${discarded.length ? `
    <h3 class="board-section" style="margin-top:30px">Discarded Ideas <span class="muted">— composite below 5.0</span></h3>
    <div class="table-wrap"><table>
      ${thead}
      <tbody>
        ${discarded.map((r, i) => rowHtml(r, kept.length + i + 1, true)).join("")}
      </tbody>
    </table></div>` : ""}
  `;

  view.querySelectorAll("th[data-key]").forEach(el => el.addEventListener("click", () => {
    const k = el.dataset.key;
    if (k === "_title") return;
    if (state.sort.key === k) state.sort.asc = !state.sort.asc;
    else state.sort = { key: k, asc: false };
    renderList();
  }));
  view.querySelectorAll("tbody tr").forEach(tr =>
    tr.addEventListener("click", () => { location.hash = `#/idea/${encodeURIComponent(tr.dataset.id)}`; }));
  view.querySelectorAll(".dot").forEach(g =>
    g.addEventListener("click", () => { location.hash = `#/idea/${encodeURIComponent(g.dataset.id)}`; }));

  // Bubble hover: show the idea title in a tooltip that tracks the cursor
  const tip = view.querySelector(".tm-tip"), box = view.querySelector(".quad-box");
  if (tip && box) {
    view.querySelectorAll(".dot").forEach(g => {
      const idea = state.ideas.find(x => x.id === g.dataset.id);
      g.addEventListener("mouseenter", () => { tip.textContent = idea ? idea.title : ""; tip.hidden = false; });
      g.addEventListener("mousemove", e => {
        const r = box.getBoundingClientRect();
        tip.style.left = (e.clientX - r.left) + "px";
        tip.style.top = (e.clientY - r.top) + "px";
      });
      g.addEventListener("mouseleave", () => { tip.hidden = true; });
    });
  }
}

/* ---------- 2x2 quadrant (attractiveness vs ease of entry, bubble = founder-fit) ---------- */
function quadrant(rows) {
  const W = 760, H = 440, pad = 46;
  const attractiveness = i => avg([i.scores?.market?.score, i.scores?.margins?.score, i.scores?.moat?.score, i.scores?.saturation?.score, i.scores?.risk?.score]);
  const ease = i => avg([i.scores?.entry?.score, i.scores?.cost?.score]);
  const x = v => pad + ((v - 1) / 9) * (W - pad * 2);
  const y = v => (H - pad) - ((v - 1) / 9) * (H - pad * 2);

  // Bubbles are numbered and keyed to the table below. Ideas that share the same
  // attractiveness/ease scores land on identical coordinates, so a light collision-avoidance
  // pass nudges overlapping bubbles just clear of each other — each stays near its true spot
  // but both stay visible instead of stacking invisibly on top of one another.
  const pts = rows.map(({ idea }, i) => {
    const vote = teamVotes(idea.id).avg;      // bubble size reflects the team's average vote
    const sizeVal = vote == null ? 3 : vote;  // unvoted ideas show as small bubbles
    return { idea, i, cx: x(ease(idea)), cy: y(attractiveness(idea)), r: 7 + sizeVal * 1.6 };
  });
  // Break exact ties deterministically (a sub-pixel offset) so coincident points have a push direction.
  pts.forEach((p, k) => { p.cx += (((k * 13) % 7) - 3) * 0.4; p.cy += (((k * 11) % 5) - 2) * 0.4; });
  const clampX = (v, r) => Math.max(pad + r, Math.min(W - pad - r, v));
  const clampY = (v, r) => Math.max(pad + r, Math.min(H - pad - r, v));
  for (let iter = 0; iter < 120; iter++) {
    let moved = false;
    for (let a = 0; a < pts.length; a++) for (let b = a + 1; b < pts.length; b++) {
      const pa = pts[a], pb = pts[b];
      const dx = pb.cx - pa.cx, dy = pb.cy - pa.cy;
      const dist = Math.hypot(dx, dy) || 0.001;
      const minGap = pa.r + pb.r + 3;         // desired clearance between bubble edges
      if (dist < minGap) {
        const push = (minGap - dist) / 2, ux = dx / dist, uy = dy / dist;
        pa.cx = clampX(pa.cx - ux * push, pa.r); pa.cy = clampY(pa.cy - uy * push, pa.r);
        pb.cx = clampX(pb.cx + ux * push, pb.r); pb.cy = clampY(pb.cy + uy * push, pb.r);
        moved = true;
      }
    }
    if (!moved) break;
  }
  const dots = pts.map(p => `<g class="dot" data-id="${esc(p.idea.id)}">
      <circle cx="${p.cx.toFixed(1)}" cy="${p.cy.toFixed(1)}" r="${p.r}" fill="var(--team)" fill-opacity="0.28" stroke="var(--team)"></circle>
      <text class="dot-num" x="${p.cx.toFixed(1)}" y="${p.cy.toFixed(1)}" text-anchor="middle" dominant-baseline="central">${p.i + 1}</text>
    </g>`).join("");

  return `<div class="quad">
    <h3>Attractiveness vs. ease of entry <span class="muted">— bubble size = team's average vote</span></h3>
    <div class="quad-box"><svg viewBox="0 0 ${W} ${H}" role="img">
      <line x1="${W/2}" y1="${pad}" x2="${W/2}" y2="${H-pad}" stroke="var(--line)"></line>
      <line x1="${pad}" y1="${H/2}" x2="${W-pad}" y2="${H/2}" stroke="var(--line)"></line>
      <text class="axis-label" x="${W-pad}" y="${H/2 - 8}" text-anchor="end">Easier entry →</text>
      <text class="axis-label" x="16" y="${H/2}" text-anchor="middle" transform="rotate(-90 16 ${H/2})">More attractive →</text>
      ${dots}
    </svg><div class="tm-tip" hidden></div></div>
  </div>`;
}
const avg = arr => { const v = arr.filter(n => n != null); return v.length ? v.reduce((a, b) => a + b, 0) / v.length : 5; };
const shortTitle = t => { const s = String(t).split("—")[0].trim(); return s.length > 22 ? s.slice(0, 21) + "…" : s; };

/* ---------- Detail view ---------- */
function renderDetail(idea) {
  const view = $("#view");
  const c = composite(idea);
  const bc = idea.businessCase || {};
  const scoreRows = Object.keys(state.rubric).map(k => {
    const s = idea.scores?.[k]; if (!s) return "";
    const conf = s.confidence ? `<span class="conf ${esc(s.confidence)}">${esc(s.confidence)} confidence</span>` : "";
    const src = (s.sources && s.sources.length)
      ? `<p class="score-why">Sources: ${s.sources.map(u => `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(hostname(u))}</a>`).join(", ")}</p>` : "";
    return `<div class="score-row">
      <div class="top"><span class="label">${esc(state.rubric[k].label)}</span>
        <span><span class="score-pill ${scoreClass(s.score)}">${s.score}</span></span></div>
      <div class="bar"><i style="width:${s.score * 10}%"></i></div>
      <p class="score-why">${esc(s.why || "")} ${conf}</p>${src}
    </div>`;
  }).join("");

  const bcSection = (h, v) => v ? `<div class="bc-section"><h4>${esc(h)}</h4><p>${esc(v)}</p></div>` : "";
  const qs = (idea.clarifyingQuestions || []);
  const examples = (idea.examples || []);
  const examplesCard = examples.length ? `
    <div class="card"><h3>Example businesses</h3>
      <ul class="examples">${examples.map(e => `<li><a href="${esc(e.url)}" target="_blank" rel="noopener">${esc(e.name)}</a>${e.note ? ` — ${esc(e.note)}` : ""}</li>`).join("")}</ul>
    </div>` : "";

  view.innerHTML = `
    <a class="back" href="#/">← All ideas</a>
    <div class="detail-head">
      <h2>${esc(idea.title)}${idea.sample ? ' <span class="badge sample">sample</span>' : ""}</h2>
      <div class="detail-meta">
        <span>Submitted by <strong>${esc(idea.owner || "—")}</strong></span>
        <span>·</span><span>Composite <strong>${c.toFixed(1)}</strong>/10</span>
        ${idea.status ? `<span>·</span><span class="badge">${esc(idea.status)}</span>` : ""}
      </div>
      ${idea.hasPlan ? `<a class="pill-link plan-link" href="plans/${encodeURIComponent(idea.id)}/index.html">Business Plan →</a>` : ""}
      ${idea.hasPitch && idea.pitchUrl ? `<a class="pill-link pitch-link" href="${idea.pitchUrl}" target="_blank" rel="noopener">Pitch ▶</a>` : ""}
    </div>
    <div class="card prop"><h3>Proposition</h3><p>${esc(idea.oneLiner || "")}</p></div>
    <div class="grid2">
      <div>
        ${bc.summary ? `<div class="card"><h3>The opportunity</h3><p>${esc(bc.summary)}</p></div>` : ""}
        <div class="card">
          ${bcSection("Customer", bc.customer)}
          ${bcSection("Market", bc.market)}
          ${bcSection("How it makes money", bc.model)}
          ${bcSection("Go to market", bc.goToMarket)}
          ${bcSection("Costs", bc.costs)}
          ${bcSection("Key risks", bc.risks)}
          ${bcSection("Next steps", bc.nextSteps)}
        </div>
      </div>
      <div>
        <div class="card"><h3>Scorecard</h3>${scoreRows}</div>
        ${examplesCard}
      </div>
    </div>
    <div class="card"><h3>Clarify or expand this idea</h3>
      <p class="muted" style="margin-top:0">Add detail, answer any open questions, or push back — it goes to the group to sharpen the analysis. Your typing is kept in this browser.</p>
      ${qs.length ? `<ul class="qs">${qs.map(q => `<li>${esc(q)}</li>`).join("")}</ul>` : ""}
      <form id="answers-form">
        <div class="ans-q"><label>Your name</label>${voterFieldHtml("ans-name")}</div>
        <div class="ans-q"><label>Clarify / expand the idea</label><textarea id="ans-response" rows="6" placeholder="Add anything useful — context, answers to the questions above, corrections…"></textarea></div>
        <div class="ans-actions">
          <button type="button" id="send-answers">Send</button>
          <button type="button" id="copy-answers" class="ghost">Copy</button>
          <span id="ans-note" class="muted"></span>
        </div>
      </form>
    </div>
    ${teamCardHtml(idea)}`;

  // ----- Clarify / expand form wiring -----
  const form = $("#answers-form");
  if (form) {
    const nameEl = form.querySelector(".ans-name");
    const respEl = $("#ans-response");
    const K = s => `ans:${idea.id}:${s}`;
    // name is the shared identity; the response is drafted per-idea in this browser
    nameEl.value = state.voter || "";
    respEl.value = localStorage.getItem(K("response")) || "";
    nameEl.addEventListener("change", () => setVoter(nameEl.value));
    respEl.addEventListener("input", () => localStorage.setItem(K("response"), respEl.value));

    const questionsAsked = qs.length ? qs.map((q, i) => `${i + 1}. ${q}`).join("  •  ") : "(none)";
    const buildText = () => {
      let out = `Clarify / expand — ${idea.title}\n`;
      const nm = nameEl.value.trim();
      if (nm) out += `From: ${nm}\n`;
      if (qs.length) out += `\nQuestions asked:\n${qs.map((q, i) => `${i + 1}. ${q}`).join("\n")}\n`;
      out += `\nResponse:\n${respEl.value.trim() || "(blank)"}\n`;
      return out;
    };
    const note = (msg) => { const n = $("#ans-note"); n.textContent = msg; setTimeout(() => { n.textContent = ""; }, 3000); };

    $("#send-answers").addEventListener("click", async () => {
      if (!respEl.value.trim()) { note("Add a note first."); return; }
      const btn = $("#send-answers");
      if (state.endpoint) {
        setBusy(btn, true, "Sending…");
        try {
          await postToStore({
            type: "answer",
            submittedAt: new Date().toISOString(),
            ideaId: idea.id,
            ideaTitle: idea.title,
            name: nameEl.value.trim(),
            answers: [
              { q: "Questions asked", a: questionsAsked },
              { q: "Response", a: respEl.value.trim() },
            ],
          });
          localStorage.removeItem(K("response"));
          respEl.value = "";
          note("Sent! Thanks — we'll fold this into the analysis.");
        } catch {
          note("Couldn't send — check your connection, or use Copy as a fallback.");
        } finally { setBusy(btn, false); }
      } else {
        const subject = encodeURIComponent(`Clarify: ${idea.title}`);
        location.href = `mailto:${state.contactEmail}?subject=${subject}&body=${encodeURIComponent(buildText())}`;
      }
    });
    $("#copy-answers").addEventListener("click", () => {
      const text = buildText();
      const done = () => note("Copied — paste it into an email or message.");
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
      } else { fallbackCopy(text, done); }
    });
  }

  // ----- Team vote wiring -----
  const voteScore = $("#vote-score");
  if (voteScore) {
    const valEl = $("#vote-val"), commentEl = $("#vote-comment");
    voteScore.addEventListener("input", () => { valEl.textContent = voteScore.value; });
    $("#vote-save").addEventListener("click", async () => {
      if (!state.voter) return;
      const score = Number(voteScore.value), comment = commentEl.value.trim();
      upsertVote(idea.id, state.voter, score, comment);
      renderDetail(idea);
      const n = $("#vote-note"); if (n) n.textContent = "Saving…";
      if (state.endpoint) {
        try {
          await postToStore({ type: "vote", submittedAt: new Date().toISOString(), ideaId: idea.id, ideaTitle: idea.title, name: state.voter, score, comment });
          const ok = $("#vote-note"); if (ok) ok.textContent = "Saved ✓";
          setTimeout(async () => { await loadVotes(); if (location.hash === `#/idea/${encodeURIComponent(idea.id)}`) renderDetail(idea); }, 1500);
        } catch {
          const bad = $("#vote-note"); if (bad) bad.textContent = "Couldn't save — try again.";
        }
      }
    });
  }
}
/* ---------- Trends: labels ---------- */
const SECTOR_LABELS = {
  "health-longevity": "Health & longevity", "food-agriculture": "Food & agriculture",
  "energy-climate": "Energy & climate", "money-finance": "Money & finance",
  "mobility-logistics": "Mobility & logistics", "built-environment": "Built environment",
  "materials-manufacturing": "Materials & manufacturing", "media-entertainment": "Media & entertainment",
  "education-skills": "Education & skills", "work-enterprise": "Work & enterprise",
  "consumer-retail": "Consumer & retail", "travel-hospitality": "Travel & hospitality",
  "security-defence": "Security & defence", "frontier": "Frontier tech",
};
const LENS_LABELS = {
  technological: "Technological", financial: "Financial", cultural: "Cultural & artistic",
  social: "Social & demographic", environmental: "Environmental & regulatory", contrarian: "Contrarian",
};
const HORIZON_LABELS = { near: "Near · 0–2 yr", mid: "Mid · 3–5 yr", far: "Far · 5–10 yr" };
const HORIZON_ORDER = { near: 0, mid: 1, far: 2 };
const titleize = s => String(s || "").replace(/-/g, " ").replace(/\b\w/g, c => c.toUpperCase());
const sectorLabel = s => SECTOR_LABELS[s] || titleize(s);
const lensLabel = s => LENS_LABELS[s] || titleize(s);
const horizonLabel = h => HORIZON_LABELS[h] || titleize(h);

/* ---------- Trends: map (signal vs. horizon, bubble = idea count) ----------
   Bubbles are numbered and keyed to a legend below, so long titles never
   overlap on the chart no matter how many trends a run produces. */
function trendMap(trends, numById) {
  const W = 760, H = 360, pad = 52;
  const bands = ["near", "mid", "far"];
  const y = v => (H - pad) - ((v - 1) / 9) * (H - 2 * pad);
  const bandX0 = i => pad + (i / 3) * (W - 2 * pad);
  const bandW = (W - 2 * pad) / 3;
  const colOf = t => t.source === "adjacency" ? "var(--team)" : "var(--accent)";
  // numById (stable creation-order numbers) is supplied by the caller (renderTrends).

  // Collect points, then a light collision-avoidance pass (as on the Idea Board) so trends that
  // share a horizon+signal don't stack invisibly. Horizontal movement is clamped WITHIN each
  // horizon band (the categorical x-axis), so a bubble never drifts into a different horizon.
  const pts = [];
  bands.forEach((b, bi) => {
    const inBand = trends.filter(t => (t.horizon || "mid") === b);
    inBand.forEach((t, idx) => {
      pts.push({
        t, bi,
        cx: bandX0(bi) + bandW * ((idx + 1) / (inBand.length + 1)),
        cy: y(t.signal || 5),
        r: Math.max(12, 8 + (t.ideas ? t.ideas.length : 0) * 3),
      });
    });
  });
  // Break exact ties deterministically (sub-pixel) so coincident bubbles have a push direction.
  pts.forEach((p, k) => { p.cx += (((k * 13) % 7) - 3) * 0.4; p.cy += (((k * 11) % 5) - 2) * 0.4; });
  const clampBandX = p => Math.max(bandX0(p.bi) + p.r, Math.min(bandX0(p.bi) + bandW - p.r, p.cx));
  const clampY = p => Math.max(pad + p.r, Math.min(H - pad - p.r, p.cy));
  for (let iter = 0; iter < 120; iter++) {
    let moved = false;
    for (let a = 0; a < pts.length; a++) for (let bx = a + 1; bx < pts.length; bx++) {
      const pa = pts[a], pb = pts[bx];
      const dx = pb.cx - pa.cx, dy = pb.cy - pa.cy;
      const dist = Math.hypot(dx, dy) || 0.001;
      const minGap = pa.r + pb.r + 3;         // desired clearance between bubble edges
      if (dist < minGap) {
        const push = (minGap - dist) / 2, ux = dx / dist, uy = dy / dist;
        pa.cx -= ux * push; pa.cy -= uy * push;
        pb.cx += ux * push; pb.cy += uy * push;
        pa.cx = clampBandX(pa); pa.cy = clampY(pa);
        pb.cx = clampBandX(pb); pb.cy = clampY(pb);
        moved = true;
      }
    }
    if (!moved) break;
  }
  const dots = pts.map(p => `<g class="dot" data-id="${esc(p.t.id)}">
        <circle cx="${p.cx.toFixed(1)}" cy="${p.cy.toFixed(1)}" r="${p.r}" fill="${colOf(p.t)}" fill-opacity="0.30" stroke="${colOf(p.t)}"></circle>
        <text class="dot-num" x="${p.cx.toFixed(1)}" y="${p.cy.toFixed(1)}" text-anchor="middle" dominant-baseline="central">${numById.get(p.t.id)}</text>
      </g>`).join("");
  const bandLabels = bands.map((b, bi) => `<text class="axis-label" x="${bandX0(bi) + bandW / 2}" y="${H - pad + 26}" text-anchor="middle">${esc(horizonLabel(b))}</text>`).join("");
  const gridlines = [1, 2].map(i => `<line x1="${pad + (i / 3) * (W - 2 * pad)}" y1="${pad}" x2="${pad + (i / 3) * (W - 2 * pad)}" y2="${H - pad}" stroke="var(--line)"></line>`).join("");

  return `<div class="quad">
    <h3>Trend map <span class="muted">— opportunity signal vs. time horizon · bubble size = number of ideas · <span style="color:var(--accent)">broad</span> vs <span style="color:var(--team)">adjacent to your ideas</span></span></h3>
    <div class="quad-box"><svg viewBox="0 0 ${W} ${H}" role="img">
      ${gridlines}
      <line x1="${pad}" y1="${H - pad}" x2="${W - pad}" y2="${H - pad}" stroke="var(--line)"></line>
      <text class="axis-label" x="16" y="${H / 2}" text-anchor="middle" transform="rotate(-90 16 ${H / 2})">Stronger signal →</text>
      ${bandLabels}
      ${dots}
    </svg><div class="tm-tip" hidden></div></div>
  </div>`;
}

/* ---------- Trends: list view ---------- */
function renderTrends() {
  const view = $("#view");
  if (!state.trends.length) {
    view.innerHTML = `<div class="empty"><h2>No trends yet</h2><p>Run the trends agent to research emerging markets across sectors and surface fresh business ideas.</p><p><a href="#/" class="btn-primary">← Back to the Idea Board</a></p></div>`;
    return;
  }
  const rows = state.trends.slice();
  // Stable # keyed to creation order (1 = oldest, N = newest); the table defaults to newest-first.
  const creationNum = new Map();
  state.trends.forEach((t, i) => creationNum.set(t.id, i + 1));
  const { key, asc } = state.trendSort;
  const sortVal = t => {
    switch (key) {
      case "created": return creationNum.get(t.id) || 0;
      case "sector": return sectorLabel(t.sector);
      case "lens": return lensLabel(t.lens);
      case "horizon": return HORIZON_ORDER[t.horizon] ?? 1;
      case "ideas": return t.ideas ? t.ideas.length : 0;
      default: return t.signal || 0;
    }
  };
  rows.sort((a, b) => {
    const av = sortVal(a), bv = sortVal(b);
    if (typeof av === "string") return asc ? av.localeCompare(bv) : bv.localeCompare(av);
    return asc ? av - bv : bv - av;
  });
  const th = (k, label, cls) => `<th data-key="${k}" class="${cls || ""} ${key === k ? "sorted " + (asc ? "asc" : "") : ""}">${esc(label)}</th>`;

  view.innerHTML = `
    <div class="list-head">
      <div><h2>Trends & Markets</h2><p class="muted">Emerging trends across sectors, viewed through different lenses — a scan of where opportunity is building. <strong>Broad</strong> picks span the whole economy; <strong>adjacent</strong> ones grow out of ideas your group has already posted. Click any bubble or row for the trend and its business ideas.</p></div>
      <a href="#/submit" class="btn-primary">+ Submit an idea</a>
    </div>
    ${trendMap(rows, creationNum)}
    <div class="table-wrap trends-table"><table>
      <thead><tr>
        ${th("created", "#", "num")}
        <th data-key="_title">Trend</th>
        ${th("sector", "Sector")}
        ${th("lens", "Lens")}
        ${th("horizon", "Horizon", "num")}
        ${th("signal", "Signal", "num")}
        ${th("ideas", "Ideas", "num")}
      </tr></thead>
      <tbody>
        ${rows.map((t, i) => `
          <tr data-id="${esc(t.id)}">
            <td class="num"><span class="tm-leg-num" style="background:${t.source === "adjacency" ? "var(--team)" : "var(--accent)"}">${creationNum.get(t.id)}</span></td>
            <td class="idea-title">${esc(t.title)}${t.sample ? ' <span class="badge sample">sample</span>' : ""}${t.source === "adjacency" ? ' <span class="badge adj">adjacent</span>' : ""}
              <small>${esc(t.oneLiner || "")}</small></td>
            <td>${esc(sectorLabel(t.sector))}</td>
            <td>${esc(lensLabel(t.lens))}</td>
            <td class="num">${esc((t.horizon || "").toUpperCase())}</td>
            <td class="num"><span class="composite">${t.signal != null ? t.signal : "—"}</span></td>
            <td class="num">${t.ideas ? t.ideas.length : 0}</td>
          </tr>`).join("")}
      </tbody>
    </table></div>`;

  view.querySelectorAll("th[data-key]").forEach(el => el.addEventListener("click", () => {
    const k = el.dataset.key;
    if (k === "_title") return;
    if (state.trendSort.key === k) state.trendSort.asc = !state.trendSort.asc;
    else state.trendSort = { key: k, asc: false };
    renderTrends();
  }));
  view.querySelectorAll("tbody tr").forEach(tr =>
    tr.addEventListener("click", () => { location.hash = `#/trend/${encodeURIComponent(tr.dataset.id)}`; }));
  view.querySelectorAll(".dot").forEach(g =>
    g.addEventListener("click", () => { location.hash = `#/trend/${encodeURIComponent(g.dataset.id)}`; }));

  // Bubble hover: show the trend name in a tooltip that tracks the cursor
  const tip = view.querySelector(".tm-tip"), box = view.querySelector(".quad-box");
  if (tip && box) {
    view.querySelectorAll(".dot").forEach(g => {
      const t = state.trends.find(x => x.id === g.dataset.id);
      g.addEventListener("mouseenter", () => { tip.textContent = t ? t.title : ""; tip.hidden = false; });
      g.addEventListener("mousemove", e => {
        const r = box.getBoundingClientRect();
        tip.style.left = (e.clientX - r.left) + "px";
        tip.style.top = (e.clientY - r.top) + "px";
      });
      g.addEventListener("mouseleave", () => { tip.hidden = true; });
    });
  }
}

/* ---------- Trends: detail view ---------- */
function renderTrendDetail(t) {
  const view = $("#view");
  const seed = t.seededBy ? state.ideas.find(i => i.id === t.seededBy) : null;
  const drivers = (t.drivers || []).map(d => `<span class="badge">${esc(titleize(d))}</span>`).join(" ");
  const conf = t.confidence ? `<span class="conf ${esc(t.confidence)}">${esc(t.confidence)} confidence</span>` : "";
  const src = (t.sources && t.sources.length)
    ? `<p class="score-why">Sources: ${t.sources.map(u => `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(hostname(u))}</a>`).join(", ")}</p>` : "";
  const seedChip = t.seededBy
    ? `<a class="inspired" href="#/idea/${encodeURIComponent(t.seededBy)}">💡 Inspired by your idea: <strong>${esc(seed ? seed.title : titleize(t.seededBy))}</strong></a>` : "";
  const ideas = (t.ideas || []).map((idea, idx) => `
    <div class="trend-idea">
      <div class="trend-idea-main">
        <div class="trend-idea-head"><span class="trend-idea-title">${esc(idea.title)}</span>${idea.pattern ? `<span class="badge pat">${esc(titleize(idea.pattern))}</span>` : ""}</div>
        <p class="score-why">${esc(idea.oneLiner || "")}</p>
      </div>
      <button type="button" class="ghost send-idea" data-idx="${idx}">Send to Idea Board</button>
    </div>`).join("");

  view.innerHTML = `
    <a class="back" href="#/trends">← All trends</a>
    <div class="detail-head">
      <h2>${esc(t.title)}${t.sample ? ' <span class="badge sample">sample</span>' : ""}</h2>
      <div class="detail-meta">
        <span class="badge">${esc(sectorLabel(t.sector))}</span>
        <span class="badge lens">${esc(lensLabel(t.lens))}</span>
        <span class="badge">${esc(horizonLabel(t.horizon))}</span>
        <span>·</span><span>Signal <strong>${t.signal != null ? t.signal : "—"}</strong>/10</span>
      </div>
    </div>
    ${seedChip}
    <div class="card prop"><h3>The trend</h3><p>${esc(t.oneLiner || "")}</p></div>
    <div class="card"><h3>Why now</h3><p>${esc(t.why || "")} ${conf}</p>${drivers ? `<p class="drivers">${drivers}</p>` : ""}${src}</div>
    <div class="card"><h3>Business ideas</h3>
      <p class="muted" style="margin-top:0">Concrete plays this trend opens up. Send any to the Idea Board to have it researched and scored.</p>
      <div class="ans-q"><label>Your name</label>${voterFieldHtml("trend-name")}</div>
      <div class="trend-ideas">${ideas || '<p class="muted">No ideas listed.</p>'}</div>
    </div>`;

  const nameEl = view.querySelector(".trend-name");
  if (nameEl) { nameEl.value = state.voter || ""; nameEl.addEventListener("change", () => setVoter(nameEl.value)); }

  view.querySelectorAll(".send-idea").forEach(btn => btn.addEventListener("click", async () => {
    const idea = (t.ideas || [])[Number(btn.dataset.idx)];
    if (!idea) return;
    const name = (state.voter || "").trim();
    const title = idea.title;
    const pitch = idea.oneLiner || "";
    const description = `From the Trends board — trend "${t.title}" (${sectorLabel(t.sector)} · ${lensLabel(t.lens)}). ${idea.oneLiner || ""}${idea.pattern ? ` [pattern: ${titleize(idea.pattern)}]` : ""}`;
    if (state.endpoint) {
      setBusy(btn, true, "Sending…");
      try {
        await postToStore({ type: "idea", submittedAt: new Date().toISOString(), name, title, pitch, description });
        setBusy(btn, false);
        btn.textContent = "Sent ✓"; btn.disabled = true; btn.classList.add("sent");
      } catch {
        setBusy(btn, false);
        btn.textContent = "Try again";
      }
    } else {
      const subject = encodeURIComponent(`New idea: ${title}`);
      const body = `New business idea\n\nYour name: ${name || "(blank)"}\n\nIdea title: ${title}\n\nOne-line pitch: ${pitch}\n\nIdea description: ${description}\n`;
      location.href = `mailto:${state.contactEmail}?subject=${subject}&body=${encodeURIComponent(body)}`;
    }
  }));
}

/* ---------- Team roles: interest voting ----------
   Reuses the SAME vote store as the Idea Board — each role is voted on under a
   "role:"-prefixed id, so role votes and idea votes share one endpoint and can
   never collide (teamVotes only ever reads real idea ids). No backend change.
   The headline metric here is the TOTAL interest (sum of everyone's 1–10), not
   an average — a role two people rate 8 beats one that a single person rates 10. */
function roleTally(roleId) {
  const arr = (state.votes && state.votes[roleId]) || [];
  const valid = arr.filter(v => v.score > 0);
  const total = valid.reduce((a, b) => a + b.score, 0);
  return { total, count: valid.length, votes: valid };
}
function myRoleScore(roleId) {
  const arr = (state.votes && state.votes[roleId]) || [];
  const mine = arr.find(v => v.name === state.voter && v.score > 0);
  return mine ? mine.score : null;
}
// Team totals stay hidden until the current voter has rated EVERY role —
// the anchoring guard from the Idea Board, applied to the whole set so nobody
// sees the group's leanings before committing their own full pass.
function myRatedCount() {
  return state.roles.filter(r => myRoleScore(r.id) != null).length;
}
function hasSetInterest() {
  return !!state.voter && state.roles.length > 0 && myRatedCount() === state.roles.length;
}

function renderTeam() {
  const view = $("#view");
  if (!state.roles.length) {
    view.innerHTML = `<div class="empty"><h2>No team roles yet</h2><p>Add roles to <code>roles.json</code> to start collecting the group's interest.</p><p><a href="#/" class="btn-primary">← Back to the Idea Board</a></p></div>`;
    return;
  }
  const voters = state.voters.slice();
  const nVoters = voters.length || 1;

  // ----- Headline: roles ranked by TOTAL interest (sum of all 1–10 ratings) -----
  const ranked = state.roles.map(r => ({ role: r, ...roleTally(r.id) })).sort((a, b) => b.total - a.total);
  const maxTotal = Math.max(1, ...ranked.map(r => r.total));
  const rankBars = ranked.map((r, i) => `
    <div class="role-rank">
      <div class="role-rank-head">
        <span class="role-rank-name"><span class="rank-num">${i + 1}</span>${esc(r.role.title)}</span>
        <span class="role-rank-total">${r.total || 0}<span class="muted"> · ${r.count}/${nVoters} rated</span></span>
      </div>
      <div class="bar"><i style="width:${Math.max(2, (r.total / maxTotal) * 100)}%"></i></div>
    </div>`).join("");

  // ----- Your interest: one 1–10 slider per role, saved together -----
  const mineCard = state.voter
    ? `<div class="card">
         <h3>Your interest <span class="muted" style="text-transform:none;letter-spacing:0;font-weight:600">— as ${esc(state.voter)}</span></h3>
         <p class="muted" style="margin:0 0 4px">Set how much you'd want to own each role, 1 (not for me) to 10 (all in). Tap or drag each slider to rate it — untouched roles stay <em>unrated</em>. Rate all ${state.roles.length} and save to reveal the team's totals.</p>
         <div class="role-set-list">
           ${state.roles.map(r => {
             const saved = myRoleScore(r.id);
             const val = saved == null ? 5 : saved;
             return `<div class="role-set" data-id="${esc(r.id)}">
               <div class="role-set-info"><span class="role-set-name">${esc(r.title)}</span><span class="role-set-blurb">${esc(r.blurb || "")}</span></div>
               <div class="vote-slider role-slider-wrap${saved == null ? " unrated" : ""}">
                 <input type="range" class="role-slider" min="1" max="10" step="1" value="${val}" data-initial="${saved == null ? "" : saved}" />
                 <output>${val}</output>
                 <span class="muted role-note">${saved == null ? "not rated" : "/ 10"}</span>
               </div>
             </div>`;
           }).join("")}
         </div>
         <div class="ans-actions"><button type="button" id="roles-save">Save my interest</button><span id="roles-note" class="muted"></span></div>
       </div>`
    : `<div class="card"><h3>Your interest</h3><p class="muted" style="margin-bottom:0">Your login isn't recognised as a founder, so rating is disabled.</p></div>`;

  // ----- Breakdown: who's interested in what (read-only matrix) -----
  const matrix = `
    <div class="table-wrap"><table class="roles-matrix">
      <thead><tr>
        <th data-key="_role">Role</th>
        ${voters.map(n => `<th class="num">${esc(n)}</th>`).join("")}
        <th class="num">Total</th>
      </tr></thead>
      <tbody>
        ${ranked.map(({ role, total }) => {
          const byName = {};
          (state.votes[role.id] || []).forEach(v => { if (v.score > 0) byName[v.name] = v.score; });
          return `<tr>
            <td class="idea-title">${esc(role.title)}</td>
            ${voters.map(n => {
              const s = byName[n];
              return `<td class="num">${s == null ? '<span class="muted">—</span>' : `<span class="score-pill ${scoreClass(s)}">${s}</span>`}</td>`;
            }).join("")}
            <td class="num"><span class="composite team-score">${total || 0}</span></td>
          </tr>`;
        }).join("")}
      </tbody>
    </table></div>`;

  // The team totals + breakdown reveal only once the current voter has rated,
  // so nobody anchors their own interest on what the group already picked.
  const revealed = hasSetInterest();
  const aggregates = revealed
    ? `<div class="quad" style="margin-top:26px">
         <h3>Total interest by role <span class="muted">— sum of everyone's 1–10 ratings (max ${nVoters * 10})</span></h3>
         <div class="card" style="margin-bottom:0">${rankBars}</div>
       </div>
       <h3 class="board-section" style="margin-top:26px">Who's interested in what</h3>
       ${matrix}`
    : `<div class="card locked-reveal" style="margin-top:26px">
         <h3>Team totals & who's interested</h3>
         <p class="muted" style="margin-bottom:0">🔒 Rate all ${state.roles.length} roles above${state.voter ? ` — you've rated <strong>${myRatedCount()} of ${state.roles.length}</strong>` : ""} and save to reveal the group's totals and the full breakdown. You rate before you see how everyone else did — that keeps the interest levels honest.</p>
       </div>`;

  view.innerHTML = `
    <div class="list-head">
      <div><h2>Team & Roles</h2><p class="muted">${esc(state.roleMeta.subtitle || "Rate your interest in each role; the board totals everyone's scores to show where the group's interest is concentrated.")}</p></div>
    </div>
    ${mineCard}
    ${aggregates}`;

  // ----- Slider wiring: moving a slider marks the role as rated -----
  view.querySelectorAll(".role-set").forEach(el => {
    const inp = el.querySelector(".role-slider");
    const out = el.querySelector("output");
    const wrap = el.querySelector(".role-slider-wrap");
    const note = el.querySelector(".role-note");
    // Any interaction rates the role — a plain tap counts too, so leaving a
    // slider at its default 5 still registers (needed now all 10 are required).
    const markRated = () => {
      out.textContent = inp.value;
      inp.dataset.rated = "true";
      wrap.classList.remove("unrated");
      note.textContent = "/ 10";
    };
    inp.addEventListener("input", markRated);      // drag / arrow keys (value changes)
    inp.addEventListener("pointerdown", markRated); // tap without moving
  });

  // ----- Save: send only rated + changed roles, SEQUENTIALLY -----
  //  The Apps Script vote handler reads-then-appends with no lock, so parallel
  //  POSTs of brand-new rows can drop or duplicate. One await at a time is safe.
  const saveBtn = $("#roles-save");
  if (saveBtn) {
    saveBtn.addEventListener("click", async () => {
      const note = (m) => { const n = $("#roles-note"); if (n) n.textContent = m; };
      const changed = [...view.querySelectorAll(".role-set")].filter(el => {
        const inp = el.querySelector(".role-slider");
        const initial = inp.dataset.initial;                       // "" when previously unrated
        const rated = inp.dataset.rated === "true" || initial !== "";
        return rated && String(inp.value) !== String(initial);     // skip untouched / unchanged
      });
      if (!changed.length) { note("No new ratings to save."); setTimeout(() => note(""), 3000); return; }

      setBusy(saveBtn, true, "Saving…");
      let ok = 0;
      for (let i = 0; i < changed.length; i++) {
        const el = changed[i];
        const roleId = el.dataset.id;
        const role = state.roles.find(r => r.id === roleId);
        const score = Number(el.querySelector(".role-slider").value);
        upsertVote(roleId, state.voter, score, "");               // optimistic local update
        note(`Saving ${i + 1}/${changed.length}…`);
        if (state.endpoint) {
          try {
            await postToStore({ type: "vote", submittedAt: new Date().toISOString(), ideaId: roleId, ideaTitle: role ? role.title : roleId, name: state.voter, score, comment: "" });
            ok++;
          } catch { /* keep going; the optimistic local value still shows */ }
        } else { ok++; }
      }
      setBusy(saveBtn, false);
      note(state.endpoint
        ? (ok === changed.length ? "Saved ✓" : `Saved ${ok}/${changed.length} — check your connection and re-save.`)
        : "Saved locally (no endpoint configured).");
      if (state.endpoint && ok) { await loadVotes(); }
      if (location.hash === "#/team") renderTeam();
    });
  }
}

/* ---------- Submit-an-idea view ---------- */
const SUBMIT_FIELDS = [
  { k: "name",        label: "Your name",       type: "voter" },
  { k: "title",       label: "Idea title",      type: "input",    ph: "e.g. Alpine Mind — coaching for amateur athletes" },
  { k: "pitch",       label: "One-line pitch",  type: "input",    ph: "the idea in a single sentence" },
  { k: "description", label: "Idea description", type: "textarea", rows: 7, ph: "Describe the idea in as much detail as you like — who it's for, why now, how it might make money, and what it would take to get started." },
];
function renderSubmit() {
  const view = $("#view");
  view.innerHTML = `
    <a class="back" href="#/">← All ideas</a>
    <div class="detail-head"><h2>Submit a new idea</h2></div>
    <p class="one-liner muted">Fill this in and send — your idea goes to the group to be researched and scored. Your answers are saved in this browser so you won't lose them.</p>
    <div class="card">
      <form id="submit-form">
        ${SUBMIT_FIELDS.map(f => `<div class="ans-q"><label>${esc(f.label)}</label>${
          f.type === "voter"
            ? voterFieldHtml("voter-field", ` data-k="${f.k}"`)
            : f.type === "textarea"
            ? `<textarea data-k="${f.k}" rows="${f.rows || 3}" placeholder="${esc(f.ph || "")}"></textarea>`
            : `<input data-k="${f.k}" type="text" placeholder="${esc(f.ph || "")}" />`}</div>`).join("")}
        <div class="ans-actions">
          <button type="button" id="send-idea">Submit idea</button>
          <button type="button" id="copy-idea" class="ghost">Copy</button>
          <span id="idea-note" class="muted"></span>
        </div>
      </form>
    </div>`;

  const form = $("#submit-form");
  const els = [...form.querySelectorAll("[data-k]")];
  const K = k => `newidea:${k}`;
  els.forEach(e => {
    if (e.classList.contains("voter-field")) {
      e.value = state.voter || "";
      e.addEventListener("change", () => setVoter(e.value));
    } else {
      e.value = localStorage.getItem(K(e.dataset.k)) || "";
      e.addEventListener("input", () => localStorage.setItem(K(e.dataset.k), e.value));
    }
  });
  const val = k => (form.querySelector(`[data-k="${k}"]`).value || "").trim();
  const buildText = () => "New business idea\n\n" + SUBMIT_FIELDS.map(f => `${f.label}: ${val(f.k) || "(blank)"}`).join("\n\n") + "\n";
  const note = msg => { const n = $("#idea-note"); n.textContent = msg; setTimeout(() => { n.textContent = ""; }, 4000); };

  $("#send-idea").addEventListener("click", async () => {
    if (!val("title")) { note("Add an idea title first."); return; }
    const btn = $("#send-idea");
    if (state.endpoint) {
      setBusy(btn, true, "Sending…");
      try {
        await postToStore({
          type: "idea",
          submittedAt: new Date().toISOString(),
          ...Object.fromEntries(SUBMIT_FIELDS.map(f => [f.k, val(f.k)])),
        });
        SUBMIT_FIELDS.forEach(f => localStorage.removeItem(K(f.k)));
        els.forEach(e => { if (!e.classList.contains("voter-field")) e.value = ""; });
        note("Sent! The group will review it. Thank you.");
      } catch {
        note("Couldn't send — check your connection, or use Copy as a fallback.");
      } finally { setBusy(btn, false); }
    } else {
      const subject = encodeURIComponent(`New idea: ${val("title")}`);
      location.href = `mailto:${state.contactEmail}?subject=${subject}&body=${encodeURIComponent(buildText())}`;
    }
  });
  $("#copy-idea").addEventListener("click", () => {
    const text = buildText();
    const done = () => note("Copied — paste it into an email or message.");
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
    } else { fallbackCopy(text, done); }
  });
}

/* POST a submission to the Google Apps Script store.
   Uses text/plain to stay a "simple" request (no CORS preflight, which Apps Script can't answer).
   Resolves when the request lands. */
function postToStore(payload) {
  return fetch(state.endpoint, {
    method: "POST",
    headers: { "Content-Type": "text/plain;charset=utf-8" },
    body: JSON.stringify(payload),
  });
}
function setBusy(btn, busy, busyLabel) {
  if (busy) { btn.dataset.label = btn.textContent; btn.textContent = busyLabel; btn.disabled = true; }
  else { btn.textContent = btn.dataset.label || btn.textContent; btn.disabled = false; }
}

function fallbackCopy(text, done) {
  const ta = document.createElement("textarea");
  ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
  document.body.appendChild(ta); ta.select();
  try { document.execCommand("copy"); done(); } catch { alert("Couldn't copy automatically — please select and copy manually."); }
  document.body.removeChild(ta);
}
const hostname = u => { try { return new URL(u).hostname.replace(/^www\./, ""); } catch { return u; } };
