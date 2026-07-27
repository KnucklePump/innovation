/* Innovation idea board — client-side app.
   NOTE ON SECURITY: this password gate hides the UI only. The data in ideas.json
   is still fetchable by anyone who reaches this URL, so ideas.json must never
   contain the group's private founder descriptions. Keep those in /analysis
   (which is never deployed). Casual protection only — good enough for a friends group. */

// SHA-256 hex of the group password (the plaintext is never stored here).
// To change it: run  printf '%s' 'YOUR-PASSWORD' | shasum -a 256  and paste the hash here.
const PASSWORD_HASH = "2ecfd1b8a9c8e6f2f97748fd28ab531c0491e152108690abab45421d68c35551";

const $ = (s, el = document) => el.querySelector(s);
const state = { ideas: [], rubric: {}, votes: {}, voters: [], voter: "", sort: { key: "composite", asc: false }, trends: [], trendMeta: {}, trendSort: { key: "signal", asc: false } };
let voteCbSeq = 0;

/* ---------- Password gate ----------
   Self-contained SHA-256 (works on file://, IP, localhost or https alike — no
   dependency on crypto.subtle, which only exists in a "secure context"). */
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

function unlock() {
  $("#gate").hidden = true;
  $("#app").hidden = false;
  boot();
}
$("#signout").addEventListener("click", () => {
  sessionStorage.removeItem("unlocked");
  location.reload();
});
$("#gate-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const err = $("#gate-error");
  try {
    if (sha256(utf8($("#gate-input").value)) === PASSWORD_HASH) {
      sessionStorage.setItem("unlocked", "1");
      unlock();
    } else {
      err.textContent = "Incorrect password.";
      err.hidden = false;
    }
  } catch (ex) {
    err.textContent = "Something went wrong checking the password: " + ex.message;
    err.hidden = false;
  }
});
if (sessionStorage.getItem("unlocked") === "1") unlock();

/* ---------- Data + scoring ---------- */
async function boot() {
  const [ideasRes, cfgRes, trendsRes] = await Promise.all([
    fetch("ideas.json").then(r => r.json()),
    fetch("config.json").then(r => r.json()),
    // trends.json is optional — a missing/empty file just yields no trends.
    fetch("trends.json").then(r => r.ok ? r.json() : {}).catch(() => ({})),
  ]);
  state.ideas = ideasRes.ideas || [];
  state.rubric = cfgRes.rubric || {};
  state.contactEmail = cfgRes.contactEmail || "";
  state.endpoint = cfgRes.endpoint || "";
  state.voters = cfgRes.voters || [];
  state.trends = (trendsRes && trendsRes.trends) || [];
  state.trendMeta = (trendsRes && trendsRes.meta) || {};
  $("#brand-sub").textContent = (ideasRes.meta && ideasRes.meta.subtitle) || "";
  setupVoter();
  route();
  loadVotes().then(route); // fill in live tallies without blocking first paint
}
window.addEventListener("hashchange", route);

/* ---------- Team voting ---------- */
// Single source of truth for "who am I" — used by the top picker, both forms, and voting.
function setVoter(name) {
  state.voter = name || "";
  localStorage.setItem("voterName", state.voter);
  const top = $("#voter-pick"); if (top && top.value !== state.voter) top.value = state.voter;
}
function voterOptions(placeholder) {
  const cur = state.voter || "";
  return `<option value="">${esc(placeholder || "Select your name…")}</option>` +
    state.voters.map(n => `<option value="${esc(n)}"${n === cur ? " selected" : ""}>${esc(n)}</option>`).join("");
}
function setupVoter() {
  const sel = $("#voter-pick");
  state.voter = localStorage.getItem("voterName") || "";
  sel.innerHTML = voterOptions("Who are you?");
  sel.addEventListener("change", () => { setVoter(sel.value); route(); });
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
function upsertVote(ideaId, name, score, comment) {
  const arr = state.votes[ideaId] = state.votes[ideaId] || [];
  const existing = arr.find(v => v.name === name);
  if (existing) { existing.score = score; existing.comment = comment; }
  else { arr.push({ name, score, comment }); }
}
function teamCardHtml(idea) {
  const { avg, count, votes } = teamVotes(idea.id);
  const mine = votes.find(v => v.name === state.voter);
  const summary = count
    ? `<div class="vote-summary"><span class="composite team-score">${avg.toFixed(1)}</span><span class="muted">/ 10 · ${count} vote${count > 1 ? "s" : ""}</span></div>`
    : `<p class="muted" style="margin:0 0 4px">No team ratings yet.</p>`;
  const list = votes.length
    ? `<div class="vote-list">${votes.map(v => `<div class="vote-row"><span class="vote-name">${esc(v.name)}</span><span class="score-pill ${scoreClass(v.score)}">${v.score}</span>${v.comment ? `<span class="vote-comment">${esc(v.comment)}</span>` : ""}</div>`).join("")}</div>`
    : "";
  const mineForm = state.voter
    ? `<form id="vote-form" class="vote-mine">
         <label>Your rating (as ${esc(state.voter)})</label>
         <div class="vote-slider"><input type="range" id="vote-score" min="1" max="10" step="1" value="${mine ? mine.score : 7}" /><output id="vote-val">${mine ? mine.score : 7}</output><span class="muted">/ 10</span></div>
         <textarea id="vote-comment" rows="2" placeholder="Why? (optional)">${esc(mine ? mine.comment : "")}</textarea>
         <div class="ans-actions"><button type="button" id="vote-save">${mine ? "Update my rating" : "Save my rating"}</button><span id="vote-note" class="muted"></span></div>
       </form>`
    : `<p class="muted" style="margin-bottom:0">Pick your name (top-right) to add your rating.</p>`;
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

  view.innerHTML = `
    <div class="list-head">
      <div><h2>Idea Board</h2><p class="muted">The chart plots each idea by <strong>attractiveness</strong> (higher up = more attractive) against <strong>ease of entry</strong> (further right = easier to enter); <strong>bubble size</strong> is the team's average vote. Click any bubble or table row for the full business case.</p></div>
      <a href="#/submit" class="btn-primary">+ Submit an idea</a>
    </div>
    ${quadrant(rows)}
    <div class="table-wrap"><table>
      <thead><tr>
        <th data-key="_title">Idea</th>
        <th data-key="composite" class="num ${key === "composite" ? "sorted " + (asc ? "asc" : "") : ""}">Composite</th>
        <th data-key="team" class="num ${key === "team" ? "sorted " + (asc ? "asc" : "") : ""}" title="Team rating (1–10 average)">Team</th>
        ${cols.map(th).join("")}
      </tr></thead>
      <tbody>
        ${rows.map(({ idea, composite: c }) => `
          <tr data-id="${esc(idea.id)}">
            <td class="idea-title">${esc(idea.title)}${idea.sample ? ' <span class="badge sample">sample</span>' : ""}
              <small>${esc(idea.oneLiner || "")}</small></td>
            <td class="num"><span class="composite">${c.toFixed(1)}</span></td>
            <td class="num">${teamVotes(idea.id).avg == null ? '<span class="muted">—</span>' : `<span class="composite team-score">${teamVotes(idea.id).avg.toFixed(1)}</span>`}</td>
            ${cols.map(k => {
              const s = idea.scores?.[k]?.score;
              return `<td class="num">${s == null ? "—" : `<span class="score-pill ${scoreClass(s)}">${s}</span>`}</td>`;
            }).join("")}
          </tr>`).join("")}
      </tbody>
    </table></div>
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
}

/* ---------- 2x2 quadrant (attractiveness vs ease of entry, bubble = founder-fit) ---------- */
function quadrant(rows) {
  const W = 760, H = 440, pad = 46;
  const attractiveness = i => avg([i.scores?.market?.score, i.scores?.margins?.score, i.scores?.moat?.score, i.scores?.saturation?.score, i.scores?.risk?.score]);
  const ease = i => avg([i.scores?.entry?.score, i.scores?.cost?.score]);
  const x = v => pad + ((v - 1) / 9) * (W - pad * 2);
  const y = v => (H - pad) - ((v - 1) / 9) * (H - pad * 2);

  const dots = rows.map(({ idea }) => {
    const vote = teamVotes(idea.id).avg;      // bubble size reflects the team's average vote
    const sizeVal = vote == null ? 3 : vote;  // unvoted ideas show as small bubbles
    const cx = x(ease(idea)), cy = y(attractiveness(idea)), r = 7 + sizeVal * 1.6;
    return `<g class="dot" data-id="${esc(idea.id)}">
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="var(--team)" fill-opacity="0.28" stroke="var(--team)"></circle>
      <text class="dot-label" x="${cx}" y="${cy - r - 5}" text-anchor="middle">${esc(shortTitle(idea.title))}</text>
    </g>`;
  }).join("");

  return `<div class="quad">
    <h3>Attractiveness vs. ease of entry <span class="muted">— bubble size = team's average vote</span></h3>
    <div class="quad-box"><svg viewBox="0 0 ${W} ${H}" role="img">
      <line x1="${W/2}" y1="${pad}" x2="${W/2}" y2="${H-pad}" stroke="var(--line)"></line>
      <line x1="${pad}" y1="${H/2}" x2="${W-pad}" y2="${H/2}" stroke="var(--line)"></line>
      <text class="axis-label" x="${W-pad}" y="${H/2 - 8}" text-anchor="end">Easier entry →</text>
      <text class="axis-label" x="16" y="${H/2}" text-anchor="middle" transform="rotate(-90 16 ${H/2})">More attractive →</text>
      ${dots}
    </svg></div>
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

  view.innerHTML = `
    <a class="back" href="#/">← All ideas</a>
    <div class="detail-head">
      <h2>${esc(idea.title)}${idea.sample ? ' <span class="badge sample">sample</span>' : ""}</h2>
      <div class="detail-meta">
        <span>Submitted by <strong>${esc(idea.owner || "—")}</strong></span>
        <span>·</span><span>Composite <strong>${c.toFixed(1)}</strong>/10</span>
        ${idea.status ? `<span>·</span><span class="badge">${esc(idea.status)}</span>` : ""}
      </div>
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
      </div>
    </div>
    <div class="card"><h3>Clarify or expand this idea</h3>
      <p class="muted" style="margin-top:0">Add detail, answer any open questions, or push back — it goes to the group to sharpen the analysis. Your typing is kept in this browser.</p>
      ${qs.length ? `<ul class="qs">${qs.map(q => `<li>${esc(q)}</li>`).join("")}</ul>` : ""}
      <form id="answers-form">
        <div class="ans-q"><label>Your name</label><select class="ans-name voter-select">${voterOptions()}</select></div>
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

/* ---------- Trends: map (signal vs. horizon, bubble = idea count) ---------- */
function trendMap(trends) {
  const W = 760, H = 440, pad = 52;
  const bands = ["near", "mid", "far"];
  const y = v => (H - pad) - ((v - 1) / 9) * (H - 2 * pad);
  const bandX0 = i => pad + (i / 3) * (W - 2 * pad);
  const bandW = (W - 2 * pad) / 3;
  let dots = "";
  bands.forEach((b, bi) => {
    const inBand = trends.filter(t => (t.horizon || "mid") === b);
    inBand.forEach((t, idx) => {
      const cx = bandX0(bi) + bandW * ((idx + 1) / (inBand.length + 1));
      const cy = y(t.signal || 5);
      const r = 7 + (t.ideas ? t.ideas.length : 0) * 3;
      const col = t.source === "adjacency" ? "var(--team)" : "var(--accent)";
      dots += `<g class="dot" data-id="${esc(t.id)}">
        <circle cx="${cx}" cy="${cy}" r="${r}" fill="${col}" fill-opacity="0.28" stroke="${col}"></circle>
        <text class="dot-label" x="${cx}" y="${cy - r - 5}" text-anchor="middle">${esc(shortTitle(t.title))}</text>
      </g>`;
    });
  });
  const bandLabels = bands.map((b, bi) => `<text class="axis-label" x="${bandX0(bi) + bandW / 2}" y="${H - pad + 24}" text-anchor="middle">${esc(horizonLabel(b))}</text>`).join("");
  const gridlines = [1, 2].map(i => `<line x1="${pad + (i / 3) * (W - 2 * pad)}" y1="${pad}" x2="${pad + (i / 3) * (W - 2 * pad)}" y2="${H - pad}" stroke="var(--line)"></line>`).join("");
  return `<div class="quad">
    <h3>Trend map <span class="muted">— opportunity signal vs. time horizon · bubble size = number of ideas · <span style="color:var(--accent)">broad</span> vs <span style="color:var(--team)">adjacent to your ideas</span></span></h3>
    <div class="quad-box"><svg viewBox="0 0 ${W} ${H}" role="img">
      ${gridlines}
      <line x1="${pad}" y1="${H - pad}" x2="${W - pad}" y2="${H - pad}" stroke="var(--line)"></line>
      <text class="axis-label" x="16" y="${H / 2}" text-anchor="middle" transform="rotate(-90 16 ${H / 2})">Stronger signal →</text>
      ${bandLabels}
      ${dots}
    </svg></div>
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
  const { key, asc } = state.trendSort;
  const sortVal = t => {
    switch (key) {
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
    ${trendMap(rows)}
    <div class="table-wrap"><table>
      <thead><tr>
        <th data-key="_title">Trend</th>
        ${th("sector", "Sector")}
        ${th("lens", "Lens")}
        ${th("horizon", "Horizon", "num")}
        ${th("signal", "Signal", "num")}
        ${th("ideas", "Ideas", "num")}
      </tr></thead>
      <tbody>
        ${rows.map(t => `
          <tr data-id="${esc(t.id)}">
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
      <div class="ans-q"><label>Your name</label><select class="trend-name voter-select">${voterOptions()}</select></div>
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
            ? `<select data-k="${f.k}" class="voter-select voter-field">${voterOptions()}</select>`
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
