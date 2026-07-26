/* Innovation idea board — client-side app.
   NOTE ON SECURITY: this password gate hides the UI only. The data in ideas.json
   is still fetchable by anyone who reaches this URL, so ideas.json must never
   contain the group's private founder descriptions. Keep those in /analysis
   (which is never deployed). Casual protection only — good enough for a friends group. */

// SHA-256 hex of the group password (the plaintext is never stored here).
// To change it: run  printf '%s' 'YOUR-PASSWORD' | shasum -a 256  and paste the hash here.
const PASSWORD_HASH = "2ecfd1b8a9c8e6f2f97748fd28ab531c0491e152108690abab45421d68c35551";

const $ = (s, el = document) => el.querySelector(s);
const state = { ideas: [], rubric: {}, sort: { key: "composite", asc: false } };

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
  const [ideasRes, cfgRes] = await Promise.all([
    fetch("ideas.json").then(r => r.json()),
    fetch("config.json").then(r => r.json()),
  ]);
  state.ideas = ideasRes.ideas || [];
  state.rubric = cfgRes.rubric || {};
  state.contactEmail = cfgRes.contactEmail || "";
  state.endpoint = cfgRes.endpoint || "";
  $("#brand-sub").textContent = (ideasRes.meta && ideasRes.meta.subtitle) || "";
  route();
}
window.addEventListener("hashchange", route);

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
  if (location.hash === "#/submit") { renderSubmit(); window.scrollTo(0, 0); return; }
  const m = location.hash.match(/^#\/idea\/(.+)$/);
  if (m) {
    const idea = state.ideas.find(i => i.id === decodeURIComponent(m[1]));
    idea ? renderDetail(idea) : renderList();
  } else {
    renderList();
  }
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
    const av = key === "composite" ? a.composite : (a.idea.scores?.[key]?.score ?? 0);
    const bv = key === "composite" ? b.composite : (b.idea.scores?.[key]?.score ?? 0);
    return asc ? av - bv : bv - av;
  });

  const cols = Object.keys(state.rubric); // all scorecard metrics
  const th = k => `<th data-key="${k}" class="num ${key === k ? "sorted " + (asc ? "asc" : "") : ""}" title="${esc(state.rubric[k]?.label || k)}">${esc(state.rubric[k]?.short || state.rubric[k]?.label || k)}</th>`;

  view.innerHTML = `
    <div class="list-head">
      <div><h2>Idea Board</h2><p class="muted">${state.ideas.length} idea${state.ideas.length > 1 ? "s" : ""} · click any row for the full business case</p></div>
      <a href="#/submit" class="btn-primary">+ Submit an idea</a>
    </div>
    ${quadrant(rows)}
    <div class="table-wrap"><table>
      <thead><tr>
        <th data-key="_title">Idea</th>
        <th data-key="composite" class="num ${key === "composite" ? "sorted " + (asc ? "asc" : "") : ""}">Composite</th>
        ${cols.map(th).join("")}
      </tr></thead>
      <tbody>
        ${rows.map(({ idea, composite: c }) => `
          <tr data-id="${esc(idea.id)}">
            <td class="idea-title">${esc(idea.title)}${idea.sample ? ' <span class="badge sample">sample</span>' : ""}
              <small>${esc(idea.oneLiner || "")}</small></td>
            <td class="num"><span class="composite">${c.toFixed(1)}</span></td>
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
    const ff = idea.scores?.founderFit?.score ?? 5;
    const cx = x(ease(idea)), cy = y(attractiveness(idea)), r = 7 + ff * 1.6;
    return `<g class="dot" data-id="${esc(idea.id)}">
      <circle cx="${cx}" cy="${cy}" r="${r}" fill="var(--accent)" fill-opacity="0.28" stroke="var(--accent)"></circle>
      <text class="dot-label" x="${cx}" y="${cy - r - 5}" text-anchor="middle">${esc(shortTitle(idea.title))}</text>
    </g>`;
  }).join("");

  return `<div class="quad">
    <h3>Attractiveness vs. ease of entry <span class="muted">— bubble size = founder-fit</span></h3>
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
    <p class="one-liner">${esc(idea.oneLiner || "")}</p>
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
        <div class="card"><h3>Clarify or expand this idea</h3>
          <p class="muted" style="margin-top:0">Add detail, answer any open questions, or push back — it goes to the group to sharpen the analysis. Your typing is kept in this browser.</p>
          ${qs.length ? `<ul class="qs">${qs.map(q => `<li>${esc(q)}</li>`).join("")}</ul>` : ""}
          <form id="answers-form">
            <div class="ans-q"><label>Your name (optional)</label><input class="ans-name" type="text" placeholder="Who's answering?" /></div>
            <div class="ans-q"><label>Clarify / expand the idea</label><textarea id="ans-response" rows="6" placeholder="Add anything useful — context, answers to the questions above, corrections…"></textarea></div>
            <div class="ans-actions">
              <button type="button" id="send-answers">Send</button>
              <button type="button" id="copy-answers" class="ghost">Copy</button>
              <span id="ans-note" class="muted"></span>
            </div>
          </form></div>
      </div>
      <div>
        <div class="card"><h3>Scorecard</h3>${scoreRows}</div>
      </div>
    </div>`;

  // ----- Clarify / expand form wiring -----
  const form = $("#answers-form");
  if (form) {
    const nameEl = form.querySelector(".ans-name");
    const respEl = $("#ans-response");
    const K = s => `ans:${idea.id}:${s}`;
    // restore anything typed earlier in this browser
    nameEl.value = localStorage.getItem(K("name")) || "";
    respEl.value = localStorage.getItem(K("response")) || "";
    // persist as they type
    nameEl.addEventListener("input", () => localStorage.setItem(K("name"), nameEl.value));
    respEl.addEventListener("input", () => localStorage.setItem(K("response"), respEl.value));

    const buildText = () => {
      let out = `Clarify / expand — ${idea.title}\n`;
      const nm = nameEl.value.trim();
      if (nm) out += `From: ${nm}\n`;
      out += `\n${respEl.value.trim() || "(blank)"}\n`;
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
            answers: [{ q: "Clarify / expand", a: respEl.value.trim() }],
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
}
/* ---------- Submit-an-idea view ---------- */
const SUBMIT_FIELDS = [
  { k: "name",        label: "Your name",       type: "input",    ph: "" },
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
          f.type === "textarea"
            ? `<textarea data-k="${f.k}" rows="${f.rows || 3}" placeholder="${esc(f.ph)}"></textarea>`
            : `<input data-k="${f.k}" type="text" placeholder="${esc(f.ph)}" />`}</div>`).join("")}
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
    e.value = localStorage.getItem(K(e.dataset.k)) || "";
    e.addEventListener("input", () => localStorage.setItem(K(e.dataset.k), e.value));
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
        els.forEach(e => { e.value = ""; });
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
