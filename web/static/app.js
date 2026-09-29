"use strict";
const $ = (s) => document.querySelector(s);
const $$ = (s) => document.querySelectorAll(s);
const api = async (url, opts) => {
  const r = await fetch(url, opts);
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || r.statusText);
  return d;
};
const esc = (s) => (s == null ? "" : String(s)).replace(/[&<>"]/g,
  (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const nf = (n) => (n >= 0 ? Number(n).toLocaleString("tr-TR") : "?");
function toast(msg) {
  const t = document.createElement("div");
  t.className = "toast"; t.textContent = msg; document.body.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

/* ---------- tabs ---------- */
$$(".tab").forEach((b) => b.onclick = () => {
  $$(".tab").forEach((x) => x.classList.remove("active"));
  $$(".panel").forEach((x) => x.classList.remove("active"));
  b.classList.add("active");
  $("#" + b.dataset.tab).classList.add("active");
  if (b.dataset.tab === "findings") loadFindings();
  if (b.dataset.tab === "pipeline") loadJobs();
  if (b.dataset.tab === "plugins") loadInstalled();
});

/* ---------- eklenti arama ---------- */
async function searchPlugins() {
  const q = $("#q").value.trim();
  const browse = $("#browse").value;
  $("#pluginResults").innerHTML = "<p class='muted'>Yükleniyor…</p>";
  try {
    const url = "/api/plugins/search?" + new URLSearchParams(
      q ? { q } : { browse });
    const d = await api(url);
    $("#pluginResults").innerHTML = d.plugins.map(pluginCard).join("") ||
      "<p class='muted'>Sonuç yok.</p>";
  } catch (e) { $("#pluginResults").innerHTML = `<p class='status-error'>${esc(e.message)}</p>`; }
}
function pluginCard(p) {
  const old = p.last_updated && p.last_updated < "2024-01-01";
  return `<div class="card">
    <h4>${esc(p.name)}</h4>
    <div class="meta">
      <span class="badge installs">${nf(p.active_installs)}+ kurulum</span>
      <span class="badge ${old ? "old" : ""}">güncelleme ${esc(p.last_updated) || "?"}</span>
      · v${esc(p.version)} · ⭐${Math.round((p.rating || 0) / 20)}/5
    </div>
    <div class="desc">${esc(p.desc)}</div>
    <div class="dlrow">
      <code style="flex:1;color:#79c0ff">${esc(p.slug)}</code>
      <button onclick="downloadPlugin('${esc(p.slug)}',this)">İndir</button>
    </div>
  </div>`;
}
window.downloadPlugin = async (slug, btn) => {
  btn.disabled = true; btn.textContent = "…";
  try {
    const d = await api("/api/download", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ slug }),
    });
    toast(`İndirme başladı: ${slug} (job #${d.job})`);
    btn.textContent = "✓ kuyrukta";
    setTimeout(loadInstalled, 3000);
  } catch (e) { toast("Hata: " + e.message); btn.disabled = false; btn.textContent = "İndir"; }
};

/* ---------- indirilmis eklentiler ---------- */
async function loadInstalled() {
  try {
    const rows = await api("/api/installed");
    if (!rows.length) { $("#installed").innerHTML = "<p class='muted' style='padding:10px'>Henüz indirilmiş eklenti yok.</p>"; return; }
    $("#installed").innerHTML = `<table><thead><tr>
      <th>slug</th><th>sürüm</th><th>kurulum</th><th>bulgu</th>
      <th>kuyruk</th><th>real</th><th>fp</th></tr></thead><tbody>` +
      rows.map((r) => `<tr>
        <td><b>${esc(r.slug)}</b></td><td>${esc(r.version)}</td>
        <td>${nf(r.active_installs)}</td><td>${r.findings || 0}</td>
        <td class="spin">${r.open_q || 0}</td>
        <td class="v real">${r.real_c || 0}</td><td class="muted">${r.fp_c || 0}</td>
      </tr>`).join("") + "</tbody></table>";
  } catch (e) { $("#installed").innerHTML = `<p class='status-error' style='padding:10px'>${esc(e.message)}</p>`; }
}

/* ---------- boru hatti ---------- */
async function runAction(url, body, btn) {
  btn.disabled = true;
  try {
    const d = await api(url, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    toast(`Başladı (job #${d.job})`);
    await loadJobs();
    watchJob(d.job);
  } catch (e) { toast("Hata: " + e.message); }
  finally { btn.disabled = false; }
}
$("#btnScan").onclick = (e) => runAction("/api/scan", {}, e.currentTarget);
$("#btnDiscover").onclick = (e) => runAction("/api/discover",
  { limit_plugins: $("#discLimit").value }, e.currentTarget);
$("#btnTriage").onclick = (e) => runAction("/api/triage",
  { limit: $("#triLimit").value }, e.currentTarget);

async function loadJobs() {
  try {
    const rows = await api("/api/jobs");
    $("#jobList").innerHTML = rows.length ? `<table><thead><tr>
      <th>#</th><th>iş</th><th>durum</th><th>başladı</th></tr></thead><tbody>` +
      rows.map((j) => `<tr onclick="watchJob(${j.id})" style="cursor:pointer">
        <td>${j.id}</td><td>${esc(j.label)}</td>
        <td class="status-${j.status}">${j.status}${j.returncode != null ? " (" + j.returncode + ")" : ""}</td>
        <td class="muted">${esc(j.started)}</td></tr>`).join("") + "</tbody></table>"
      : "<p class='muted' style='padding:10px'>Henüz job yok.</p>";
  } catch (e) { /* sessiz */ }
}

let _watch = null, _watchSince = 0, _watchId = null;
window.watchJob = (jid) => {
  if (_watch) clearInterval(_watch);
  _watchId = jid; _watchSince = 0; $("#logView").textContent = "";
  const poll = async () => {
    try {
      const d = await api(`/api/jobs/${jid}?since=${_watchSince}`);
      $("#logLabel").textContent = `#${d.id} ${d.label} — ${d.status}`;
      $("#logLabel").className = "status-" + d.status;
      if (d.log.length) {
        _watchSince = d.total;
        const el = $("#logView");
        el.textContent += (el.textContent ? "\n" : "") + d.log.join("\n");
        el.scrollTop = el.scrollHeight;
      }
      if (d.status !== "running") {
        clearInterval(_watch); _watch = null;
        loadJobs(); loadInstalled();
      }
    } catch (e) { clearInterval(_watch); _watch = null; }
  };
  poll();
  _watch = setInterval(poll, 1500);
};

/* ---------- bulgular ---------- */
let _selFinding = null;
async function loadFindings() {
  const verdict = $("#fVerdict").value, auth = $("#fAuth").value;
  $("#findingList").innerHTML = "<p class='muted' style='padding:10px'>Yükleniyor…</p>";
  try {
    const rows = await api("/api/findings?" + new URLSearchParams({ verdict, auth }));
    if (!rows.length) { $("#findingList").innerHTML = "<p class='muted' style='padding:10px'>Bulgu yok.</p>"; return; }
    $("#findingList").innerHTML = `<table><thead><tr>
      <th>id</th><th>eklenti</th><th>sınıf</th><th>yetki</th><th>güven</th></tr></thead><tbody>` +
      rows.map((r) => `<tr id="fr${r.id}" onclick="showFinding(${r.id})" style="cursor:pointer">
        <td>${r.id}</td><td><b>${esc(r.slug)}</b><br><span class="muted">${nf(r.active_installs)}+</span></td>
        <td>${esc(r.vuln_class)}</td>
        <td class="a ${esc(r.auth_context)}">${esc(r.auth_context)}</td>
        <td>${(r.confidence ?? 0).toFixed(2)}</td></tr>`).join("") + "</tbody></table>";
  } catch (e) { $("#findingList").innerHTML = `<p class='status-error' style='padding:10px'>${esc(e.message)}</p>`; }
}
$("#fRefresh").onclick = loadFindings;

window.showFinding = async (fid) => {
  $$("#findingList tr").forEach((t) => t.classList.remove("sel"));
  $("#fr" + fid)?.classList.add("sel");
  _selFinding = fid;
  $("#findingDetail").innerHTML = "<p class='muted'>Yükleniyor…</p>";
  try {
    const r = await api(`/api/finding/${fid}`);
    $("#findingDetail").innerHTML = `
      <div class="row" style="justify-content:space-between">
        <div><span class="v ${esc(r.triage_verdict)}">${esc(r.triage_verdict)}</span>
          · <span class="a ${esc(r.auth_context)}">${esc(r.auth_context)}</span>
          · ${esc(r.vuln_class)} · güven ${(r.confidence ?? 0).toFixed(2)}</div>
        <div class="muted">#${r.id} · ${esc(r.engine)}</div>
      </div>
      <div class="muted" style="margin:6px 0">${esc(r.file_path)} : ${r.start_line}</div>
      <div class="vbtns">
        <button class="real" onclick="setVerdict(${fid},'real')">real</button>
        <button class="warn" style="background:#d29922" onclick="setVerdict(${fid},'likely')">likely</button>
        <button class="fp" onclick="setVerdict(${fid},'false_positive')">false_positive</button>
        <button style="margin-left:auto" onclick="loadReach(${fid})">🔎 Reachability grep</button>
      </div>
      ${codeBlock(r.code)}
      <h3>Not</h3><div class="grep" style="max-height:160px">${esc(r.triage_notes) || "-"}</div>
      <div id="reach"></div>`;
  } catch (e) { $("#findingDetail").innerHTML = `<p class='status-error'>${esc(e.message)}</p>`; }
};

function codeBlock(code) {
  if (!code) return "";
  if (code.error) return `<p class="status-error">${esc(code.error)}</p>`;
  const html = code.lines.map((l) =>
    `<div class="${l.n === code.focus ? "focus" : ""}"><span class="ln">${l.n}</span>${esc(l.t)}</div>`
  ).join("");
  return `<h3>Kod (${esc(code.path)})</h3><div class="code">${html}</div>`;
}

window.setVerdict = async (fid, verdict) => {
  const note = prompt(`Verdict = ${verdict}. Kısa not (opsiyonel):`, "");
  if (note === null) return;
  try {
    await api(`/api/finding/${fid}/verdict`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verdict, note }),
    });
    toast(`#${fid} → ${verdict}`);
    loadFindings();
    showFinding(fid);
  } catch (e) { toast("Hata: " + e.message); }
};

window.loadReach = async (fid) => {
  $("#reach").innerHTML = "<h3>Reachability</h3><p class='muted'>grep çalışıyor…</p>";
  try {
    const d = await api(`/api/finding/${fid}/reachability`);
    const fmt = (arr) => arr.map((g) => {
      const nopriv = /nopriv/.test(g.text) ? "nopriv" : "";
      return `<div class="${nopriv}"><b>${esc(g.file)}:${g.line}</b> ${esc(g.text)}</div>`;
    }).join("") || "<div class='muted'>—</div>";
    $("#reach").innerHTML = `
      <h3>Giriş noktaları <span class="muted">(nopriv = unauth!)</span></h3>
      <div class="grep">${fmt(d.entrypoints)}</div>
      <h3>Gate'ler (cap / nonce)</h3>
      <div class="grep">${fmt(d.gates)}</div>`;
  } catch (e) { $("#reach").innerHTML = `<p class='status-error'>${esc(e.message)}</p>`; }
};

/* ---------- ilk yukleme ---------- */
$("#searchBtn").onclick = searchPlugins;
$("#q").addEventListener("keydown", (e) => { if (e.key === "Enter") searchPlugins(); });
searchPlugins();
loadInstalled();
