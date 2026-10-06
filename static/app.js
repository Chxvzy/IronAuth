const $ = s => document.querySelector(s);
const view = id => document.querySelectorAll("section").forEach(s => s.hidden = s.id !== id);
const tab = n => { $("#login").hidden = n !== "login"; $("#register").hidden = n !== "register"; };

// Aviso que aparece no topo e some sozinho
let tt;
const msg = (t, ok) => {
  const el = $("#toast"); clearTimeout(tt);
  if (!t) { el.hidden = true; return; }
  el.textContent = t; el.className = ok ? "ok" : "err"; el.hidden = false;
  tt = setTimeout(() => el.hidden = true, 4500);
};

// Pop-up de confirmação (devolve true ou false)
const ask = (title, text, label = "Confirmar", danger = true) => new Promise(res => {
  const d = $("#dlg"), y = $("#dyes");
  $("#dtitle").textContent = title; $("#dtext").textContent = text;
  y.textContent = label; y.className = danger ? "danger" : "";
  const done = v => { d.close(); res(v); };
  y.onclick = () => done(true); $("#dno").onclick = () => done(false);
  d.oncancel = () => res(false);
  d.showModal();
});

async function api(path, method = "GET", body) {
  const r = await fetch("/api/" + path, { method, headers: { "Content-Type": "application/json" }, body: body && JSON.stringify(body) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(typeof d.detail === "string" ? d.detail : "Dados inválidos: usuário com 3-20 letras/números e senha com mínimo de 8 caracteres.");
  return d;
}
const btn = (t, fn, c = "") => { const b = document.createElement("button"); b.textContent = t; b.className = c; b.onclick = fn; return b; };
const act = async (p, m, b) => { try { await api(p, m, b); home(); } catch (e) { msg(e.message); } };
const roleCell = r => { const td = document.createElement("td"), s = document.createElement("span"); s.className = "badge " + r; s.textContent = r; td.append(s); return td; };
const cell = v => { const td = document.createElement("td"); td.textContent = v; return td; };

async function panel(me) {
  const tb = $("#rows"); tb.replaceChildren();
  for (const u of await api("admin/users")) {
    const tr = document.createElement("tr"); tr.append(cell(u.id), cell(u.username), roleCell(u.role));
    const td = document.createElement("td");
    if (me.role === "admin" && u.id !== me.id) {
      ["user", "mod", "admin"].filter(r => r !== u.role).forEach(r => td.append(btn("Tornar " + r, async () => {
        if (await ask("Alterar cargo", `Tornar "${u.username}" ${r}?`, "Confirmar", false)) act(`admin/users/${u.id}/role`, "PATCH", { role: r });
      })));
      td.append(btn("Excluir", async () => {
        if (await ask("Excluir usuário", `Excluir "${u.username}"? Essa ação não pode ser desfeita.`, "Excluir")) act(`admin/users/${u.id}`, "DELETE");
      }, "danger"));
    }
    tr.append(td); tb.append(tr);
  }
  $("#logbox").hidden = me.role !== "admin";
  if (me.role === "admin") $("#logs").replaceChildren(...(await api("admin/logs")).map(l => {
    const li = document.createElement("li"), t = document.createElement("span"); t.className = "time"; t.textContent = new Date(l.at * 1000).toLocaleString();
    li.append(t, ` ${l.actor}: ${l.action}`); return li; }));
}
async function home() {
  try {
    const me = await api("me");
    $("#uname").textContent = me.username; $("#urole").textContent = me.role; $("#urole").className = "badge " + me.role;
    document.querySelector("main").classList.toggle("wide", me.role !== "user"); $("#plain").hidden = me.role !== "user";
    view("home"); $("#admin").hidden = me.role === "user";
    if (me.role !== "user") await panel(me);
  } catch { view("auth"); }
}
const submit = (sel, fn) => $(sel).onsubmit = async e => {
  e.preventDefault(); const f = e.target;
  try { await fn(Object.fromEntries(new FormData(f))); f.reset(); } catch (x) { msg(x.message); }
};
submit("#login", async d => { await api("login", "POST", d); msg(); home(); });
submit("#register", async d => { await api("register", "POST", d); msg("Conta criada! Faça login.", 1); tab("login"); });
submit("#fgt", async d => msg((await api("forgot-password", "POST", d)).message, 1));
submit("#reset", async d => { msg((await api("reset-password", "POST", d)).message, 1); view("auth"); });
document.querySelectorAll("[data-tab]").forEach(b => b.onclick = () => tab(b.dataset.tab));
$("#toforgot").onclick = e => { e.preventDefault(); msg(); view("forgot"); };
$("#back").onclick = e => { e.preventDefault(); msg(); view("auth"); };
$("#out").onclick = async () => { await api("logout", "POST"); msg(); view("auth"); };
const m = location.hash.match(/^#reset=([\w-]+)$/);
if (m) { $("#reset").token.value = m[1]; history.replaceState(null, "", location.pathname); view("forgot"); }
else home();