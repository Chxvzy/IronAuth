const $ = s => document.querySelector(s);
const view = id => {
  document.querySelectorAll("section").forEach(s => s.hidden = s.id !== id);
  if (id !== "home") document.querySelector("main").classList.remove("wide"); // volta ao tamanho normal fora do painel
};
const tab = n => {
  $("#login").hidden = n !== "login";
  $("#register").hidden = n !== "register";
  $("#toforgot").hidden = n !== "login"; // "Esqueci a senha" só na tela de login
};

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
  const [users, logs] = await Promise.all([api("admin/users"), me.role === "admin" ? api("admin/logs") : Promise.resolve([])]);
  const tb = $("#rows"); tb.replaceChildren();
  for (const u of users) {
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
  if (me.role === "admin") $("#logs").replaceChildren(...logs.map(l => {
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

// Volta os campos de senha para o modo oculto
function hidePw(f) {
  f.querySelectorAll(".pw input").forEach(i => { if (i.type === "text") i.nextElementSibling.click(); });
}
const submit = (sel, fn) => $(sel).onsubmit = async e => {
  e.preventDefault(); const f = e.target;
  try { await fn(Object.fromEntries(new FormData(f))); f.reset(); hidePw(f); } catch (x) { msg(x.message); }
};
submit("#login", async d => { await api("login", "POST", d); msg(); home(); });
submit("#register", async d => { await api("register", "POST", d); msg("Conta criada! Faça login.", 1); tab("login"); });
submit("#fgt", async d => msg((await api("forgot-password", "POST", d)).message, 1));
submit("#reset", async d => { msg((await api("reset-password", "POST", d)).message, 1); view("auth"); });
document.querySelectorAll("[data-tab]").forEach(b => b.onclick = () => tab(b.dataset.tab));
$("#toforgot").onclick = e => { e.preventDefault(); msg(); view("forgot"); };
$("#back").onclick = e => { e.preventDefault(); msg(); view("auth"); };
$("#out").onclick = async () => { await api("logout", "POST"); msg(); tab("login"); view("auth"); };

// Olho para mostrar/ocultar senha em todos os campos de senha
const EYE = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7S1 12 1 12z"/><circle cx="12" cy="12" r="3"/></svg>';
const EYE_OFF = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.9 10.9 0 0 1 12 19c-7 0-11-7-11-7a19.8 19.8 0 0 1 5.06-5.94M9.9 4.24A10.9 10.9 0 0 1 12 5c7 0 11 7 11 7a19.8 19.8 0 0 1-3.17 4.19M1 1l22 22"/><path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/></svg>';
document.querySelectorAll('input[type="password"]').forEach(inp => {
  const wrap = document.createElement("div"); wrap.className = "pw";
  inp.replaceWith(wrap); wrap.append(inp);
  const b = document.createElement("button");
  b.type = "button"; b.className = "eye"; b.setAttribute("aria-label", "Mostrar senha"); b.innerHTML = EYE;
  b.onclick = () => {
    const show = inp.type === "password";
    inp.type = show ? "text" : "password";
    b.innerHTML = show ? EYE_OFF : EYE;
    b.setAttribute("aria-label", show ? "Ocultar senha" : "Mostrar senha");
  };
  wrap.append(b);
});

// Link do e-mail (#reset=token): abre direto a tela de nova senha
const m = location.hash.match(/^#reset=([\w-]+)$/);
if (m) { $("#reset").token.value = m[1]; history.replaceState(null, "", location.pathname); view("forgot"); }
else home();