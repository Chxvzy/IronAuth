import os, ssl, secrets, time, smtplib, threading, random
from urllib.parse import urlparse
from email.message import EmailMessage
import pymysql
from pymysql.cursors import DictCursor
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, Response, Cookie, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from security import hash_password, verify_password, new_token, sha

load_dotenv()
BASE = os.path.dirname(os.path.abspath(__file__))
PUBLIC = next((os.path.join(BASE, d) for d in ("public", "static") if os.path.isdir(os.path.join(BASE, d))), None)
if not os.getenv("DB_HOST"):
    raise RuntimeError("Defina DB_HOST, DB_USER, DB_PASSWORD e DB_NAME (veja .env.example).")
SESSION_MIN, RESET_MIN, MAX_FAILS, LOCK_MIN = 30, 15, 5, 5
OWNER_ID = 1  # admin principal, criado no primeiro start
DUMMY = hash_password("dummy")  # mesmo custo de tempo para usuário inexistente

app = FastAPI(title="IronAuth")

def tls():
    if os.getenv("DB_SSL_CA"):
        return {"ca": os.getenv("DB_SSL_CA")}
    if os.getenv("DB_SSL") == "1":
        return ssl.create_default_context()
    return None

_local = threading.local()  # uma conexão por thread, reaproveitada entre as consultas

def q(sql, args=()):
    for attempt in (1, 2):
        try:
            con = getattr(_local, "con", None)
            if con is None:
                con = _local.con = pymysql.connect(
                    host=os.getenv("DB_HOST"), port=int(os.getenv("DB_PORT", "3306")),
                    user=os.getenv("DB_USER"), password=os.getenv("DB_PASSWORD"),
                    database=os.getenv("DB_NAME", "alunos_IronAuth"),
                    cursorclass=DictCursor, autocommit=True, connect_timeout=10, ssl=tls())
            with con.cursor() as cur:
                cur.execute(sql.replace("?", "%s"), args)  # sempre parametrizado
                return list(cur.fetchall())
        except (pymysql.err.OperationalError, pymysql.err.InterfaceError):
            _local.con = None  # a conexão caiu: reconecta e tenta mais uma vez
            if attempt == 2:
                raise

def log(actor, action, ip=None):
    q("INSERT INTO audit(`at`, actor, action) VALUES(?,?,?)", (time.time(), actor, action))

def init():
    q("CREATE TABLE IF NOT EXISTS users(id BIGINT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(20) UNIQUE NOT NULL, email VARCHAR(254) UNIQUE, password_hash VARCHAR(255) NOT NULL, role VARCHAR(10) NOT NULL DEFAULT 'user', fails INT DEFAULT 0, locked_until DOUBLE DEFAULT 0, created_at DOUBLE) DEFAULT CHARSET=utf8mb4")
    q("CREATE TABLE IF NOT EXISTS sessions(token_hash CHAR(64) PRIMARY KEY, user_id BIGINT, expires DOUBLE) DEFAULT CHARSET=utf8mb4")
    q("CREATE TABLE IF NOT EXISTS resets(token_hash CHAR(64) PRIMARY KEY, user_id BIGINT, expires DOUBLE, used INT DEFAULT 0) DEFAULT CHARSET=utf8mb4")
    q("CREATE TABLE IF NOT EXISTS audit(id BIGINT AUTO_INCREMENT PRIMARY KEY, `at` DOUBLE, actor VARCHAR(40), action VARCHAR(120)) DEFAULT CHARSET=utf8mb4")
    q("CREATE TABLE IF NOT EXISTS ratelimit(ip VARCHAR(64), bucket VARCHAR(16), win BIGINT, hits INT DEFAULT 0, expires DOUBLE, PRIMARY KEY(ip, bucket, win)) DEFAULT CHARSET=utf8mb4")
    if not q("SELECT 1 FROM users LIMIT 1"):
        pw = os.getenv("ADMIN_PASSWORD") or secrets.token_urlsafe(10)
        q("INSERT IGNORE INTO users(username, password_hash, role, created_at) VALUES('admin', ?, 'admin', ?)", (hash_password(pw), time.time()))
        print(f"[IronAuth] Admin criado -> usuário: admin | senha: {pw}")

init()  # roda ao carregar (também no cold start da Vercel)

# ---------- Limite de requisições por IP (guardado no banco, vale entre instâncias) ----------
def client_ip(request: Request):
    fwd = request.headers.get("x-forwarded-for")
    if fwd and os.getenv("VERCEL"):  # só confia no cabeçalho quando está atrás da Vercel
        return fwd.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "?")[:64]

def rate_limit(request: Request, bucket: str, limit: int, window_s: int):
    ip, now = client_ip(request), time.time()
    win = int(now // window_s)
    q("INSERT INTO ratelimit(ip, bucket, win, hits, expires) VALUES(?,?,?,1,?) ON DUPLICATE KEY UPDATE hits=hits+1",
      (ip, bucket, win, (win + 1) * window_s))
    hits = q("SELECT hits FROM ratelimit WHERE ip=? AND bucket=? AND win=?", (ip, bucket, win))[0]["hits"]
    if random.random() < 0.02:  # limpeza ocasional de janelas antigas
        q("DELETE FROM ratelimit WHERE expires < ?", (now,))
    if hits > limit:
        raise HTTPException(429, "Muitas tentativas. Aguarde alguns minutos e tente de novo.")

# ---------- Cabeçalhos de segurança e verificação de origem (CSRF) ----------
@app.middleware("http")
async def security_headers(request, call_next):
    if request.method in ("POST", "PUT", "PATCH", "DELETE") and request.url.path.startswith("/api"):
        origin = request.headers.get("origin")
        if origin and urlparse(origin).netloc != request.headers.get("host"):
            return JSONResponse({"detail": "Origem não permitida."}, status_code=403)
    r = await call_next(request)
    if not request.url.path.startswith(("/docs", "/openapi")):
        r.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if os.getenv("COOKIE_SECURE") == "1":
        r.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return r

class Cred(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_]{3,20}$")
    email: str = Field(max_length=254, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
    password: str = Field(min_length=8, max_length=128)
class Login(BaseModel):
    username: str = Field(min_length=1, max_length=254)  # usuário ou e-mail
    password: str = Field(max_length=128)
class Forgot(BaseModel):
    email: str = Field(max_length=254)
class Reset(BaseModel):
    token: str = Field(max_length=100)
    password: str = Field(min_length=8, max_length=128)
class RoleIn(BaseModel):
    role: str = Field(pattern="^(user|mod|admin)$")

def current_user(session: str | None = Cookie(default=None)):
    if session:
        rows = q("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>?", (sha(session), time.time()))
        if rows:
            return rows[0]
    raise HTTPException(401, "Não autenticado.")

def need(*roles):
    def dep(u=Depends(current_user)):
        if u["role"] not in roles:
            raise HTTPException(403, "Sem permissão.")
        return u
    return dep

@app.post("/api/register", status_code=201)
def register(c: Cred, request: Request):
    rate_limit(request, "register", 5, 3600)  # 5 cadastros por hora por IP
    try:
        q("INSERT INTO users(username, email, password_hash, created_at) VALUES(?,?,?,?)",
          (c.username, c.email.strip().lower(), hash_password(c.password), time.time()))
    except pymysql.err.IntegrityError:
        raise HTTPException(400, "Usuário ou e-mail indisponível.")
    log(c.username, "register")
    return {"ok": True}

@app.post("/api/login")
def login(c: Login, request: Request, resp: Response):
    rate_limit(request, "login", 10, 300)  # 10 tentativas a cada 5 minutos por IP
    ident = c.username.strip()
    if "@" in ident:  # entrou com e-mail
        rows = q("SELECT * FROM users WHERE email=?", (ident.lower(),))
    else:
        rows = q("SELECT * FROM users WHERE username=?", (ident,))
    u = rows[0] if rows else None
    if u and u["locked_until"] > time.time():
        raise HTTPException(429, "Conta bloqueada temporariamente. Tente mais tarde.")
    ok = verify_password(c.password, u["password_hash"] if u else DUMMY) and u is not None
    if not ok:
        if u:
            f = u["fails"] + 1
            lock = f >= MAX_FAILS
            q("UPDATE users SET fails=?, locked_until=? WHERE id=?", (0 if lock else f, time.time() + LOCK_MIN * 60 if lock else 0, u["id"]))
        raise HTTPException(401, "Usuário ou senha inválidos.")
    if u["fails"] or u["locked_until"]:
        q("UPDATE users SET fails=0, locked_until=0 WHERE id=?", (u["id"],))
    tok = new_token()
    q("INSERT INTO sessions VALUES(?,?,?)", (sha(tok), u["id"], time.time() + SESSION_MIN * 60))
    resp.set_cookie("session", tok, max_age=SESSION_MIN * 60, httponly=True, samesite="strict", secure=os.getenv("COOKIE_SECURE") == "1")
    log(u["username"], "login")
    return {"username": u["username"], "role": u["role"]}

@app.post("/api/logout")
def logout(resp: Response, session: str | None = Cookie(default=None)):
    if session:
        q("DELETE FROM sessions WHERE token_hash=?", (sha(session),))
    resp.delete_cookie("session")
    return {"ok": True}

@app.get("/api/me")
def me(u=Depends(current_user)):
    return {"id": u["id"], "username": u["username"], "role": u["role"]}

def send_reset(to, token):
    link = f"{os.getenv('APP_URL', 'http://localhost:8000').rstrip('/')}/#reset={token}"
    host, user, pw = os.getenv("SMTP_HOST"), os.getenv("SMTP_USER"), os.getenv("SMTP_PASS")
    if not (host and user and pw):
        print(f"[IronAuth] (modo teste, SMTP não configurado) link de redefinição: {link}")
        return
    try:
        m = EmailMessage()
        m["Subject"], m["From"], m["To"] = "IronAuth: redefinir senha", f"IronAuth <{user}>", to
        m.set_content(f"Abra o link para criar uma nova senha (vale 15 minutos e só funciona uma vez):\n\n{link}\n\nSe não foi você, ignore este e-mail.")
        with smtplib.SMTP_SSL(host, 465) as s:
            s.login(user, pw)
            s.send_message(m)
    except Exception as e:
        print("[IronAuth] erro ao enviar e-mail:", e)

@app.post("/api/forgot-password")
def forgot(f: Forgot, request: Request):
    rate_limit(request, "forgot", 5, 3600)  # 5 pedidos por hora por IP (protege a conta de e-mail)
    email = f.email.strip().lower()
    rows = q("SELECT id FROM users WHERE email=?", (email,))
    if rows:
        tok = new_token()
        q("INSERT INTO resets VALUES(?,?,?,0)", (sha(tok), rows[0]["id"], time.time() + RESET_MIN * 60))
        send_reset(email, tok)  # envio direto: em serverless, tarefas em segundo plano podem ser cortadas
    return {"message": "Se o e-mail estiver cadastrado, enviamos um link para redefinir a senha."}

@app.post("/api/reset-password")
def reset(r: Reset, request: Request):
    rate_limit(request, "reset", 10, 3600)  # 10 tentativas por hora por IP
    rows = q("SELECT * FROM resets WHERE token_hash=? AND used=0 AND expires>?", (sha(r.token), time.time()))
    if not rows:
        raise HTTPException(400, "Token inválido ou expirado.")
    uid = rows[0]["user_id"]
    q("UPDATE resets SET used=1 WHERE token_hash=?", (sha(r.token),))
    q("UPDATE users SET password_hash=?, fails=0, locked_until=0 WHERE id=?", (hash_password(r.password), uid))
    q("DELETE FROM sessions WHERE user_id=?", (uid,))  # invalida sessões antigas
    log(f"user#{uid}", "reset_password")
    return {"message": "Senha alterada. Faça login."}

@app.get("/api/admin/users")
def list_users(u=Depends(need("mod", "admin"))):
    return q("SELECT id, username, role FROM users ORDER BY id")

def guard(actor, uid, new_role=None):
    rows = q("SELECT role FROM users WHERE id=?", (uid,))
    if not rows:
        raise HTTPException(404, "Usuário não encontrado.")
    if uid == actor["id"]:
        raise HTTPException(400, "Você não pode alterar a si mesmo.")
    if uid == OWNER_ID:
        raise HTTPException(403, "O administrador principal não pode ser alterado.")
    if actor["id"] != OWNER_ID and (rows[0]["role"] == "admin" or new_role == "admin"):
        raise HTTPException(403, "Só o administrador principal gerencia outros admins.")

@app.patch("/api/admin/users/{uid}/role")
def set_role(uid: int, b: RoleIn, u=Depends(need("admin"))):
    guard(u, uid, b.role)
    q("UPDATE users SET role=? WHERE id=?", (b.role, uid))
    log(u["username"], f"role user#{uid} -> {b.role}")
    return {"ok": True}

@app.delete("/api/admin/users/{uid}")
def delete_user(uid: int, u=Depends(need("admin"))):
    guard(u, uid)
    q("DELETE FROM sessions WHERE user_id=?", (uid,))
    q("DELETE FROM users WHERE id=?", (uid,))
    log(u["username"], f"delete user#{uid}")
    return {"ok": True}

@app.get("/api/admin/logs")
def logs(u=Depends(need("admin"))):
    return q("SELECT `at`, actor, action FROM audit ORDER BY id DESC LIMIT 20")

if PUBLIC and not os.getenv("VERCEL"):  # localmente o FastAPI serve o frontend; na Vercel quem serve é a pasta public
    app.mount("/", StaticFiles(directory=PUBLIC, html=True))