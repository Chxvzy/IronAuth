import os, ssl, getpass
import pymysql
from dotenv import load_dotenv
from security import hash_password

load_dotenv()
pw = getpass.getpass("Nova senha do admin (mín. 12 caracteres): ")
if len(pw) < 12 or pw != getpass.getpass("Repita a senha: "):
    raise SystemExit("Senha curta ou diferente. Nada foi alterado.")

con = pymysql.connect(
    host=os.getenv("DB_HOST"), port=int(os.getenv("DB_PORT", "3306")),
    user=os.getenv("DB_USER"), password=os.getenv("DB_PASSWORD"),
    database=os.getenv("DB_NAME", "alunos_IronAuth"),
    ssl=ssl.create_default_context() if os.getenv("DB_SSL") == "1" else None)
with con.cursor() as cur:
    cur.execute("UPDATE users SET password_hash=%s, fails=0, locked_until=0 WHERE id=1", (hash_password(pw),))
    cur.execute("DELETE FROM sessions WHERE user_id=1")
con.commit()
con.close()
print("Senha do admin atualizada.")