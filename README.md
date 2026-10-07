# 🔐 IronAuth

API de autenticação em **FastAPI + MySQL** com frontend web, sessões com expiração, controle de cargos (RBAC), painel de administração e redefinição de senha por e-mail. Projeto de estudo sobre segurança de aplicações.

## Funcionalidades
- Cadastro (usuário, e-mail e senha), login e logout
- Sessão por cookie `HttpOnly` e `SameSite=Strict`, com expiração de 30 minutos
- Cargos `user`, `mod` e `admin`
  - `mod` vê a lista de usuários
  - `admin` altera cargos e exclui contas, com confirmação em pop-up
  - Apenas o **admin principal** (ID 1) gerencia outros admins
- Log de auditoria das ações, visível ao admin
- Recuperação de senha por e-mail com link de uso único (15 minutos)

## Decisões de segurança
| Risco | O que foi feito |
|---|---|
| Senhas expostas | Hash **scrypt** com salt aleatório e comparação em tempo constante |
| Força bruta | Bloqueio de 5 minutos após 5 senhas erradas; mesmo tempo de resposta para usuário inexistente |
| SQL Injection | Consultas parametrizadas e validação de entrada com Pydantic |
| Roubo de sessão | Token aleatório salvo apenas como hash SHA-256; cookie HttpOnly; sessões apagadas ao trocar a senha |
| Escalada de privilégio | Cargo verificado no servidor em cada rota; admin principal protegido; ninguém altera a si mesmo |
| Token de redefinição | Uso único, 15 minutos, salvo como hash; o link usa `#`, que o navegador não envia ao servidor |
| Enumeração de usuários | Mensagens genéricas no login e na recuperação de senha |
| XSS e clickjacking | Frontend com `textContent`, CSP, `X-Frame-Options` e `nosniff` |

> Durante os testes, encontrei uma falha: um admin secundário conseguia rebaixar o admin principal. Corrigi com a função `guard` em `main.py`.

## Requisitos
- Python 3.10 ou superior
- Um servidor MySQL com um banco criado e um usuário com permissão de `SELECT`, `INSERT`, `UPDATE`, `DELETE` e `CREATE` nele
- (Opcional) Uma conta Gmail com senha de app, para enviar o e-mail de redefinição

## Como rodar

**1. Baixe o projeto**
```
git clone https://github.com/Chxvzy/IronAuth.git
cd IronAuth
```

**2. Crie o ambiente e instale as dependências**

Windows:
```
py -m venv .venv
.venv\Scripts\activate
py -m pip install -r requirements.txt
```

Mac/Linux:
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**3. Configure o arquivo `.env`**

Copie o `.env.example` para `.env` e preencha os valores. O `.env` não vai para o GitHub.

Windows:
```
copy .env.example .env
```
Mac/Linux:
```
cp .env.example .env
```

**4. Crie o banco no MySQL**
```sql
CREATE DATABASE IF NOT EXISTS alunos_IronAuth CHARACTER SET utf8mb4;
```
Use no `DB_NAME` exatamente o mesmo nome, com as mesmas maiúsculas. As tabelas são criadas sozinhas no primeiro start.

**5. Inicie o servidor**
```
py -m uvicorn main:app --reload
```
Abra http://localhost:8000. No primeiro start é criado o usuário `admin`: a senha aparece no terminal, ou é a definida em `ADMIN_PASSWORD`. A documentação das rotas fica em `/docs`.

## Variáveis de ambiente (`.env`)
| Variável | Para que serve |
|---|---|
| `DB_HOST`, `DB_PORT` | Endereço e porta do MySQL (porta padrão: 3306) |
| `DB_USER`, `DB_PASSWORD` | Usuário e senha do MySQL |
| `DB_NAME` | Nome do banco (ex.: `alunos_IronAuth`) |
| `DB_SSL` | `1` para conectar com TLS; `DB_SSL_CA` aponta para o certificado do servidor, se for autoassinado |
| `ADMIN_PASSWORD` | Senha do admin, usada só na criação dele (primeiro start) |
| `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS` | Envio do e-mail de redefinição (Gmail: `smtp.gmail.com` e senha de app) |
| `APP_URL` | Endereço público usado no link do e-mail (padrão: `http://localhost:8000`) |
| `COOKIE_SECURE` | `1` para o cookie só trafegar por HTTPS (use em produção) |

Sem `SMTP_*`, o link de redefinição aparece no terminal (modo de teste).

## Trocar a senha do admin
O `ADMIN_PASSWORD` só vale quando o admin é criado. Para trocar a senha de um admin que já existe, rode:
```
py set_admin_password.py
```
O script pede a nova senha (mínimo de 12 caracteres, sem mostrar na tela), grava só o hash no banco e encerra as sessões do admin.

## Rodar em outro computador
1. Instale Python e Git e repita os passos 1 e 2 acima.
2. Leve o seu `.env` por um meio seguro (ele não está no GitHub) ou preencha um novo a partir do `.env.example`.
3. Suba o servidor. Usuários, cargos e auditoria ficam no MySQL, então aparecem iguais em qualquer computador que acesse o mesmo banco.

## Rotas principais
`POST /api/register` · `POST /api/login` · `POST /api/logout` · `GET /api/me` · `POST /api/forgot-password` · `POST /api/reset-password` · `GET /api/admin/users` · `PATCH /api/admin/users/{id}/role` · `DELETE /api/admin/users/{id}` · `GET /api/admin/logs`

## Estrutura
```
main.py                  rotas, regras de acesso e acesso ao banco
security.py              hash de senhas e tokens
set_admin_password.py    troca a senha do admin pelo terminal
static/                  frontend (HTML, CSS e JavaScript)
requirements.txt
.env.example             modelo das variáveis de ambiente
```

## Limitações
- Sem testes automatizados, 2FA e limite de tentativas por IP
- O admin criado automaticamente não tem e-mail, então não recupera a senha pelo fluxo (use `set_admin_password.py`)
- Cada operação abre uma nova conexão com o banco, o que é mais lento que um pool de conexões
- O envio de e-mail é feito dentro da requisição, e por isso a resposta de "esqueci a senha" demora um pouco mais quando o e-mail existe

## Próximos passos
Testes com pytest, GitHub Actions, 2FA (TOTP) e deploy.