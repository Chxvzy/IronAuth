# 🔐 IronAuth

API de autenticação em **FastAPI + SQLite** com frontend web, sessões com expiração, controle de cargos (RBAC), painel de administração e redefinição de senha por e-mail. Projeto de estudo sobre segurança de aplicações.

## Funcionalidades
- Cadastro (usuário, e-mail e senha), login e logout
- Sessão por cookie `HttpOnly` e `SameSite=Strict`, com expiração de 30 minutos
- Cargos `user`, `mod` e `admin`
  - `mod` vê a lista de usuários
  - `admin` altera cargos e exclui contas, com confirmação em pop-up
  - Apenas o **admin principal** gerencia outros admins
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

## Como rodar

**1. Crie o ambiente e instale as dependências**

Windows:
```
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Mac/Linux:
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**2. Inicie o servidor**
```
python -m uvicorn main:app --reload
```

Abra http://localhost:8000. No primeiro start é criado o usuário `admin`, e a senha aparece no terminal (ou defina `ADMIN_PASSWORD`). A documentação das rotas fica em `/docs`.

### Variáveis de ambiente
| Variável | Para que serve |
|---|---|
| `ADMIN_PASSWORD` | Senha do admin criado no primeiro start |
| `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS` | Envio do e-mail de redefinição (ex.: Gmail com senha de app) |
| `APP_URL` | Endereço público usado no link do e-mail (padrão: `http://localhost:8000`) |
| `COOKIE_SECURE=1` | Cookie só por HTTPS (use em produção) |

Sem `SMTP_*`, o link de redefinição aparece no terminal (modo de teste).

## Rotas principais
`POST /api/register` · `POST /api/login` · `POST /api/logout` · `GET /api/me` · `POST /api/forgot-password` · `POST /api/reset-password` · `GET /api/admin/users` · `PATCH /api/admin/users/{id}/role` · `DELETE /api/admin/users/{id}` · `GET /api/admin/logs`

## Estrutura
```
main.py          rotas, regras de acesso e banco
security.py      hash de senhas e tokens
static/          frontend (HTML, CSS e JavaScript)
requirements.txt
```

## Limitações
- Sem testes automatizados, 2FA e limite de tentativas por IP
- O admin criado automaticamente não tem e-mail, então não recupera senha pelo fluxo
- SQLite em arquivo: em hospedagem serverless (como a Vercel), o banco seria apagado a cada reinício

## Próximos passos
Testes com pytest, GitHub Actions, 2FA (TOTP) e migração para PostgreSQL com deploy.
