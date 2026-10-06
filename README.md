# 🔐 IronAuth

API de autenticação em **FastAPI + SQLite** com frontend web, sessões com expiração, controle de cargos (RBAC) e painel de administração. Projeto de estudo sobre segurança de aplicações.

## Funcionalidades
- Cadastro, login, logout e sessão (cookie `HttpOnly`, `SameSite=Strict`, expira em 30 min)
- Cargos `user`, `mod` e `admin`; o painel lista usuários (mod/admin) e altera cargos ou exclui (só admin)
- Redefinição de senha com token de uso único (15 min)
- Log de auditoria das ações (visível ao admin)

## Decisões de segurança
| Risco | O que foi feito |
|---|---|
| Senhas expostas | Hash **scrypt** com salt aleatório; comparação em tempo constante |
| Força bruta | Bloqueio de 5 min após 5 falhas; mesmo tempo de resposta para usuário inexistente |
| SQL Injection | Consultas parametrizadas e validação de entrada (Pydantic) |
| Roubo de sessão | Token aleatório salvo só como hash SHA-256; cookie HttpOnly; sessões apagadas ao trocar a senha |
| Acesso indevido | Cargo verificado no servidor em cada rota; admin não altera nem exclui a si mesmo |
| XSS / clickjacking | Frontend usa `textContent`; CSP, `X-Frame-Options` e `nosniff` |
| Enumeração de usuários | Mensagens genéricas em login e recuperação de senha |

## Como rodar
```bash
pip install -r requirements.txt
uvicorn main:app --reload
```
Abra http://localhost:8000. No primeiro start é criado o usuário `admin`; a senha aparece no terminal (ou defina `ADMIN_PASSWORD`). Documentação das rotas em `/docs`. Em produção, use HTTPS e `COOKIE_SECURE=1`.

## Limitações
- Na redefinição de senha, o token aparece no terminal do servidor, simulando o e-mail.
- Sem testes automatizados, 2FA e limite de tentativas por IP.

## Próximos passos
Testes com pytest, GitHub Actions, 2FA (TOTP) e deploy.
