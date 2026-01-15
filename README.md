🔐 IronAuth

IronAuth é um sistema de autenticação em Python com banco de dados em arquivo JSON, proteção de senhas por hash, sessões por token, controle de cargos (roles) e painel administrativo — simulando como sistemas reais funcionam.

⚙️ Funcionalidades:  
- Cadastro de usuários  
- Login com senha protegida por SHA-256  
- Banco de dados persistente em users.json  
- Sistema de sessão com token  
- Verificação de sessão ativa  
- Logout  
- Recuperação de senha com token temporário
- Controle de cargos (RBAC: user / mod / admin)
- Painel administrativo protegido por token e cargo
- Promoção de usuários (user → mod → admin)
- Exclusão segura de usuários
- Proteção contra autoexclusão
- Invalidação de sessão após troca de senha
- Compatibilidade com bancos antigos

🧠 Como funciona:    
Cada usuário é armazenado como um objeto JSON:    

{"username":"fe","password":"HASH","token":null,"reset_token":null,"role":"user"}
  
O token representa uma sessão ativa e é necessário para acessar funções protegidas.

▶️ Como usar 

1️⃣ Execute o sistema:  
python main.py

2️⃣ Menu:  
  1 - Register  
  2 - Login  
  3 - Check session  
  4 - Logout  
  5 - Forgot password          
    6 - Exit          
    7 - Admin panel


3️⃣ Fluxo:               
- Cadastre um usuário  
- Faça login e receba um token de sessão
- Use o token para validar sessão
- Acesse o painel admin se tiver cargo de admin
- Promova usuários ou exclua contas
- Recupere senhas com tokens temporários
- Faça logout quando quiser

🔒 Segurança:  
- Senhas nunca são salvas em texto puro  
- Hash SHA-256 protege as credenciais  
- Tokens são gerados com secrets.token_hex()  
- Proteção contra erro humano com .strip()  
- Compatível com bancos antigos usando .get()
- Tokens de recuperação são descartáveis
- Sessões são invalidadas após troca de senha
- Sistema protegido contra exclusão acidental de contas

📁 Estrutura  
main.py  
users.json  
README.md  

👤 Autor        
Felipe — Backend Python Developer in training
