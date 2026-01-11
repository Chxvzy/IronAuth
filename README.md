🔐 IronAuth

IronAuth é um sistema de autenticação em Python com banco de dados em arquivo JSON,
proteção de senha por hash e sistema de sessão por token — simulando como sites reais funcionam.

⚙️ Funcionalidades:  
- Cadastro de usuários  
- Login com senha protegida por SHA-256  
- Banco de dados persistente em users.json  
- Sistema de sessão com token  
- Verificação de sessão ativa  
- Logout  
- Tratamento de erros e compatibilidade com versões antigas

🧠 Como funciona:    
Cada usuário é armazenado como um objeto JSON:    

{"username":"fe","password":"HASH","token":null}  
  
O token funciona como uma sessão ativa, permitindo manter o usuário autenticado.

▶️ Como usar  
1️⃣ Execute o sistema:  

python main.py


2️⃣ Menu:  
  1 - Register  
  2 - Login  
  3 - Check session  
  4 - Logout  
  5 - Exit    


3️⃣ Fluxo:
- Cadastre um usuário  
- Faça login  
- Guarde o token gerado  
- Use o token para validar sessão
- Faça logout quando quiser

🔒 Segurança:  
- Senhas nunca são salvas em texto puro  
- Hash SHA-256 protege as credenciais  
- Tokens são gerados com secrets.token_hex()  
- Proteção contra erro humano com .strip()  
- Compatível com bancos antigos usando .get()  

📁 Estrutura  
main.py  
users.json  
README.md  

👤 Autor

Felipe — Backend Python Developer in training
