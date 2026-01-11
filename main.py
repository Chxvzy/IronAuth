import json, hashlib, secrets

with open("users.json", "a", encoding="utf-8") as file:
    username = input("Create username: ")
    password = input("Create password: ")

    user = {
        "username": username,
        "password": hashlib.sha256(password.encode()).hexdigest(),
        "token": None
    }

    file.write(json.dumps(user) + "\n")

with open("users.json", "r", encoding="utf-8") as file:

    found = False

    username = input("Login username: ")
    password = input("Login password: ")
    hashed = hashlib.sha256(password.encode()).hexdigest()

    for line in file:
        if line.strip() != "":
            user = json.loads(line.strip())

            if user["username"] == username:
                found = True
                if user["password"] == hashed:
                    token = secrets.token_hex(16)
                    user["token"] = token
                    print("Access granted")
                    print("Session token:", token)
                else:
                    print("Wrong password")
                break

    if not found:
        print("User not found")
