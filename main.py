import json, hashlib

with open("users.json", "a", encoding="utf-8") as file:
    username = input("Create username: ")
    password = input("Create password: ")

    user = {
        "username": username,
        "password": hashlib.sha256(password.encode()).hexdigest()
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
                    print("Access granted")
                else:
                    print("Wrong password")
                break

    if not found:
        print("User not found")
