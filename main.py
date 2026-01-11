import json, hashlib, secrets

DB = "users.json"


def load_users():
    users = []
    try:
        with open(DB, "r", encoding="utf-8") as file:
            for line in file:
                if line.strip() != "":
                    users.append(json.loads(line.strip()))
    except FileNotFoundError:
        open(DB, "w").close()
    return users


def save_users(users):
    with open(DB, "w", encoding="utf-8") as file:
        for user in users:
            file.write(json.dumps(user) + "\n")


def register():
    users = load_users()
    username = input("Create username: ")

    for u in users:
        if u["username"] == username:
            print("User already exists")
            return

    password = input("Create password: ")

    users.append({
        "username": username,
        "password": hashlib.sha256(password.encode()).hexdigest(),
        "token": None
    })

    save_users(users)
    print("User registered!")


def login():
    users = load_users()
    username = input("Username: ")
    password = input("Password: ")
    hashed = hashlib.sha256(password.encode()).hexdigest()

    for user in users:
        if user["username"] == username:
            if user["password"] == hashed:
                user["token"] = secrets.token_hex(16)
                save_users(users)
                print("Access granted")
                print("Session token:", user["token"])
            else:
                print("Wrong password")
            return
    print("User not found")


def check_session():
    users = load_users()
    token = input("Token: ").strip()

    for user in users:
        if user.get("token") == token:
            print("Session valid for:", user["username"])
            return
    print("Session invalid")


def logout():
    users = load_users()
    token = input("Token: ").strip()

    for user in users:
        if user.get("token") == token:
            user["token"] = None
            save_users(users)
            print("Logged out")
            return
    print("Invalid token")


while True:
    print("\n1 - Register")
    print("2 - Login")
    print("3 - Check session")
    print("4 - Logout")
    print("5 - Exit")

    option = input("Choose: ")

    if option == "1":
        register()
    elif option == "2":
        login()
    elif option == "3":
        check_session()
    elif option == "4":
        logout()
    elif option == "5":
        break
