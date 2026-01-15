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
        "token": None,
        "reset_token": None
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

def forgot_password():
        users = load_users()
        username = input("Username: ")

        for user in users:
            if user["username"] == username:
                reset = secrets.token_hex(8)
                user["reset_token"] = reset
                save_users(users)
                print("Reset token:", reset)
                break
        else:
            print("User not found")
            return

        reset_token = input("Enter reset token: ").strip()

        for user in users:
            if user.get("reset_token") == reset_token:
                new_pass = input("Enter new password: ")
                user["password"] = hashlib.sha256(new_pass.encode()).hexdigest()
                save_users(users)
                print("Password changed")
                return

        print("Invalid reset token")

while True:
    print("\n1 - Register")
    print("2 - Login")
    print("3 - Check session")
    print("4 - Logout")
    print("5 - Forgot password")
    print("6 - Exit")

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
        forgot_password()
    elif option == "6":
        break
