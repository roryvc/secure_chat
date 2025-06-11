import json
import bcrypt
import os

USER_DB = "users.json"

def load_users():
    if not os.path.exists(USER_DB):
        return {}
    with open(USER_DB, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USER_DB, 'w') as f:
        json.dump(users, f)

def signup(username, password):
    users = load_users()
    if username in users:
        return False, "Username already exists."

    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = hashed_pw
    save_users(users)
    return True, "Sign-up successful."

def login(username, password):
    users = load_users()
    if username not in users:
        return False, "User not found."

    hashed_pw = users[username].encode()
    if bcrypt.checkpw(password.encode(), hashed_pw):
        return True, "Login successful."
    else:
        return False, "Incorrect password."

def run():
    print("Welcome! Please select:")
    print("1 - Sign Up")
    print("2 - Login")
    choice = input("Enter choice: ")

    username = input("Username: ")
    password = input("Password: ")

    if choice == '1':
        success, message = signup(username, password)
    elif choice == '2':
        success, message = login(username, password)
    else:
        message = "Invalid choice"
        success = False

    return success, message

if __name__ == "__main__":
    run()