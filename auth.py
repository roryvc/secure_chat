"""
auth.py - User authentication module.

Handles user sign-up, login, and credential storage using bcrypt and a JSON file database.
"""

import json
import bcrypt
import os

USER_DB = "users.json"

def load_users():
    """
    Loads user credentials from the local JSON database.

    Returns:
        dict: A dictionary mapping usernames to hashed passwords.
    """
    if not os.path.exists(USER_DB):
        return {}
    with open(USER_DB, 'r') as f:
        return json.load(f)

def save_users(users):
    """
    Saves user credentials to the local JSON database.

    Args:
        users (dict): A dictionary mapping usernames to hashed passwords.
    """
    with open(USER_DB, 'w') as f:
        json.dump(users, f)

def signup(username, password):
    """
    Registers a new user with a hashed password.

    Args:
        username (str): The desired username.
        password (str): The plaintext password.

    Returns:
        tuple: (bool, str) where the boolean indicates success, and the string is a status message.
    """
    users = load_users()
    if username in users:
        return False, "Username already exists."

    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = hashed_pw
    save_users(users)
    return True, "Sign-up successful."

def login(username, password):
    """
    Authenticates a user by verifying the password against the stored hash.

    Args:
        username (str): The username to authenticate.
        password (str): The plaintext password entered by the user.

    Returns:
        tuple: (bool, str) where the boolean indicates success, and the string is a status message.
    """
    users = load_users()
    if username not in users:
        return False, "User not found."

    hashed_pw = users[username].encode()
    if bcrypt.checkpw(password.encode(), hashed_pw):
        return True, "Login successful."
    else:
        return False, "Incorrect password."

def run():
    """
    Prompts the user to either sign up or log in via console input.

    Returns:
        tuple: (bool, str, str) containing:
            - success (bool): Whether authentication was successful.
            - message (str): Status message.
            - username (str): The entered username.
    """
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

    return success, message, username

if __name__ == "__main__":
    run()