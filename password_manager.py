import bcrypt
import getpass
import re
import time

USER_FILE = "users.txt"
LOCK_FILE = "locked_users.txt"
MAX_ATTEMPTS = 3
LOCK_TIME = 30  # in seconds

# -----------------------------------
def check_password_strength(password):
    if (len(password) < 8 or not re.search(r"[A-Z]", password)
        or not re.search(r"[a-z]", password)
        or not re.search(r"[0-9]", password)
        or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        return False
    return True

def is_locked(username):
    try:
        with open(LOCK_FILE, 'r') as f:
            for line in f:
                name, timestamp = line.strip().split(",")
                if name == username:
                    if time.time() - float(timestamp) < LOCK_TIME:
                        return True
        return False
    except FileNotFoundError:
        return False

def lock_user(username):
    with open(LOCK_FILE, "a") as f:
        f.write(f"{username},{time.time()}\n")

# -----------------------------------
def register_user():
    username = input("Enter username: ")

    while True:
        password = getpass.getpass("Enter password: ")
        if not check_password_strength(password):
            print("❌ Weak password. Must be at least 8 characters with uppercase, lowercase, number, and symbol.")
            continue
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("❌ Passwords do not match.")
            continue
        break

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    with open(USER_FILE, "a") as f:
        f.write(f"{username},{hashed.decode()}\n")

    print("✅ User registered successfully!")

# -----------------------------------
def verify_user():
    username = input("Enter username: ")

    if is_locked(username):
        print(f"⛔ Account temporarily locked. Try again after {LOCK_TIME} seconds.")
        return

    attempts = 0
    with open(USER_FILE, "r") as f:
        users = dict(line.strip().split(",") for line in f)

    if username not in users:
        print("❌ Username not found.")
        return

    while attempts < MAX_ATTEMPTS:
        password = getpass.getpass("Enter password: ")
        if bcrypt.checkpw(password.encode(), users[username].encode()):
            print("✅ Password match! Access granted.")
            return
        else:
            attempts += 1
            print(f"❌ Wrong password. Attempts left: {MAX_ATTEMPTS - attempts}")

    print("⛔ Too many failed attempts. Account locked.")
    lock_user(username)

# -----------------------------------
def main():
    while True:
        print("\n🔐 Secure Password Manager")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            register_user()
        elif choice == '2':
            verify_user()
        elif choice == '3':
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid option.")

if __name__ == "__main__":
    main()

