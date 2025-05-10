import json
import hashlib as hash

def sign_up(username: str, password: str) -> str:
    """
    Registers a new user by adding their credentials to the clients.json file.
    If the username already exists, it returns a failure message.
    Args:
        username (str): The username of the user.
        password (str): The password of the user.
    Returns:
        str: A message indicating the result of the signup attempt.
    """
    try:
        # Load existing data if the file exists
        try:
            with open("clients.json", "r") as f:
                users = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            users = []

        # Check if the username already exists
        for user in users:
            if user["username"] == username:
                print(f"SIGNUP_FAIL: Username '{username}' already exists.")
                return f"SIGNUP_FAIL: Username '{username}' already exists."

        # Add the new user
        users.append({
            "username": username, 
            "password": hash.sha256(password.encode()).hexdigest()
            })

        # Write the updated list back to the file
        with open("clients.json", "w") as f:
            json.dump(users, f, indent=4)
            print(f"SIGNUP_OK: {username}")
            return f"SIGNUP_OK: {username}"
    except Exception as e:
        print(f"SIGNUP_FAIL: {e}")
        return f"SIGNUP_FAIL: {e}"
    
def sign_in(username: str, password: str) -> str:
    """
    Checks if the provided username and password match the stored credentials.
    Args:
        username (str): The username of the user.
        password (str): The password of the user.
    """
    try:
        with open("clients.json", "r") as f:
            users = json.load(f)
            for user in users:
                if user["username"] == username and (user["password"] == hash.sha256(password.encode()).hexdigest()):
                    print(f"SIGNIN_OK: {username}")
                    return f"SIGNIN_OK: {username}"
            print(f"SIGNIN_FAIL: Invalid credentials.")
            return f"SIGNIN_FAIL: Invalid credentials."
    except Exception as e:
        print(f"SIGNIN_FAIL: {e}")
        return f"SIGNIN_FAIL: {e}"