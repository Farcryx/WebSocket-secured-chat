import requests

def get_username(sender: tuple) -> str:
    """Get username of user."""
    url = f"http://authentication:5001/username/{sender}"
    try:
        response = requests.get(url)
        response_data = response.json()
        username = response_data.get('username', 'Unknown')
    except Exception as e:
        # logger.error(f"Error communicating with authentication service: {e}")
        username = "Unknown"
    return username

def get_clients() -> dict:
    """Get list of clients"""
    url = "http://authentication:5001/clients"
    try:
        response = requests.get(url)
        response_data = response.json()
        clients = response_data.get('clients', {})
    except Exception as e:
        clients = {}
    return clients

def get_session_key(sender: str) -> str:
    """Get session key of user"""
    url = f"http://authentication:5001/session_key/{sender}"
    try:
        response = requests.get(url)
        response_data = response.json()
        session_key = response_data.get('session_key', 'Error: No session key found.')
    except Exception as e:
        session_key = f"Error: Unable to retrieve session key. {e}"
    return session_key

def get_sender_by_username(username: str) -> str:
    """Get sender by username"""
    url = f"http://authentication:5001/sender_by_username/{username}"
    try:
        response = requests.get(url)
        response_data = response.json()
        sender = response_data.get('sender', 'Error: No sender found.')
    except Exception as e:
        sender = f"Error: Unable to retrieve sender. {e}"
    return sender

def set_dm_recipient(sender: str, recipient: str) -> str:
    """Set direct message recipient"""
    url = "http://authentication:5001/set_dm_recipient"
    data = {"sender": sender, "recipient": recipient}
    try:
        response = requests.post(url, json=data)
        response_data = response.json()
        message = response_data.get('message', 'Error: No response from authentication service.')
    except Exception as e:
        message = f"Error: Unable to set DM recipient. {e}"
    return message

def get_nonce(sender: str) -> str:
    """Get nonce of user"""
    url = f"http://authentication:5001/nonce/{sender}"
    try:
        response = requests.get(url)
        response_data = response.json()
        nonce = response_data.get('nonce', 'Error: No nonce found.')
    except Exception as e:
        nonce = f"Error: Unable to retrieve nonce. {e}"
    return nonce