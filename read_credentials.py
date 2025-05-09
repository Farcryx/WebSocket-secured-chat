def load_server_credentials() -> tuple:
    """
    Loads the server credentials from a server.json file.
    Returns:
        tuple: The server address and port.
    """
    try:
        with open("server.json", "r") as f:
            data = f.read()
            server_address = data.split('"address": "')[1].split('"')[0]
            server_port = int(data.split('"port": ')[1].split('}')[0])
            return server_address, server_port
    except FileNotFoundError:
        print("Server credentials file not found.")
        return None, None