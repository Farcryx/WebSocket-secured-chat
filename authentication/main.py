from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from AuthenticationManager import AuthenticationManager
from encryption_module import EncryptionModule
from console_logger import logger
from requests_endpoints import signin_request, signup_request

app = FastAPI()
auth_manager = AuthenticationManager(logger=logger)

# Define request models for validation
class ConnectionRequest(BaseModel):
    sender: str
    client_public_key: str
    prime: str
    generator: str

class AuthenticationRequest(BaseModel):
    sender: str
    nonce: str
    encrypted: str
    tag: str

class SignInRequest(BaseModel):
    sender: str
    username: str
    password: str

class SignUpRequest(BaseModel):
    username: str
    password: str

class AddClientRequest(BaseModel):
    sender: str
    username: str
    session_key: str
    nonce: str

class EncryptMessageRequest(BaseModel):
    sender: str
    message: str

class SetDMRecipientRequest(BaseModel):
    sender: str
    recipient: str

@app.post("/connection")
async def handle_connection_request(request: ConnectionRequest):
    message = auth_manager.init_connection_for_client(
        request.sender, request.client_public_key, request.prime, request.generator
    )
    return {"message": message}

@app.post("/authenticate")
async def handle_authentication_request(request: AuthenticationRequest):
    session_key = auth_manager.get_session_key(request.sender)
    decrypted_session_key = EncryptionModule.decrypt_AES(
        session_key, request.nonce, request.encrypted, request.tag
    )
    if session_key.upper() == decrypted_session_key.upper():
        auth_manager.set_authenticated_client(request.sender)
        return {"status": "success", "message": "Connected to the server successfully."}
    else:
        raise HTTPException(status_code=401, detail="Authentication failed.")

@app.post("/signin")
async def handle_signin_request(request: SignInRequest):
    if auth_manager.check_if_username_logged(request.username):
        message = f"SIGNIN_FAIL: User {request.username} is already logged in."
    else:
        auth_manager.signin_client(request.sender, request.username)
        message = signin_request(request.username, request.password)
    return {"message": message}

@app.post("/signup")
async def handle_signup_request(request: SignUpRequest):
    message = signup_request(request.username, request.password)
    return {"message": message}

@app.get("/clients")
async def get_clients():
    clients = auth_manager.get_list_of_clients()
    return {"clients": clients}

@app.post("/add_client")
async def add_client(request: AddClientRequest):
    auth_manager.add_client(request.sender, request.username, request.session_key, request.nonce)
    return {"status": "success", "message": f"Client {request.sender} added successfully."}

@app.get("/session_key/{sender}")
async def get_session_key(sender: str):
    session_key = auth_manager.get_session_key(sender)
    if session_key:
        return {"session_key": session_key}
    else:
        raise HTTPException(status_code=404, detail="Session key not found.")

@app.get("/username/{sender}")
async def get_username(sender: str):
    username = auth_manager.get_username(sender)
    return {"username": username}

@app.get("/is_logged/{sender}")
async def get_client_logged(sender: str):
    logged = auth_manager.get_client_logged(sender)
    return {"logged": logged}

@app.post("/set_authenticated")
async def set_authenticated_client(sender: str):
    auth_manager.set_authenticated_client(sender)
    return {"status": "success", "message": f"Client {sender} authenticated successfully."}

@app.get("/is_username_logged/{username}")
async def check_if_username_logged(username: str):
    logged = auth_manager.check_if_username_logged(username)
    return {"logged": logged}

@app.post("/encrypt_message")
async def encrypt_message(request: EncryptMessageRequest):
    encrypted_message = auth_manager.encrypt_message(request.sender, request.message)
    if encrypted_message:
        return {"encrypted_message": encrypted_message}
    else:
        raise HTTPException(status_code=404, detail="Sender not found.")

@app.get("/sender_by_username/{username}")
async def get_sender_by_username(username: str):
    sender = auth_manager.get_sender_by_username(username)
    if sender:
        return {"sender": sender}
    else:
        raise HTTPException(status_code=404, detail="Sender not found.")

@app.get("/nonce/{sender}")
async def get_nonce(sender: str):
    nonce = auth_manager.get_nonce(sender)
    if nonce:
        return {"nonce": nonce}
    else:
        raise HTTPException(status_code=404, detail="Nonce not found.")

@app.post("/set_dm_recipient")
async def set_dm_recipient(request: SetDMRecipientRequest):
    auth_manager.set_dm_recipient(request.sender, request.recipient)
    return {"status": "success", "message": f"DM recipient for {request.sender} set to {request.recipient}."}