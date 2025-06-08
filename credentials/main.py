from fastapi import FastAPI
from pydantic import BaseModel
from console_logger import logger
from sign_ip_in import sign_up, sign_in

app = FastAPI()

# Define request models for validation
class SignInRequest(BaseModel):
    username: str
    password: str

class SignUpRequest(BaseModel):
    username: str
    password: str

@app.post("/signup")
async def handle_sign_up(request: SignUpRequest):
    """
    Handle user sign-up requests.
    """
    result = sign_up(request.username, request.password)
    if result == "SIGNUP_OK":
        logger.info(f"User {request.username} signed up successfully.")
    else:
        logger.error(f"Sign-up failed for user {request.username}.")

    return {"message": result}

@app.post("/signin")
async def handle_sign_in(request: SignInRequest):
    """
    Handle user sign-in requests.
    """
    result = sign_in(request.username, request.password)
    if result == "SIGNIN_OK":
        logger.info(f"User {request.username} signed in successfully.")
    else:
        logger.error(f"Sign-in failed for user {request.username}.")
    
    return {"message": result}