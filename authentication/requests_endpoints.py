import requests
from console_logger import logger

def signin_request(username: str, password: str) -> str:
    """Handles the signin request by delegating to the authentication microservice."""
    url = "http://credentials:5002/signin"  # Replace with the actual URL of the authentication microservice
    payload = {
        "username": username,
        "password": password
    }
    try:
        logger.debug(f"Payload for /signin: {payload}")
        response = requests.post(url, json=payload)
        response_data = response.json()
        message = response_data.get('message', 'Error: No response from authentication service.')
    except Exception as e:
        logger.error(f"SIGNIN_FAIL: Error communicating with authentication service: {e}")
        message = "SIGNIN_FAIL: Unable to process signin request."
    logger.debug(f"Message from signin service: \n{message}")
    return message

def signup_request(username: str, password: str) -> str:
    """Handles the signup request by delegating to the authentication microservice."""
    url = "http://credentials:5002/signup"  # Replace with the actual URL of the authentication microservice
    payload = {
        "username": username,
        "password": password
    }
    try:
        logger.debug(f"Payload for /signup: {payload}")
        response = requests.post(url, json=payload)
        response_data = response.json()
        message = response_data.get('message', 'Error: No response from authentication service.')
    except Exception as e:
        logger.error(f"SIGNUP_FAIL: Error communicating with authentication service: {e}")
        message = "SIGNUP_FAIL: Unable to process signup request."
    logger.debug(f"Message from signup service: \n{message}")
    return message
