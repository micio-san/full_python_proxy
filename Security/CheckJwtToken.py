from dotenv import load_dotenv
import os
import jwt
from jwt import InvalidTokenError, ExpiredSignatureError
from logConf import logger

# Load environment variables
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# expects SimpleHTTPRequestHandler
def checkJwt(handler):
    auth_header = handler.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]  # "Bearer " is 7 characters
        try:
            # Decode JWT
            payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
            logger.info(f"JWT verified for subject: {payload.get('sub')}")
            return True
        except ExpiredSignatureError:
            logger.warning("JWT token expired")
            return False
        except InvalidTokenError:
            logger.warning("Invalid JWT token")
            return False
    else:
        logger.warning("Missing Authorization header or not Bearer token")
        return False
