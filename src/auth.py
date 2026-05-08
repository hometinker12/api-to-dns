import os
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from fastapi import HTTPException, Request

SECRET_KEY = os.getenv("SECRET_KEY", "please-change-this-secret")
serializer = URLSafeTimedSerializer(SECRET_KEY, salt="session-cookie")


def create_session_cookie(username: str) -> str:
    return serializer.dumps(username)


def verify_session_cookie(token: str) -> str:
    return serializer.loads(token, max_age=86400)


def get_current_user(request: Request) -> str:
    session_token = request.cookies.get("session")
    if not session_token:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        return verify_session_cookie(session_token)
    except (BadSignature, SignatureExpired):
        raise HTTPException(status_code=401, detail="Invalid or expired session")
