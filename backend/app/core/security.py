import hashlib
import secrets
from fastapi import Header, Request
from app.core.exceptions import ETISException
from app.core.settings import settings

class AuthenticationError(ETISException):
    pass
def verify_api_key(x_api_key: str | None = Header(default=None)):
    if settings.api_key and not secrets.compare_digest(x_api_key or '', settings.api_key):
        raise AuthenticationError('authentication_required')
def rate_limit_identity(request: Request):
    # Never trust a browser-supplied session header without the proxy's key.
    key = request.headers.get('x-api-key', '')
    if settings.api_key and secrets.compare_digest(key, settings.api_key):
        session = request.headers.get('x-etis-session', '') or key
        return hashlib.sha256(session.encode()).hexdigest()
    return request.client.host if request.client else 'local'
