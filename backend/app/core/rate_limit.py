from slowapi import Limiter
from app.core.security import rate_limit_identity
limiter = Limiter(key_func=rate_limit_identity)
