"""API with component-aware health; one missing engine cannot mask a partial scan."""
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import SQLAlchemyError
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.core.database import SessionLocal
from app.core.settings import settings
from app.core.rate_limit import limiter
from app.core.exceptions import ETISException, InvalidScanInputError
from app.core.security import AuthenticationError
import app.models
from app.routers import analyze, threats, stats
import logging

app = FastAPI(title='ETIS', version='0.2.0')
@app.middleware('http')
async def private_failures(request, call_next):
    try:return await call_next(request)
    except Exception:
        logging.getLogger(__name__).warning('request_failed')
        return JSONResponse(status_code=503,content={'error':'ServiceUnavailable','detail':'service_unavailable'})
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
if settings.cors_origins:
    app.add_middleware(CORSMiddleware, allow_origins=list(settings.cors_origins), allow_methods=['GET','POST'], allow_headers=['Content-Type','X-API-Key'])
app.include_router(analyze.router)
app.include_router(threats.router)
app.include_router(stats.router)

@app.exception_handler(ETISException)
async def etis_error(request, exc):
    status = 401 if isinstance(exc, AuthenticationError) else 400 if isinstance(exc, InvalidScanInputError) else 503
    return JSONResponse(status_code=status, content={'error': type(exc).__name__, 'detail': str(exc)})
@app.exception_handler(RequestValidationError)
async def validation_error(request, exc):
    # Pydantic's default errors include the original submitted input.
    return JSONResponse(status_code=400, content={'error': 'InvalidScanInputError', 'detail': 'invalid_input'})
@app.exception_handler(SQLAlchemyError)
async def database_error(request, exc):
    return JSONResponse(status_code=503, content={'error': 'ServiceUnavailable', 'detail': 'database_unavailable'})
@app.get('/')
def root():
    return {'service': 'ETIS', 'version': '0.2.0'}
@app.get('/health/live')
def live():
    return {'status': 'alive'}
@app.get('/health/ready')
def ready():
    from app.engines.threat_intel.blacklist_lookup import blacklist_health
    from app.engines.text_model import score_text
    try:
        with SessionLocal() as db:
            blacklist = blacklist_health(db)
    except Exception:
        blacklist = {'available': False, 'reason': 'database_unavailable'}
    try:
        score_text('اختبار')
        model = {'available': True, 'backend': settings.model_backend}
    except Exception:
        model = {'available': False, 'reason': 'text_model_unavailable'}
    usable = blacklist['available'] or model['available']
    status = 'ready' if blacklist['available'] and model['available'] else 'degraded' if usable else 'unavailable'
    return JSONResponse(status_code=200 if usable else 503, content={'status': status, 'blacklist': blacklist, 'text_model': model})
