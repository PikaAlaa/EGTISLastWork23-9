from __future__ import annotations

from fastapi import Request
from fastapi.responses import JSONResponse


class ETISException(Exception):
    status_code = 400
    code = "etis_error"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class InvalidAnalysisInput(ETISException):
    status_code = 422
    code = "invalid_analysis_input"


async def etis_exception_handler(_: Request, exc: ETISException) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": {"code": exc.code, "message": exc.message}})
