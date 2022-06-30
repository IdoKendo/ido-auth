import sys

import uvicorn
from fastapi import FastAPI
from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from ido_auth.registration.exceptions import UnverifiedException
from ido_auth.registration.routes import registration_app
from loguru import logger

logger.add("./ido_auth.log", rotation="500 MB", level="INFO")
logger.add(sys.stderr, format="{time} {level} {message}", level="INFO")

app = FastAPI(title="Ido Auth API", description="Use WebAuth with web API", version="0.0.1")

app.include_router(registration_app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(UnverifiedException)
async def unverified_exception_handler(_: Request, exc: UnverifiedException):
    return JSONResponse(
        status_code=400,
        content={"verified": "false", "msg": exc.err},
    )


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, log_level="info", reload=True, proxy_headers=True, lifespan="on")
