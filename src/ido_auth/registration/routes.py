from typing import Any

from fastapi import APIRouter
from fastapi import Request
from ido_auth.registration.logic import generate_options
from ido_auth.registration.logic import login_user
from ido_auth.registration.logic import verify_user
from ido_auth.registration.logic import verify_user_login
from ido_auth.registration.models import LoginVerificationRequest
from ido_auth.registration.models import RegisterVerificationRequest
from ido_auth.registration.models import UsernameRequest
from loguru import logger

registration_app = APIRouter()


@registration_app.post("/register", status_code=200)
async def register(
    request: Request,
    registration_request: UsernameRequest,
) -> dict[str, str | dict[str, Any]]:
    logger.info(f"Registration request received from {request.client.host}: {registration_request=}")
    options = generate_options(registration_request.username)
    return {"status": "OK", "options": options}


@registration_app.post("/verify-register", status_code=200)
async def verify_registration(
    request: Request,
    verification_request: RegisterVerificationRequest,
) -> dict[str, bool]:
    logger.info(f"Register verification request received from {request.client.host}: {verification_request=}")
    verify_user(verification_request)
    return {"verified": True}


@registration_app.post("/login", status_code=200)
async def login(
    request: Request,
    login_request: UsernameRequest,
) -> dict[str, str | dict[str, Any]]:
    logger.info(f"Login request received from {request.client.host}: {login_request=}")
    options = login_user(login_request.username)
    return {"status": "OK", "options": options}


@registration_app.post("/verify-login", status_code=200)
async def verify_login(
    request: Request,
    verification_request: LoginVerificationRequest,
) -> dict[str, bool]:
    logger.info(f"Login verification request received from {request.client.host}: {verification_request=}")
    verify_user_login(verification_request)
    return {"verified": True}
