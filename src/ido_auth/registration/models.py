from pydantic import BaseModel
from webauthn.helpers.structs import AuthenticatorTransport


class UsernameRequest(BaseModel):
    username: str


class RegisterVerificationRequest(BaseModel):
    username: str
    id: str
    rawId: str
    response: dict[str, str]
    type: str
    clientExtensionResults: dict
    transports: list[str]


class LoginVerificationRequest(BaseModel):
    username: str
    id: str
    rawId: str
    response: dict[str, str]
    type: str
    clientExtensionResults: dict


class Credential(BaseModel):
    id: bytes
    public_key: bytes
    sign_count: int
    transports: list[AuthenticatorTransport] | None = None
