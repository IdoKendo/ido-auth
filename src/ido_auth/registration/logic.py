import json
import uuid
from typing import Any

from fastapi import HTTPException
from fastapi import status
from ido_auth.registration.exceptions import UnverifiedException
from ido_auth.registration.models import Credential
from ido_auth.registration.models import LoginVerificationRequest
from ido_auth.registration.models import RegisterVerificationRequest
from webauthn import generate_authentication_options
from webauthn import generate_registration_options
from webauthn import options_to_json
from webauthn import verify_authentication_response
from webauthn import verify_registration_response
from webauthn.authentication.verify_authentication_response import VerifiedAuthentication
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import AuthenticationCredential
from webauthn.helpers.structs import AuthenticatorSelectionCriteria
from webauthn.helpers.structs import PublicKeyCredentialDescriptor
from webauthn.helpers.structs import RegistrationCredential
from webauthn.helpers.structs import UserVerificationRequirement
from webauthn.registration.verify_registration_response import VerifiedRegistration

rp_name = "Local Host"
rp_id = "localhost"
origin = "http://localhost:8000"
current_challenges: dict[str, bytes] = {}
users_credentials: dict[str, list[Credential]] = {}


def generate_options(username: str) -> dict[str, Any]:
    user_id = str(uuid.uuid4())
    challenge = str(uuid.uuid4()).encode()
    options = generate_registration_options(
        rp_name=rp_name,
        rp_id=rp_id,
        user_id=user_id,
        user_name=username,
        user_display_name=username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        challenge=challenge,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=challenge),
        ],
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
    )
    current_challenges[username] = options.challenge

    options = json.loads(options_to_json(options))

    return options


def verify_user(verification_request: RegisterVerificationRequest) -> VerifiedRegistration:
    username = verification_request.username
    current_challenge = current_challenges.get(username)
    body = {k: v for k, v in verification_request.dict().items() if k not in ("user_id", "username")}

    try:
        credential = RegistrationCredential.parse_raw(json.dumps(body))
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=current_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=True,
        )
    except Exception as err:
        raise UnverifiedException(str(err))
    else:
        new_credential = Credential(
            id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            transports=body.get("transports", []),
        )
        if not users_credentials.get(username):
            users_credentials[username] = []

        users_credentials[username].append(new_credential)
        return verification


def login_user(username: str):
    credentials = users_credentials.get(username)
    challenge = str(uuid.uuid4()).encode()

    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"User {username} is not registered!")

    options = generate_authentication_options(
        rp_id=rp_id,
        challenge=challenge,
        allow_credentials=[PublicKeyCredentialDescriptor(id=p.id, transports=p.transports) for p in credentials],
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    current_challenges[username] = options.challenge
    options = options_to_json(options)

    return json.loads(options)


def verify_user_login(verification_request: LoginVerificationRequest) -> VerifiedAuthentication:
    username = verification_request.username
    current_challenge = current_challenges.get(username)
    user_credentials = users_credentials.get(username)
    verification = {k: v for k, v in verification_request.dict().items() if k not in ("user_id", "username")}

    try:
        credential = AuthenticationCredential.parse_raw(json.dumps(verification))
        final_credential = None
        for user_credential in user_credentials:
            if credential.raw_id == user_credential.id:
                final_credential = user_credential
        if final_credential is None:
            raise Exception(f"No corresponding public key for {username}")
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=current_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=final_credential.public_key,
            credential_current_sign_count=final_credential.sign_count,
            require_user_verification=True,
        )
    except Exception as err:
        raise UnverifiedException(str(err))
    else:
        final_credential.sign_count = verification.new_sign_count
        return verification
