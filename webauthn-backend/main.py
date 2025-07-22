from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    RegistrationCredential,
    AuthenticationCredential,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from pydantic import BaseModel
from typing import Optional, List
from dotenv import load_dotenv
import os
import base64
from database import users_collection
from models import User, Credential
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

load_dotenv()

app = FastAPI()

# Configure CORS to allow Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("ORIGIN", "http://localhost:5173")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


RP_ID = os.getenv("RP_ID", "localhost")
RP_NAME = os.getenv("RP_NAME", "My Biometric App")
ORIGIN = os.getenv("ORIGIN", "http://localhost:5173")


class RegisterRequest(BaseModel):
    email: str


class RegisterVerifyRequest(BaseModel):
    email: str
    response: dict
    challenge: str


class AuthRequest(BaseModel):
    email: str


class AuthVerifyRequest(BaseModel):
    email: str
    response: dict
    challenge: str


@app.post("/api/register/options")
async def register_options(request: RegisterRequest):
    user = await users_collection.find_one({"email": request.email})
    print(f"{user = }")

    if not user:
        print(f"{user = }")

        user = {"email": request.email, "credentials": []}
        await users_collection.insert_one(user)

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user["_id"].binary,
        user_name=request.email,
        user_display_name=request.email,
        attestation="none",
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED,
            resident_key=ResidentKeyRequirement.PREFERRED,
        ),
        supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256],
        exclude_credentials=[
            {"id": cred["credential_id"], "type": "public-key"}
            for cred in user["credentials"]
        ],
    )

    print(f"{options = }")

    # Store challenge in database
    await users_collection.update_one(
        {"email": request.email}, {"$set": {"challenge": options.challenge}}
    )

    # Convert options to JSON-compatible dict
    options_dict = {
        "rp": {"id": options.rp.id, "name": options.rp.name},
        "user": {
            "id": bytes_to_base64url(options.user.id),
            "name": options.user.name,
            "displayName": options.user.display_name,
        },
        "challenge": bytes_to_base64url(options.challenge),
        "pubKeyCredParams": [
            {"type": param.type, "alg": param.alg.value}
            for param in options.pub_key_cred_params
        ],
        "timeout": options.timeout,
        "attestation": options.attestation,
        "authenticatorSelection": {
            "userVerification": options.authenticator_selection.user_verification,
            "residentKey": options.authenticator_selection.resident_key,
        },
        "excludeCredentials": [
            {"id": bytes_to_base64url(cred.id), "type": cred.type}
            for cred in options.exclude_credentials
        ],
    }

    return options_dict


@app.post("/api/register/verify")
async def register_verify(request: RegisterVerifyRequest):
    user = await users_collection.find_one({"email": request.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        # Parse the client response manually
        response = request.response
        credential = RegistrationCredential(
            id=response["id"],
            raw_id=base64url_to_bytes(response["rawId"]),
            response=AuthenticatorAttestationResponse(
                client_data_json=base64url_to_bytes(
                    response["response"]["clientDataJSON"]
                ),
                attestation_object=base64url_to_bytes(
                    response["response"]["attestationObject"]
                ),
            ),
            type=response["type"],
        )
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=base64url_to_bytes(request.challenge),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
        )

    except Exception as e:
        print(f"{e = }")
        raise HTTPException(status_code=400, detail=f"Verification failed: {str(e)}")

    if verification.credential_id:
        credential_data = {
            "credential_id": verification.credential_id,
            "public_key": verification.credential_public_key,
            "counter": verification.sign_count,
        }
        await users_collection.update_one(
            {"email": request.email}, {"$push": {"credentials": credential_data}}
        )
        return {"verified": True}

    raise HTTPException(status_code=400, detail="Verification failed")


@app.post("/api/auth/options")
async def auth_options(request: AuthRequest):
    user = await users_collection.find_one({"email": request.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[
            {"id": cred["credential_id"], "type": "public-key"}
            for cred in user["credentials"]
        ],
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    # Store challenge in database
    await users_collection.update_one(
        {"email": request.email},
        {"$set": {"challenge": bytes_to_base64url(options.challenge)}},
    )

    print(
        [
            {"id": bytes_to_base64url(cred.get("id")), "type": cred.get("type")}
            for cred in options.allow_credentials
        ]
    )

    # Convert options to JSON-compatible dict
    options_dict = {
        "challenge": bytes_to_base64url(options.challenge),
        "allowCredentials": [
            {"id": bytes_to_base64url(cred.get("id")), "type": cred.get("type")}
            for cred in options.allow_credentials
        ],
        "userVerification": options.user_verification,
        "timeout": options.timeout,
    }

    return options_dict


@app.post("/api/auth/verify")
async def auth_verify(request: AuthVerifyRequest):
    user = await users_collection.find_one({"email": request.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    credential = next(
        (
            cred
            for cred in user["credentials"]
            if cred["credential_id"] == base64url_to_bytes(request.response["id"])
        ),
        None,
    )
    if not credential:
        raise HTTPException(status_code=404, detail="Credential not found")

    try:
        # Parse the client response manually
        response = request.response
        auth_credential = AuthenticationCredential(
            id=response["id"],
            raw_id=base64url_to_bytes(response["rawId"]),
            response=AuthenticatorAssertionResponse(
                client_data_json=base64url_to_bytes(
                    response["response"]["clientDataJSON"]
                ),
                authenticator_data=base64url_to_bytes(
                    response["response"]["authenticatorData"]
                ),
                signature=base64url_to_bytes(response["response"]["signature"]),
                user_handle=(
                    base64url_to_bytes(response["response"].get("userHandle"))
                    if response["response"].get("userHandle")
                    else None
                ),
            ),
            type=response["type"],
        )
        verification = verify_authentication_response(
            credential=auth_credential,
            expected_challenge=base64url_to_bytes(request.challenge),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=credential["public_key"],
            credential_current_sign_count=credential["counter"],
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Verification failed: {str(e)}")

    if verification:
        # Update counter
        await users_collection.update_one(
            {
                "email": request.email,
                "credentials.credential_id": credential["credential_id"],
            },
            {"$set": {"credentials.$.counter": verification.new_sign_count}},
        )
        return {"verified": True}

    raise HTTPException(status_code=400, detail="Verification failed")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
