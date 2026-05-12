import base64
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import jwt
import ocivault
import requests
from fdk import response
from jwt import PyJWKClient


logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger("entra-oic-authorizer")

# These values are cached inside the warm function container.
# FUNCTION_CONFIG_CACHE_SECONDS controls how often config and Vault secret are refreshed.
FUNCTION_CONFIG: Dict[str, str] = {}
FUNCTION_CONFIG_LOADED_AT = 0.0
OCI_IAM_CLIENT_SECRET: Optional[str] = None
OCI_IAM_CLIENT_SECRET_LOADED_AT = 0.0
OIDC_METADATA: Optional[Dict[str, Any]] = None
OIDC_METADATA_EXPIRES_AT = 0.0
JWK_CLIENT: Optional[PyJWKClient] = None
DEFAULT_FUNCTION_CONFIG_CACHE_SECONDS = 300

# Placeholders are useful in func.yaml, but the function should never use them.
PLACEHOLDER_PREFIXES = ("<", "CHANGE_ME", "TODO")


class AuthError(Exception):
    """Raised when the request should be denied by API Gateway."""


def handler(ctx, data=None):
    """OCI Functions entry point used by API Gateway custom authorizer."""
    try:
        LOGGER.info("Authorizer invocation started")
        initialize_function(ctx)

        # API Gateway sends the authorizer token/arguments as JSON in `data`.
        # The Fn `ctx` object is used for function config, not for the caller token.
        authorizer_payload = read_authorizer_payload(data)
        entra_token = read_entra_token_from_gateway_payload(authorizer_payload)

        # Validate the Microsoft Entra token before minting any OCI token.
        entra_claims = validate_entra_token(entra_token)

        # OIC does not trust the Entra token, so we generate an OCI IAM token.
        oci_access_token = get_oci_iam_access_token()

        # API Gateway stores response context values under request.auth[...].
        principal = entra_claims.get("azp") or entra_claims.get("appid") or entra_claims.get("sub")
        authorizer_response = build_allow_response(principal, entra_claims, oci_access_token)
        LOGGER.info(
            "Authorizer invocation completed successfully principal=%s response_context_keys=%s",
            mask_value(principal),
            sorted(authorizer_response["context"].keys()),
        )
        return json_response(ctx, authorizer_response)
    except AuthError as exc:
        LOGGER.warning("Authorization denied: %s", exc)
        return json_response(ctx, build_deny_response(str(exc)))
    except Exception:
        LOGGER.exception("Unexpected authorizer failure")
        return json_response(ctx, build_deny_response("unexpected_authorizer_error"))


def initialize_function(ctx) -> None:
    """Load Fn config and the OCI IAM client secret with a simple shared TTL."""
    global FUNCTION_CONFIG, FUNCTION_CONFIG_LOADED_AT, OCI_IAM_CLIENT_SECRET, OCI_IAM_CLIENT_SECRET_LOADED_AT

    now = time.time()
    current_context_config = dict(ctx.Config())
    cache_seconds = parse_cache_seconds(
        current_context_config.get("FUNCTION_CONFIG_CACHE_SECONDS") or os.getenv("FUNCTION_CONFIG_CACHE_SECONDS"),
        DEFAULT_FUNCTION_CONFIG_CACHE_SECONDS,
    )
    config_cache_expired = is_cache_expired(FUNCTION_CONFIG_LOADED_AT, cache_seconds, now)
    secret_cache_expired = is_cache_expired(OCI_IAM_CLIENT_SECRET_LOADED_AT, cache_seconds, now)

    if not FUNCTION_CONFIG or config_cache_expired:
        # Values from func.yaml config are available through ctx.Config().
        FUNCTION_CONFIG = current_context_config
        FUNCTION_CONFIG_LOADED_AT = now
        LOGGER.info(
            "Initialized function config keys=%s cache_seconds=%s",
            sorted(FUNCTION_CONFIG.keys()),
            cache_seconds,
        )
    else:
        LOGGER.info(
            "Using cached function config keys=%s cache_seconds=%s",
            sorted(FUNCTION_CONFIG.keys()),
            cache_seconds,
        )

    if OCI_IAM_CLIENT_SECRET is None or secret_cache_expired:
        # The real client secret is stored in OCI Vault, not in func.yaml.
        secret_ocid = required_config("OCI_IAM_CLIENT_SECRET_OCID")
        LOGGER.info("Loading OCI IAM client secret from Vault secret=%s", mask_value(secret_ocid))
        OCI_IAM_CLIENT_SECRET = ocivault.get_secret(secret_ocid)
        OCI_IAM_CLIENT_SECRET_LOADED_AT = now
        LOGGER.info("Loaded OCI IAM client secret from Vault cache_seconds=%s", cache_seconds)
    else:
        LOGGER.info("Using cached OCI IAM client secret from Vault cache_seconds=%s", cache_seconds)


def read_authorizer_payload(data) -> Dict[str, Any]:
    """Read the JSON payload that API Gateway passed to the authorizer function."""
    if data is None:
        LOGGER.info("Received empty authorizer payload")
        return {}

    raw_payload = data.read() if hasattr(data, "read") else data
    if not raw_payload:
        LOGGER.info("Received blank authorizer payload")
        return {}

    if isinstance(raw_payload, bytes):
        raw_payload = raw_payload.decode("utf-8")

    try:
        payload = json.loads(raw_payload)
        LOGGER.info(
            "Received authorizer payload type=%s top_level_keys=%s data_keys=%s",
            payload.get("type"),
            sorted(payload.keys()),
            sorted((payload.get("data") or {}).keys()),
        )
        return payload
    except json.JSONDecodeError as exc:
        raise AuthError("invalid_authorizer_payload") from exc


def read_entra_token_from_gateway_payload(payload: Dict[str, Any]) -> str:
    """Extract the Entra bearer token from OCI API Gateway authorizer input.

    OCI API Gateway supports two authorizer input styles:
    - Single argument: {"type": "TOKEN", "token": "<value>"}
    - Multi argument: {"type": "USER_DEFINED", "data": {"authorization": "<value>"}}

    For this project, configure the API Gateway authorizer argument to pass:
    request.headers[Authorization] -> authorization
    """
    token = payload.get("token")

    if not token:
        data = payload.get("data") or {}
        token = read_case_insensitive_value(data, "authorization")
        token = token or read_case_insensitive_value(data, "token")

    if not token:
        headers = payload.get("headers") or {}
        token = read_case_insensitive_value(headers, "authorization")

    if not token:
        raise AuthError("missing_authorization_token")

    if isinstance(token, list):
        token = token[0] if token else ""

    token = token.strip()
    LOGGER.info("Received authorization token token_length=%s bearer_prefix=%s", len(token), token.lower().startswith("bearer "))
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    if not token:
        raise AuthError("empty_bearer_token")

    LOGGER.info("Extracted Entra access token token_length=%s", len(token))
    return token


def validate_entra_token(token: str) -> Dict[str, Any]:
    """Validate signature, issuer, audience, tenant, and authorization claims."""
    tenant_id = required_config("ENTRA_TENANT_ID")
    audience = required_config("ENTRA_AUDIENCE")
    authority_host = optional_config("ENTRA_AUTHORITY_HOST", "https://login.microsoftonline.com").rstrip("/")
    expected_issuer = f"{authority_host}/{tenant_id}/v2.0"
    clock_skew_seconds = int(optional_config("JWT_LEEWAY_SECONDS", "60"))
    unverified_header = jwt.get_unverified_header(token)
    LOGGER.info(
        "Read Entra token header alg=%s kid=%s typ=%s",
        unverified_header.get("alg"),
        mask_value(unverified_header.get("kid")),
        unverified_header.get("typ"),
    )

    metadata = get_entra_oidc_metadata(authority_host, tenant_id)
    jwks_uri = metadata.get("jwks_uri")
    if not jwks_uri:
        raise AuthError("missing_jwks_uri")
    LOGGER.info("Using Entra JWKS URI %s", mask_url(jwks_uri))

    signing_key = get_jwk_client(jwks_uri).get_signing_key_from_jwt(token)
    LOGGER.info("Found public signing key for token kid=%s", mask_value(unverified_header.get("kid")))
    claims = jwt.decode(
        token,
        signing_key.key,
        algorithms=["RS256"],
        audience=audience,
        issuer=expected_issuer,
        leeway=clock_skew_seconds,
        options={"require": ["exp"]},
    )
    LOGGER.info(
        "Verified Entra token claims keys=%s tid=%s aud=%s client_id=%s roles=%s scopes_present=%s",
        sorted(claims.keys()),
        mask_value(claims.get("tid")),
        mask_value(claims.get("aud")),
        mask_value(claims.get("azp") or claims.get("appid")),
        mask_list(claims.get("roles") or []),
        bool(claims.get("scp")),
    )

    if claims.get("tid") != tenant_id:
        raise AuthError("invalid_tenant")
    LOGGER.info("Validated Entra tenant")

    client_id = claims.get("azp") or claims.get("appid")
    allowed_clients = csv_config("ENTRA_ALLOWED_CLIENT_IDS")
    if allowed_clients and client_id not in allowed_clients:
        raise AuthError("client_not_allowed")
    LOGGER.info("Validated Entra client id client_id=%s", mask_value(client_id))

    required_roles = csv_config("ENTRA_REQUIRED_ROLES")
    token_roles = claims.get("roles") or []
    if required_roles and not set(required_roles).issubset(set(token_roles)):
        raise AuthError("missing_required_role")
    LOGGER.info("Validated Entra roles required_roles=%s token_roles=%s", mask_list(required_roles), mask_list(token_roles))

    required_scopes = csv_config("ENTRA_REQUIRED_SCOPES")
    token_scopes = set((claims.get("scp") or "").split())
    if required_scopes and not set(required_scopes).issubset(token_scopes):
        raise AuthError("missing_required_scope")
    if required_scopes:
        LOGGER.info("Validated Entra scopes required_scopes=%s", mask_list(required_scopes))

    return claims


def get_entra_oidc_metadata(authority_host: str, tenant_id: str) -> Dict[str, Any]:
    """Download and cache Entra OIDC metadata, including the JWKS URI."""
    global OIDC_METADATA, OIDC_METADATA_EXPIRES_AT

    now = time.time()
    if OIDC_METADATA and now < OIDC_METADATA_EXPIRES_AT:
        LOGGER.info("Using cached Entra OIDC metadata")
        return OIDC_METADATA

    metadata_url = f"{authority_host}/{tenant_id}/v2.0/.well-known/openid-configuration"
    timeout = float(optional_config("HTTP_TIMEOUT_SECONDS", "10"))
    LOGGER.info("Fetching Entra OIDC metadata url=%s", mask_url(metadata_url))
    response_from_entra = requests.get(metadata_url, timeout=timeout)
    response_from_entra.raise_for_status()

    OIDC_METADATA = response_from_entra.json()
    cache_seconds = int(optional_config("ENTRA_JWKS_CACHE_SECONDS", "3600"))
    OIDC_METADATA_EXPIRES_AT = now + cache_seconds
    LOGGER.info(
        "Fetched Entra OIDC metadata keys=%s jwks_uri=%s cache_seconds=%s",
        sorted(OIDC_METADATA.keys()),
        mask_url(OIDC_METADATA.get("jwks_uri")),
        cache_seconds,
    )
    return OIDC_METADATA


def get_jwk_client(jwks_uri: str) -> PyJWKClient:
    """Create the PyJWT JWKS client once and let it pick keys by token kid."""
    global JWK_CLIENT

    if JWK_CLIENT is None:
        LOGGER.info("Initializing JWKS client")
        JWK_CLIENT = PyJWKClient(jwks_uri)
    else:
        LOGGER.info("Using cached JWKS client")

    return JWK_CLIENT


def get_oci_iam_access_token() -> str:
    """Use OCI IAM client credentials flow to mint the token accepted by OIC."""
    token_endpoint = required_config("OCI_IAM_TOKEN_ENDPOINT")
    client_id = required_config("OCI_IAM_CLIENT_ID")
    client_secret = required_cached_secret()
    scope = required_config("OCI_IAM_SCOPE")
    timeout = float(optional_config("HTTP_TIMEOUT_SECONDS", "10"))
    auth_method = optional_config("OCI_TOKEN_AUTH_METHOD", "client_secret_basic")
    LOGGER.info(
        "Requesting OCI IAM access token endpoint=%s client_id=%s scope=%s auth_method=%s",
        mask_url(token_endpoint),
        mask_value(client_id),
        mask_value(scope),
        auth_method,
    )

    form = {
        "grant_type": "client_credentials",
        "scope": scope,
    }
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    if auth_method == "client_secret_post":
        form["client_id"] = client_id
        form["client_secret"] = client_secret
    else:
        basic_auth = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode("ascii")
        headers["Authorization"] = f"Basic {basic_auth}"

    token_response = requests.post(token_endpoint, data=form, headers=headers, timeout=timeout)
    LOGGER.info("OCI IAM token endpoint responded status=%s", token_response.status_code)
    if token_response.status_code >= 400:
        LOGGER.warning("OCI token request failed with status %s response_length=%s", token_response.status_code, len(token_response.text or ""))
        raise AuthError("oci_token_request_failed")

    token_body = token_response.json()
    LOGGER.info(
        "Received OCI IAM token response keys=%s expires_in=%s token_type=%s scope=%s",
        sorted(token_body.keys()),
        token_body.get("expires_in"),
        token_body.get("token_type"),
        mask_value(token_body.get("scope")),
    )
    access_token = token_body.get("access_token")
    if not access_token:
        raise AuthError("oci_token_missing_access_token")

    LOGGER.info("Extracted OCI IAM access token token_length=%s", len(access_token))
    return access_token


def build_allow_response(principal: Optional[str], claims: Dict[str, Any], oci_token: str) -> Dict[str, Any]:
    """Return the successful API Gateway custom authorizer response."""
    expires_at = None
    if claims.get("exp"):
        expires_at = datetime.fromtimestamp(claims["exp"], tz=timezone.utc).isoformat()

    result = {
        "active": True,
        "principal": principal or "entra-client",
        "scope": csv_config("AUTHORIZER_SCOPE") or ["oic.invoke"],
        "context": {
            "back_end_token": oci_token,
            "entra_client_id": claims.get("azp") or claims.get("appid") or "",
            "entra_tenant_id": claims.get("tid") or "",
            "entra_subject": claims.get("sub") or "",
        },
    }

    if expires_at:
        result["expiresAt"] = expires_at

    LOGGER.info(
        "Built allow response principal=%s scope=%s expiresAt=%s context_keys=%s backend_token_length=%s",
        mask_value(result["principal"]),
        mask_list(result["scope"]),
        result.get("expiresAt"),
        sorted(result["context"].keys()),
        len(oci_token),
    )
    return result


def build_deny_response(reason: str) -> Dict[str, Any]:
    """Return the failed API Gateway custom authorizer response."""
    LOGGER.info("Built deny response reason=%s", reason)
    return {
        "active": False,
        "wwwAuthenticate": f'Bearer error="invalid_token", error_description="{reason}"',
    }


def json_response(ctx, body: Dict[str, Any]):
    """Serialize the authorizer response for the Fn Python FDK."""
    return response.Response(
        ctx,
        response_data=json.dumps(body),
        headers={"Content-Type": "application/json"},
    )


def required_config(name: str) -> str:
    """Read a required config value and reject template placeholders."""
    value = config_value(name)
    if not value:
        raise AuthError(f"missing_config_{name}")
    if is_placeholder(value):
        raise AuthError(f"placeholder_config_{name}")
    LOGGER.info("Read required config name=%s value=%s", name, display_config_value(name, value))
    return value


def optional_config(name: str, default: str) -> str:
    """Read an optional config value; placeholders fall back to the default."""
    value = config_value(name) or default
    resolved = default if is_placeholder(value) else value
    LOGGER.info("Read optional config name=%s value=%s", name, display_config_value(name, resolved))
    return resolved


def csv_config(name: str) -> List[str]:
    """Read a comma-separated config value and drop blanks/placeholders."""
    value = config_value(name) or ""
    items = [item.strip() for item in value.split(",") if item.strip() and not is_placeholder(item.strip())]
    LOGGER.info("Read CSV config name=%s item_count=%s items=%s", name, len(items), items)
    return items


def config_value(name: str) -> Optional[str]:
    """Prefer Fn context config, then fall back to environment variables for local tests."""
    value = FUNCTION_CONFIG.get(name)
    if value is None:
        value = os.getenv(name)
    return value


def parse_cache_seconds(value: Optional[str], default: int) -> int:
    """Parse cache duration config; placeholders or bad values fall back to default."""
    if value is None or is_placeholder(str(value)):
        return default
    try:
        parsed = int(str(value).strip())
    except ValueError:
        LOGGER.warning("Invalid FUNCTION_CONFIG_CACHE_SECONDS value=%s; using default=%s", mask_value(value), default)
        return default
    return max(parsed, 0)


def is_cache_expired(loaded_at: float, cache_seconds: int, now: float) -> bool:
    """Return True when a cached value should be refreshed."""
    if not loaded_at:
        return True
    if cache_seconds == 0:
        return True
    return now >= loaded_at + cache_seconds


def required_cached_secret() -> str:
    """Return the OCI IAM client secret loaded from OCI Vault."""
    if not OCI_IAM_CLIENT_SECRET:
        raise AuthError("missing_secret_OCI_IAM_CLIENT_SECRET")
    return OCI_IAM_CLIENT_SECRET


def read_case_insensitive_value(values: Dict[str, Any], name: str) -> Optional[Any]:
    """Read a dictionary value without depending on exact header casing."""
    for key, value in values.items():
        if key.lower() == name:
            return value
    return None


def is_placeholder(value: str) -> bool:
    """Detect placeholder values left in func.yaml."""
    return value.strip().startswith(PLACEHOLDER_PREFIXES)


def mask_value(value: Optional[Any]) -> str:
    """Mask values so logs show shape without exposing identifiers or secrets."""
    if value is None:
        return "<none>"
    text = str(value)
    if not text:
        return "<empty>"
    if len(text) <= 8:
        return f"<masked:{len(text)}>"
    return f"{text[:4]}...{text[-4:]}(len={len(text)})"


def mask_list(values: List[Any]) -> List[str]:
    """Mask every item in a list before logging."""
    return [mask_value(value) for value in values]


def mask_url(value: Optional[str]) -> str:
    """Mask URLs while keeping scheme and host visible enough for troubleshooting."""
    if not value:
        return "<none>"
    try:
        scheme, rest = value.split("://", 1)
        host = rest.split("/", 1)[0]
        return f"{scheme}://{mask_value(host)}/...(len={len(value)})"
    except ValueError:
        return mask_value(value)


def display_config_value(name: str, value: str) -> str:
    """Avoid logging secrets while keeping config troubleshooting useful."""
    if "SECRET" in name:
        return mask_value(value) if name.endswith("_OCID") else "<redacted>"
    if name.endswith("_CLIENT_ID") or name in {"ENTRA_ALLOWED_CLIENT_IDS", "ENTRA_AUDIENCE", "ENTRA_TENANT_ID"}:
        return mask_value(value)
    if name.endswith("_ENDPOINT") or name.endswith("_SCOPE") or name.endswith("_HOST"):
        return mask_url(value) if name.endswith("_ENDPOINT") or name.endswith("_HOST") else mask_value(value)
    return mask_value(value)
