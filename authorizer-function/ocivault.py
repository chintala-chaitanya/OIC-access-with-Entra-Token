import base64
import logging

import oci


LOGGER = logging.getLogger("entra-oic-authorizer.vault")


def get_secret(secret_ocid: str) -> str:
    # Resource Principal lets the function call OCI APIs without storing OCI keys.
    signer = oci.auth.signers.get_resource_principals_signer()

    # The Secrets client reads secret bundles from OCI Vault.
    secrets_client = oci.secrets.SecretsClient(config={}, signer=signer)

    # Secret content is returned base64-encoded by the Secrets API.
    secret_bundle = secrets_client.get_secret_bundle(secret_ocid).data
    content = secret_bundle.secret_bundle_content

    if not content or not content.content:
        raise ValueError("Vault secret has no content")

    decoded = base64.b64decode(content.content).decode("utf-8")
    LOGGER.info("Loaded secret from OCI Vault: %s", secret_ocid)
    return decoded
