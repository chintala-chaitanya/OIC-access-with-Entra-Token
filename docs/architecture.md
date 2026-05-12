# Architecture

## Target M2M Flow

```text
Client application
  -> Microsoft Entra ID client_credentials token
  -> OCI API Gateway
  -> OCI Functions custom authorizer
  -> OCI IAM Domain client_credentials token
  -> Oracle Integration Cloud endpoint
```

## Identity Flow Choice

This project focuses on machine-to-machine access, where there is no user password and no user identity to propagate.
The authorizer validates the calling application identity from the Entra token, then uses a trusted OCI IAM confidential application to obtain the token that OIC accepts.

If user identity propagation is required later, use federation between Microsoft Entra ID and OCI IAM Domain and let OCI IAM issue a user-context token.

## API Gateway Contract

The authorizer returns:

```json
{
  "active": true,
  "scope": ["oic.invoke"],
  "expiresAt": "2026-04-30T16:30:00+00:00",
  "context": {
    "back_end_token": "<oci_access_token>",
    "entra_client_id": "<client-id>",
    "entra_tenant_id": "<tenant-id>"
  }
}
```

API Gateway can use `back_end_token` in a request header transformation:

```text
Authorization: Bearer ${request.auth[back_end_token]}
```
