# OIC Access With Microsoft Entra Token

This project builds an OCI API Gateway authorizer function for this flow:

1. A client gets a Microsoft Entra ID access token using client credentials.
2. The client calls OCI API Gateway with that token.
3. API Gateway invokes an OCI Function authorizer.
4. The authorizer validates the Entra JWT using Entra OpenID metadata and JWKS.
5. If valid, the authorizer gets an OCI IAM Domain access token using client credentials.
6. API Gateway forwards the request to Oracle Integration Cloud with the OCI token.

The authorizer returns the OCI token in API Gateway auth context as `back_end_token`.
Configure the OIC route request header transformation like this:

```text
Authorization: Bearer ${request.auth[back_end_token]}
```

## Layout

```text
authorizer-function/        Source of truth
docs/                       Design and setup notes
```

## Next Values To Collect

- Entra tenant ID.
- Entra API audience, from the generated access token `aud` claim.
- Allowed Entra caller client ID or IDs.
- Required Entra app role, if used.
- OCI IAM Domain token endpoint.
- OCI IAM confidential app client ID.
- OCI Vault secret OCID containing the OCI IAM confidential app client secret.
- OCI IAM scope for invoking OIC.

## Microsoft Entra ID Configuration

Create two Microsoft Entra app registrations:

```text
API app registration:
  Represents the protected API exposed through OCI API Gateway.

Client app registration:
  Represents the M2M caller that requests an access token.
```

### 1. Create The API App Registration

In Microsoft Entra admin center:

```text
Identity
-> Applications
-> App registrations
-> New registration
```

Use:

```text
Name: OIC API Gateway API
Supported account types: Single tenant
Redirect URI: leave blank
```

After creating it, note:

```text
Application/client ID
Directory/tenant ID
```

### 2. Configure The API App For v2 Access Tokens

In the API app registration:

```text
Manifest
```

Set the access token version to `2`. Depending on the portal manifest field name, update one of these:

```json
"requestedAccessTokenVersion": 2
```

or:

```json
"accessTokenAcceptedVersion": 2
```

This makes Entra issue access tokens with:

```json
"ver": "2.0",
"iss": "https://login.microsoftonline.com/<tenant-id>/v2.0"
```

### 3. Expose The API App

In the API app registration:

```text
Expose an API
-> Application ID URI
-> Set
```

The default value is usually:

```text
api://<api-app-client-id>
```

For client credentials token requests, the client will request:

```text
scope=api://<api-app-client-id>/.default
```

### 4. Add An Application App Role

In the API app registration:

```text
App roles
-> Create app role
```

Use:

```text
Display name: OIC Invoke
Allowed member types: Applications
Value: OIC.Invoke
Description: Allows an application to invoke OIC through OCI API Gateway
Enabled: Yes
```

For M2M client credentials, this app role appears in the access token as:

```json
"roles": ["OIC.Invoke"]
```

### 5. Create The Client App Registration

Create another app registration:

```text
Name: OIC M2M Client
Supported account types: Single tenant
Redirect URI: leave blank
```

After creating it, note:

```text
Application/client ID
```

This is the caller app ID. It should appear in the v2 token as:

```json
"azp": "<client-app-client-id>"
```

### 6. Create A Client Secret For The Client App

In the client app registration:

```text
Certificates & secrets
-> Client secrets
-> New client secret
```

Copy the secret value immediately. This is used only by the client or test tool to request an Entra token.
Do not put this client secret into OCI Function config.

### 7. Grant The Client App Access To The API App

In the client app registration:

```text
API permissions
-> Add a permission
-> My APIs or APIs my organization uses
-> OIC API Gateway API
-> Application permissions
-> OIC.Invoke
-> Add permissions
-> Grant admin consent
```

If the API app is not visible:

```text
1. Confirm the API app has an Application ID URI.
2. Confirm the API app has an enabled app role with Allowed member types = Applications.
3. Confirm your user is an owner of both app registrations.
4. Search under APIs my organization uses, not only My APIs.
```

A delegated scope is not required for this M2M design. The important permission is the application app role, which creates the `roles` claim.

### 8. Request A Client Credentials Token

Use the v2 token endpoint:

```text
POST https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded
```

Form body:

```text
client_id=<client-app-client-id>
client_secret=<client-app-secret>
grant_type=client_credentials
scope=api://<api-app-client-id>/.default
```

Decode the returned access token and confirm this shape:

```json
{
  "aud": "<api-audience>",
  "iss": "https://login.microsoftonline.com/<tenant-id>/v2.0",
  "azp": "<client-app-client-id>",
  "roles": ["OIC.Invoke"],
  "tid": "<tenant-id>",
  "ver": "2.0"
}
```

Record these values. They will be used later as OCI Function configuration:

```text
ENTRA_TENANT_ID=<tenant-id>
ENTRA_AUDIENCE=<aud-claim-from-token>
ENTRA_ALLOWED_CLIENT_IDS=<client-app-client-id>
ENTRA_REQUIRED_ROLES=OIC.Invoke
ENTRA_AUTHORITY_HOST=https://login.microsoftonline.com
```

Use the actual `aud` claim from the token as `ENTRA_AUDIENCE`. Depending on token version and API configuration, it may be the API app client ID or the App ID URI.

## OCI IAM Domain And Vault Configuration

The function validates the Entra token first. If the Entra token is valid, the function gets a second access token from OCI IAM Domain using client credentials.
That OCI IAM token is what OIC accepts.

This section configures these function values:

```text
OCI_IAM_TOKEN_ENDPOINT
OCI_IAM_CLIENT_ID
OCI_IAM_CLIENT_SECRET_OCID
OCI_IAM_SCOPE
```

### 1. Open The OIC Identity Domain

In OCI Console:

```text
Identity & Security
-> Domains
-> Select the compartment that contains the OIC identity domain
-> Select the identity domain used by the OIC instance
```

Confirm the domain URL. The token endpoint will be:

```text
https://<identity-domain-url>/oauth2/v1/token
```

Record this value as `OCI_IAM_TOKEN_ENDPOINT`.

### 2. Create A Confidential Application

In the selected identity domain:

```text
Integrated applications
-> Add application
-> Confidential Application
-> Launch workflow
```

Use a name such as:

```text
oic-api-gateway-backend-client
```

Create the application.

### 3. Configure OAuth Client Credentials

Open the confidential application:

```text
OAuth configuration
-> Edit OAuth configuration
```

Configure it as an OAuth client:

```text
Configure this application as a client now: Yes
Allowed grant types: Client credentials
Client type: Confidential
```

Save the configuration.

### 4. Add OIC Resource Scope

In the same OAuth configuration area:

```text
Token issuance policy
-> Authorized resources
-> Add resources
-> Select the Oracle Integration resource
-> Add scope
```

For invoking OIC through the gateway, use the OIC consumer scope shown by the identity domain.

Use the exact scope value shown in the OCI IAM Domain UI. Do not invent or shorten this value.
Record this value as `OCI_IAM_SCOPE`.

### 5. Assign OIC Application Role

The confidential application must be allowed to invoke OIC.

In the identity domain:

```text
Oracle cloud services
-> Select the Oracle Integration application for the OIC instance
-> Application roles
-> ServiceInvoker
-> Assigned applications
-> Assign application
-> Select the confidential application
```

Save the role assignment.

### 6. Activate The Confidential Application

Open the confidential application:

```text
Actions
-> Activate
```

Copy the client ID. This becomes:

```text
OCI_IAM_CLIENT_ID=<confidential-app-client-id>
```

Copy the client secret only long enough to store it in OCI Vault. Do not put the raw client secret in Git or function config.

### 7. Store The Client Secret In OCI Vault

In OCI Console:

```text
Identity & Security
-> Vault
-> Select or create a vault
-> Secrets
-> Create secret
```

Use:

```text
Name: oic-api-gateway-backend-client-secret
Secret content: <OCI IAM confidential app client secret>
```

After the secret is created, copy the secret OCID. This becomes:

```text
OCI_IAM_CLIENT_SECRET_OCID=<secret-ocid>
```

Record this value as `OCI_IAM_CLIENT_SECRET_OCID`.

### 8. Record OCI IAM Values

At the end of this section, you should have these values ready for OCI Function configuration:

```text
OCI_IAM_TOKEN_ENDPOINT=<identity-domain-token-endpoint>
OCI_IAM_CLIENT_ID=<confidential-app-client-id>
OCI_IAM_CLIENT_SECRET_OCID=<vault-secret-ocid>
OCI_IAM_SCOPE=<oic-resource-scope>
```

Do not store the raw OCI IAM client secret in Git or function config. Store only the Vault secret OCID.

### 9. Runtime Behavior

At runtime:

```text
1. API Gateway invokes the authorizer function.
2. The function reads OCI_IAM_CLIENT_SECRET_OCID from function config.
3. The function uses Resource Principal authentication.
4. The function reads the client secret from OCI Vault.
5. The function calls OCI IAM Domain /oauth2/v1/token with client_credentials.
6. OCI IAM returns an access token for OIC.
7. The function returns that token in API Gateway auth context as back_end_token.
```

API Gateway then forwards to OIC using:

```text
Authorization: Bearer ${request.auth[back_end_token]}
```

## OCI Function Deployment And Configuration

Deploy an OCI Function using the source code in `authorizer-function/`. Follow Oracle's official OCI Functions documentation for creating the application, building the function image, and deploying the function: https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionsuploading.htm

After the function is deployed, open it in the OCI Console and add the function configuration values manually:

```text
ENTRA_TENANT_ID=<tenant-id>
ENTRA_AUDIENCE=<aud-claim-from-token>
ENTRA_ALLOWED_CLIENT_IDS=<client-app-client-id>
ENTRA_REQUIRED_ROLES=OIC.Invoke
ENTRA_AUTHORITY_HOST=https://login.microsoftonline.com
FUNCTION_CONFIG_CACHE_SECONDS=300
OCI_IAM_TOKEN_ENDPOINT=<identity-domain-token-endpoint>
OCI_IAM_CLIENT_ID=<confidential-app-client-id>
OCI_IAM_CLIENT_SECRET_OCID=<vault-secret-ocid>
OCI_IAM_SCOPE=<oic-resource-scope>
```

The function uses Resource Principal authentication to read the OCI IAM confidential app secret from Vault. After deployment, create a dynamic group for the function.

Example dynamic group:

```text
Name: <dynamic-group-name>
Matching rule:
resource.id = '<authorizer-function-ocid>'
```

Then allow that dynamic group to read only the required secret bundle:

```text
Allow dynamic-group <dynamic-group-name> to read secret-bundles in compartment <secret-compartment-name>
  where target.secret.id = '<vault-secret-ocid>'
```

## OCI API Gateway Configuration

API Gateway is the enforcement and token-bridging layer.

It receives the original Microsoft Entra token from the caller, invokes the custom authorizer function, and then forwards the request to OIC using the OCI IAM token returned by the function.

Target flow:

```text
Client
  -> Authorization: Bearer <entra-access-token>
  -> OCI API Gateway
  -> Custom authorizer function
  -> request.auth[back_end_token]
  -> OIC backend with Authorization: Bearer <oci-iam-access-token>
```

### 1. Create Or Select An API Gateway

In OCI Console:

```text
Developer Services
-> API Management
-> Gateways
```

Create a gateway or use an existing one.

Typical values:

```text
Name: oic-entra-gateway
Type: Public
Compartment: <target compartment>
VCN/Subnet: <network that can reach OIC>
```

After the gateway is created, note the gateway hostname.

### 2. Create An API Deployment

Open the gateway:

```text
Deployments
-> Create deployment
```

Use:

```text
Name: oic-entra-deployment
Path prefix: /oic
Deployment source: From scratch
```

The public URL will later look like:

```text
https://<gateway-hostname>/oic/<route-path>
```

### 3. Allow API Gateway To Invoke The Authorizer Function

Create an OCI IAM policy that allows API Gateway to use OCI Functions in the function compartment.

Policy shape:

```text
Allow any-user to use functions-family in compartment <function-compartment-name>
  where ALL {
    request.principal.type = 'ApiGateway',
    request.resource.compartment.id = '<api-gateway-compartment-ocid>'
  }
```

Use the API Gateway compartment OCID in the condition. The function compartment in the policy statement should be the compartment that contains the authorizer function.

### 4. Configure Custom Authorizer

On the deployment authentication step:

```text
Authentication: Single authentication
Authentication type: Custom authorizer
Authorizer function application: <function-application-name>
Authorizer function: <function-name>
```

Use a multi-argument authorizer function.

Add this authorizer argument:

```text
Argument name: authorization
Argument source/value: request.headers[Authorization]
```

This makes API Gateway pass the caller token to the function as:

```json
{
  "type": "USER_DEFINED",
  "data": {
    "authorization": "Bearer <entra-token>"
  }
}
```

The function reads this value, validates the Entra JWT, and returns an authorizer response.

Successful authorizer response shape:

```json
{
  "active": true,
  "principal": "<entra-client-id>",
  "scope": ["oic.invoke"],
  "context": {
    "back_end_token": "<oci-iam-access-token>",
    "entra_client_id": "<entra-client-id>",
    "entra_tenant_id": "<entra-tenant-id>",
    "entra_subject": "<entra-subject>"
  }
}
```

API Gateway exposes these context values as:

```text
${request.auth[back_end_token]}
${request.auth[entra_client_id]}
${request.auth[entra_tenant_id]}
${request.auth[entra_subject]}
```

### 5. Add Route To OIC Backend

Add a route for the OIC endpoint you want to expose.

Example:

```text
Path: /orders
Methods: POST
Backend type: HTTP
Backend URL: https://<oic-host>/ic/api/integration/v1/flows/rest/<integration-path>
```

Use the exact OIC invoke URL for the integration REST trigger or OIC API you want to test.

Do not expose the OIC endpoint directly to the client. The client should call API Gateway only.

### 6. Set Backend Authorization Header

On the route, configure request header transformation:

```text
Route request policies
-> Header transformations
-> Add header transformation
```

Set or overwrite the backend `Authorization` header:

```text
Action: Set
Header name: Authorization
Value: Bearer ${request.auth[back_end_token]}
If header exists: Overwrite
```

The `Bearer` prefix is required here.

The authorizer function returns only the raw OCI IAM access token in `back_end_token`.
API Gateway does not automatically add `Bearer` when a header is set from a context variable.

So this is correct:

```text
Authorization: Bearer ${request.auth[back_end_token]}
```

This is not enough:

```text
Authorization: ${request.auth[back_end_token]}
```

### 7. Optional Caller Context Headers

If the OIC integration should receive caller context for logging or audit, add extra route request header transformations:

```text
X-Entra-Client-Id: ${request.auth[entra_client_id]}
X-Entra-Tenant-Id: ${request.auth[entra_tenant_id]}
X-Entra-Subject: ${request.auth[entra_subject]}
```

Only trust these headers if OIC is reachable only through API Gateway or the gateway overwrites any incoming values from the client.

### 8. Save The Deployment

Review and save the deployment.

The final gateway endpoint will be:

```text
https://<gateway-hostname>/oic/<route-path>
```

### 9. Test End To End

Request a Microsoft Entra token with client credentials:

```text
POST https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

client_id=<client-app-client-id>
client_secret=<client-app-secret>
grant_type=client_credentials
scope=api://<api-app-client-id>/.default
```

Call API Gateway with the Entra token:

```bash
curl -i \
  -X POST \
  "https://<gateway-hostname>/oic/<route-path>" \
  -H "Authorization: Bearer <entra-access-token>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Expected execution:

```text
1. API Gateway receives the Entra bearer token.
2. API Gateway invokes the custom authorizer function.
3. The function validates Entra JWT signature and claims.
4. The function reads the OCI IAM client secret from OCI Vault.
5. The function requests an OCI IAM access token.
6. The function returns context.back_end_token to API Gateway.
7. API Gateway overwrites backend Authorization with Bearer ${request.auth[back_end_token]}.
8. OIC receives the OCI IAM token and invokes the integration.
```

### 10. Troubleshooting

Gateway returns `401`:

```text
Likely authorizer validation failure.
Check function logs for:
- missing_authorization_token
- invalid_tenant
- client_not_allowed
- missing_required_role
- placeholder_config_*
```

Gateway returns `502` or backend error:

```text
Likely route/backend configuration issue.
Check:
- OIC backend URL
- HTTP method
- gateway network access
- request body required by the integration
```

OIC returns unauthorized:

```text
Check:
- Authorization header transformation includes Bearer
- request.auth[back_end_token] is populated
- OCI IAM confidential app has the correct OIC scope
- OCI IAM confidential app is assigned ServiceInvoker
- OCI_IAM_TOKEN_ENDPOINT is correct
```

Function logs show Vault or permission errors:

```text
Check:
- OCI_IAM_CLIENT_SECRET_OCID
- dynamic group matching rule
- policy grants read secret-bundles
- secret is in the expected compartment
```

Function logs show OCI token request failure:

```text
Check:
- OCI_IAM_CLIENT_ID
- secret stored in Vault is the correct client secret
- OCI_IAM_SCOPE exactly matches the OIC scope
- confidential app has client_credentials enabled
- confidential app is activated
```

### 11. Function Logging

The authorizer logs each major step without printing secrets, access tokens, or full identifiers.
Tenant IDs, client IDs, audiences, scopes, endpoints, subjects, key IDs, and Vault OCIDs are masked.

Expected successful log flow:

```text
Authorizer invocation started
Initialized function config keys=[...] cache_seconds=300
Loading OCI IAM client secret from Vault secret=ocid...xxxx(len=<length>)
Loaded OCI IAM client secret from Vault cache_seconds=300
Received authorizer payload type=USER_DEFINED top_level_keys=[...] data_keys=[authorization]
Received authorization token token_length=<length> bearer_prefix=True
Extracted Entra access token token_length=<length>
Read Entra token header alg=RS256 kid=abcd...wxyz(len=40) typ=JWT
Fetching Entra OIDC metadata url=https://logi....com(len=103)/...
Fetched Entra OIDC metadata keys=[...] jwks_uri=https://logi....com(len=84)/... cache_seconds=3600
Using Entra JWKS URI https://logi....com(len=84)/...
Initializing JWKS client
Found public signing key for token kid=abcd...wxyz(len=40)
Verified Entra token claims keys=[...] tid=<masked-tenant-id> aud=<masked-audience> client_id=<masked-client-id> roles=['OIC...voke(len=10)']
Validated Entra tenant
Validated Entra client id client_id=<masked-client-id>
Validated Entra roles required_roles=['OIC...voke(len=10)'] token_roles=['OIC...voke(len=10)']
Requesting OCI IAM access token endpoint=https://idcs...com(len=<length>)/... client_id=<masked-client-id> scope=http...:all(len=<length>) auth_method=client_secret_basic
OCI IAM token endpoint responded status=200
Received OCI IAM token response keys=[...] expires_in=<seconds> token_type=Bearer scope=http...:all(len=<length>)
Extracted OCI IAM access token token_length=<length>
Built allow response principal=<masked-client-id> scope=['oic....voke(len=10)'] context_keys=['back_end_token', 'entra_client_id', 'entra_subject', 'entra_tenant_id']
Authorizer invocation completed successfully principal=<masked-client-id> response_context_keys=[...]
```

The logs intentionally do not print:

```text
Microsoft Entra access token value
OCI IAM access token value
OCI IAM client secret value
Full Vault secret payload
Full tenant/client/application IDs
Full endpoints or scopes
```

The `back_end_token` is returned only in the API Gateway authorizer context so the route can set:

```text
Authorization: Bearer ${request.auth[back_end_token]}
```

## Function Configuration

OCI Functions exposes application and function config parameters as environment variables.
This project keeps the expected keys in `func.yaml` under `config:` so deployment is explicit.

Do not commit real client secrets. Add real function configuration values manually in the OCI Console after deployment.

The main `func.yaml` includes a `config:` block as a template that documents the expected keys.
Do not deploy placeholder config values to a real function.
Use the deployed function's Configuration tab in OCI Console to update live values.

Required keys:

```text
ENTRA_TENANT_ID
ENTRA_AUDIENCE
ENTRA_ALLOWED_CLIENT_IDS
ENTRA_REQUIRED_ROLES
OCI_IAM_TOKEN_ENDPOINT
OCI_IAM_CLIENT_ID
OCI_IAM_CLIENT_SECRET_OCID
OCI_IAM_SCOPE
```

The OCI IAM confidential app client secret is read from OCI Vault using Resource Principal authentication. The function dynamic group needs permission to read secret bundles from the compartment or vault that contains the secret.

### Cache Settings

`FUNCTION_CONFIG_CACHE_SECONDS` controls how long the warm function container caches both function configuration and the OCI IAM client secret read from Vault.

Example:

```text
FUNCTION_CONFIG_CACHE_SECONDS=300
```

With this value, a warm function container refreshes config and the Vault secret after five minutes. Set it to `0` only if you want to reload function config and the Vault secret on every invocation.

`ENTRA_JWKS_CACHE_SECONDS` controls how long the function caches the Microsoft Entra OpenID metadata response. That metadata includes the `jwks_uri`. The `PyJWKClient` object is reused inside the warm container and handles JWKS key lookup internally.

### Entra Validation Settings

`ENTRA_ALLOWED_CLIENT_IDS` is a comma-separated list of trusted Microsoft Entra client application IDs.

Example:

```text
ENTRA_ALLOWED_CLIENT_IDS=<client-app-id-1>,<client-app-id-2>,<client-app-id-3>
```

The incoming Entra access token must contain one of these values as its caller client ID. For v2 tokens, the function checks `azp`; for v1 tokens, it checks `appid`.

`ENTRA_REQUIRED_ROLES` is also comma-separated. For this M2M design, Entra application permissions are expected in the token's `roles` claim.

Example:

```text
ENTRA_REQUIRED_ROLES=OIC.Invoke
```

If `ENTRA_REQUIRED_ROLES` is empty or not configured, the function will not enforce role validation. For this use case, keeping a role configured is the better design because it confirms the caller app was granted the expected application permission.

`ENTRA_REQUIRED_SCOPES` is optional and is not needed for the current M2M client credentials flow. It can be used later for delegated or user-based flows where Entra sends permissions in the token's `scp` claim instead of the `roles` claim.

Example:

```text
ENTRA_REQUIRED_SCOPES=<delegated-scope-1>,<delegated-scope-2>
```

Leave `ENTRA_REQUIRED_SCOPES` empty for the M2M flow described in this tutorial.

`AUTHORIZER_SCOPE` is different from Entra scopes. It is the scope value that the custom authorizer returns to OCI API Gateway in the successful authorizer response.

Example authorizer response:

```json
{
  "active": true,
  "principal": "<client-id>",
  "scope": ["oic.invoke"],
  "context": {
    "back_end_token": "<oci-iam-access-token>"
  }
}
```

API Gateway can use the returned authorizer scope for route restriction if required. In this tutorial, the main authorization checks are tenant, audience, allowed client ID, and Entra app role.

## Authorizer Input

The function uses the Fn `ctx` object for function configuration:

```python
ctx.Config()
```

The Microsoft Entra bearer token does not come from Fn `ctx`. OCI API Gateway sends the authorizer input as JSON in the function request body.

Recommended API Gateway setup:

```text
Authorizer type:
  Multi-argument authorizer function

Function argument:
  authorization = request.headers[Authorization]
```

That arrives in the function as:

```json
{
  "type": "USER_DEFINED",
  "data": {
    "authorization": "Bearer <entra-token>"
  }
}
```

The function also supports the simpler single-token payload:

```json
{
  "type": "TOKEN",
  "token": "Bearer <entra-token>"
}
```

Optional keys have safe defaults in the function:

```text
ENTRA_AUTHORITY_HOST=https://login.microsoftonline.com
ENTRA_JWKS_CACHE_SECONDS=3600
FUNCTION_CONFIG_CACHE_SECONDS=300
JWT_LEEWAY_SECONDS=60
OCI_TOKEN_AUTH_METHOD=client_secret_basic
AUTHORIZER_SCOPE=oic.invoke
HTTP_TIMEOUT_SECONDS=10
```
