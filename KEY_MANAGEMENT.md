# Signing Key Management Setup

identity-service signs credentials with issuer keys kept in a key management system (KMS). Keys are created inside the KMS and never leave it. Pick a provider, set its environment variables, restart identity-service.

## 1. Choose a provider

| Provider | `KEY_PROVIDER` | Key types |
|---|---|---|
| HashiCorp Vault Transit | `vault-transit` (default) | Ed25519, P-256 |
| Azure Key Vault (Standard, Premium) or Managed HSM | `azure-keyvault` | P-256 only |
| Your own (AWS KMS, GCP KMS, …) | `custom` | Your choice |

## 2. Vault Transit (default)

```bash
VAULT_BASE_URL=http://vault:8200/v1
VAULT_TOKEN=<token>            # sign-only token (see below), never the root token
VAULT_TRANSIT_MOUNT=transit    # optional
```

identity-service gets a sign-only token: it can create keys and sign, nothing else, and is valid for 10 years. The root token stays in `keys.txt` for admin work.

**Docker Compose:** `setup_vault.sh` or `enable-v2.sh` enables Transit and writes the token to `.env`. To create it for an existing setup, run `./vault-identity-token.sh`.

**Kubernetes:** run once with the root token and store the output as a Kubernetes Secret:

```bash
cat > identity-signer.hcl <<'EOF'
path "transit/keys/+"          { capabilities = ["create", "update", "read"] }
path "transit/sign/+"          { capabilities = ["update"] }
path "transit/sign/+/sha2-256" { capabilities = ["update"] }
EOF
vault auth tune -max-lease-ttl=87600h token/
vault policy write identity-signer identity-signer.hcl
vault token create -policy=identity-signer -ttl=87600h -field=token   # -> Kubernetes Secret -> VAULT_TOKEN
```

If the token leaks, revoke it (`vault token revoke <token>`) and issue a new one.

## 3. Azure Key Vault / Managed HSM

```bash
KEY_PROVIDER=azure-keyvault
AZURE_KEYVAULT_URL=https://<name>.vault.azure.net   # Managed HSM: https://<name>.managedhsm.azure.net
AZURE_KEY_PROTECTION=hsm        # hsm (Premium, Managed HSM) or software (Standard)
AZURE_AUTH_METHOD=client-secret # or managed-identity
AZURE_TENANT_ID=<tenant-id>     # client-secret only
AZURE_CLIENT_ID=<app-id>        # client-secret; managed identity only if user-assigned
AZURE_CLIENT_SECRET=<secret>    # client-secret only; keep in a secret store
REQUIRED_KEY_ALGORITHMS=P-256   # Azure has no Ed25519
SIGNING_ALGORITHM=JsonWebSignature2020
```

**Login**

| Method | Use on | Steps |
|---|---|---|
| `client-secret` | Outside Azure, and AKS | `az ad sp create-for-rbac --name rc-identity-service`; use `appId`, `tenant`, `password` as client ID, tenant ID, secret |
| `managed-identity` | Azure VM, App Service, Functions | Enable an identity on the host; set `AZURE_CLIENT_ID` only for a user-assigned identity |

**Access:** give the login identity read, create and sign on keys only.

```bash
# Key Vault
az role definition create --role-definition '{
  "Name": "Sunbird RC Signing Key User", "Actions": [], "NotDataActions": [],
  "DataActions": ["Microsoft.KeyVault/vaults/keys/read",
                  "Microsoft.KeyVault/vaults/keys/create/action",
                  "Microsoft.KeyVault/vaults/keys/sign/action"],
  "AssignableScopes": ["/subscriptions/<subscription-id>"]}'
az role assignment create --role "Sunbird RC Signing Key User" --assignee <app-or-principal-id> \
  --scope "$(az keyvault show -n <name> --query id -o tsv)"

# Managed HSM
az keyvault role assignment create --hsm-name <name> --role "Managed HSM Crypto User" \
  --assignee <app-or-principal-id> --scope /keys
```

JSON-LD credentials on Azure need the ECDSA cryptosuite; JWT, SD-JWT and mdoc work.

## 4. Custom provider

Set `KEY_PROVIDER=custom` and `KEY_PROVIDER_MODULE=/absolute/path/provider.js`. The module exports `createProvider(env)` returning the interface in `services/identity-service/src/keys/key-provider.ts`. Test it with `services/identity-service/src/keys/testing/key-provider.contract.ts`.

## 5. Check it works

1. Start identity-service. Log shows `Signing keys held by KEY_PROVIDER '<provider>'`.
2. `POST /did/generate` returns a DID document with `#key-0`.
3. Issue and verify a credential.

| Startup error | Fix |
|---|---|
| `... is required` | Set the named variable |
| `does not support: Ed25519` | Azure: `REQUIRED_KEY_ALGORITHMS=P-256` |
| `Default key type ... is not supported` | Azure: `SIGNING_ALGORITHM=JsonWebSignature2020` |
| `403` when creating a DID | Vault: token lacks the policy or was revoked. Azure: role not assigned |
| Fails after Vault restart | Unseal Vault |
