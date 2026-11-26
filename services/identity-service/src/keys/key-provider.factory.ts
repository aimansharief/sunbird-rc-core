import { ClientSecretCredential, ManagedIdentityCredential, TokenCredential } from '@azure/identity';
import { KeyClient } from '@azure/keyvault-keys';
import * as path from 'path';
import { KEY_ALGORITHMS, KeyAlgorithm, KeyProvider } from './key-provider';
import { AzureKeyVaultProvider } from './providers/azure-keyvault.provider';
import { VaultTransitProvider } from './providers/vault-transit.provider';
import { algorithmForVmType, defaultVmType, isSupportedVmType } from './verification-method';

const SUPPORTED = ['vault-transit', 'azure-keyvault', 'custom'];
const REQUIRED_METHODS = ['capabilities', 'createKey', 'getPublicKey', 'sign'];

function required(env: NodeJS.ProcessEnv, name: string): string {
  const v = env[name];
  if (!v || !v.trim()) throw new Error(`${name} is required for KEY_PROVIDER '${env.KEY_PROVIDER || 'vault-transit'}'`);
  return v.trim();
}

export function requiredAlgorithms(env: NodeJS.ProcessEnv = process.env): KeyAlgorithm[] {
  const list = (env.REQUIRED_KEY_ALGORITHMS || 'Ed25519,P-256').split(',').map((s) => s.trim()).filter(Boolean);
  list.forEach((a) => {
    if (!KEY_ALGORITHMS.includes(a as KeyAlgorithm)) throw new Error(`Unknown algorithm '${a}' in REQUIRED_KEY_ALGORITHMS`);
  });
  return list as KeyAlgorithm[];
}

export async function createKeyProvider(env: NodeJS.ProcessEnv = process.env): Promise<KeyProvider> {
  const name = (env.KEY_PROVIDER || 'vault-transit').trim();
  switch (name) {
    case 'vault-transit':
      return new VaultTransitProvider({
        baseUrl: required(env, 'VAULT_BASE_URL'),
        token: required(env, 'VAULT_TOKEN'),
        mount: env.VAULT_TRANSIT_MOUNT || 'transit',
        timeoutMs: Number(env.VAULT_TIMEOUT) || 5000,
      });
    case 'azure-keyvault': {
      const settings = azureKeyVaultSettings(env);
      return new AzureKeyVaultProvider({
        client: new KeyClient(settings.vaultUrl, azureCredential(settings)),
        hsm: settings.hsm,
      });
    }
    case 'custom':
      return loadCustomProvider(required(env, 'KEY_PROVIDER_MODULE'), env);
    default:
      throw new Error(`Unknown KEY_PROVIDER '${name}'. Supported: ${SUPPORTED.join(', ')}`);
  }
}

export interface AzureKeyVaultSettings {
  vaultUrl: string;
  hsm: boolean;
  authMethod: 'client-secret' | 'managed-identity';
  tenantId?: string;
  clientId?: string;
  clientSecret?: string;
}

// Key Vault Standard (software keys), Premium (HSM keys) and Managed HSM share one API; see DEC-12 for login.
export function azureKeyVaultSettings(env: NodeJS.ProcessEnv): AzureKeyVaultSettings {
  const vaultUrl = required(env, 'AZURE_KEYVAULT_URL');
  let host: string;
  try {
    const url = new URL(vaultUrl);
    if (url.protocol !== 'https:') throw new Error();
    host = url.hostname;
  } catch {
    throw new Error(`AZURE_KEYVAULT_URL must be an https URL, got '${vaultUrl}'`);
  }
  const protection = (env.AZURE_KEY_PROTECTION || 'hsm').trim();
  if (!['hsm', 'software'].includes(protection)) {
    throw new Error(`AZURE_KEY_PROTECTION must be 'hsm' or 'software', got '${protection}'`);
  }
  if (host.includes('.managedhsm.') && protection === 'software') {
    throw new Error('AZURE_KEY_PROTECTION=software is not possible: Managed HSM only holds HSM keys');
  }
  const authMethod = (env.AZURE_AUTH_METHOD || '').trim();
  const settings = { vaultUrl, hsm: protection === 'hsm' };
  switch (authMethod) {
    case 'client-secret':
      return {
        ...settings,
        authMethod,
        tenantId: required(env, 'AZURE_TENANT_ID'),
        clientId: required(env, 'AZURE_CLIENT_ID'),
        clientSecret: required(env, 'AZURE_CLIENT_SECRET'),
      };
    case 'managed-identity':
      return { ...settings, authMethod, clientId: env.AZURE_CLIENT_ID?.trim() || undefined };
    default:
      throw new Error(`AZURE_AUTH_METHOD must be 'client-secret' or 'managed-identity', got '${authMethod}'`);
  }
}

function azureCredential(s: AzureKeyVaultSettings): TokenCredential {
  if (s.authMethod === 'client-secret') return new ClientSecretCredential(s.tenantId!, s.clientId!, s.clientSecret!);
  return s.clientId ? new ManagedIdentityCredential({ clientId: s.clientId }) : new ManagedIdentityCredential();
}

// Adopter-supplied provider (e.g. AWS KMS, GCP Cloud KMS): a local JS file exporting
// createProvider(env): Promise<KeyProvider>. Loaded once at startup; local paths only.
async function loadCustomProvider(file: string, env: NodeJS.ProcessEnv): Promise<KeyProvider> {
  if (!path.isAbsolute(file)) throw new Error(`KEY_PROVIDER_MODULE must be an absolute file path, got '${file}'`);
  let mod: any;
  try {
    mod = require(file);
  } catch (e) {
    throw new Error(`Cannot load KEY_PROVIDER_MODULE '${file}': ${(e as Error).message}`);
  }
  if (typeof mod?.createProvider !== 'function') {
    throw new Error(`KEY_PROVIDER_MODULE '${file}' must export createProvider(env)`);
  }
  const provider = await mod.createProvider(env);
  const missing = REQUIRED_METHODS.filter((m) => typeof provider?.[m] !== 'function');
  if (!provider?.name) missing.unshift('name');
  if (missing.length) {
    throw new Error(`Custom key provider '${provider?.name ?? file}' is missing: ${missing.join(', ')}`);
  }
  return provider;
}

export async function assertCapabilities(provider: KeyProvider, needed: KeyAlgorithm[]): Promise<void> {
  const caps = await provider.capabilities();
  const missing = needed.filter((a) => !caps.includes(a));
  if (missing.length) {
    throw new Error(
      `KEY_PROVIDER '${provider.name}' does not support: ${missing.join(', ')}. ` +
      `Supported: ${caps.join(', ') || 'none'}. Adjust REQUIRED_KEY_ALGORITHMS or choose another provider.`,
    );
  }
}

// The key type created when POST /did/generate has no keyPairType must be creatable by the provider.
export async function assertDefaultKeyType(provider: KeyProvider, env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const signingAlgorithm = env.SIGNING_ALGORITHM || '';
  const vmType = defaultVmType(signingAlgorithm);
  if (!isSupportedVmType(vmType)) {
    throw new Error(
      `SIGNING_ALGORITHM '${signingAlgorithm}' gives default key type '${vmType}', which cannot be created. ` +
      'Use Ed25519Signature2020, Ed25519Signature2018 or JsonWebSignature2020.',
    );
  }
  const alg = algorithmForVmType(vmType);
  if (!(await provider.capabilities()).includes(alg)) {
    throw new Error(
      `Default key type '${vmType}' (${alg}, from SIGNING_ALGORITHM='${signingAlgorithm}') is not supported by ` +
      `KEY_PROVIDER '${provider.name}'. Set SIGNING_ALGORITHM=JsonWebSignature2020 for P-256 keys.`,
    );
  }
}
