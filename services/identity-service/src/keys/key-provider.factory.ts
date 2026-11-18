import { KEY_ALGORITHMS, KeyAlgorithm, KeyProvider } from './key-provider';
import { VaultTransitProvider } from './providers/vault-transit.provider';

const SUPPORTED = ['vault-transit'];

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
    default:
      throw new Error(`Unknown KEY_PROVIDER '${name}'. Supported: ${SUPPORTED.join(', ')}`);
  }
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
