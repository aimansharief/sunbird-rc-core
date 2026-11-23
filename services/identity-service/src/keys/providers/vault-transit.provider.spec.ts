import axios from 'axios';
import { describeKeyProviderContract, verifyWithJwk } from '../testing/key-provider.contract';
import { VaultTransitProvider } from './vault-transit.provider';

// Runs against the real Vault from the environment (VAULT_BASE_URL, VAULT_TOKEN) when Transit is enabled.
async function transitOrNull() {
  const baseUrl = process.env.VAULT_BASE_URL;
  const token = process.env.VAULT_TOKEN;
  if (!baseUrl || !token) return null;
  try {
    const { data } = await axios.get(`${baseUrl.replace(/\/$/, '')}/sys/mounts`, {
      headers: { 'X-Vault-Token': token },
      timeout: 2000,
    });
    if (!data?.['transit/'] && !data?.data?.['transit/']) throw new Error('transit not mounted');
    return new VaultTransitProvider({ baseUrl, token, mount: process.env.VAULT_TRANSIT_MOUNT || 'transit' });
  } catch {
    return null;
  }
}

describeKeyProviderContract('vault-transit', transitOrNull);

describe('VaultTransitProvider', () => {
  it('advertises Ed25519 and P-256', async () => {
    const p = new VaultTransitProvider({ baseUrl: 'http://unused/v1', token: 't' });
    expect(await p.capabilities()).toEqual(['Ed25519', 'P-256']);
  });
});

describe('VaultTransitProvider against real Vault: failure and drift cases', () => {
  let provider: VaultTransitProvider | null;
  const baseUrl = process.env.VAULT_BASE_URL;
  const token = process.env.VAULT_TOKEN;
  const mount = process.env.VAULT_TRANSIT_MOUNT || 'transit';

  beforeAll(async () => { provider = await transitOrNull(); });

  it('fails cleanly with a 403 when the token is not allowed (no key material, no crash)', async () => {
    if (!provider) return;
    const denied = new VaultTransitProvider({ baseUrl, token: 'not-a-real-token', mount });
    await expect(denied.createKey(`rc-test-denied-${Date.now()}`, 'Ed25519')).rejects.toThrow('403');
    await expect(denied.sign('rc-anything', 'Ed25519', Buffer.from('x'))).rejects.toThrow('403');
  });

  it.each(['Ed25519', 'P-256'] as const)(
    'keeps signing with the published key version even if the key is rotated inside Vault (%s)',
    async (alg) => {
      if (!provider) return;
      const ref = `rc-test-drift-${alg === 'Ed25519' ? 'ed' : 'ec'}-${Date.now()}`;
      const published = await provider.createKey(ref, alg); // what the DID document carries
      await axios.post(`${baseUrl.replace(/\/$/, '')}/${mount}/keys/${ref}/rotate`, {}, { headers: { 'X-Vault-Token': token } });
      const data = Buffer.from('signed after a Vault-side rotation');
      const sig = await provider.sign(ref, alg, data);
      expect(verifyWithJwk(alg, published, data, sig)).toBe(true);
    },
  );
});
