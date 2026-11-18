import axios from 'axios';
import { describeKeyProviderContract } from '../testing/key-provider.contract';
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
