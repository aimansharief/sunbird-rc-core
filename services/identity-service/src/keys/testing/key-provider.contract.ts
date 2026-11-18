import * as crypto from 'crypto';
import type { JWK } from 'jose';
import { v4 as uuid } from 'uuid';
import { KEY_ALGORITHMS, KeyAlgorithm, KeyProvider } from '../key-provider';

export function verifyWithJwk(alg: KeyAlgorithm, jwk: JWK, data: Uint8Array, sig: Uint8Array): boolean {
  const key = crypto.createPublicKey({ key: jwk, format: 'jwk' } as any);
  return alg === 'Ed25519'
    ? crypto.verify(null, Buffer.from(data), key, Buffer.from(sig))
    : crypto.verify('sha256', Buffer.from(data), { key, dsaEncoding: 'ieee-p1363' } as any, Buffer.from(sig));
}

const newRef = (alg: KeyAlgorithm) =>
  `rc-contract-${alg === 'Ed25519' ? 'ed' : 'p256'}-${uuid().replace(/-/g, '')}`.slice(0, 60);

// Every KeyProvider implementation runs this suite. A provider is "supported" only when it passes.
export function describeKeyProviderContract(
  label: string,
  factory: () => Promise<KeyProvider | null>,
  options: { cleanup?: (keyRefs: string[]) => Promise<void> } = {},
) {
  describe(`KeyProvider contract: ${label}`, () => {
    let provider: KeyProvider | null;
    let caps: KeyAlgorithm[] = [];
    const created: string[] = [];

    beforeAll(async () => {
      provider = await factory();
      if (!provider) {
        console.warn(`[contract] ${label}: backend not available, skipping`);
        return;
      }
      caps = await provider.capabilities();
    });

    afterAll(async () => {
      if (provider && options.cleanup && created.length) await options.cleanup(created);
    });

    it('advertises at least one supported algorithm', () => {
      if (!provider) return;
      expect(caps.length).toBeGreaterThan(0);
      caps.forEach((c) => expect(KEY_ALGORITHMS).toContain(c));
    });

    it('creates keys whose signatures verify with the returned public JWK', async () => {
      if (!provider) return;
      for (const alg of caps) {
        const ref = newRef(alg);
        created.push(ref);
        const jwk = await provider.createKey(ref, alg);
        expect((jwk as any).d).toBeUndefined(); // never private material
        expect(jwk).toEqual(await provider.getPublicKey(ref, alg));
        const data = crypto.randomBytes(200);
        const sig = await provider.sign(ref, alg, data);
        expect(sig.length).toBe(64);
        expect(verifyWithJwk(alg, jwk, data, sig)).toBe(true);
        expect(verifyWithJwk(alg, jwk, Buffer.from('tampered'), sig)).toBe(false);
      }
    });

    it('rejects algorithms it does not advertise', async () => {
      if (!provider) return;
      for (const alg of KEY_ALGORITHMS.filter((a) => !caps.includes(a))) {
        await expect(provider.createKey(newRef(alg), alg)).rejects.toThrow();
      }
    });

    it('rejects signing with an unknown key', async () => {
      if (!provider) return;
      await expect(provider.sign(newRef(caps[0]), caps[0], Buffer.from('x'))).rejects.toThrow();
    });

    it('imports PKCS#8 keys (if supported) and signs with the imported key', async () => {
      if (!provider || !provider.importKey) return;
      for (const alg of caps) {
        const pair = alg === 'Ed25519'
          ? crypto.generateKeyPairSync('ed25519')
          : crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
        const der = pair.privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer;
        const original: any = pair.publicKey.export({ format: 'jwk' } as any);
        const ref = newRef(alg);
        created.push(ref);
        const jwk: any = await provider.importKey(ref, alg, der);
        expect(jwk.x).toBe(original.x);
        const data = crypto.randomBytes(64);
        expect(verifyWithJwk(alg, original, data, await provider.sign(ref, alg, data))).toBe(true);
      }
    });
  });
}
