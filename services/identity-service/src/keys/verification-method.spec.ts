import * as crypto from 'crypto';
import {
  algorithmForVmType, buildVerificationMethod, isSupportedVmType, publicJwkFromVerificationMethod,
} from './verification-method';

describe('verification-method', () => {
  const did = 'did:test:vm';
  const ed: any = crypto.generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' } as any);
  const ec: any = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' } as any);
  const edJwk = { kty: 'OKP', crv: 'Ed25519', x: ed.x };
  const ecJwk = { kty: 'EC', crv: 'P-256', x: ec.x, y: ec.y };

  it('builds an Ed25519VerificationKey2020 that matches the digitalbazaar format', async () => {
    const vm = buildVerificationMethod(`${did}#key-0`, did, 'Ed25519VerificationKey2020', edJwk);
    expect(vm).toMatchObject({
      '@context': 'https://w3id.org/security/suites/ed25519-2020/v1',
      id: `${did}#key-0`, type: 'Ed25519VerificationKey2020', controller: did,
    });
    expect(vm.publicKeyMultibase.startsWith('z6Mk')).toBe(true);
    const { Ed25519VerificationKey2020 } = await import('@digitalbazaar/ed25519-verification-key-2020');
    const kp = await Ed25519VerificationKey2020.from(vm);
    expect(kp.publicKeyMultibase).toBe(vm.publicKeyMultibase);
    expect(publicJwkFromVerificationMethod(vm)).toEqual(edJwk);
  });

  it('builds Ed25519VerificationKey2018 and JsonWebKey2020 and reads them back', () => {
    const vm2018 = buildVerificationMethod(`${did}#key-0`, did, 'Ed25519VerificationKey2018', edJwk);
    expect(typeof vm2018.publicKeyBase58).toBe('string');
    expect(publicJwkFromVerificationMethod(vm2018)).toEqual(edJwk);
    const vmJwk = buildVerificationMethod(`${did}#key-0`, did, 'JsonWebKey2020', ecJwk);
    expect(vmJwk.publicKeyJwk).toEqual(ecJwk);
    expect(publicJwkFromVerificationMethod(vmJwk)).toEqual(ecJwk);
  });

  it('maps types to algorithms and rejects RSA', () => {
    expect(algorithmForVmType('JsonWebKey2020')).toBe('P-256');
    expect(algorithmForVmType('Ed25519VerificationKey2018')).toBe('Ed25519');
    expect(isSupportedVmType('RsaVerificationKey2018')).toBe(false);
    expect(() => buildVerificationMethod('x', did, 'Ed25519VerificationKey2020', ecJwk)).toThrow();
  });
});
