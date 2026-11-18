import * as crypto from 'crypto';
import {
  b64url, fromB64url, base58Encode, base58Decode, derToP1363,
  ed25519JwkFromRaw, ed25519RawFromJwk, publicJwkFromPem, ecPointToJwk,
} from './encoding';

describe('encoding', () => {
  it('base58 matches the standard test vector and round-trips leading zeros', () => {
    expect(base58Encode(Buffer.from('hello world'))).toBe('StV1DL6CwTryKyV');
    const bytes = new Uint8Array([0, 0, 1, 2, 255]);
    expect(Array.from(base58Decode(base58Encode(bytes)))).toEqual(Array.from(bytes));
    expect(() => base58Decode('0OIl')).toThrow('Invalid base58 character');
  });

  it('base64url round-trips', () => {
    const bytes = crypto.randomBytes(33);
    expect(Buffer.from(fromB64url(b64url(bytes))).equals(bytes)).toBe(true);
  });

  it('converts a DER ECDSA signature to a P1363 signature that node verifies', () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const data = Buffer.from('payload');
    const der = crypto.sign('sha256', data, privateKey); // DER by default
    const p1363 = derToP1363(der);
    expect(p1363.length).toBe(64);
    expect(crypto.verify('sha256', data, { key: publicKey, dsaEncoding: 'ieee-p1363' } as any, Buffer.from(p1363))).toBe(true);
  });

  it('builds Ed25519 and P-256 JWKs that node accepts', () => {
    const ed = crypto.generateKeyPairSync('ed25519');
    const edJwk: any = ed.publicKey.export({ format: 'jwk' } as any);
    const raw = ed25519RawFromJwk(edJwk);
    expect(raw.length).toBe(32);
    expect(ed25519JwkFromRaw(raw)).toEqual({ kty: 'OKP', crv: 'Ed25519', x: edJwk.x });

    const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pem = ec.publicKey.export({ format: 'pem', type: 'spki' }) as string;
    const ecJwk: any = ec.publicKey.export({ format: 'jwk' } as any);
    expect(publicJwkFromPem(pem)).toEqual({ kty: 'EC', crv: 'P-256', x: ecJwk.x, y: ecJwk.y });
    const point = Buffer.concat([Buffer.from([4]), Buffer.from(fromB64url(ecJwk.x)), Buffer.from(fromB64url(ecJwk.y))]);
    expect(ecPointToJwk(point)).toEqual({ kty: 'EC', crv: 'P-256', x: ecJwk.x, y: ecJwk.y });
  });
});
