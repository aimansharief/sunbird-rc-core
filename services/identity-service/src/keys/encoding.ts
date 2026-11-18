import * as crypto from 'crypto';
import * as jose from 'jose';
import type { JWK } from 'jose';

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export const b64url = (u: Uint8Array): string => jose.base64url.encode(u);
export const fromB64url = (s: string): Uint8Array => jose.base64url.decode(s);
export const sha256 = (data: Uint8Array): Buffer => crypto.createHash('sha256').update(data).digest();

export function base58Encode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  return '1'.repeat(zeros) + digits.reverse().map((d) => ALPHABET[d]).join('');
}

export function base58Decode(s: string): Uint8Array {
  let zeros = 0;
  while (zeros < s.length && s[zeros] === '1') zeros++;
  const bytes: number[] = [];
  for (let i = zeros; i < s.length; i++) {
    const value = ALPHABET.indexOf(s[i]);
    if (value < 0) throw new Error(`Invalid base58 character '${s[i]}'`);
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  return new Uint8Array([...new Array(zeros).fill(0), ...bytes.reverse()]);
}

// ASN.1 SEQUENCE { INTEGER r, INTEGER s } -> r||s, each left-padded to `size` bytes.
export function derToP1363(der: Uint8Array, size = 32): Uint8Array {
  let i = 0;
  if (der[i++] !== 0x30) throw new Error('Invalid DER signature: expected SEQUENCE');
  const len = der[i++];
  if (len & 0x80) i += len & 0x7f;
  const readInt = (): Uint8Array => {
    if (der[i++] !== 0x02) throw new Error('Invalid DER signature: expected INTEGER');
    const l = der[i++];
    let v = der.slice(i, i + l);
    i += l;
    while (v.length > size && v[0] === 0) v = v.slice(1);
    if (v.length > size) throw new Error('Invalid DER signature: integer too long');
    const out = new Uint8Array(size);
    out.set(v, size - v.length);
    return out;
  };
  const r = readInt();
  const s = readInt();
  const out = new Uint8Array(size * 2);
  out.set(r, 0);
  out.set(s, size);
  return out;
}

export const ed25519JwkFromRaw = (raw: Uint8Array): JWK => ({ kty: 'OKP', crv: 'Ed25519', x: b64url(raw) });

export function ed25519RawFromJwk(jwk: JWK): Uint8Array {
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || !jwk.x) throw new Error('Not an Ed25519 public JWK');
  return fromB64url(jwk.x);
}

export function publicJwkFromPem(pem: string): JWK {
  const jwk: any = crypto.createPublicKey(pem).export({ format: 'jwk' } as any);
  if (jwk.kty === 'EC') return { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y };
  if (jwk.kty === 'OKP') return { kty: 'OKP', crv: jwk.crv, x: jwk.x };
  throw new Error(`Unsupported public key type ${jwk.kty}`);
}

export function ecPointToJwk(point: Uint8Array): JWK {
  if (point.length !== 65 || point[0] !== 0x04) throw new Error('Expected an uncompressed P-256 point');
  return { kty: 'EC', crv: 'P-256', x: b64url(point.slice(1, 33)), y: b64url(point.slice(33, 65)) };
}
