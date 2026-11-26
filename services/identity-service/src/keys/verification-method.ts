import type { JWK } from 'jose';
import { base58Decode, base58Encode, ed25519JwkFromRaw, ed25519RawFromJwk } from './encoding';
import { KeyAlgorithm } from './key-provider';

export type SupportedVmType = 'Ed25519VerificationKey2020' | 'Ed25519VerificationKey2018' | 'JsonWebKey2020';
const ED25519_PUB_MULTICODEC = [0xed, 0x01];

export function isSupportedVmType(type: string): type is SupportedVmType {
  return ['Ed25519VerificationKey2020', 'Ed25519VerificationKey2018', 'JsonWebKey2020'].includes(type);
}

const DEFAULT_VM_TYPE_FOR_SIGNING_ALGORITHM: Record<string, string> = {
  Ed25519Signature2020: 'Ed25519VerificationKey2020',
  Ed25519Signature2018: 'Ed25519VerificationKey2018',
  JsonWebSignature2020: 'JsonWebKey2020',
  RsaSignature2018: 'RsaVerificationKey2018',
};

// Key type used when POST /did/generate has no keyPairType.
export function defaultVmType(signingAlgorithm?: string): string {
  return DEFAULT_VM_TYPE_FOR_SIGNING_ALGORITHM[signingAlgorithm || ''] || 'Ed25519VerificationKey2020';
}

export function algorithmForVmType(type: SupportedVmType): KeyAlgorithm {
  return type === 'JsonWebKey2020' ? 'P-256' : 'Ed25519';
}

export function buildVerificationMethod(id: string, controller: string, type: SupportedVmType, jwk: JWK): any {
  switch (type) {
    case 'Ed25519VerificationKey2020': {
      const raw = ed25519RawFromJwk(jwk);
      return {
        '@context': 'https://w3id.org/security/suites/ed25519-2020/v1',
        id, type, controller,
        publicKeyMultibase: 'z' + base58Encode(new Uint8Array([...ED25519_PUB_MULTICODEC, ...raw])),
      };
    }
    case 'Ed25519VerificationKey2018':
      return {
        '@context': 'https://w3id.org/security/suites/ed25519-2018/v1',
        id, type, controller,
        publicKeyBase58: base58Encode(ed25519RawFromJwk(jwk)),
      };
    case 'JsonWebKey2020':
      if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw new Error('JsonWebKey2020 requires a P-256 JWK');
      return { id, type, controller, publicKeyJwk: { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y } };
  }
}

export function publicJwkFromVerificationMethod(vm: any): JWK {
  switch (vm?.type) {
    case 'Ed25519VerificationKey2020': {
      const bytes = base58Decode(String(vm.publicKeyMultibase).slice(1));
      return ed25519JwkFromRaw(bytes.slice(2));
    }
    case 'Ed25519VerificationKey2018':
      return ed25519JwkFromRaw(base58Decode(vm.publicKeyBase58));
    case 'JsonWebKey2020':
      return { kty: vm.publicKeyJwk.kty, crv: vm.publicKeyJwk.crv, x: vm.publicKeyJwk.x, y: vm.publicKeyJwk.y };
    default:
      throw new Error(`Unsupported verification method type ${vm?.type}`);
  }
}
