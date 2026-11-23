import {
  Injectable,
  InternalServerErrorException,
  Logger,
  NotFoundException,
  BadRequestException,
  HttpException,
} from '@nestjs/common';
import { PrismaService } from '../utils/prisma.service';
import { resolveSelfContainedDidToJwk } from '../utils/self-contained-did.util';
import { KeyAlreadyRegisteredError, SigningService } from '../keys/signing.service';
import { KeyRegistryService } from '../keys/key-registry.service';
import { SignContext } from '../keys/sign-context';
import { DidService } from '../did/did.service';
import { Identity } from '@prisma/client';
import * as crypto from 'crypto';
import * as jose from 'jose';

const ES256 = 'ES256';
const SD_ALG = 'sha-256';

export interface SdJwtVerifyResult {
  verified: boolean;
  claims?: Record<string, any>;
  error?: string;
}

// JWS/JWT + SD-JWT signing for OID4VC formats (jwt_vc_json, vc+sd-jwt).
// Additive to the existing JSON-LD signing path in VcService:
// - P-256 (ES256) keys are appended as extra verificationMethods on the DID
//   document (index >= 1), so VcService.sign() — which uses index 0 — is untouched.
// - Private keys live in the configured KeyProvider; only signatures come back.
@Injectable()
export class JwtSignerService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly didService: DidService,
    private readonly signing: SigningService,
    private readonly registry: KeyRegistryService,
  ) {}

  // Returns the DID's ACTIVE P-256 key, creating '#jwt-key-1' inside the KeyProvider if it has none.
  async ensureES256Key(signerDID: string, ctx: SignContext = {}): Promise<{ kid: string }> {
    let identity: Identity;
    try {
      identity = await this.prisma.identity.findUnique({
        where: { id: signerDID },
      });
    } catch (err) {
      Logger.error('Error fetching signerDID:', err);
      throw new InternalServerErrorException('Error fetching signerDID');
    }
    if (!identity) throw new NotFoundException('Signer DID not found!');

    const active = await this.registry.findActive(signerDID, 'P-256');
    if (active) return { kid: active.id };

    const didDoc = this.parseDidDoc(identity);
    const legacy = (didDoc.verificationMethod || []).find(
      (vm: any) => vm?.publicKeyJwk?.crv === 'P-256',
    );
    if (legacy) {
      throw new InternalServerErrorException(
        `P-256 key '${legacy.id}' exists on the DID but not in the key registry; it must be migrated to the key provider before it can sign`,
      );
    }
    return this.generateES256Key(signerDID, didDoc, ctx);
  }

  private async generateES256Key(signerDID: string, didDoc: any, ctx: SignContext) {
    const kid = `${signerDID}#jwt-key-1`;
    const existing = await this.registry.listByDid(signerDID);
    const authority = existing[0]?.authority ?? ctx.authority;
    let jwk: jose.JWK;
    try {
      jwk = await this.signing.createKey({ keyId: kid, did: signerDID, algorithm: 'P-256', authority });
    } catch (err) {
      // A concurrent request created this DID's JWT key first; use it (it also updates the DID document).
      if (err instanceof KeyAlreadyRegisteredError) return { kid };
      throw err;
    }
    const verificationMethod = {
      id: kid,
      type: 'JsonWebKey2020',
      controller: signerDID,
      publicKeyJwk: { ...jwk, alg: ES256, use: 'sig', kid },
    };
    didDoc.verificationMethod = [
      ...(didDoc.verificationMethod || []),
      verificationMethod,
    ];
    // `assertionMethod` covers signing credentials; `authentication` covers the
    // DID authenticating *itself*, which is what signing an OpenID4VP request
    // object (JAR) with a `did:` client_id is. Without the authentication
    // entry, a conformant wallet resolves the DID, fails to find this key in
    // that relationship, and rejects the request with a "verification method
    // not found in purpose 'authentication'" error. This ES256 key is
    // legitimately used for both purposes.
    didDoc.assertionMethod = [...(didDoc.assertionMethod || []), kid];
    didDoc.authentication = [...(didDoc.authentication || []), kid];

    try {
      await this.prisma.identity.update({
        where: { id: signerDID },
        data: { didDoc: JSON.stringify(didDoc) },
      });
    } catch (err) {
      Logger.error(`Error updating DID document with ES256 key: ${err}`);
      await this.signing.discardKey(kid).catch(() => undefined);
      throw new InternalServerErrorException('Error updating DID document');
    }
    return { kid };
  }

  // Signs an arbitrary JSON payload as a compact JWS (ES256). The signing input
  // is sent to the key provider; the private key never enters this process.
  // The caller controls the claim set; only alg/kid/typ go in the header.
  async signJwt(
    signerDID: string,
    payload: object,
    header: Record<string, any> = {},
    ctx: SignContext = {},
  ): Promise<string> {
    const { kid } = await this.ensureES256Key(signerDID, ctx);
    const encodedHeader = jose.base64url.encode(JSON.stringify({ ...header, alg: ES256, kid }));
    const encodedPayload = jose.base64url.encode(JSON.stringify(payload));
    try {
      const signature = await this.signing.sign(
        kid, new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`), 'jwt', ctx,
      );
      return `${encodedHeader}.${encodedPayload}.${jose.base64url.encode(signature)}`;
    } catch (err) {
      if (err instanceof HttpException) throw err;
      Logger.error('Error signing JWT:', err);
      throw new InternalServerErrorException('Error signing JWT');
    }
  }

  // Verifies a compact JWS against the signer's DID document (kid header,
  // or an explicitly provided DID). Returns the decoded payload on success.
  async verifyJwt(
    token: string,
    signerDID?: string,
  ): Promise<{ verified: boolean; payload?: any; error?: string }> {
    try {
      const header = jose.decodeProtectedHeader(token);
      const kid = header.kid;
      const did = signerDID || (kid ? kid.split('#')[0] : undefined);
      if (!did) return { verified: false, error: 'No kid header or DID given' };
      const didDoc = await this.didService.resolveDID(did);
      const vms = (didDoc.verificationMethod || []).filter(
        (vm: any) => vm?.publicKeyJwk,
      );
      // A `kid` that names a verification method not on this DID document
      // must fail closed, not silently fall back to the DID's first key — a
      // DID can carry multiple keys for different purposes (e.g. an mdoc EC
      // key at #key-0 alongside a JWT signing key at #jwt-key-1), and falling
      // back would let a signature made for one purpose validate as if it
      // were made for another, or hide the fact that the token referenced an
      // unknown/rotated key entirely.
      const vm = kid ? vms.find((m: any) => m.id === kid) : vms[0];
      if (!vm) {
        return {
          verified: false,
          error: kid ? `No verification method matching kid '${kid}'` : 'No JWK verification method on DID',
        };
      }
      // Pinned rather than trusting header.alg: this service only ever signs
      // ES256, so honoring an attacker-controlled alg from the header buys
      // nothing and only widens the algorithm-confusion attack surface.
      const key = await jose.importJWK(vm.publicKeyJwk, ES256);
      const { payload } = await jose.compactVerify(token, key);
      return { verified: true, payload: JSON.parse(new TextDecoder().decode(payload)) };
    } catch (err) {
      return { verified: false, error: `${err}` };
    }
  }

  // --- SD-JWT (vc+sd-jwt) --------------------------------------------------

  // Issues an SD-JWT: claims listed in `disclosable` are replaced by salted
  // SHA-256 digests in `_sd`; each disclosure travels alongside the JWT.
  // Output: <issuer-jws>~<disclosure-1>~...~<disclosure-n>~
  async signSdJwt(
    signerDID: string,
    payload: Record<string, any>,
    disclosable: string[] = [],
    header: Record<string, any> = {},
    ctx: SignContext = {},
  ): Promise<string> {
    const sdPayload: Record<string, any> = { ...payload };
    const disclosures: string[] = [];
    const digests: string[] = [];

    for (const claim of disclosable) {
      if (!(claim in sdPayload)) continue;
      const salt = jose.base64url.encode(crypto.randomBytes(16));
      const disclosure = jose.base64url.encode(
        JSON.stringify([salt, claim, sdPayload[claim]]),
      );
      disclosures.push(disclosure);
      digests.push(this.disclosureDigest(disclosure));
      delete sdPayload[claim];
    }

    if (digests.length) {
      sdPayload._sd = digests.sort();
      sdPayload._sd_alg = SD_ALG;
    }

    const jws = await this.signJwt(signerDID, sdPayload, {
      typ: 'vc+sd-jwt',
      ...header,
    }, ctx);
    return [jws, ...disclosures, ''].join('~');
  }

  // Verifies an SD-JWT (optionally with key-binding JWT) and reconstructs the
  // disclosed claims. KB-JWT nonce/audience checks are the caller's contract.
  async verifySdJwt(
    sdJwt: string,
    signerDID?: string,
    keyBinding?: { nonce?: string; audience?: string },
  ): Promise<SdJwtVerifyResult> {
    try {
      const endsWithTilde = sdJwt.endsWith('~');
      const parts = sdJwt.split('~');
      const jws = parts[0];
      // If the string does NOT end with '~', the final segment is a KB-JWT.
      const kbJwt = endsWithTilde ? null : parts.pop();
      const disclosures = parts.slice(1).filter((d) => d.length > 0);

      const jwsResult = await this.verifyJwt(jws, signerDID);
      if (!jwsResult.verified) {
        return { verified: false, error: `Issuer signature invalid: ${jwsResult.error}` };
      }
      const payload = jwsResult.payload;
      const sdDigests: string[] = payload._sd || [];

      const claims: Record<string, any> = { ...payload };
      delete claims._sd;
      delete claims._sd_alg;

      for (const disclosure of disclosures) {
        const digest = this.disclosureDigest(disclosure);
        if (!sdDigests.includes(digest)) {
          return { verified: false, error: 'Disclosure digest not found in _sd' };
        }
        const [, name, value] = JSON.parse(
          new TextDecoder().decode(jose.base64url.decode(disclosure)),
        );
        claims[name] = value;
      }

      // A caller that supplies a nonce/audience to check is asking for holder
      // binding to be enforced, not merely reported if present. Without this,
      // an SD-JWT with its KB-JWT stripped (the token simply ends in '~')
      // skips the whole block below and returns verified:true with no holder
      // proof at all — letting a captured presentation be replayed against a
      // different verifier, nonce, or audience than the one it was actually
      // made for.
      if (!kbJwt && (keyBinding?.nonce || keyBinding?.audience)) {
        return {
          verified: false,
          error: 'Key Binding JWT required (nonce/audience expected) but not present in SD-JWT',
        };
      }

      if (kbJwt) {
        // Key binding is expressed either by value (`cnf.jwk`) or by reference
        // (`cnf.kid`, a DID URL) — a wallet that requested the credential with a
        // DID-bound proof gets the latter. Resolve the reference back to a key:
        // did:key/did:jwk are self-contained, anything else goes to the registry.
        let cnfJwk = payload?.cnf?.jwk;
        const cnfKid = payload?.cnf?.kid;
        if (!cnfJwk && cnfKid) {
          try {
            cnfJwk = resolveSelfContainedDidToJwk(cnfKid);
          } catch (err) {
            return { verified: false, error: `cnf.kid unresolvable: ${err}` };
          }
          if (!cnfJwk) {
            try {
              const didDoc = await this.didService.resolveDID(cnfKid.split('#')[0]);
              const vm = (didDoc.verificationMethod || []).find(
                (m: any) => m.id === cnfKid && m.publicKeyJwk,
              );
              cnfJwk = vm?.publicKeyJwk;
            } catch (err) {
              return { verified: false, error: `cnf.kid not resolvable: ${err}` };
            }
          }
        }
        if (!cnfJwk) {
          return {
            verified: false,
            error: 'KB-JWT present but SD-JWT has no resolvable cnf (jwk/kid)',
          };
        }
        try {
          const kbHeader = jose.decodeProtectedHeader(kbJwt);
          const key = await jose.importJWK(cnfJwk, (kbHeader.alg as string) || ES256);
          const { payload: kbRaw } = await jose.compactVerify(kbJwt, key);
          const kbPayload = JSON.parse(new TextDecoder().decode(kbRaw));
          if (keyBinding?.nonce && kbPayload.nonce !== keyBinding.nonce) {
            return { verified: false, error: 'KB-JWT nonce mismatch' };
          }
          if (keyBinding?.audience && kbPayload.aud !== keyBinding.audience) {
            return { verified: false, error: 'KB-JWT audience mismatch' };
          }
        } catch (err) {
          return { verified: false, error: `KB-JWT invalid: ${err}` };
        }
      }

      return { verified: true, claims };
    } catch (err) {
      return { verified: false, error: `${err}` };
    }
  }

  private disclosureDigest(disclosure: string): string {
    return jose.base64url.encode(
      crypto.createHash('sha256').update(disclosure, 'ascii').digest(),
    );
  }

  // --- JWKS ----------------------------------------------------------------

  // Public JWKs of every DID that carries a publicKeyJwk verification method.
  // Only issuer DIDs gain ES256 keys (via signJwt), so this set stays small.
  async getJwks(): Promise<{ keys: jose.JWK[] }> {
    let identities: Identity[] = [];
    try {
      identities = await this.prisma.identity.findMany({
        where: { didDoc: { string_contains: 'publicKeyJwk' } as any },
      });
    } catch (err) {
      // string_contains unsupported on this connector — fall back to full scan
      Logger.warn(`JWKS json filter failed (${err}); falling back to full scan`);
      identities = await this.prisma.identity.findMany();
    }
    const keys: jose.JWK[] = [];
    for (const identity of identities) {
      let didDoc: any;
      try {
        didDoc = this.parseDidDoc(identity);
      } catch {
        continue;
      }
      for (const vm of didDoc?.verificationMethod || []) {
        // Only JWT-signing keys (added by ensureES256Key/generateES256Key
        // above, kid suffix '#jwt-key-1') belong in a JWKS meant for JWS
        // verification — a DID's base signing key (e.g. mdoc's '#key-0'
        // EC key, or an Ed25519/RSA LD-proof key) has publicKeyJwk too in
        // the mdoc case, but has nothing to do with what a relying party
        // fetching this endpoint needs.
        if (vm?.publicKeyJwk && typeof vm.id === 'string' && /#jwt-key-\d+$/.test(vm.id)) {
          keys.push({ ...vm.publicKeyJwk, kid: vm.publicKeyJwk.kid || vm.id });
        }
      }
    }
    return { keys };
  }

  private parseDidDoc(identity: Identity): any {
    const raw = identity.didDoc;
    if (typeof raw === 'string') return JSON.parse(raw);
    if (raw && typeof raw === 'object') return raw;
    throw new BadRequestException('Malformed DID document');
  }
}
