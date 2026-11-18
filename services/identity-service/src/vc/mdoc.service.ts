import { HttpException, Injectable, Logger, NotFoundException, InternalServerErrorException } from '@nestjs/common';
import { PrismaService } from '../utils/prisma.service';
import { SigningService } from '../keys/signing.service';
import { KeyRegistryService } from '../keys/key-registry.service';
import { SignContext } from '../keys/sign-context';
import { Identity } from '@prisma/client';
import * as nodeCrypto from 'crypto';
// @types/node is pinned to 16.0.0 in this service (predates the `webcrypto`
// named export) even though the runtime is Node 20 and has it — cast rather
// than bump a repo-wide type dependency for one file.
const webcrypto: any = (nodeCrypto as any).webcrypto;
import { Document, parse } from '@auth0/mdl';
import { Verifier } from '@auth0/mdl';
import * as x509 from '@peculiar/x509';

// mso_mdoc (ISO/IEC 18013-5) issuance and verification. Kept separate from
// jwt.service.ts/vc.service.ts since mdoc is CBOR/COSE, not JOSE/JSON-LD —
// a genuinely different wire format, not just another proof suite.
@Injectable()
export class MdocService {
  private readonly logger = new Logger(MdocService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly signing: SigningService,
    private readonly registry: KeyRegistryService,
  ) {}

  // Finds the signer DID's active P-256 (JsonWebKey2020) key. Only its public
  // half is read here; the private key stays in the KeyProvider.
  private async getSignerKey(signerDID: string): Promise<{ keyId: string; publicKeyJwk: any }> {
    let did: Identity;
    try {
      did = await this.prisma.identity.findUnique({ where: { id: signerDID } });
    } catch (err) {
      this.logger.error('Error fetching signerDID:', err);
      throw new InternalServerErrorException('Error fetching signerDID');
    }
    if (!did) throw new NotFoundException('Signer DID not found!');

    const didDoc = JSON.parse(did.didDoc as string);
    const active = await this.registry.findActive(signerDID, 'P-256');
    const vm = active && (didDoc.verificationMethod || []).find((v: any) => v.id === active.id && v.publicKeyJwk);
    if (!vm) {
      throw new NotFoundException(
        `DID '${signerDID}' has no JsonWebKey2020 (EC P-256) verification method — required for mso_mdoc issuance`,
      );
    }
    return { keyId: vm.id, publicKeyJwk: vm.publicKeyJwk };
  }

  // Generates a fresh self-signed X.509 cert wrapping the issuer's own
  // public key. This deployment has no real IACA root chain (same trust
  // model as every other format here: we trust our own DIDs' key material
  // directly, not a PKI) — verification correspondingly always passes
  // `disableCertificateChainValidation: true`, so the cert only needs to
  // correctly wrap the actual signing key, not chain to anything.
  // The certificate signature is made by the KeyProvider: @peculiar/x509 is
  // given a crypto object whose subtle.sign is routed to SigningService.
  private async buildSelfSignedCert(
    signerDID: string,
    keyId: string,
    publicKeyJwk: any,
    ctx: SignContext,
  ): Promise<string> {
    const subtle = webcrypto.subtle;
    const publicKey = await subtle.importKey(
      'jwk',
      publicKeyJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify'],
    );
    const signing = this.signing;
    // WebCrypto ECDSA = sign SHA-256(data), return P1363 r||s: the same contract as SigningService for P-256.
    const remoteCrypto = {
      getRandomValues: (a: any) => webcrypto.getRandomValues(a),
      subtle: new Proxy(subtle, {
        get(target: any, prop: string) {
          if (prop === 'sign') {
            return async (_alg: any, _key: any, data: any) => {
              const bytes = ArrayBuffer.isView(data)
                ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
                : new Uint8Array(data);
              const sig = await signing.sign(keyId, bytes, 'x509', ctx);
              return sig.buffer.slice(sig.byteOffset, sig.byteOffset + sig.byteLength);
            };
          }
          const value = target[prop];
          return typeof value === 'function' ? value.bind(target) : value;
        },
      }),
    };
    const remotePrivateKey: any = {
      type: 'private', extractable: false, usages: ['sign'], algorithm: { name: 'ECDSA', namedCurve: 'P-256' },
    };
    const cert = await x509.X509CertificateGenerator.createSelfSigned(
      {
        serialNumber: Date.now().toString(16),
        // The standard org.iso.18013.5.1 (mDL) namespace requires the
        // issuer cert's subject to carry a Country (C) — found live: without
        // it, @auth0/mdl's own mDL-specific check
        // ("Country name (C) must be present...") fails even though the
        // signature itself verifies fine. Harmless placeholder for non-mDL
        // custom namespaces too.
        name: `CN=${signerDID}, C=US`,
        notBefore: new Date(),
        notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
        signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
        keys: { publicKey, privateKey: remotePrivateKey },
      },
      remoteCrypto as any,
    );
    return cert.toString('pem');
  }

  // Signs an mso_mdoc credential. Returns the base64url-encoded CBOR MDoc
  // (analogous to the compact-JWT/SD-JWT string envelope the other
  // enveloped formats use).
  async signMdoc(
    signerDID: string,
    docType: string,
    namespaces: Record<string, Record<string, any>>,
    deviceKeyJwk?: Record<string, any>,
    ctx: SignContext = {},
  ): Promise<string> {
    const { keyId, publicKeyJwk } = await this.getSignerKey(signerDID);
    await this.signing.assertCanSign(keyId, 'mdoc', ctx);
    const issuerCertificate = await this.buildSelfSignedCert(signerDID, keyId, publicKeyJwk, ctx);

    let document = new Document(docType);
    for (const [namespace, values] of Object.entries(namespaces)) {
      document = document.addIssuerNameSpace(namespace, values);
    }
    document = document.useDigestAlgorithm('SHA-256').addValidityInfo({});
    if (deviceKeyJwk) {
      document = document.addDeviceKeyInfo({ deviceKey: deviceKeyJwk as any });
    }

    try {
      // @auth0/mdl only signs with a private JWK, so it signs with a throwaway
      // key to build the COSE_Sign1 structure. The issuer signature is then
      // recomputed by the KeyProvider over the same Sig_structure (built by
      // the library's own encoder) and replaces the throwaway signature.
      const { privateKey: throwaway } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const signed = await document.sign({
        issuerPrivateKey: throwaway.export({ format: 'jwk' }) as any,
        issuerCertificate,
        alg: 'ES256',
      });
      const issuerAuth: any = signed.issuerSigned.issuerAuth;
      const toBeSigned = issuerAuth.constructor.Signature1(
        issuerAuth.encodedProtectedHeaders, new Uint8Array(), issuerAuth.payload,
      );
      issuerAuth.signature = await this.signing.sign(keyId, toBeSigned, 'mdoc', ctx);
      const { MDoc } = await import('@auth0/mdl');
      const mdoc = new MDoc([signed]);
      return mdoc.encode().toString('base64url');
    } catch (err) {
      if (err instanceof HttpException) throw err;
      this.logger.error('Error signing mdoc:', err);
      throw new InternalServerErrorException('Error signing mdoc');
    }
  }

  // Verifies a standalone mso_mdoc credential (issuer signature + per-item
  // digests) — no device/presentation context. Deliberately reuses
  // @auth0/mdl's own Verifier internals (verifyIssuerSignature/verifyData)
  // rather than reimplementing COSE_Sign1/digest verification by hand; those
  // methods are TS-`private`-annotated only (not real JS `#private`), so
  // they're runtime-accessible — the same library that built these digests
  // at signing time is the most reliable thing to check them, versus a
  // hand-rolled reimplementation of ISO 18013-5 Annex B digest matching.
  async verifyMdoc(encodedMdoc: string): Promise<{ verified: boolean; claims?: Record<string, any>; docType?: string; error?: string }> {
    try {
      const bytes = Buffer.from(encodedMdoc, 'base64url');
      const mdoc = parse(bytes);
      const doc = mdoc.documents[0];
      if (!doc) return { verified: false, error: 'No documents in mdoc' };

      const failures: any[] = [];
      const onCheck = (result: any) => {
        if (result.status === 'FAILED') failures.push(result);
      };
      const verifier: any = new Verifier([]);
      await verifier.verifyIssuerSignature(doc.issuerSigned.issuerAuth, true, onCheck);
      await verifier.verifyData(doc, onCheck);

      if (failures.length) {
        return { verified: false, error: failures.map((f) => f.check).join('; ') };
      }
      const claims: Record<string, any> = {};
      for (const ns of doc.issuerSignedNameSpaces) {
        claims[ns] = doc.getIssuerNameSpace(ns);
      }
      return { verified: true, claims, docType: doc.docType };
    } catch (err) {
      this.logger.error('Error verifying mdoc:', err);
      return { verified: false, error: `${err}` };
    }
  }
}
