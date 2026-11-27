import { BadRequestException, HttpException, Injectable, InternalServerErrorException, Logger, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../utils/prisma.service';
import { DidService } from '../did/did.service';
const { DIDDocument } = require('did-resolver');
type DIDDocument = typeof DIDDocument;
import { SigningService } from '../keys/signing.service';
import { KeyRegistryService } from '../keys/key-registry.service';
import { SignContext } from '../keys/sign-context';
import { Identity } from '@prisma/client';
import * as jsigs from '@digitalcredentials/jsonld-signatures';
import * as jsigs2 from 'jsonld-signatures';
import * as jsonld from 'jsonld';
import { DOCUMENTS } from './documents';
import { RSAKeyPair } from "crypto-ld";
const AssertionProofPurpose = jsigs.purposes.AssertionProofPurpose;
@Injectable()
export default class VcService {
  map = {
    Ed25519VerificationKey2020: null,
    JsonWebKey2020: null,
    Ed25519Signature2020: null,
    Ed25519VerificationKey2018: null,
    Ed25519Signature2018: null,
    RsaVerificationKey2018: null,
    RsaSignature2018: null,
    DataIntegrityProof: null,
    ecdsaRdfc2019: null
  };
  signTypeForKey = {
    Ed25519VerificationKey2020: "Ed25519Signature2020",
    JsonWebKey2020: "Ed25519Signature2020",
    Ed25519VerificationKey2018: "Ed25519Signature2018",
    RsaVerificationKey2018: "RsaSignature2018"
  }
  documents: object
  constructor(
    private readonly primsa: PrismaService,
    private readonly didService: DidService,
    private readonly signing: SigningService,
    private readonly registry: KeyRegistryService,
  ) {
    this.init();
  }

  async init() {
    const {Ed25519VerificationKey2020} = await import('@digitalbazaar/ed25519-verification-key-2020');
    const {Ed25519Signature2020} = await import('@digitalbazaar/ed25519-signature-2020');
    const {Ed25519VerificationKey2018} = await import('@digitalbazaar/ed25519-verification-key-2018');
    const {Ed25519Signature2018} = await import('@digitalbazaar/ed25519-signature-2018');
    this.map.Ed25519VerificationKey2020 = Ed25519VerificationKey2020;
    this.map.JsonWebKey2020 = Ed25519VerificationKey2020;
    this.map.Ed25519Signature2020 = Ed25519Signature2020;
    this.map.Ed25519VerificationKey2018 = Ed25519VerificationKey2018;
    this.map.Ed25519Signature2018 = Ed25519Signature2018;
    this.map.RsaSignature2018 = jsigs2.suites.RsaSignature2018;
    this.map.RsaVerificationKey2018 = RSAKeyPair;
    const {DataIntegrityProof} = await import('@digitalbazaar/data-integrity');
    const {cryptosuite} = await import('@digitalbazaar/ecdsa-rdfc-2019-cryptosuite');
    this.map.DataIntegrityProof = DataIntegrityProof;
    this.map.ecdsaRdfc2019 = cryptosuite;
  }

  async sign(signerDID: string, toSign: object, ctx: SignContext = {}) {
    let did: Identity;
    try {
      did = await this.primsa.identity.findUnique({
        where: { id: signerDID },
      });
    } catch (err) {
      Logger.error('Error fetching signerDID:', err);
      throw new InternalServerErrorException(`Error fetching signerDID`);
    }

    if (!did) throw new NotFoundException('Signer DID not found!');

    const didDoc = (JSON.parse(did.didDoc as string) as DIDDocument);
    // Ed25519 signs with Ed25519Signature2020/2018; P-256 (e.g. Azure Key Vault) with DataIntegrityProof / ecdsa-rdfc-2019.
    const active = (await this.registry.findActive(signerDID, 'Ed25519')) ?? (await this.registry.findActive(signerDID, 'P-256'));
    if (!active) {
      throw new BadRequestException(
        `DID '${signerDID}' has no active Ed25519 or P-256 signing key (RSA is not supported). ` +
        'If this DID predates this release, its keys must be migrated to the key provider first.',
      );
    }
    await this.signing.assertCanSign(active.id, 'ldp_vc', ctx);
    const verificationMethod = (didDoc.verificationMethod || []).find((vm: any) => vm.id === active.id);
    const isP256 = active.algorithm === 'P-256';
    const signatureType = isP256 ? 'DataIntegrityProof' : this.signTypeForKey[verificationMethod?.type];
    if (!verificationMethod || !signatureType || signatureType === 'RsaSignature2018') {
      throw new InternalServerErrorException(`Active key '${active.id}' has no usable verification method on the DID document`);
    }
    if (!this.map[signatureType]) await this.init();

    // The suite canonicalises and hashes the document; only those bytes are sent to the key provider.
    const signer = {
      id: verificationMethod.id,
      algorithm: active.algorithm,
      sign: async ({ data }: { data: Uint8Array }) => this.signing.sign(verificationMethod.id, data, 'ldp_vc', ctx),
    };
    try {
      return await jsigs.sign({...toSign}, {
        purpose: new AssertionProofPurpose(),
        suite: isP256
          ? new this.map.DataIntegrityProof({ signer, cryptosuite: this.map.ecdsaRdfc2019 })
          : new this.map[signatureType]({ signer }),
        documentLoader: this.getDocumentLoader(didDoc),
        addSuiteContext: true,
        compactProof: false
      });
    } catch (err) {
      if (err instanceof HttpException) throw err;
      Logger.error('Error signing the document:', err);
      throw new InternalServerErrorException(`Error signing the document`);
    }
  }

  async verify(signerDID: string, signedDoc: any): Promise<boolean> {
    let didDocument: DIDDocument;
    try {
      didDocument = await this.didService.resolveDID(signerDID);
    } catch (err) {
      Logger.error(`Error resolving signer did: `, err);
      throw new InternalServerErrorException(`Error resolving signer did`);
    }

    try {
      const verificationMethod =
        (didDocument.verificationMethod || []).find((vm: any) => vm.id === signedDoc?.proof?.verificationMethod)
        ?? didDocument.verificationMethod[0];
      const suite = await this.getSuite(verificationMethod, signedDoc?.proof?.type);
      const signatures = verificationMethod.type === "RsaVerificationKey2018" ? jsigs2: jsigs;
      const results = await signatures.verify(signedDoc, {
        purpose: new AssertionProofPurpose(),
        suite: [suite],
        documentLoader: this.getDocumentLoader(didDocument),
        compactProof: false
      });
      return !!results?.verified;
    } catch (e) {
      Logger.error(e);
      return false;
    }
  }

  async getSuite(verificationMethod, signatureType: string) {
    const supportedSignatures = {
      "Ed25519Signature2020": ["Ed25519VerificationKey2020", "JsonWebKey2020", "Ed25519VerificationKey2018"],
      "Ed25519Signature2018": ["Ed25519VerificationKey2018"],
      "RsaSignature2018": ["RsaVerificationKey2018"],
      "DataIntegrityProof": ["JsonWebKey2020"],
    };
    if(!(signatureType in supportedSignatures)) {
      throw new NotFoundException("Suite for signature type not found");
    }
    if(!supportedSignatures[signatureType].includes(verificationMethod?.type)) {
      throw new NotFoundException("Suite for verification type not found");
    }
    if(!supportedSignatures[signatureType]) await this.init();
    if(signatureType === "DataIntegrityProof") {
      // The verifier reads the public key from the verification method itself (via the document loader).
      return new this.map.DataIntegrityProof({cryptosuite: this.map.ecdsaRdfc2019});
    }
    let keyPair = await this.map[verificationMethod?.type].from(verificationMethod);
    return new this.map[signatureType]({key: keyPair});
  }

  getDocumentLoader(didDoc: DIDDocument) {
    return jsigs.extendContextLoader(async url => {
      if(url === didDoc?.id) {
        return {
          contextUrl: null,
          documentUrl: url,
          document: didDoc
        };
      }
      // Verification-method URLs (did:...#key-0); DataIntegrityProof loads these directly.
      const vm = url.includes('#') && (didDoc?.verificationMethod || []).find((v: any) => v.id === url);
      if(vm) {
        return {
          contextUrl: null,
          documentUrl: url,
          document: { '@context': didDoc['@context'], ...vm }
        };
      }
      if(DOCUMENTS[url]) {
        return {
          contextUrl: null,
          documentUrl: url,
          document: DOCUMENTS[url]
        }
      }
      return await jsonld.documentLoaders.node()(url);
    })
  }
}
