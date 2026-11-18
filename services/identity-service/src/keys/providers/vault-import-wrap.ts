import * as crypto from 'crypto';

// Vault Transit BYOK: base64( RSA-OAEP-SHA256(ephemeralAesKey) || AES-256-KWP(ephemeralAesKey, keyDer) )
export function wrapForVaultImport(wrappingKeyPem: string, keyDer: Buffer): string {
  const ephemeral = crypto.randomBytes(32);
  const kwp = crypto.createCipheriv('id-aes256-wrap-pad', ephemeral, Buffer.from('A65959A6', 'hex'));
  const wrappedKey = Buffer.concat([kwp.update(keyDer), kwp.final()]);
  const wrappedEphemeral = crypto.publicEncrypt(
    { key: wrappingKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' } as any,
    ephemeral,
  );
  ephemeral.fill(0);
  return Buffer.concat([wrappedEphemeral, wrappedKey]).toString('base64');
}
