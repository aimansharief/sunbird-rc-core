import { Injectable, Logger } from "@nestjs/common";
const Vault = require("hashi-vault-js");

// Vault connectivity for the health check only. Signing keys live in Vault Transit and are used through
// src/keys/providers/vault-transit.provider.ts; identity-service does not use the KV secrets engine.
@Injectable()
export class VaultService {
  private vault: any;
  constructor() {
    this.vault = new Vault({
      https: false,
      baseUrl: process.env.VAULT_BASE_URL,
      timeout: process.env.VAULT_TIMEOUT,
      proxy: process.env.VAULT_PROXY === "true" ? true : false,
    });
  }

  async checkStatus() {
    let status;
    try {
      status = await this.vault.healthCheck();
    } catch (err) {
      Logger.error(`Error in checking vault status: ${err}`);
    }
    return { status };
  }
}
