import { InternalServerErrorException, Logger } from '@nestjs/common';
import { VaultService } from './vault.service';
const Vault = require('hashi-vault-js');

jest.mock('hashi-vault-js');

describe('VaultService', () => {
  let vaultService: VaultService;
  let mockVault: any;

  beforeEach(() => {
    vaultService = new VaultService();
    mockVault = new Vault();
    (vaultService as any).vault = mockVault;
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('should be defined', () => {
    expect(vaultService).toBeDefined();
  });

  describe('checkStatus', () => {
    it('should return status and vault_config', async () => {
      const status = { sealed: false, initialized: true };
      const vault_config = { example: 'config' };
      jest.spyOn(mockVault, 'healthCheck').mockResolvedValueOnce(status);
      jest.spyOn(mockVault, 'readKVEngineConfig').mockResolvedValueOnce(vault_config);

      const result = await vaultService.checkStatus();

      expect(result).toEqual({ status, vault_config });
      expect(mockVault.healthCheck).toHaveBeenCalled();
      expect(mockVault.readKVEngineConfig).toHaveBeenCalledWith((vaultService as any).token);
    });

    it('should handle errors and return default values', async () => {
      jest.spyOn(mockVault, 'healthCheck').mockRejectedValueOnce(new Error('Health check failed'));
      jest.spyOn(mockVault, 'readKVEngineConfig').mockRejectedValueOnce(new Error('Config read failed'));
      const loggerErrorSpy = jest.spyOn(Logger, 'error').mockImplementation();

      const result = await vaultService.checkStatus();

      expect(result).toEqual({ status: undefined, vault_config: undefined });
      expect(loggerErrorSpy).toHaveBeenCalledTimes(2);
      expect(loggerErrorSpy).toHaveBeenCalledWith('Error in checking vault status: Error: Health check failed');
      expect(loggerErrorSpy).toHaveBeenCalledWith('Error in checking vault config: Error: Config read failed');
    });
  });
});
