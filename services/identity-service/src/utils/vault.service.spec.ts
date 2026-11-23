import { Logger } from '@nestjs/common';
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

  it('is created without a KV mount path (keys live in Transit; KV is not used)', () => {
    const args = (Vault as jest.Mock).mock.calls[(Vault as jest.Mock).mock.calls.length - 2][0];
    expect(args.rootPath).toBeUndefined();
  });

  describe('checkStatus', () => {
    it('returns Vault health only and never reads the KV engine', async () => {
      const status = { sealed: false, initialized: true };
      jest.spyOn(mockVault, 'healthCheck').mockResolvedValueOnce(status);
      const kvSpy = jest.spyOn(mockVault, 'readKVEngineConfig');

      const result = await vaultService.checkStatus();

      expect(result).toEqual({ status });
      expect(mockVault.healthCheck).toHaveBeenCalled();
      expect(kvSpy).not.toHaveBeenCalled();
    });

    it('logs once and returns undefined status when Vault is unreachable', async () => {
      jest.spyOn(mockVault, 'healthCheck').mockRejectedValueOnce(new Error('Health check failed'));
      const loggerErrorSpy = jest.spyOn(Logger, 'error').mockImplementation();

      const result = await vaultService.checkStatus();

      expect(result).toEqual({ status: undefined });
      expect(loggerErrorSpy).toHaveBeenCalledTimes(1);
      expect(loggerErrorSpy).toHaveBeenCalledWith('Error in checking vault status: Error: Health check failed');
    });
  });
});
