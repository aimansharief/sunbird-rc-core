import { Test, TestingModule } from '@nestjs/testing';
import { AppController } from './app.controller';
import {
  HealthCheckError,
  HealthCheckService,
  HealthIndicatorResult,
  HttpHealthIndicator,
  TerminusModule,
} from '@nestjs/terminus';
import { PrismaHealthIndicator } from './utils/prisma.health';
import { VaultHealthIndicator } from './utils/vault.health';
import { HealthCheckExecutor } from '@nestjs/terminus/dist/health-check/health-check-executor.service';
import {
  ERROR_LOGGER,
  getErrorLoggerProvider,
} from '@nestjs/terminus/dist/health-check/error-logger/error-logger.provider';
import { getLoggerProvider, TERMINUS_LOGGER } from '@nestjs/terminus/dist/health-check/logger/logger.provider';
import { HttpModule } from '@nestjs/axios';
import { ServiceUnavailableException } from '@nestjs/common';

describe('AppController', () => {
  let appController: AppController;
  let prismaHealthIndicator: PrismaHealthIndicator;
  let vaultHealthIndicator: VaultHealthIndicator;

  beforeAll(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [
        HttpModule,
        TerminusModule
      ],
      controllers: [AppController],
      providers: [
        getLoggerProvider(),
        getErrorLoggerProvider(),
        HealthCheckExecutor,
        HealthCheckError,
        HealthCheckService,
        HttpHealthIndicator,
        {
          provide: PrismaHealthIndicator,
          useFactory: () => ({
            isHealthy: jest.fn(),
          }),
        },
        {
          provide: VaultHealthIndicator,
          useFactory: () => ({
            isHealthy: jest.fn(),
          }),
        },
      ],
    }).compile();

    appController = module.get<AppController>(AppController);
    prismaHealthIndicator = module.get<PrismaHealthIndicator>(PrismaHealthIndicator);
    vaultHealthIndicator = module.get<VaultHealthIndicator>(VaultHealthIndicator);
  });

  beforeEach(async () => {
    jest.restoreAllMocks();
  })

  describe('checkHealth', () => {
    it('should return a health check result with all services healthy', async () => {
      jest.spyOn(prismaHealthIndicator, 'isHealthy')
        .mockResolvedValue(new Promise((resolve) => {
          resolve({ db: { status: 'up' }} as HealthIndicatorResult);
        }));
      jest.spyOn(vaultHealthIndicator, 'isHealthy')
        .mockResolvedValue(new Promise((resolve) => {
          resolve({ vault: { status: 'up' }} as HealthIndicatorResult);
        }));
      const result = await appController.checkHealth();
      expect(result.status).toEqual('ok');
      expect(result.info.db.status).toEqual('up');
      expect(result.info.vault.status).toEqual('up');
    });

    it('should return a health check result with one service unhealthy', async () => {
      jest.spyOn(prismaHealthIndicator, 'isHealthy')
        .mockRejectedValue(new HealthCheckError("Prisma health check failed", null));
      jest.spyOn(vaultHealthIndicator, 'isHealthy')
        .mockResolvedValue(new Promise((resolve) => {
          resolve({ vault: { status: 'up' }} as HealthIndicatorResult);
        }));
      await expect(appController.checkHealth()).rejects.toThrow(ServiceUnavailableException);
    });

    it('checks Vault only when signing keys are held in Vault Transit', async () => {
      const original = process.env.KEY_PROVIDER;
      jest.spyOn(prismaHealthIndicator, 'isHealthy').mockResolvedValue({ db: { status: 'up' } } as HealthIndicatorResult);
      const vault = jest.spyOn(vaultHealthIndicator, 'isHealthy')
        .mockRejectedValue(new HealthCheckError('Vault health check failed', null));
      vault.mockClear();
      try {
        process.env.KEY_PROVIDER = 'azure-keyvault';
        const result = await appController.checkHealth();
        expect(result.status).toEqual('ok');
        expect(result.info.vault).toBeUndefined();
        expect(vault).not.toHaveBeenCalled();

        delete process.env.KEY_PROVIDER; // default is vault-transit
        await expect(appController.checkHealth()).rejects.toThrow(ServiceUnavailableException);
      } finally {
        if (original === undefined) delete process.env.KEY_PROVIDER; else process.env.KEY_PROVIDER = original;
      }
    });
  });
});
