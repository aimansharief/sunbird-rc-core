import { Controller, Get, Post } from '@nestjs/common';
import { HealthCheck, HealthCheckService, HttpHealthIndicator } from '@nestjs/terminus';
import { PrismaHealthIndicator } from './utils/prisma.health';
import { VaultHealthIndicator } from './utils/vault.health';

@Controller()
export class AppController {
  constructor(
    private readonly healthCheckService: HealthCheckService,
    private readonly prismaIndicator: PrismaHealthIndicator,
    private readonly vaultIndicator: VaultHealthIndicator,
    private readonly http: HttpHealthIndicator
  ) {}
  @Get('/health')
  @HealthCheck()
  public async checkHealth() {
    const usesVault = (process.env.KEY_PROVIDER || 'vault-transit').trim() === 'vault-transit';
    return this.healthCheckService.check([
      async () => this.prismaIndicator.isHealthy('db'),
      ...(usesVault ? [async () => this.vaultIndicator.isHealthy('vault')] : []),
    ])
  }
}
