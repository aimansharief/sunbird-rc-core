// Test-only helper: use the real Postgres/Vault dev instances when they're
// reachable (so specs exercise real Prisma/Vault behavior), fall back to a
// minimal in-memory fake when they're not (so `npm test` still runs without
// docker up). Production code never imports this.
import { PrismaService } from './prisma.service';
import { VaultService } from './vault.service';

function createTable(defaults: Record<string, any> = {}) {
  const rows = new Map<string, any>();
  const matches = (row: any, where: any = {}) =>
    Object.entries(where).every(([k, v]: [string, any]) =>
      v && typeof v === 'object' && Array.isArray(v.in) ? v.in.includes(row[k]) : row[k] === v);
  return {
    rows,
    create: jest.fn(async ({ data }: any) => {
      const now = new Date(Date.now() + rows.size); // strictly increasing createdAt
      const record = { createdAt: now, updatedAt: now, ...defaults, ...data, id: data.id ?? `${rows.size + 1}` };
      if (rows.has(record.id)) throw new Error(`Unique constraint failed on id ${record.id}`);
      rows.set(record.id, record);
      return record;
    }),
    findUnique: jest.fn(async ({ where }: any) => rows.get(where.id) ?? null),
    findFirst: jest.fn(async ({ where, orderBy }: any = {}) => {
      const found = [...rows.values()].filter((r) => matches(r, where));
      if (orderBy?.createdAt === 'desc') found.sort((a, b) => b.createdAt - a.createdAt);
      return found[0] ?? null;
    }),
    findMany: jest.fn(async ({ where }: any = {}) =>
      [...rows.values()].filter((r) => matches(r, where)).sort((a, b) => a.createdAt - b.createdAt)),
    update: jest.fn(async ({ where, data }: any) => {
      const row = rows.get(where.id);
      if (!row) throw new Error(`Record ${where.id} not found`);
      Object.assign(row, data, { updatedAt: new Date() });
      return row;
    }),
    delete: jest.fn(async ({ where }: any) => {
      const row = rows.get(where.id);
      rows.delete(where.id);
      return row;
    }),
  };
}

export function createInMemoryPrismaMock(): any {
  return {
    identity: createTable(),
    signingKey: createTable({ status: 'ACTIVE' }), // mirrors the DB column default
    signingAuditLog: createTable(),
    $disconnect: jest.fn(async () => undefined),
  };
}

function createInMemoryVaultMock(): any {
  const store = new Map<string, any>();
  return {
    readPvtKey: jest.fn(async (name: string) => store.get(name) ?? null),
  };
}

export async function createPrismaServiceOrMock(): Promise<PrismaService> {
  try {
    const prisma = new PrismaService();
    await prisma.$queryRaw`SELECT 1`;
    return prisma;
  } catch {
    return createInMemoryPrismaMock();
  }
}

export async function createVaultServiceOrMock(): Promise<VaultService> {
  const vault = new VaultService();
  try {
    await vault.readPvtKey('__connectivity_probe__');
    return vault;
  } catch (err: any) {
    // A genuine 404 (tagged isVaultError by hashi-vault-js) means Vault IS
    // reachable, the probe key just doesn't exist — use the real client.
    // Any other error (connection refused, timeout, auth failure) means
    // Vault isn't usable right now — fall back to the in-memory fake.
    if (err?.isVaultError && err?.response?.status === 404) return vault;
    return createInMemoryVaultMock();
  }
}
