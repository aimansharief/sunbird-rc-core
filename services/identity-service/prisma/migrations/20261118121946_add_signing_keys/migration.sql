-- CreateEnum
CREATE TYPE "SigningKeyStatus" AS ENUM ('ACTIVE', 'RETIRED', 'REVOKED');

-- CreateTable
CREATE TABLE "SigningKey" (
    "id" TEXT NOT NULL,
    "did" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "keyRef" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL,
    "authority" TEXT,
    "status" "SigningKeyStatus" NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SigningKey_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SigningAuditLog" (
    "id" TEXT NOT NULL,
    "keyId" TEXT NOT NULL,
    "did" TEXT NOT NULL,
    "provider" TEXT NOT NULL,
    "algorithm" TEXT NOT NULL,
    "authority" TEXT,
    "actor" TEXT,
    "purpose" TEXT NOT NULL,
    "payloadSha256" TEXT NOT NULL,
    "outcome" TEXT NOT NULL,
    "error" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SigningAuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "SigningKey_did_algorithm_status_idx" ON "SigningKey"("did", "algorithm", "status");

-- CreateIndex
CREATE INDEX "SigningAuditLog_did_createdAt_idx" ON "SigningAuditLog"("did", "createdAt");

-- CreateIndex
CREATE INDEX "SigningAuditLog_keyId_createdAt_idx" ON "SigningAuditLog"("keyId", "createdAt");
