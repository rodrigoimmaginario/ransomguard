-- Esquema REAL do banco do painel na RC 0.9.0.
-- Gerado em 2026-11-16 executando o binario publicado da RC (painel portatil do zip RansomGuard-0.9.0-rc.zip,
-- SHA-256 a83b4d02...d4d2) e lendo sqlite_master do banco que ele criou. Nao editar a mao: e o ponto de partida do
-- teste de upgrade (C2).

CREATE TABLE "AgentPolicies" (
    "Id" INTEGER NOT NULL CONSTRAINT "PK_AgentPolicies" PRIMARY KEY AUTOINCREMENT,
    "Server" TEXT NOT NULL,
    "Mode" TEXT NOT NULL,
    "MaxStep" TEXT NOT NULL,
    "AllowlistedUsers" TEXT NOT NULL,
    "AllowlistedIps" TEXT NOT NULL,
    "LearningMode" INTEGER NOT NULL,
    "BlockedIps" TEXT NOT NULL,
    "Version" INTEGER NOT NULL,
    "UpdatedAt" TEXT NOT NULL
);

CREATE TABLE "Detections" (
    "Id" INTEGER NOT NULL CONSTRAINT "PK_Detections" PRIMARY KEY AUTOINCREMENT,
    "ServerId" INTEGER NOT NULL,
    "At" TEXT NOT NULL,
    "User" TEXT NOT NULL,
    "SourceIp" TEXT NOT NULL,
    "Share" TEXT NOT NULL,
    "Confidence" INTEGER NOT NULL,
    "AffectedFiles" INTEGER NOT NULL,
    "Reasons" TEXT NOT NULL,
    "Alerted" INTEGER NOT NULL,
    "IncidentId" TEXT NULL,
    "Source" TEXT NOT NULL,
    "Mode" TEXT NULL,
    "Rationale" TEXT NULL,
    "Contained" INTEGER NOT NULL,
    "AffectedPathsJson" TEXT NULL,
    CONSTRAINT "FK_Detections_Servers_ServerId" FOREIGN KEY ("ServerId") REFERENCES "Servers" ("Id") ON DELETE CASCADE
);

CREATE TABLE "Heartbeats" (
    "Id" INTEGER NOT NULL CONSTRAINT "PK_Heartbeats" PRIMARY KEY AUTOINCREMENT,
    "Server" TEXT NOT NULL,
    "LastBeat" TEXT NOT NULL,
    "TamperAlerted" INTEGER NOT NULL
);

CREATE TABLE "Installations" (
    "Id" INTEGER NOT NULL CONSTRAINT "PK_Installations" PRIMARY KEY AUTOINCREMENT,
    "InstallId" TEXT NOT NULL,
    "CreatedAt" TEXT NOT NULL,
    "HighWaterUtc" TEXT NOT NULL
);

CREATE TABLE "Licenses" (
    "Id" INTEGER NOT NULL CONSTRAINT "PK_Licenses" PRIMARY KEY AUTOINCREMENT,
    "LicenseJson" TEXT NOT NULL,
    "Signature" TEXT NOT NULL,
    "ActivatedAt" TEXT NOT NULL,
    "Customer" TEXT NOT NULL,
    "Plan" TEXT NOT NULL,
    "ExpiresAt" TEXT NOT NULL
);

CREATE TABLE "NotificationChannels" (
    "Id" INTEGER NOT NULL CONSTRAINT "PK_NotificationChannels" PRIMARY KEY AUTOINCREMENT,
    "Kind" INTEGER NOT NULL,
    "Enabled" INTEGER NOT NULL,
    "NtfyServer" TEXT NULL,
    "NtfyTopic" TEXT NULL,
    "NtfyToken" TEXT NULL,
    "WebhookUrl" TEXT NULL,
    "WebhookFormat" INTEGER NULL,
    "TelegramBotToken" TEXT NULL,
    "TelegramChatId" TEXT NULL,
    "SmtpHost" TEXT NULL,
    "SmtpPort" INTEGER NOT NULL,
    "SmtpSsl" INTEGER NOT NULL,
    "SmtpUser" TEXT NULL,
    "SmtpPassword" TEXT NULL,
    "SmtpFrom" TEXT NULL,
    "SmtpTo" TEXT NULL,
    "LastAttemptAt" TEXT NULL,
    "LastAttemptOk" INTEGER NULL,
    "LastAttemptDetail" TEXT NULL
);

CREATE TABLE "NotificationSettings" (
    "Id" INTEGER NOT NULL CONSTRAINT "PK_NotificationSettings" PRIMARY KEY AUTOINCREMENT,
    "MinimumSeverity" INTEGER NOT NULL,
    "FloodWindowMinutes" INTEGER NOT NULL,
    "NotifyAgentSilent" INTEGER NOT NULL
);

CREATE TABLE "OperatorAudit" (
    "Id" INTEGER NOT NULL CONSTRAINT "PK_OperatorAudit" PRIMARY KEY AUTOINCREMENT,
    "At" TEXT NOT NULL,
    "User" TEXT NOT NULL,
    "Action" TEXT NOT NULL,
    "Detail" TEXT NOT NULL,
    "Origin" TEXT NOT NULL
);

CREATE TABLE "OwnerAccounts" (
    "Id" INTEGER NOT NULL CONSTRAINT "PK_OwnerAccounts" PRIMARY KEY AUTOINCREMENT,
    "Username" TEXT NOT NULL,
    "PasswordHash" TEXT NOT NULL,
    "CreatedAt" TEXT NOT NULL,
    "Role" TEXT NOT NULL
);

CREATE TABLE "PaymentOrders" (
    "Id" INTEGER NOT NULL CONSTRAINT "PK_PaymentOrders" PRIMARY KEY AUTOINCREMENT,
    "OrderId" TEXT NOT NULL,
    "Customer" TEXT NOT NULL,
    "Plan" TEXT NOT NULL,
    "Seats" INTEGER NOT NULL,
    "InstallId" TEXT NOT NULL,
    "ReceivedAt" TEXT NOT NULL,
    "Fulfilled" INTEGER NOT NULL
);

CREATE TABLE "PostureRecords" (
    "Id" INTEGER NOT NULL CONSTRAINT "PK_PostureRecords" PRIMARY KEY AUTOINCREMENT,
    "ServerId" INTEGER NOT NULL,
    "At" TEXT NOT NULL,
    "Score" INTEGER NOT NULL,
    "Band" INTEGER NOT NULL,
    "FindingsJson" TEXT NOT NULL,
    "UnknownJson" TEXT NOT NULL,
    CONSTRAINT "FK_PostureRecords_Servers_ServerId" FOREIGN KEY ("ServerId") REFERENCES "Servers" ("Id") ON DELETE CASCADE
);

CREATE TABLE "ResponseActions" (
    "Id" INTEGER NOT NULL CONSTRAINT "PK_ResponseActions" PRIMARY KEY AUTOINCREMENT,
    "DetectionId" INTEGER NOT NULL,
    "At" TEXT NOT NULL,
    "Actor" TEXT NOT NULL,
    "Operation" TEXT NOT NULL,
    "Step" TEXT NOT NULL,
    "Target" TEXT NOT NULL,
    "Justification" TEXT NOT NULL,
    "RevertRequestedAt" TEXT NULL,
    "RevertedAt" TEXT NULL,
    "RevertStatus" TEXT NULL,
    "RevertDetail" TEXT NULL,
    "Account" TEXT NULL,
    CONSTRAINT "FK_ResponseActions_Detections_DetectionId" FOREIGN KEY ("DetectionId") REFERENCES "Detections" ("Id") ON DELETE CASCADE
);

CREATE TABLE "Servers" (
    "Id" INTEGER NOT NULL CONSTRAINT "PK_Servers" PRIMARY KEY AUTOINCREMENT,
    "Name" TEXT NOT NULL,
    "FirstSeen" TEXT NOT NULL,
    "LastSeen" TEXT NOT NULL,
    "LastScore" INTEGER NOT NULL,
    "LastBand" INTEGER NOT NULL
);

CREATE UNIQUE INDEX "IX_AgentPolicies_Server" ON "AgentPolicies" ("Server");

CREATE UNIQUE INDEX "IX_Detections_IncidentId" ON "Detections" ("IncidentId") WHERE "IncidentId" IS NOT NULL;

CREATE INDEX "IX_Detections_ServerId_At" ON "Detections" ("ServerId", "At");

CREATE UNIQUE INDEX "IX_Heartbeats_Server" ON "Heartbeats" ("Server");

CREATE INDEX "IX_OperatorAudit_At" ON "OperatorAudit" ("At");

CREATE UNIQUE INDEX "IX_PaymentOrders_OrderId" ON "PaymentOrders" ("OrderId");

CREATE INDEX "IX_PostureRecords_ServerId" ON "PostureRecords" ("ServerId");

CREATE INDEX "IX_ResponseActions_DetectionId" ON "ResponseActions" ("DetectionId");

CREATE UNIQUE INDEX "IX_Servers_Name" ON "Servers" ("Name");
