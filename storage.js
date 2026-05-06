const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const { v4: uuid } = require("uuid");

const DATABASE_URL = process.env.DATABASE_URL;
const MAX_LOGS = parsePositiveInt(process.env.MAX_LOGS, 500);
const LOG_RETENTION_DAYS = parsePositiveInt(process.env.LOG_RETENTION_DAYS, 7);
const MAX_SYSTEM_LOGS = parsePositiveInt(process.env.MAX_SYSTEM_LOGS, 100);
const SYSTEM_LOG_RETENTION_DAYS = parsePositiveInt(process.env.SYSTEM_LOG_RETENTION_DAYS, 7);

let pool = null;
let initialized = false;

function getPool() {
  if (!DATABASE_URL) {
    throw new Error("DATABASE_URL não configurada. Configure a conexão PostgreSQL/Supabase no Render.");
  }

  if (!pool) {
    pool = new Pool({
      connectionString: DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    });
  }

  return pool;
}

function parsePositiveInt(value, fallback) {
  const number = Number.parseInt(value, 10);
  return Number.isFinite(number) && number > 0 ? number : fallback;
}

function nowIso() {
  return new Date().toISOString();
}

const PERMISSIONS = {
  console_access: "Acesso ao Console",
  user_create: "Criar usuários",
  user_edit: "Editar usuários",
  user_reset_password: "Resetar senhas",
  user_delete: "Excluir usuários",
  key_create: "Criar keys",
  key_edit: "Editar keys",
  key_delete: "Excluir keys",
  key_lifetime: "Criar key vitalícia",
  manage_sites: "Configurar sites",
  online_connection: "Conexão Online",
  control_repost: "Controlar Repost",
  backup_export: "Exportar backup",
  backup_import: "Importar backup",
  system_logs: "Log do Sistema",
  dev_tools: "Área Dev"
};

const ROLE_PERMISSIONS = {
  adm: Object.keys(PERMISSIONS),
  parceiro: ["console_access", "user_create", "user_edit", "user_reset_password", "key_create", "control_repost"],
  usuario: ["control_repost"],
  dev: ["console_access", "system_logs", "dev_tools", "control_repost"]
};

function normalizeRole(role) {
  return ["adm", "parceiro", "usuario", "dev"].includes(role) ? role : "usuario";
}

function defaultPermissions(role) {
  return [...(ROLE_PERMISSIONS[normalizeRole(role)] || ROLE_PERMISSIONS.usuario)];
}

function normalizePermissions(userOrRole, permissions = null) {
  const role = typeof userOrRole === "string" ? normalizeRole(userOrRole) : normalizeRole(userOrRole?.role);
  const received = Array.isArray(permissions) ? permissions : Array.isArray(userOrRole?.permissions) ? userOrRole.permissions : [];
  if (role === "adm") return defaultPermissions("adm");
  const allowed = new Set(defaultPermissions(role));
  return Array.from(new Set([...defaultPermissions(role), ...received.filter((item) => allowed.has(item))]));
}

function normalizeUserRole(user) {
  if (!user) return user;
  const role = normalizeRole(user.role);
  return {
    ...user,
    role,
    permissions: normalizePermissions({ role, permissions: user.permissions }),
    accountLimit: role === "parceiro" ? normalizeLimit(user.accountLimit ?? 3) : null
  };
}

function defaultSites() {
  return [
    {
      id: "vivastreet",
      name: "VivaStreet",
      tabName: "Viva",
      buttonLabel: "Repost",
      loginUrl: "https://www.vivastreet.co.uk/user/login",
      pageUrl: "https://www.vivastreet.co.uk/user/account/ads",
      baseUrl: "https://www.vivastreet.co.uk",
      mode: "exact-text",
      buttonText: "repost",
      buttonSelectors: [
        "button",
        "a",
        "input[type='button']",
        "input[type='submit']",
        "[role='button']"
      ],
      clickAll: true,
      intervalMinutes: 15,
      retryUsedMinutes: 1,
      waitSeconds: 4,
      loginWaitSeconds: 0,
      captchaDelaySeconds: 4,
      loginDelaySeconds: 4,
      clickDelaySeconds: 4,
      enabled: true
    },
    {
      id: "kommons",
      name: "Kommons",
      tabName: "Kommons",
      buttonLabel: "Manual boost",
      loginUrl: "https://kommons.com/members-area/login",
      pageUrl: "https://kommons.com/members-area",
      baseUrl: "https://kommons.com",
      mode: "exact-text",
      buttonText: "manual boost",
      buttonSelector: "button.boostButton",
      buttonSelectors: [
        "button.boostButton",
        "button.btn-advertise.boostButton",
        ".btn-advertise.boostButton",
        "button[data-escort][data-premium]"
      ],
      clickAll: false,
      intervalMinutes: 60,
      retryUsedMinutes: 10,
      waitSeconds: 4,
      loginWaitSeconds: 0,
      captchaDelaySeconds: 4,
      loginDelaySeconds: 4,
      clickDelaySeconds: 4,
      enabled: true
    }
  ];
}

async function ensureSchema() {
  if (initialized) return;
  const db = getPool();

  await db.query(`
    CREATE TABLE IF NOT EXISTS upsystem_users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS upsystem_activation_keys (
      code TEXT PRIMARY KEY,
      id TEXT UNIQUE,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS upsystem_sites (
      id TEXT PRIMARY KEY,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS upsystem_logs (
      id TEXT PRIMARY KEY,
      data JSONB NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS upsystem_system_logs (
      id TEXT PRIMARY KEY,
      level TEXT NOT NULL DEFAULT 'error',
      origin TEXT NOT NULL DEFAULT 'unknown',
      data JSONB NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await db.query(`
    CREATE INDEX IF NOT EXISTS idx_upsystem_logs_created_at
    ON upsystem_logs (created_at DESC)
  `);

  await db.query(`
    CREATE INDEX IF NOT EXISTS idx_upsystem_system_logs_created_at
    ON upsystem_system_logs (created_at DESC)
  `);

  await db.query(`
    CREATE INDEX IF NOT EXISTS idx_upsystem_system_logs_level
    ON upsystem_system_logs (level)
  `);

  await ensureInitialData();
  initialized = true;
}

async function ensureInitialData() {
  const db = getPool();

  const adminCount = await db.query("SELECT COUNT(*)::int AS count FROM upsystem_users");
  if (adminCount.rows[0].count === 0) {
    const username = process.env.ADMIN_USERNAME || "admiro";
    const password = process.env.ADMIN_PASSWORD || "P4bl0_mur1l0";

    const admin = {
      id: "admin-root",
      name: "Administrador",
      username,
      email: "",
      passwordHash: await bcrypt.hash(password, 10),
      role: "adm",
      accessType: "lifetime",
      expiresAt: null,
      isActive: true,
      permissions: defaultPermissions("adm"),
      accountLimit: null,
      createdBy: null,
      activeKey: null,
      createdAt: nowIso(),
      updatedAt: nowIso()
    };

    await db.query(
      `INSERT INTO upsystem_users (id, username, data, updated_at)
       VALUES ($1, $2, $3::jsonb, NOW())
       ON CONFLICT (id) DO UPDATE SET username = EXCLUDED.username, data = EXCLUDED.data, updated_at = NOW()`,
      [admin.id, admin.username, JSON.stringify(admin)]
    );
  }

  const siteCount = await db.query("SELECT COUNT(*)::int AS count FROM upsystem_sites");
  if (siteCount.rows[0].count === 0) {
    for (const site of defaultSites()) {
      await db.query(
        `INSERT INTO upsystem_sites (id, data, updated_at)
         VALUES ($1, $2::jsonb, NOW())
         ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()`,
        [site.id, JSON.stringify(site)]
      );
    }
  }
}

function rowData(row) {
  return row?.data || {};
}

async function cleanupLogs(client) {
  if (LOG_RETENTION_DAYS > 0) {
    await client.query(
      "DELETE FROM upsystem_logs WHERE created_at < NOW() - ($1::int * INTERVAL '1 day')",
      [LOG_RETENTION_DAYS]
    );
  }

  await client.query(
    `DELETE FROM upsystem_logs
     WHERE id IN (
       SELECT id FROM (
         SELECT id, ROW_NUMBER() OVER (ORDER BY created_at DESC) AS rn
         FROM upsystem_logs
       ) ranked
       WHERE ranked.rn > $1
     )`,
    [MAX_LOGS]
  );
}

async function cleanupSystemLogs(client) {
  if (SYSTEM_LOG_RETENTION_DAYS > 0) {
    await client.query(
      "DELETE FROM upsystem_system_logs WHERE created_at < NOW() - ($1::int * INTERVAL '1 day')",
      [SYSTEM_LOG_RETENTION_DAYS]
    );
  }

  await client.query(
    `DELETE FROM upsystem_system_logs
     WHERE id IN (
       SELECT id FROM (
         SELECT id, ROW_NUMBER() OVER (ORDER BY created_at DESC) AS rn
         FROM upsystem_system_logs
       ) ranked
       WHERE ranked.rn > $1
     )`,
    [MAX_SYSTEM_LOGS]
  );
}

async function readDb() {
  await ensureSchema();
  const db = getPool();

  const [users, keys, sites, logs, systemLogs] = await Promise.all([
    db.query("SELECT data FROM upsystem_users ORDER BY updated_at ASC"),
    db.query("SELECT data FROM upsystem_activation_keys ORDER BY updated_at ASC"),
    db.query("SELECT data FROM upsystem_sites ORDER BY id ASC"),
    db.query(
      `SELECT data FROM upsystem_logs
       WHERE created_at >= NOW() - ($2::int * INTERVAL '1 day')
       ORDER BY created_at DESC
       LIMIT $1`,
      [MAX_LOGS, LOG_RETENTION_DAYS]
    ),
    db.query(
      `SELECT data FROM upsystem_system_logs
       WHERE created_at >= NOW() - ($2::int * INTERVAL '1 day')
       ORDER BY created_at DESC
       LIMIT $1`,
      [MAX_SYSTEM_LOGS, SYSTEM_LOG_RETENTION_DAYS]
    )
  ]);

  return {
    users: users.rows.map(rowData).map(normalizeUserRole),
    activationKeys: keys.rows.map(rowData),
    sites: sites.rows.map(rowData),
    logs: logs.rows.map(rowData).reverse(),
    systemLogs: systemLogs.rows.map(rowData).reverse()
  };
}

async function writeDb(state) {
  await ensureSchema();
  const db = getPool();
  const client = await db.connect();

  try {
    await client.query("BEGIN");

    for (const rawUser of state.users || []) {
      const user = normalizeUserRole(rawUser);
      if (!user?.id || !user?.username) continue;
      user.updatedAt = user.updatedAt || nowIso();
      await client.query(
        `INSERT INTO upsystem_users (id, username, data, updated_at)
         VALUES ($1, $2, $3::jsonb, NOW())
         ON CONFLICT (id) DO UPDATE SET username = EXCLUDED.username, data = EXCLUDED.data, updated_at = NOW()`,
        [user.id, user.username, JSON.stringify(user)]
      );
    }

    for (const key of state.activationKeys || []) {
      if (!key?.code) continue;
      await client.query(
        `INSERT INTO upsystem_activation_keys (code, id, data, updated_at)
         VALUES ($1, $2, $3::jsonb, NOW())
         ON CONFLICT (code) DO UPDATE SET id = EXCLUDED.id, data = EXCLUDED.data, updated_at = NOW()`,
        [key.code, key.id || key.code, JSON.stringify(key)]
      );
    }

    for (const site of state.sites || []) {
      if (!site?.id) continue;
      await client.query(
        `INSERT INTO upsystem_sites (id, data, updated_at)
         VALUES ($1, $2::jsonb, NOW())
         ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()`,
        [site.id, JSON.stringify(site)]
      );
    }

    const incomingLogs = Array.isArray(state.logs) ? state.logs.filter((log) => log?.id) : [];
    const incomingLogIds = incomingLogs.map((log) => log.id);

    if (Array.isArray(state.logs)) {
      if (incomingLogIds.length) {
        await client.query("DELETE FROM upsystem_logs WHERE NOT (id = ANY($1::text[]))", [incomingLogIds]);
      } else {
        await client.query("DELETE FROM upsystem_logs");
      }
    }

    for (const log of incomingLogs) {
      await client.query(
        `INSERT INTO upsystem_logs (id, data, created_at)
         VALUES ($1, $2::jsonb, COALESCE($3::timestamptz, NOW()))
         ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data`,
        [log.id, JSON.stringify(log), log.createdAt || log.at || null]
      );
    }

    if (state.__replaceSystemLogs === true) {
      const incomingSystemLogs = Array.isArray(state.systemLogs) ? state.systemLogs.filter((log) => log?.id) : [];
      const incomingSystemLogIds = incomingSystemLogs.map((log) => log.id);

      if (incomingSystemLogIds.length) {
        await client.query("DELETE FROM upsystem_system_logs WHERE NOT (id = ANY($1::text[]))", [incomingSystemLogIds]);
      } else {
        await client.query("DELETE FROM upsystem_system_logs");
      }

      for (const log of incomingSystemLogs) {
        await client.query(
          `INSERT INTO upsystem_system_logs (id, level, origin, data, created_at)
           VALUES ($1, $2, $3, $4::jsonb, COALESCE($5::timestamptz, NOW()))
           ON CONFLICT (id) DO UPDATE SET level = EXCLUDED.level, origin = EXCLUDED.origin, data = EXCLUDED.data`,
          [
            log.id,
            String(log.level || "error").slice(0, 20),
            String(log.origin || "unknown").slice(0, 120),
            JSON.stringify(log),
            log.createdAt || log.at || null
          ]
        );
      }
    }

    await cleanupLogs(client);
    await cleanupSystemLogs(client);

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

function publicUser(user) {
  if (!user) return null;
  const { passwordHash, ...safe } = user;
  return safe;
}

function isExpired(user) {
  return Boolean(user?.expiresAt && new Date(user.expiresAt).getTime() < Date.now());
}

function calcExpiresAt(accessType) {
  const d = new Date();
  if (accessType === "weekly") {
    d.setDate(d.getDate() + 7);
    return d.toISOString();
  }
  if (accessType === "monthly") {
    d.setMonth(d.getMonth() + 1);
    return d.toISOString();
  }
  return null;
}

function hasPermission(user, permission) {
  if (!user) return false;
  if (normalizeRole(user.role) === "adm") return true;
  return normalizePermissions(user).includes(permission);
}
function canAccessConsole(user) {
  return hasPermission(user, "console_access");
}

function canDeleteUser(currentUser, targetUser) {
  if (!currentUser || !targetUser) return false;
  if (normalizeRole(currentUser.role) !== "adm") return false;
  if (targetUser.role === "adm" || targetUser.username === "admin" || targetUser.id === "admin-root") return false;
  if (targetUser.id === currentUser.id || targetUser.username === currentUser.username) return false;
  return true;
}

function canCreateKey(currentUser, accessType = "weekly") {
  if (!currentUser) return false;
  const role = normalizeRole(currentUser.role);
  if (role === "adm") return true;
  if (role !== "parceiro") return false;
  return ["weekly", "monthly"].includes(accessType) && hasPermission(currentUser, "key_create");
}

function canDeleteKey(currentUser) {
  return normalizeRole(currentUser?.role) === "adm";
}

function canManageUser(currentUser, targetUser) {
  if (!currentUser || !targetUser) return false;
  if (normalizeRole(currentUser.role) === "adm") return true;
  if (normalizeRole(currentUser.role) === "parceiro") {
    return targetUser.role === "usuario" && (targetUser.createdBy === currentUser.username || targetUser.createdByUser === currentUser.username);
  }
  return false;
}

function makeId(prefix) {
  return `${prefix}-${uuid()}`;
}

function shortKey() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const part = (n = 4) => Array.from({ length: n }, () => chars[Math.floor(Math.random() * chars.length)]).join("");
  return `UP-${part()}-${part()}-${part()}`;
}

function normalizeLimit(value) {
  if (value === "unlimited") return "unlimited";
  const number = Number(value);
  if (!Number.isFinite(number)) return 3;
  return Math.max(0, Math.floor(number));
}

function countPartnerAccounts(db, partnerUsername) {
  return db.users.filter((u) =>
    u.role === "usuario" &&
    (u.createdBy === partnerUsername || u.createdByUser === partnerUsername)
  ).length;
}

function countPartnerReservedKeys(db, partnerUsername) {
  return db.activationKeys.filter((key) =>
    key.createdBy === partnerUsername &&
    key.role === "usuario" &&
    key.status === "available" &&
    (!key.keyExpiresAt || new Date(key.keyExpiresAt).getTime() >= Date.now())
  ).length;
}

function assertPartnerLimit(db, partner, includeReserved = false) {
  if (partner?.role !== "parceiro") return;

  const limit = normalizeLimit(partner.accountLimit ?? 3);
  if (limit === "unlimited") return;

  const used = countPartnerAccounts(db, partner.username);
  const reserved = includeReserved ? countPartnerReservedKeys(db, partner.username) : 0;

  if (used + reserved >= limit) {
    const err = new Error(`Limite de contas atingido (${used + reserved}/${limit}). Solicite ao Admin a liberação de mais contas.`);
    err.status = 403;
    throw err;
  }
}

async function appendSystemLog(log) {
  await ensureSchema();
  const db = getPool();
  const client = await db.connect();
  const entry = {
    ...log,
    id: log.id || makeId("syslog"),
    level: String(log.level || "error").slice(0, 20),
    origin: String(log.origin || "unknown").slice(0, 120),
    createdAt: log.createdAt || nowIso()
  };

  try {
    await client.query("BEGIN");
    await client.query(
      `INSERT INTO upsystem_system_logs (id, level, origin, data, created_at)
       VALUES ($1, $2, $3, $4::jsonb, COALESCE($5::timestamptz, NOW()))
       ON CONFLICT (id) DO UPDATE SET level = EXCLUDED.level, origin = EXCLUDED.origin, data = EXCLUDED.data`,
      [entry.id, entry.level, entry.origin, JSON.stringify(entry), entry.createdAt]
    );
    await cleanupSystemLogs(client);
    await client.query("COMMIT");
    return entry;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}


async function deleteActivationKey(idOrCode) {
  await ensureSchema();
  const db = getPool();
  await db.query(
    `DELETE FROM upsystem_activation_keys
     WHERE code = $1 OR id = $1 OR data->>'id' = $1`,
    [idOrCode]
  );
}

async function deleteUserById(idOrUsername) {
  await ensureSchema();
  const db = getPool();
  await db.query(
    `DELETE FROM upsystem_users
     WHERE id = $1 OR username = $1 OR data->>'id' = $1 OR data->>'username' = $1`,
    [idOrUsername]
  );
}

async function clearSystemLogs() {
  await ensureSchema();
  const db = getPool();
  await db.query("DELETE FROM upsystem_system_logs");
}

async function healthDb() {
  await ensureSchema();
  const db = getPool();
  const result = await db.query("SELECT NOW() AS now");
  return result.rows[0];
}

module.exports = {
  readDb,
  writeDb,
  publicUser,
  PERMISSIONS,
  ROLE_PERMISSIONS,
  normalizeRole,
  defaultPermissions,
  normalizePermissions,
  normalizeUserRole,
  hasPermission,
  canAccessConsole,
  canDeleteUser,
  canCreateKey,
  canDeleteKey,
  canManageUser,
  isExpired,
  calcExpiresAt,
  makeId,
  shortKey,
  nowIso,
  bcrypt,
  normalizeLimit,
  assertPartnerLimit,
  appendSystemLog,
  deleteActivationKey,
  deleteUserById,
  clearSystemLogs,
  healthDb
};
