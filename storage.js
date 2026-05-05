const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const { v4: uuid } = require("uuid");

const DATABASE_URL = process.env.DATABASE_URL;

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

function nowIso() {
  return new Date().toISOString();
}

function defaultPermissions(role) {
  if (role === "adm") return [
    "user_create",
    "user_edit",
    "user_delete",
    "user_reset_password",
    "manage_sites",
    "online_connection",
    "dev_tools",
    "control_repost"
  ];
  if (role === "parceiro") return ["user_create", "user_edit", "user_reset_password", "control_repost"];
  if (role === "dev") return ["manage_sites", "online_connection", "control_repost", "dev_tools"];
  return ["control_repost"];
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

async function readDb() {
  await ensureSchema();
  const db = getPool();

  const [users, keys, sites, logs] = await Promise.all([
    db.query("SELECT data FROM upsystem_users ORDER BY updated_at ASC"),
    db.query("SELECT data FROM upsystem_activation_keys ORDER BY updated_at ASC"),
    db.query("SELECT data FROM upsystem_sites ORDER BY id ASC"),
    db.query("SELECT data FROM upsystem_logs ORDER BY created_at ASC LIMIT 5000")
  ]);

  return {
    users: users.rows.map(rowData),
    activationKeys: keys.rows.map(rowData),
    sites: sites.rows.map(rowData),
    logs: logs.rows.map(rowData)
  };
}

async function writeDb(state) {
  await ensureSchema();
  const db = getPool();
  const client = await db.connect();

  try {
    await client.query("BEGIN");

    for (const user of state.users || []) {
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
  if (user.role === "adm") return true;
  return Boolean(user.permissions?.includes(permission));
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
  defaultPermissions,
  hasPermission,
  isExpired,
  calcExpiresAt,
  makeId,
  shortKey,
  nowIso,
  bcrypt,
  normalizeLimit,
  assertPartnerLimit,
  healthDb
};
