const fs = require("fs");
const path = require("path");
const bcrypt = require("bcryptjs");
const { v4: uuid } = require("uuid");

const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, "data", "db.json");

function nowIso() {
  return new Date().toISOString();
}

function ensureDir() {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
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

async function initialDb() {
  const username = process.env.ADMIN_USERNAME || "admiro";
  const password = process.env.ADMIN_PASSWORD || "P4bl0_mur1l0";

  return {
    users: [
      {
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
      }
    ],
    activationKeys: [],
    sites: defaultSites(),
    logs: []
  };
}

async function readDb() {
  ensureDir();
  if (!fs.existsSync(DATA_FILE)) {
    const db = await initialDb();
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
    return db;
  }

  const raw = fs.readFileSync(DATA_FILE, "utf8");
  return JSON.parse(raw);
}

function writeDb(db) {
  ensureDir();
  fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
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
  assertPartnerLimit
};
