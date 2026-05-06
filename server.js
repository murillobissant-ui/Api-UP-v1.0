require("dotenv").config();

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const {
  readDb,
  writeDb,
  publicUser,
  normalizeRole,
  defaultPermissions,
  normalizePermissions,
  hasPermission,
  canDeleteUser,
  canCreateKey,
  canDeleteKey,
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
  deleteActivationKeysForUser,
  repairOrphanActivationKeys,
  clearSystemLogs,
  healthDb
} = require("./storage");

const app = express();
const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
const MAX_LOGS = Math.max(1, Number.parseInt(process.env.MAX_LOGS || "500", 10) || 500);
const LOG_RETENTION_DAYS = Math.max(1, Number.parseInt(process.env.LOG_RETENTION_DAYS || "7", 10) || 7);
const LOG_RETENTION_MS = LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000;

app.use(cors({ origin: CORS_ORIGIN === "*" ? true : CORS_ORIGIN, credentials: true }));
app.use(express.json({ limit: "1mb" }));

function sign(user) {
  return jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: "7d" });
}

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Token ausente." });

    const payload = jwt.verify(token, JWT_SECRET);
    const db = await readDb();
    const user = db.users.find((u) => u.id === payload.id);

    if (!user) return res.status(401).json({ error: "Usuário inválido." });

    if (isExpired(user)) {
      user.isActive = false;
      user.updatedAt = nowIso();
      writeDb(db);
      return res.status(403).json({ error: "O acesso deste usuário expirou. Renove sua conta com uma nova key." });
    }

    if (!user.isActive) return res.status(403).json({ error: "Usuário inativo." });

    req.db = db;
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Sessão inválida." });
  }
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!hasPermission(req.user, permission)) return res.status(403).json({ error: "Sem permissão." });
    next();
  };
}

async function optionalAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return next();

    const payload = jwt.verify(token, JWT_SECRET);
    const db = await readDb();
    const user = db.users.find((u) => u.id === payload.id);
    if (user && user.isActive && !isExpired(user)) {
      req.db = db;
      req.user = user;
    }
  } catch {
    // Log técnico pode ser recebido mesmo quando a sessão quebrou/expirou.
  }
  next();
}

function canReadSystemLogs(user) {
  return user?.role === "adm" || user?.role === "dev";
}

function sanitizeSystemLog(body = {}, user = null, req = null) {
  const allowedLevels = new Set(["error", "warning", "info"]);
  const level = allowedLevels.has(String(body.level || "").toLowerCase())
    ? String(body.level).toLowerCase()
    : "error";

  return {
    id: makeId("syslog"),
    level,
    origin: String(body.origin || body.source || "unknown").slice(0, 120),
    message: String(body.message || "Erro técnico sem mensagem.").slice(0, 1000),
    stack: String(body.stack || "").slice(0, 4000),
    file: String(body.file || "").slice(0, 240),
    line: body.line === undefined ? null : Number(body.line) || null,
    column: body.column === undefined ? null : Number(body.column) || null,
    context: body.context && typeof body.context === "object" && !Array.isArray(body.context) ? body.context : {},
    url: String(body.url || "").slice(0, 500),
    userId: user?.id || null,
    username: user?.username || String(body.username || "").slice(0, 80) || null,
    clientVersion: String(req?.get?.("X-UpSystem-Version") || body.clientVersion || "").slice(0, 40),
    clientBuild: String(req?.get?.("X-UpSystem-Build") || body.clientBuild || "").slice(0, 80),
    userAgent: String(req?.get?.("user-agent") || body.userAgent || "").slice(0, 240),
    createdAt: nowIso()
  };
}

function visibleUsers(db, current) {
  if (current.role === "adm") return db.users;
  if (current.role === "dev") return db.users.filter((u) => ["usuario", "parceiro"].includes(u.role));
  if (current.role === "parceiro") {
    return db.users.filter((u) =>
      u.role === "usuario" &&
      (u.createdBy === current.username || u.createdByUser === current.username)
    );
  }
  return [];
}

function visibleKeys(db, current) {
  if (current.role === "adm") return db.activationKeys;
  return db.activationKeys.filter((key) => key.createdBy === current.username);
}


function normalizeAccess(accessType) {
  return ["weekly", "monthly", "lifetime"].includes(accessType) ? accessType : "weekly";
}

function normalizeDevice(device = {}) {
  const installId = String(device.installId || device.deviceId || "").trim();
  const computerId = String(device.computerId || device.deviceId || "").trim();

  if (!computerId) return null;

  return {
    installId,
    deviceId: installId,
    computerId,
    deviceName: String(device.deviceName || "").slice(0, 180),
    computerName: String(device.computerName || device.deviceName || "").slice(0, 180),
    platform: String(device.platform || "").slice(0, 80),
    browser: String(device.browser || "").slice(0, 80),
    screen: String(device.screen || "").slice(0, 60),
    timezone: String(device.timezone || "").slice(0, 100),
    userAgent: String(device.userAgent || "").slice(0, 240)
  };
}

function assertDeviceAllowed(user, device, allowBind = true) {
  const normalized = normalizeDevice(device);

  if (!normalized?.computerId) {
    const err = new Error("Computador não identificado. Reinstale/atualize a extensão.");
    err.status = 403;
    throw err;
  }

  if (user.role === "adm") return normalized;

  const boundComputer = user.computerId || user.deviceId;

  if (!boundComputer && allowBind) {
    user.computerId = normalized.computerId;
    user.computerName = normalized.computerName;
    user.computerPlatform = normalized.platform;
    user.computerScreen = normalized.screen;
    user.computerTimezone = normalized.timezone;
    user.computerBoundAt = nowIso();

    user.deviceId = normalized.installId || normalized.computerId;
    user.deviceName = normalized.deviceName;
    user.devicePlatform = normalized.platform;
    user.deviceUserAgent = normalized.userAgent;
    user.deviceBoundAt = user.deviceBoundAt || nowIso();

    user.lastBrowser = normalized.browser;
    user.lastDeviceId = normalized.installId || null;

    return normalized;
  }

  if (boundComputer && boundComputer !== normalized.computerId) {
    const err = new Error("Conta vinculada a outro computador. Solicite ao Admin a liberação do computador.");
    err.status = 403;
    throw err;
  }

  user.lastBrowser = normalized.browser;
  user.lastDeviceId = normalized.installId || null;
  user.lastComputerId = normalized.computerId;

  return normalized;
}

function validateKey(key) {
  if (!key) {
    const err = new Error("Key inválida.");
    err.status = 400;
    throw err;
  }

  if (key.status === "used") {
    const err = new Error("Esta key já foi utilizada.");
    err.status = 400;
    throw err;
  }

  if (key.status === "replaced") {
    const err = new Error("Esta key foi substituída.");
    err.status = 400;
    throw err;
  }

  if (["inactive", "inativa", "disabled", "revoked", "cancelled", "canceled"].includes(String(key.status || "").toLowerCase())) {
    const err = new Error("Esta key está inativa pelo administrador.");
    err.status = 400;
    throw err;
  }

  if (key.keyExpiresAt && new Date(key.keyExpiresAt).getTime() < Date.now()) {
    const err = new Error("Key expirada. Solicite uma nova key ao administrador.");
    err.status = 400;
    throw err;
  }
}

async function redeemKeyForUser(db, key, user, passwordHash = null, name = null, device = null) {
  const oldKey = user.activeKey || user.createdByKey || null;
  const now = nowIso();

  if (oldKey && oldKey !== key.code) {
    const old = db.activationKeys.find((k) => k.code === oldKey);
    if (old && old.usedBy === user.username && old.status === "used") {
      old.status = "replaced";
      old.replacedAt = now;
      old.replacedByKey = key.code;
    }
  }

  const normalizedDevice = normalizeDevice(device);
  if (normalizedDevice) {
    user.computerId = normalizedDevice.computerId;
    user.computerName = normalizedDevice.computerName;
    user.computerPlatform = normalizedDevice.platform;
    user.computerScreen = normalizedDevice.screen;
    user.computerTimezone = normalizedDevice.timezone;
    user.computerBoundAt = user.computerBoundAt || now;

    user.deviceId = normalizedDevice.installId || normalizedDevice.computerId;
    user.deviceName = normalizedDevice.deviceName;
    user.devicePlatform = normalizedDevice.platform;
    user.deviceUserAgent = normalizedDevice.userAgent;
    user.deviceBoundAt = user.deviceBoundAt || now;
    user.lastBrowser = normalizedDevice.browser;
  }

  user.name = name || user.name;
  user.role = key.role;
  user.accessType = key.accessType;
  user.expiresAt = calcExpiresAt(key.accessType);
  user.isActive = true;
  user.permissions = key.permissions || defaultPermissions(key.role);
  user.updatedAt = now;
  user.activeKey = key.code;
  user.createdByKey = user.createdByKey || key.code;
  user.createdBy = user.createdBy || key.createdBy || null;
  user.createdByRole = user.createdByRole || key.createdByRole || null;
  user.keyHistory = [...(user.keyHistory || []), key.code];
  if (passwordHash) user.passwordHash = passwordHash;

  key.status = "used";
  key.usedAt = now;
  key.usedBy = user.username;
  key.usedUserId = user.id;

  writeDb(db);
  return user;
}


function compareVersion(a = "0.0.0", b = "0.0.0") {
  const pa = String(a).split(".").map((n) => Number(n) || 0);
  const pb = String(b).split(".").map((n) => Number(n) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const da = pa[i] || 0;
    const db = pb[i] || 0;
    if (da > db) return 1;
    if (da < db) return -1;
  }
  return 0;
}

function clientSecurity(req, res, next) {
  res.setHeader("X-UpSystem-API", "1.1.0");

  if (req.method === "OPTIONS" || req.path === "/health") {
    return next();
  }

  const minVersion = String(process.env.MIN_EXTENSION_VERSION || "").trim();
  const requiredBuild = String(process.env.REQUIRED_EXTENSION_BUILD || "").trim();
  const clientVersion = String(req.get("X-UpSystem-Version") || "").trim();
  const clientBuild = String(req.get("X-UpSystem-Build") || "").trim();

  if (minVersion && (!clientVersion || compareVersion(clientVersion, minVersion) < 0)) {
    return res.status(426).json({
      error: `Extensão desatualizada. Versão mínima exigida: ${minVersion}.`,
      code: "EXTENSION_OUTDATED",
      minVersion
    });
  }

  if (requiredBuild && clientBuild !== requiredBuild) {
    return res.status(426).json({
      error: "Build da extensão não autorizado. Atualize a extensão para continuar.",
      code: "EXTENSION_BUILD_BLOCKED",
      requiredBuild
    });
  }

  next();
}


app.use(clientSecurity);

app.get("/health", async (req, res, next) => {
  try {
    await healthDb();
    res.json({ ok: true, service: "UpSysteM API", version: "1.1.0", database: "postgresql" });
  } catch (error) {
    next(error);
  }
});

app.post("/auth/login", async (req, res, next) => {
  try {
    const db = await readDb();
    const username = String(req.body.username || "").trim().toLowerCase();
    const user = db.users.find((u) => u.username.toLowerCase() === username);

    if (!user) return res.status(401).json({ error: "Usuário ou senha incorretos." });

    if (isExpired(user)) {
      user.isActive = false;
      user.updatedAt = nowIso();
      writeDb(db);
      return res.status(403).json({ error: "O acesso deste usuário expirou. Renove sua conta com uma nova key." });
    }

    if (!user.isActive) return res.status(403).json({ error: "Este usuário está inativo." });

    const ok = await bcrypt.compare(String(req.body.password || ""), user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Usuário ou senha incorretos." });

    const device = assertDeviceAllowed(user, req.body.device, true);
    user.lastLoginAt = nowIso();
    user.lastDeviceId = device.deviceId;
    user.updatedAt = nowIso();
    writeDb(db);

    res.json({ token: sign(user), user: publicUser(user) });
  } catch (e) {
    next(e);
  }
});

app.get("/me", auth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.post("/auth/register-key", async (req, res, next) => {
  try {
    const db = await readDb();
    const code = String(req.body.activationKey || "").trim().toUpperCase();
    const key = db.activationKeys.find((k) => k.code === code);
    validateKey(key);

    const username = String(req.body.username || "").trim();
    const name = String(req.body.name || "").trim();
    const password = String(req.body.password || "");
    const confirmPassword = String(req.body.confirmPassword || "");

    if (!username) return res.status(400).json({ error: "Informe um usuário." });
    if (!name) return res.status(400).json({ error: "Informe seu nome." });
    if (!password) return res.status(400).json({ error: "Informe uma senha." });
    if (password !== confirmPassword) return res.status(400).json({ error: "As senhas não conferem." });

    const existing = db.users.find((u) => u.username.toLowerCase() === username.toLowerCase());
    const passwordHash = await bcrypt.hash(password, 10);

    let user;
    if (existing) {
      user = await redeemKeyForUser(db, key, existing, passwordHash, name, req.body.device);
    } else {
      const normalizedDevice = normalizeDevice(req.body.device);
      if (!normalizedDevice?.deviceId) return res.status(400).json({ error: "Dispositivo não identificado. Atualize a extensão." });

      user = {
        id: makeId("user"),
        name,
        username,
        email: key.customerEmail || "",
        passwordHash,
        role: key.role,
        accessType: key.accessType,
        expiresAt: calcExpiresAt(key.accessType),
        isActive: true,
        permissions: key.permissions || defaultPermissions(key.role),
        accountLimit: key.role === "parceiro" ? 3 : null,
        createdBy: key.createdBy || null,
        createdByRole: key.createdByRole || null,
        createdByKey: key.code,
        activeKey: key.code,
        keyHistory: [key.code],
        computerId: normalizedDevice.computerId,
        computerName: normalizedDevice.computerName,
        computerPlatform: normalizedDevice.platform,
        computerScreen: normalizedDevice.screen,
        computerTimezone: normalizedDevice.timezone,
        computerBoundAt: nowIso(),
        deviceId: normalizedDevice.installId || normalizedDevice.computerId,
        deviceName: normalizedDevice.deviceName,
        devicePlatform: normalizedDevice.platform,
        deviceUserAgent: normalizedDevice.userAgent,
        deviceBoundAt: nowIso(),
        lastBrowser: normalizedDevice.browser,
        createdAt: nowIso(),
        updatedAt: nowIso()
      };

      db.users.push(user);
      key.status = "used";
      key.usedAt = nowIso();
      key.usedBy = username;
      key.usedUserId = user.id;
      writeDb(db);
    }

    res.json({ user: publicUser(user) });
  } catch (e) {
    next(e);
  }
});

app.post("/auth/renew-key", async (req, res, next) => {
  try {
    const db = await readDb();
    const username = String(req.body.username || "").trim();
    const user = db.users.find((u) => u.username.toLowerCase() === username.toLowerCase());

    if (!user) return res.status(401).json({ error: "Usuário ou senha incorretos." });

    const ok = await bcrypt.compare(String(req.body.password || ""), user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Usuário ou senha incorretos." });

    const code = String(req.body.activationKey || "").trim().toUpperCase();
    const key = db.activationKeys.find((k) => k.code === code);
    validateKey(key);

    assertDeviceAllowed(user, req.body.device, true);
    const updated = await redeemKeyForUser(db, key, user, null, null, req.body.device);
    res.json({ user: publicUser(updated) });
  } catch (e) {
    next(e);
  }
});

app.get("/users", auth, (req, res) => {
  res.json({ users: visibleUsers(req.db, req.user).map(publicUser) });
});

app.post("/users", auth, requirePermission("user_create"), async (req, res, next) => {
  try {
    const db = req.db;
    const current = req.user;
    const editing = Boolean(req.body.id);
    const target = editing ? db.users.find((u) => u.id === req.body.id) : null;

    if (editing && !hasPermission(current, "user_edit")) return res.status(403).json({ error: "Sem permissão para editar usuários." });
    if (target?.username === "admin" || target?.id === "admin-root") return res.status(403).json({ error: "O Administrador principal não pode ser editado." });

    const role = current.role === "adm" ? (normalizeRole(req.body.role) === "adm" ? "usuario" : normalizeRole(req.body.role)) : "usuario";
    const accessType = current.role === "adm" ? normalizeAccess(req.body.accessType) : (req.body.accessType === "lifetime" ? "monthly" : normalizeAccess(req.body.accessType));

    if (!editing && current.role === "parceiro") assertPartnerLimit(db, current, false);
    if (current.role !== "adm" && editing && target?.role !== "usuario") return res.status(403).json({ error: "Seu perfil só pode editar usuários com cargo Usuário." });

    const duplicate = db.users.find((u) => u.username.toLowerCase() === String(req.body.username || "").trim().toLowerCase() && u.id !== req.body.id);
    if (duplicate) return res.status(400).json({ error: "Já existe usuário com esse login." });

    let user;

    if (editing) {
      user = target;
      user.name = req.body.name || user.name;
      user.username = req.body.username || user.username;
      user.role = role;
      user.accessType = accessType;
      user.expiresAt = req.body.expiresAt ?? calcExpiresAt(accessType);
      user.isActive = Boolean(req.body.isActive);
      user.permissions = current.role === "adm" ? normalizePermissions({ role, permissions: req.body.permissions }) : defaultPermissions("usuario");
      user.accountLimit = role === "parceiro" ? normalizeLimit(req.body.accountLimit ?? user.accountLimit ?? 3) : null;
      user.updatedAt = nowIso();
      if (req.body.password) user.passwordHash = await bcrypt.hash(String(req.body.password), 10);
    } else {
      if (!req.body.password) return res.status(400).json({ error: "Informe uma senha inicial." });

      const normalizedDevice = normalizeDevice(req.body.device);
      if (!normalizedDevice?.deviceId) return res.status(400).json({ error: "Dispositivo não identificado. Atualize a extensão." });

      user = {
        id: makeId("user"),
        name: req.body.name,
        username: req.body.username,
        email: req.body.email || "",
        passwordHash: await bcrypt.hash(String(req.body.password), 10),
        role,
        accessType,
        expiresAt: calcExpiresAt(accessType),
        isActive: true,
        permissions: current.role === "adm" ? normalizePermissions({ role, permissions: req.body.permissions }) : defaultPermissions("usuario"),
        accountLimit: role === "parceiro" ? normalizeLimit(req.body.accountLimit ?? 3) : null,
        createdBy: current.role === "adm" ? null : current.username,
        createdByRole: current.role,
        activeKey: null,
        createdAt: nowIso(),
        updatedAt: nowIso()
      };

      db.users.push(user);
    }

    writeDb(db);
    res.json({ user: publicUser(user) });
  } catch (e) {
    next(e);
  }
});

app.delete("/users/:id/device", auth, (req, res) => {
  if (req.user.role !== "adm") return res.status(403).json({ error: "Apenas Admin pode liberar computador." });

  const target = req.db.users.find((u) => u.id === req.params.id || u.username === req.params.id);
  if (!target) return res.status(404).json({ error: "Usuário não encontrado." });

  if (target.role === "adm" || target.id === req.user.id) {
    return res.status(403).json({ error: "Não é possível liberar o computador deste Administrador." });
  }

  target.computerId = null;
  target.computerName = null;
  target.computerPlatform = null;
  target.computerScreen = null;
  target.computerTimezone = null;
  target.computerBoundAt = null;
  target.deviceId = null;
  target.deviceName = null;
  target.devicePlatform = null;
  target.deviceUserAgent = null;
  target.deviceBoundAt = null;
  target.lastBrowser = null;
  target.lastDeviceId = null;
  target.lastComputerId = null;
  target.updatedAt = nowIso();

  writeDb(req.db);
  res.json({ user: publicUser(target) });
});

app.delete("/users/:id", auth, requirePermission("user_delete"), async (req, res, next) => {
  try {
    const db = req.db;
    const target = db.users.find((u) => u.id === req.params.id || u.username === req.params.id);
    if (!target) return res.json({ ok: true });

    if (!canDeleteUser(req.user, target)) {
      return res.status(403).json({ error: "Apenas Admin pode excluir usuários permitidos." });
    }

    await deleteActivationKeysForUser(target);
    await deleteUserById(target.id);
    db.users = db.users.filter((u) => u.id !== target.id);
    db.activationKeys = db.activationKeys.filter((key) => {
      const linkedCodes = new Set([target.activeKey, target.createdByKey, ...(Array.isArray(target.keyHistory) ? target.keyHistory : [])].filter(Boolean));
      const linkedUser = String(key.usedBy || key.redeemedBy || key.username || "").toLowerCase();
      return !linkedCodes.has(key.code) && key.usedUserId !== target.id && linkedUser !== String(target.username || "").toLowerCase();
    });
    if (repairOrphanActivationKeys(db)) await writeDb(db);
    res.json({ ok: true, removedKeys: true });
  } catch (error) {
    next(error);
  }
});

app.get("/keys", auth, async (req, res, next) => {
  try {
    if (repairOrphanActivationKeys(req.db)) await writeDb(req.db);
    const keys = visibleKeys(req.db, req.user).map((key) => {
    const expired = key.keyExpiresAt && new Date(key.keyExpiresAt).getTime() < Date.now();
    return {
      ...key,
      status: ["inactive", "inativa", "disabled", "revoked", "cancelled", "canceled"].includes(String(key.status || "").toLowerCase())
        ? "inactive"
        : key.status === "used"
          ? "used"
          : key.status === "replaced"
            ? "replaced"
            : expired
              ? "expired"
              : "available"
    };
  });

    res.json({ keys });
  } catch (error) {
    next(error);
  }
});


app.patch("/keys/:id/status", auth, (req, res) => {
  if (req.user.role !== "adm") return res.status(403).json({ error: "Apenas Admin pode alterar status de keys." });

  const action = String(req.body.action || "").trim();
  const allowed = new Set(["inactive", "revoked", "cancelled", "available"]);

  if (!allowed.has(action)) {
    return res.status(400).json({ error: "Ação inválida para key." });
  }

  const key = (req.db.activationKeys || []).find((item) => item.id === req.params.id || item.code === req.params.id);

  if (!key) return res.status(404).json({ error: "Key não encontrada." });

  if (key.status === "used" || key.status === "replaced") {
    return res.status(400).json({ error: "Não é possível alterar uma key já resgatada/substituída." });
  }

  key.status = action === "revoked" || action === "cancelled" ? "inactive" : action;
  key.statusUpdatedAt = nowIso();
  key.statusUpdatedBy = req.user.username;
  key.statusNote = String(req.body.note || "").slice(0, 180);

  writeDb(req.db);

  res.json({ key });
});


app.delete("/keys/:id", auth, async (req, res, next) => {
  try {
    if (!canDeleteKey(req.user)) return res.status(403).json({ error: "Apenas Admin pode excluir keys." });

    const key = (req.db.activationKeys || []).find((item) => item.id === req.params.id || item.code === req.params.id);
    if (!key) return res.json({ ok: true });

    if (key.status === "used" || key.status === "replaced") {
      return res.status(400).json({ error: "Não é possível excluir uma key já resgatada/substituída." });
    }

    await deleteActivationKey(req.params.id);
    req.db.activationKeys = req.db.activationKeys.filter((item) => item.id !== req.params.id && item.code !== req.params.id);
    res.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.post("/keys", auth, requirePermission("user_create"), (req, res, next) => {
  try {
    const db = req.db;
    const current = req.user;

    const customerFirstName = String(req.body.customerFirstName || "").trim();
    const customerLastName = String(req.body.customerLastName || "").trim();
    const customerEmail = String(req.body.customerEmail || "").trim();

    if (!customerFirstName) return res.status(400).json({ error: "Informe o nome do cliente antes de gerar a key." });
    if (!customerLastName) return res.status(400).json({ error: "Informe o sobrenome do cliente antes de gerar a key." });
    if (!customerEmail) return res.status(400).json({ error: "Informe o e-mail do cliente antes de gerar a key." });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(customerEmail)) return res.status(400).json({ error: "Informe um e-mail válido." });

    if (current.role === "parceiro") assertPartnerLimit(db, current, true);

    const role = current.role === "adm" ? (normalizeRole(req.body.role) === "adm" ? "usuario" : normalizeRole(req.body.role)) : "usuario";
    const requestedAccess = normalizeAccess(req.body.accessType);
    if (!canCreateKey(current, requestedAccess)) {
      return res.status(403).json({ error: "Parceiro só pode gerar keys semanais ou mensais." });
    }
    const accessType = requestedAccess;
    const keyHours = Math.max(1, Math.min(720, Number(req.body.keyHours || 24)));

    let code = shortKey();
    while (db.activationKeys.some((k) => k.code === code)) code = shortKey();

    const key = {
      id: makeId("key"),
      code,
      createdAt: nowIso(),
      keyExpiresAt: new Date(Date.now() + keyHours * 60 * 60 * 1000).toISOString(),
      role,
      accessType,
      permissions: normalizePermissions(role),
      note: String(req.body.note || "").slice(0, 120),
      customerFirstName: customerFirstName.slice(0, 80),
      customerLastName: customerLastName.slice(0, 80),
      customerEmail: customerEmail.slice(0, 120),
      createdBy: current.username,
      createdByRole: current.role,
      status: "available",
      usedAt: null,
      usedBy: null
    };

    db.activationKeys.push(key);
    writeDb(db);
    res.json({ key });
  } catch (e) {
    next(e);
  }
});

app.get("/sites", auth, (req, res) => {
  res.json({ sites: req.db.sites || [] });
});

app.patch("/sites", auth, requirePermission("manage_sites"), (req, res) => {
  req.db.sites = Array.isArray(req.body.sites) ? req.body.sites : req.db.sites;
  writeDb(req.db);
  res.json({ sites: req.db.sites });
});

app.post("/logs", auth, (req, res) => {
  const log = {
    id: makeId("log"),
    userId: req.user.id,
    username: req.user.username,
    siteId: req.body.siteId || null,
    siteName: req.body.siteName || null,
    status: req.body.status || "",
    reason: req.body.reason || "",
    message: req.body.message || "",
    url: req.body.url || null,
    createdAt: nowIso()
  };

  const retentionCutoff = Date.now() - LOG_RETENTION_MS;
  req.db.logs.push(log);
  req.db.logs = req.db.logs
    .filter((item) => new Date(item.createdAt || item.at || 0).getTime() >= retentionCutoff)
    .slice(-MAX_LOGS);
  writeDb(req.db);
  res.json({ log });
});

app.get("/logs", auth, (req, res) => {
  const validLogs = (req.db.logs || []).filter((log) => log.username && log.username !== "sem-usuario");
  if (req.user.role === "adm") return res.json({ logs: validLogs.slice(-MAX_LOGS) });
  res.json({ logs: validLogs.filter((l) => l.username === req.user.username).slice(-500) });
});

app.delete("/logs", auth, (req, res) => {
  if (req.user.role === "adm") {
    req.db.logs = [];
  } else {
    req.db.logs = req.db.logs.filter((log) => log.username !== req.user.username);
  }
  writeDb(req.db);
  res.json({ ok: true });
});

app.post("/system-logs", optionalAuth, async (req, res, next) => {
  try {
    const entry = sanitizeSystemLog(req.body || {}, req.user || null, req);
    const log = await appendSystemLog(entry);
    res.json({ ok: true, log });
  } catch (error) {
    next(error);
  }
});

app.get("/system-logs", auth, (req, res) => {
  if (!canReadSystemLogs(req.user)) return res.status(403).json({ error: "Sem permissão." });
  const list = Array.isArray(req.db.systemLogs) ? req.db.systemLogs : [];
  res.json({ systemLogs: list.slice(-100) });
});


function envBool(name, fallback = false) {
  const raw = process.env[name];
  if (raw === undefined || raw === null || raw === "") return fallback;
  return ["1", "true", "yes", "on", "ativo", "enabled"].includes(String(raw).trim().toLowerCase());
}

function envText(name) {
  return String(process.env[name] || "").trim();
}

function getPaymentConfig() {
  const mpAccessToken = envText("MERCADOPAGO_ACCESS_TOKEN");
  const mercadoPago = {
    enabled: envBool("MERCADOPAGO_ENABLED", false),
    accessToken: mpAccessToken,
    accessTokenPresent: Boolean(mpAccessToken),
    webhookSecretPresent: Boolean(envText("MERCADOPAGO_WEBHOOK_SECRET")),
    notificationUrl: envText("MERCADOPAGO_NOTIFICATION_URL") || envText("MERCADOPAGO_WEBHOOK_URL") || "",
    mode: envText("MERCADOPAGO_MODE") || "production",
    configured: Boolean(mpAccessToken)
  };

  const paypalMode = (envText("PAYPAL_MODE") || "sandbox").toLowerCase() === "live" ? "live" : "sandbox";
  const paypal = {
    enabled: envBool("PAYPAL_ENABLED", false),
    clientIdPresent: Boolean(envText("PAYPAL_CLIENT_ID")),
    clientSecretPresent: Boolean(envText("PAYPAL_CLIENT_SECRET")),
    webhookIdPresent: Boolean(envText("PAYPAL_WEBHOOK_ID")),
    mode: paypalMode,
    configured: Boolean(envText("PAYPAL_CLIENT_ID") && envText("PAYPAL_CLIENT_SECRET"))
  };

  return {
    mercadoPago,
    paypal,
    phase3: {
      stripe: "aguardando",
      paddle: "aguardando",
      lemonSqueezy: "aguardando"
    },
    prepared: true,
    message: "Doações preparadas para Mercado Pago e PayPal. Pagamentos aprovados podem gerar key automaticamente quando vinculados a uma doação."
  };
}

function getPublicPaymentStatus(config = getPaymentConfig()) {
  return {
    mercadoPago: {
      enabled: config.mercadoPago.enabled,
      configured: config.mercadoPago.configured,
      accessTokenConfigured: config.mercadoPago.accessTokenPresent,
      webhookSecretConfigured: config.mercadoPago.webhookSecretPresent,
      notificationUrl: config.mercadoPago.notificationUrl || null,
      mode: config.mercadoPago.mode
    },
    paypal: {
      enabled: config.paypal.enabled,
      configured: config.paypal.configured,
      clientIdConfigured: config.paypal.clientIdPresent,
      clientSecretConfigured: config.paypal.clientSecretPresent,
      webhookIdConfigured: config.paypal.webhookIdPresent,
      mode: config.paypal.mode
    },
    phase3: config.phase3,
    prepared: config.prepared,
    message: config.message
  };
}

function requirePaymentsAdmin(req, res) {
  if (req.user?.role !== "adm") {
    res.status(403).json({ error: "Apenas Admin pode acessar pagamentos." });
    return false;
  }
  return true;
}

function normalizeDonationPlan(plan) {
  return ["weekly", "monthly"].includes(plan) ? plan : "monthly";
}

function donationPlanLabel(plan) {
  return normalizeDonationPlan(plan) === "weekly" ? "Semanal" : "Mensal";
}

function normalizePaymentProvider(provider) {
  return ["mercadopago", "paypal"].includes(provider) ? provider : "mercadopago";
}

function normalizeDonationAmount(value) {
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount <= 0) return null;
  return Math.round(amount * 100) / 100;
}

function cancelExpiredDonations(db, minutes = 5) {
  if (!db || !Array.isArray(db.discordOrders)) return { changed: false, count: 0 };
  const now = Date.now();
  let count = 0;
  db.discordOrders = db.discordOrders.map((order) => {
    const status = String(order.donationStatus || order.status || "");
    if (status !== "aguardando_doacao") return order;
    if (order.paymentStatus === "approved" || order.mercadoPagoStatus === "approved" || order.keyCode) return order;
    const created = new Date(order.createdAt || order.created_at || 0).getTime();
    if (!created || now - created < minutes * 60 * 1000) return order;
    count += 1;
    return {
      ...order,
      status: "cancelado",
      donationStatus: "cancelado",
      cancelReason: `Expirado por falta de pagamento em ${minutes} minutos.`,
      canceledAt: nowIso(),
      updatedAt: nowIso()
    };
  });
  return { changed: count > 0, count };
}


function defaultDonationAmount(plan) {
  const normalized = normalizeDonationPlan(plan);
  const envName = normalized === "weekly" ? "MERCADOPAGO_DONATION_WEEKLY_BRL" : "MERCADOPAGO_DONATION_MONTHLY_BRL";
  return normalizeDonationAmount(process.env[envName]) || (normalized === "weekly" ? 1 : 1);
}

function donationKeyHours() {
  const hours = Number.parseInt(process.env.DISCORD_DONATION_KEY_HOURS || "168", 10);
  return Number.isFinite(hours) && hours > 0 ? Math.min(hours, 720) : 168;
}

function truncateDiscordText(value, max = 1900) {
  const text = String(value || "");
  return text.length > max ? `${text.slice(0, max - 20)}\n...` : text;
}

async function sendDiscordChannelMessage(channelId, content, embeds = []) {
  const config = getDiscordConfig();
  if (!config.tokenPresent || !channelId) return { ok: false, skipped: true };
  const response = await fetch(`https://discord.com/api/v10/channels/${encodeURIComponent(channelId)}/messages`, {
    method: "POST",
    headers: {
      Authorization: `Bot ${config.token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ content: truncateDiscordText(content, 1900), embeds })
  });
  const body = await response.text().catch(() => "");
  if (!response.ok) {
    const error = new Error(`Falha ao enviar mensagem Discord (${response.status}). ${body.slice(0, 300)}`);
    error.status = response.status;
    throw error;
  }
  return { ok: true };
}

async function sendDiscordDm(userId, content) {
  const config = getDiscordConfig();
  if (!config.tokenPresent || !userId) return { ok: false, skipped: true, reason: "missing_token_or_user" };
  const dmResponse = await fetch("https://discord.com/api/v10/users/@me/channels", {
    method: "POST",
    headers: {
      Authorization: `Bot ${config.token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ recipient_id: String(userId) })
  });
  const dmBody = await dmResponse.json().catch(() => ({}));
  if (!dmResponse.ok || !dmBody?.id) {
    return { ok: false, status: dmResponse.status, reason: dmBody?.message || "Falha ao abrir DM." };
  }
  const msgResponse = await fetch(`https://discord.com/api/v10/channels/${encodeURIComponent(dmBody.id)}/messages`, {
    method: "POST",
    headers: {
      Authorization: `Bot ${config.token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ content: truncateDiscordText(content, 1900) })
  });
  const msgBody = await msgResponse.json().catch(() => ({}));
  if (!msgResponse.ok) {
    return { ok: false, status: msgResponse.status, reason: msgBody?.message || "Falha ao enviar DM." };
  }
  return { ok: true, channelId: dmBody.id };
}


function defaultDiscordTemplates() {
  return [
    {
      id: "donation_panel",
      name: "Painel de doação",
      buttonLabel: "Doar",
      title: "Apoie o UpSysteM",
      description: "Contribua com o projeto e receba uma key de acesso como agradecimento.",
      body: "Escolha um plano, faça a doação via Pix QR Code e aguarde a confirmação automática. A key será enviada por DM; se a DM estiver bloqueada, ela será entregue no canal temporário de validação.",
      plansText: "Planos disponíveis: Semanal e Mensal.",
      footer: "Após a confirmação do pagamento, a key é gerada automaticamente e vinculada ao seu ID do Discord."
    },
    {
      id: "verification_panel",
      name: "Boas-vindas / Verificação",
      buttonLabel: "Verificar",
      title: "Bem-vindo ao UpSysteM",
      description: "Faça sua verificação para liberar as áreas do servidor e o botão Doar.",
      body: "Clique no botão Verificar abaixo. O bot concederá o cargo user/verificado automaticamente.",
      plansText: "Depois da verificação, você poderá acessar o painel de doação e receber sua key após confirmação.",
      footer: "A verificação é necessária para proteger o fluxo de doação e entrega de keys."
    },
    {
      id: "payment_instructions",
      name: "Instruções de pagamento",
      buttonLabel: "Doar",
      title: "Como funciona a doação",
      description: "O pagamento padrão é Pix via QR Code.",
      body: "Ao clicar em Doar, selecione o plano. O bot criará uma sala temporária de validação com QR Code Pix, copia e cola e link alternativo.",
      plansText: "Semanal ou Mensal.",
      footer: "Guarde a key com segurança."
    },
    {
      id: "extension_info",
      name: "Informações da extensão",
      buttonLabel: "Doar",
      title: "UpSysteM Extension",
      description: "Automação com controle de acesso por key.",
      body: "A key libera o uso da extensão conforme o plano escolhido. O acesso é pessoal e vinculado às regras do sistema.",
      plansText: "Semanal e Mensal.",
      footer: "Suporte pelo servidor Discord."
    },
    {
      id: "support_key",
      name: "Suporte/key",
      buttonLabel: "Doar",
      title: "Suporte de key",
      description: "Use este canal para orientações sobre ativação.",
      body: "Depois de receber sua key, informe-a na extensão para ativar o acesso. Se houver falha, procure o suporte.",
      plansText: "A key segue o plano escolhido na doação.",
      footer: "Não compartilhe sua key com terceiros."
    }
  ];
}

function getDiscordTemplates(db) {
  const existing = Array.isArray(db.discordTemplates) ? db.discordTemplates : [];
  const map = new Map(defaultDiscordTemplates().map((tpl) => [tpl.id, tpl]));
  for (const tpl of existing) {
    if (tpl?.id && String(tpl.id).startsWith("__")) continue;
    if (tpl?.id && map.has(tpl.id)) map.set(tpl.id, { ...map.get(tpl.id), ...tpl });
  }
  return Array.from(map.values());
}

function templateToDiscordPayload(template) {
  const title = String(template?.title || "Apoie o UpSysteM").slice(0, 120);
  const description = String(template?.description || "Contribua e receba uma key de acesso como agradecimento.").slice(0, 4000);
  const body = String(template?.body || "Clique em Doar para escolher o plano e gerar o Pix.").slice(0, 4000);
  const plansText = String(template?.plansText || "Planos disponíveis: Semanal e Mensal.").slice(0, 1000);
  const footer = String(template?.footer || "Key vinculada ao seu ID do Discord.").slice(0, 1000);
  return {
    embeds: [{
      title,
      description,
      color: 0xd4af37,
      fields: [
        { name: "Informações", value: body || "-" },
        { name: "Planos", value: plansText || "-" },
        { name: "Importante", value: footer || "-" }
      ],
      footer: { text: "UpSysteM • Doação com key de acesso" }
    }]
  };
}

async function sendDiscordChannelPayload(channelId, payload = {}) {
  const config = getDiscordConfig();
  if (!config.tokenPresent || !channelId) return { ok: false, skipped: true };
  const response = await fetch(`https://discord.com/api/v10/channels/${encodeURIComponent(channelId)}/messages`, {
    method: "POST",
    headers: {
      Authorization: `Bot ${config.token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(`Falha ao enviar payload Discord (${response.status}). ${JSON.stringify(data).slice(0, 300)}`);
    error.status = response.status;
    throw error;
  }
  return { ok: true, message: data };
}

function discordSafeName(value) {
  return String(value || "usuario").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 24) || "usuario";
}

async function deleteDiscordChannelLater(channelId, minutes = 3) {
  const config = getDiscordConfig();
  if (!config.tokenPresent || !channelId) return;
  const delay = Math.max(1, Math.min(30, Number(minutes) || 3)) * 60 * 1000;
  setTimeout(async () => {
    try {
      await fetch(`https://discord.com/api/v10/channels/${encodeURIComponent(channelId)}`, {
        method: "DELETE",
        headers: { Authorization: `Bot ${config.token}` }
      });
      await sendDiscordChannelMessage(config.logChannelId, `🧹 Canal temporário de validação removido: ${channelId}`).catch(() => null);
    } catch (error) {
      await appendSystemLog({ level: "warning", origin: "api.discord.validation.delete", message: error.message || "Falha ao excluir canal temporário.", context: { channelId } }).catch(() => null);
    }
  }, delay).unref?.();
}

function ensureDiscordOrderArray(db) {
  if (!Array.isArray(db.discordOrders)) db.discordOrders = [];
  return db.discordOrders;
}

function ensureActivationKeyArray(db) {
  if (!Array.isArray(db.activationKeys)) db.activationKeys = [];
  return db.activationKeys;
}

function buildDonationKey(db, order, payment = {}) {
  const keys = ensureActivationKeyArray(db);
  let code = shortKey();
  while (keys.some((item) => item.code === code)) code = shortKey();
  const username = order.discordUsername || order.discordDisplayName || "Discord";
  const key = {
    id: makeId("key"),
    code,
    createdAt: nowIso(),
    keyExpiresAt: new Date(Date.now() + donationKeyHours() * 60 * 60 * 1000).toISOString(),
    role: "usuario",
    accessType: normalizeDonationPlan(order.plan),
    permissions: normalizePermissions("usuario"),
    note: "Key de agradecimento gerada automaticamente por doação via Discord/Mercado Pago.",
    customerFirstName: String(username).slice(0, 80),
    customerLastName: "Discord",
    customerEmail: String(order.customerEmail || "discord@upsystem.local").slice(0, 120),
    createdBy: "discord",
    createdByRole: "system",
    status: "available",
    usedAt: null,
    usedBy: null,
    source: "discord",
    donationId: order.id,
    paymentId: String(payment.id || order.paymentId || ""),
    discordUserId: order.discordUserId || null,
    discordUsername: order.discordUsername || null,
    discordDisplayName: order.discordDisplayName || null
  };
  keys.push(key);
  return key;
}

async function finalizeApprovedDonation(db, order, payment = {}) {
  if (!order) return { ok: false, reason: "order_not_found" };
  const alreadyHasKey = Boolean(order.keyCode || order.keyId);
  order.paymentId = String(payment.id || order.paymentId || "");
  order.paymentStatus = String(payment.status || order.paymentStatus || "approved");
  order.mpStatusDetail = String(payment.status_detail || order.mpStatusDetail || "");
  order.status = alreadyHasKey ? (order.deliveryStatus || "key_gerada") : "doacao_confirmada";
  order.donationStatus = alreadyHasKey ? (order.deliveryStatus || "key_gerada") : "doacao_confirmada";
  order.paidAt = order.paidAt || payment.date_approved || nowIso();
  order.updatedAt = nowIso();

  let key = null;
  if (!alreadyHasKey) {
    key = buildDonationKey(db, order, payment);
    order.keyId = key.id;
    order.keyCode = key.code;
    order.keyStatus = "generated";
    order.status = "key_gerada";
    order.donationStatus = "key_gerada";
    order.note = "Doação confirmada. Key gerada automaticamente.";
  }

  if (order.discordUserId && order.keyCode && order.deliveryStatus !== "key_entregue") {
    const dmText = [
      "Obrigado pela sua doação ao UpSysteM.",
      "",
      `Sua key de acesso: ${order.keyCode}`,
      `Plano: ${donationPlanLabel(order.plan)}`,
      "",
      "Use essa key na extensão para ativar seu acesso."
    ].join("\n");
    const delivery = await sendDiscordDm(order.discordUserId, dmText).catch((error) => ({ ok: false, reason: error.message || "Falha ao enviar DM." }));
    order.deliveryAttemptedAt = nowIso();
    if (delivery.ok) {
      order.deliveryStatus = "key_entregue";
      order.status = "key_entregue";
      order.donationStatus = "key_entregue";
      order.deliveredAt = nowIso();
      await sendDiscordChannelMessage(getDiscordConfig().logChannelId, `✅ Doação confirmada e key entregue por DM. Usuário: <@${order.discordUserId}> · Plano: ${donationPlanLabel(order.plan)} · Key: ${order.keyCode}`).catch(() => null);
    } else {
      order.deliveryError = delivery.reason || "Não foi possível enviar DM ao usuário.";
      if (order.validationChannelId) {
        await sendDiscordChannelMessage(order.validationChannelId, `✅ Doação confirmada. Não consegui enviar DM, então sua key de acesso é: **${order.keyCode}**\nEste canal será excluído automaticamente em ${getDiscordConfig().validationTtlMinutes || 3} minuto(s).`).catch(() => null);
        order.deliveryStatus = "falha_dm_key_entregue_no_canal";
        order.status = "falha_dm_key_entregue_no_canal";
        order.donationStatus = "falha_dm_key_entregue_no_canal";
        deleteDiscordChannelLater(order.validationChannelId, getDiscordConfig().validationTtlMinutes || 3);
      } else {
        order.deliveryStatus = "falha_na_entrega";
        order.status = "falha_na_entrega";
        order.donationStatus = "falha_na_entrega";
      }
      await appendSystemLog({
        level: "warning",
        origin: "api.discord.delivery",
        message: "Falha ao entregar key por DM.",
        context: { orderId: order.id, discordUserId: order.discordUserId, validationChannelId: order.validationChannelId || null, reason: order.deliveryError }
      }).catch(() => null);
      await sendDiscordChannelMessage(getDiscordConfig().logChannelId, `⚠️ Doação confirmada, mas falhou a entrega por DM. Usuário: <@${order.discordUserId}> · Key registrada. ${order.validationChannelId ? `Entregue no canal temporário ${order.validationChannelId}.` : "Sem canal temporário."}`).catch(() => null);
    }
    if (delivery.ok && order.validationChannelId) deleteDiscordChannelLater(order.validationChannelId, getDiscordConfig().validationTtlMinutes || 3);
    order.updatedAt = nowIso();
  }

  db.discordOrders = [order, ...ensureDiscordOrderArray(db).filter((item) => item.id !== order.id)].slice(0, 100);
  return { ok: true, order, key, alreadyHasKey };
}

function mercadoPagoTokenDiagnostic(config = {}) {
  const token = String(config.accessToken || "").trim();
  const prefix = token ? token.slice(0, Math.min(12, token.length)) : "";
  const tokenType = token.startsWith("APP_USR-") ? "production" : token.startsWith("TEST-") ? "test" : token.startsWith("APP_") ? "public_key_or_invalid" : "unknown";
  return {
    tokenPresent: Boolean(token),
    tokenPrefix: prefix,
    tokenLength: token.length,
    tokenType,
    looksLikePublicKey: token.startsWith("APP_USR-") && token.length < 80 ? false : token.startsWith("APP_") && !token.startsWith("APP_USR-"),
    configuredMode: String(config.mode || "production")
  };
}

function mercadoPagoErrorDiagnostic(error, config = {}, payload = {}) {
  const details = error?.details && typeof error.details === "object" ? error.details : {};
  const tokenInfo = mercadoPagoTokenDiagnostic(config);
  const code = details.code || details.error || details.status || null;
  const message = details.message || error?.message || "Falha Mercado Pago.";
  const diagnostic = {
    provider: "mercadopago",
    endpoint: "POST /checkout/preferences",
    httpStatus: error?.status || null,
    mercadoPagoCode: code,
    mercadoPagoMessage: message,
    mercadoPagoRaw: details,
    requestSummary: {
      external_reference: payload.external_reference || null,
      currency_id: payload.items?.[0]?.currency_id || null,
      unit_price: payload.items?.[0]?.unit_price || null,
      notification_url_present: Boolean(payload.notification_url),
      payer_email_present: Boolean(payload.payer?.email)
    },
    renderConfig: {
      enabled: Boolean(config.enabled),
      configured: Boolean(config.configured),
      mode: tokenInfo.configuredMode,
      tokenPresent: tokenInfo.tokenPresent,
      tokenPrefix: tokenInfo.tokenPrefix,
      tokenLength: tokenInfo.tokenLength,
      tokenType: tokenInfo.tokenType,
      looksLikePublicKey: tokenInfo.looksLikePublicKey
    },
    likelyCauses: []
  };

  if (!tokenInfo.tokenPresent) diagnostic.likelyCauses.push("MERCADOPAGO_ACCESS_TOKEN ausente no Render.");
  if (tokenInfo.looksLikePublicKey) diagnostic.likelyCauses.push("MERCADOPAGO_ACCESS_TOKEN parece Public Key. Use o Access Token produtivo ou de teste.");
  if (tokenInfo.tokenType === "test" && tokenInfo.configuredMode === "production") diagnostic.likelyCauses.push("Token de teste com MERCADOPAGO_MODE=production.");
  if (tokenInfo.tokenType === "production" && tokenInfo.configuredMode === "sandbox") diagnostic.likelyCauses.push("Token produtivo com MERCADOPAGO_MODE=sandbox.");
  if (String(code).toLowerCase().includes("unauthorized") || String(message).toLowerCase().includes("unauthorized")) {
    diagnostic.likelyCauses.push("Mercado Pago recusou a requisição por política/autorização. Verifique conta habilitada, Access Token correto, app produtivo e políticas da conta.");
  }
  if (!diagnostic.likelyCauses.length) diagnostic.likelyCauses.push("Verifique o payload, credenciais e permissões da aplicação Mercado Pago.");
  return diagnostic;
}

function createPreparedOrder(body = {}, user = null) {
  const provider = normalizePaymentProvider(String(body.provider || body.paymentProvider || "mercadopago").toLowerCase());
  const plan = normalizeDonationPlan(String(body.plan || "monthly").toLowerCase());
  const currency = String(body.currency || (provider === "paypal" ? "USD" : "BRL")).toUpperCase().slice(0, 10);
  const amount = normalizeDonationAmount(body.amount) || defaultDonationAmount(plan);
  return {
    id: makeId("donation"),
    source: String(body.source || "discord_donation").slice(0, 80),
    status: "preparada",
    donationStatus: "preparada",
    provider,
    plan,
    currency,
    amount,
    discordUserId: String(body.discordUserId || "").slice(0, 80) || null,
    discordUsername: String(body.discordUsername || "").slice(0, 120) || null,
    discordDisplayName: String(body.discordDisplayName || "").slice(0, 120) || null,
    discordChannelId: String(body.discordChannelId || "").slice(0, 80) || null,
    discordGuildId: String(body.discordGuildId || "").slice(0, 80) || null,
    customerEmail: String(body.customerEmail || "").slice(0, 180) || null,
    paymentId: null,
    paymentStatus: "not_created",
    paymentUrl: null,
    pixQrCode: null,
    pixQrCodeBase64: null,
    pixTicketUrl: null,
    keyId: null,
    keyCode: null,
    keyStatus: null,
    deliveryStatus: null,
    note: "Doação preparada. A key será gerada automaticamente quando o pagamento aprovado for confirmado.",
    createdBy: user?.username || "discord",
    createdAt: nowIso(),
    updatedAt: nowIso()
  };
}

function findDonationOrder(db, externalReference) {
  const orders = Array.isArray(db.discordOrders) ? db.discordOrders : [];
  return orders.find((order) => order.id === externalReference || order.externalReference === externalReference || order.mpPreferenceId === externalReference);
}

async function createMercadoPagoPreference(order, config) {
  const notificationUrl = envText("MERCADOPAGO_NOTIFICATION_URL") || envText("MERCADOPAGO_WEBHOOK_URL") || "";
  const payload = {
    external_reference: order.id,
    metadata: {
      upsystem_order_id: order.id,
      source: "upsystem_discord_donation",
      plan: order.plan
    },
    items: [
      {
        id: `upsystem-${order.plan}`,
        title: `Doação UpSysteM - Key ${donationPlanLabel(order.plan)}`,
        description: "Contribuição voluntária com key de acesso como agradecimento.",
        quantity: 1,
        currency_id: order.currency || "BRL",
        unit_price: order.amount
      }
    ],
    payer: {
      email: order.customerEmail || undefined
    },
    back_urls: {},
    statement_descriptor: "UPSYSTEM"
  };

  if (notificationUrl) payload.notification_url = notificationUrl;

  const response = await fetch("https://api.mercadopago.com/checkout/preferences", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.accessToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = data?.message || data?.error || `Falha ao criar preferência Mercado Pago (${response.status}).`;
    const error = new Error(message);
    error.status = response.status;
    error.details = data;
    error.mpPayload = payload;
    error.mpDiagnostic = mercadoPagoErrorDiagnostic(error, config, payload);
    throw error;
  }

  return data;
}


async function createMercadoPagoPixPayment(order, config) {
  const notificationUrl = envText("MERCADOPAGO_NOTIFICATION_URL") || envText("MERCADOPAGO_WEBHOOK_URL") || "";
  if (!order.customerEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(order.customerEmail)) {
    const error = new Error("Informe um e-mail válido para gerar Pix Mercado Pago.");
    error.status = 400;
    throw error;
  }

  const payload = {
    transaction_amount: Number(order.amount),
    description: `Doação UpSysteM - Key ${donationPlanLabel(order.plan)}`,
    payment_method_id: "pix",
    external_reference: order.id,
    notification_url: notificationUrl || undefined,
    metadata: {
      upsystem_order_id: order.id,
      source: "upsystem_discord_donation",
      plan: order.plan,
      discord_user_id: order.discordUserId || undefined
    },
    payer: {
      email: order.customerEmail,
      first_name: order.discordDisplayName || order.discordUsername || "Discord",
      last_name: "UpSysteM"
    }
  };

  const response = await fetch("https://api.mercadopago.com/v1/payments", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${config.accessToken}`,
      "Content-Type": "application/json",
      "X-Idempotency-Key": order.id
    },
    body: JSON.stringify(payload)
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message = data?.message || data?.error || `Falha ao criar pagamento Pix Mercado Pago (${response.status}).`;
    const error = new Error(message);
    error.status = response.status;
    error.details = data;
    error.mpPayload = payload;
    error.mpDiagnostic = mercadoPagoErrorDiagnostic(error, config, {
      external_reference: payload.external_reference,
      items: [{ currency_id: "BRL", unit_price: payload.transaction_amount }],
      notification_url: payload.notification_url,
      payer: payload.payer
    });
    throw error;
  }

  return data;
}

async function fetchMercadoPagoPayment(paymentId, config) {
  const response = await fetch(`https://api.mercadopago.com/v1/payments/${encodeURIComponent(paymentId)}`, {
    headers: { Authorization: `Bearer ${config.accessToken}` }
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data?.message || data?.error || `Falha ao consultar pagamento Mercado Pago (${response.status}).`);
    error.status = response.status;
    error.details = data;
    throw error;
  }
  return data;
}

function requireDiscordAdmin(req, res) {
  if (!hasPermission(req.user, "discord_integration") || req.user.role !== "adm") {
    res.status(403).json({ error: "Apenas Admin pode acessar a integração Discord." });
    return false;
  }
  return true;
}

function discordEnvConfig() {
  return {
    enabled: envBool("DISCORD_ENABLED", false),
    clientId: envText("DISCORD_CLIENT_ID"),
    guildId: envText("DISCORD_GUILD_ID"),
    salesChannelId: envText("DISCORD_SALES_CHANNEL_ID"),
    panelChannelId: envText("DISCORD_DONATION_PANEL_CHANNEL_ID") || envText("DISCORD_SALES_CHANNEL_ID"),
    logChannelId: envText("DISCORD_LOG_CHANNEL_ID"),
    validationCategoryId: envText("DISCORD_VALIDATION_CATEGORY_ID"),
    staffRoleId: envText("DISCORD_STAFF_ROLE_ID") || envText("DISCORD_ROLE_ADMIRO_ID"),
    verifyChannelId: envText("DISCORD_VERIFY_CHANNEL_ID"),
    userRoleId: envText("DISCORD_ROLE_USER_ID"),
    roleAdmiroId: envText("DISCORD_ROLE_ADMIRO_ID"),
    roleParceiroId: envText("DISCORD_ROLE_PARCEIRO_ID"),
    roleClientesId: envText("DISCORD_ROLE_CLIENTES_ID"),
    roleDevId: envText("DISCORD_ROLE_DEV_ID")
  };
}

function getSavedDiscordConfig(db) {
  const list = Array.isArray(db?.discordTemplates) ? db.discordTemplates : [];
  const found = list.find((item) => item?.id === "__discord_config");
  return found?.values && typeof found.values === "object" ? found.values : {};
}

function numericConfig(value) {
  const text = String(value || "").trim();
  return /^\d{8,}$/.test(text) ? text : "";
}

function getDiscordConfig(db = null) {
  const env = discordEnvConfig();
  const saved = getSavedDiscordConfig(db);
  const merged = { ...env };
  for (const key of ["clientId", "guildId", "salesChannelId", "panelChannelId", "logChannelId", "validationCategoryId", "staffRoleId", "verifyChannelId", "userRoleId", "roleAdmiroId", "roleParceiroId", "roleClientesId", "roleDevId"]) {
    if (numericConfig(saved[key])) merged[key] = numericConfig(saved[key]);
  }
  if (!merged.panelChannelId) merged.panelChannelId = merged.salesChannelId;
  const validationTtlMinutes = Math.max(1, Math.min(30, Number.parseInt(process.env.DISCORD_VALIDATION_CHANNEL_TTL_MINUTES || "3", 10) || 3));
  const token = envText("DISCORD_BOT_TOKEN");
  const configured = Boolean(merged.clientId && merged.guildId && merged.salesChannelId && merged.logChannelId && token);

  return {
    ...merged,
    enabled: env.enabled,
    configured,
    validationTtlMinutes,
    token,
    tokenPresent: Boolean(token),
    usingSavedConfig: Boolean(Object.keys(saved || {}).length)
  };
}

function getPublicDiscordStatus(config = getDiscordConfig()) {
  return {
    enabled: config.enabled,
    configured: config.configured,
    clientIdConfigured: Boolean(config.clientId),
    guildIdConfigured: Boolean(config.guildId),
    salesChannelConfigured: Boolean(config.salesChannelId),
    logChannelConfigured: Boolean(config.logChannelId),
    tokenConfigured: config.tokenPresent,
    clientId: config.clientId || null,
    guildId: config.guildId || null,
    salesChannelId: config.salesChannelId || null,
    panelChannelId: config.panelChannelId || null,
    logChannelId: config.logChannelId || null,
    validationCategoryConfigured: Boolean(config.validationCategoryId),
    staffRoleConfigured: Boolean(config.staffRoleId),
    verifyChannelConfigured: Boolean(config.verifyChannelId),
    userRoleConfigured: Boolean(config.userRoleId),
    verifyChannelId: config.verifyChannelId || null,
    userRoleId: config.userRoleId || null,
    roleAdmiroId: config.roleAdmiroId || null,
    roleParceiroId: config.roleParceiroId || null,
    roleClientesId: config.roleClientesId || null,
    roleDevId: config.roleDevId || null,
    validationTtlMinutes: config.validationTtlMinutes || 3,
    usingSavedConfig: Boolean(config.usingSavedConfig),
    mode: config.enabled ? "ready_to_connect" : "prepared_disabled",
    message: config.enabled
      ? "Discord ativo. Bot pronto para painéis, verificação e doações."
      : "Discord preparado, mas desativado por DISCORD_ENABLED=false."
  };
}

app.get("/discord/status", auth, (req, res) => {
  if (!requireDiscordAdmin(req, res)) return;
  const config = getDiscordConfig(req.db);
  res.json({ ok: true, discord: getPublicDiscordStatus(config) });
});

app.put("/discord/config", auth, async (req, res, next) => {
  try {
    if (!requireDiscordAdmin(req, res)) return;
    const body = req.body || {};
    const values = {
      clientId: numericConfig(body.clientId),
      guildId: numericConfig(body.guildId),
      salesChannelId: numericConfig(body.salesChannelId),
      panelChannelId: numericConfig(body.panelChannelId) || numericConfig(body.salesChannelId),
      logChannelId: numericConfig(body.logChannelId),
      verifyChannelId: numericConfig(body.verifyChannelId),
      userRoleId: numericConfig(body.userRoleId)
    };
    const invalid = Object.entries(body).filter(([key, value]) => value && ["clientId", "guildId", "salesChannelId", "panelChannelId", "logChannelId", "verifyChannelId", "userRoleId"].includes(key) && !numericConfig(value));
    if (invalid.length) return res.status(400).json({ error: `IDs inválidos: ${invalid.map(([key]) => key).join(", ")}.` });
    const configEntry = { id: "__discord_config", name: "Configuração Discord", values, updatedAt: nowIso(), updatedBy: req.user.username };
    req.db.discordTemplates = [configEntry, ...(Array.isArray(req.db.discordTemplates) ? req.db.discordTemplates.filter((item) => item.id !== "__discord_config") : [])];
    await writeDb(req.db);
    const config = getDiscordConfig(req.db);
    res.json({ ok: true, discord: getPublicDiscordStatus(config), config: values });
  } catch (error) { next(error); }
});

app.post("/discord/config/restore", auth, async (req, res, next) => {
  try {
    if (!requireDiscordAdmin(req, res)) return;
    req.db.discordTemplates = (Array.isArray(req.db.discordTemplates) ? req.db.discordTemplates : []).filter((item) => item.id !== "__discord_config");
    await writeDb(req.db);
    const config = getDiscordConfig(req.db);
    res.json({ ok: true, discord: getPublicDiscordStatus(config), message: "Configuração restaurada do Render." });
  } catch (error) { next(error); }
});

app.post("/discord/test", auth, async (req, res, next) => {
  try {
    if (!requireDiscordAdmin(req, res)) return;

    const config = getDiscordConfig(req.db);
    if (!config.tokenPresent) return res.status(400).json({ error: "Token do bot não configurado no Render." });
    if (!config.logChannelId) return res.status(400).json({ error: "Canal de logs do Discord não configurado." });

    const content = `✅ UpSysteM Bot conectado com sucesso. Teste realizado pelo Console em ${new Date().toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo" })}.`;
    const response = await fetch(`https://discord.com/api/v10/channels/${encodeURIComponent(config.logChannelId)}/messages`, {
      method: "POST",
      headers: {
        Authorization: `Bot ${config.token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ content })
    });

    if (!response.ok) {
      const body = await response.text().catch(() => "");
      const error = new Error(`Falha no teste Discord (${response.status}). ${body.slice(0, 300)}`);
      error.status = response.status;
      throw error;
    }

    res.json({
      ok: true,
      message: "Mensagem de teste enviada no canal de logs do Discord.",
      discord: getPublicDiscordStatus(config)
    });
  } catch (error) {
    appendSystemLog({
      level: "warning",
      origin: "api.discord.test",
      message: error.message || "Falha ao testar Discord.",
      userId: req.user?.id || null,
      username: req.user?.username || null,
      context: { status: error.status || null }
    }).catch(() => null);
    next(error);
  }
});



app.get("/discord/templates", auth, (req, res) => {
  if (!requireDiscordAdmin(req, res)) return;
  res.json({ ok: true, templates: getDiscordTemplates(req.db) });
});

app.put("/discord/templates/:id", auth, async (req, res, next) => {
  try {
    if (!requireDiscordAdmin(req, res)) return;
    const id = String(req.params.id || "").trim();
    const templates = getDiscordTemplates(req.db);
    const base = templates.find((tpl) => tpl.id === id);
    if (!base) return res.status(404).json({ error: "Template não encontrado." });
    const body = req.body || {};
    const updated = {
      ...base,
      title: String(body.title || base.title || "").slice(0, 120),
      description: String(body.description || base.description || "").slice(0, 4000),
      body: String(body.body || base.body || "").slice(0, 4000),
      plansText: String(body.plansText || base.plansText || "").slice(0, 1000),
      footer: String(body.footer || base.footer || "").slice(0, 1000),
      buttonLabel: String(body.buttonLabel || base.buttonLabel || "Doar").slice(0, 40),
      updatedAt: nowIso(),
      updatedBy: req.user?.username || "adm"
    };
    req.db.discordTemplates = [updated, ...templates.filter((tpl) => tpl.id !== id)];
    await writeDb(req.db);
    res.json({ ok: true, template: updated, templates: getDiscordTemplates(req.db) });
  } catch (error) { next(error); }
});

app.post("/discord/templates/send-panel", auth, async (req, res, next) => {
  try {
    if (!requireDiscordAdmin(req, res)) return;
    const config = getDiscordConfig(req.db);
    if (!config.tokenPresent) return res.status(400).json({ error: "Token do bot não configurado." });
    const templateId = String(req.body?.templateId || "donation_panel");
    const channelId = String(req.body?.channelId || config.panelChannelId || config.salesChannelId || "").trim();
    if (!channelId) return res.status(400).json({ error: "Canal do painel Discord não configurado." });
    const template = getDiscordTemplates(req.db).find((tpl) => tpl.id === templateId) || getDiscordTemplates(req.db)[0];
    const payload = templateToDiscordPayload(template);
    payload.components = [{
      type: 1,
      components: [{ type: 2, style: 3, custom_id: "upsystem_donate_start", label: template.buttonLabel || "Doar" }]
    }];
    const sent = await sendDiscordChannelPayload(channelId, payload);
    await sendDiscordChannelMessage(config.logChannelId, `📌 Painel de doação enviado no canal <#${channelId}> pelo Console.`).catch(() => null);
    res.json({ ok: true, message: "Painel enviado no canal configurado.", discordMessageId: sent.message?.id || null });
  } catch (error) { next(error); }
});

app.post("/discord/templates/send-verify-panel", auth, async (req, res, next) => {
  try {
    if (!requireDiscordAdmin(req, res)) return;
    const config = getDiscordConfig(req.db);
    if (!config.tokenPresent) return res.status(400).json({ error: "Token do bot não configurado." });
    const channelId = String(req.body?.channelId || config.verifyChannelId || "").trim();
    if (!channelId) return res.status(400).json({ error: "Canal de verificação do Discord não configurado." });
    const template = getDiscordTemplates(req.db).find((tpl) => tpl.id === "verification_panel") || getDiscordTemplates(req.db)[0];
    const payload = templateToDiscordPayload(template);
    payload.components = [{
      type: 1,
      components: [{ type: 2, style: 1, custom_id: "upsystem_verify_user", label: template.buttonLabel || "Verificar" }]
    }];
    const sent = await sendDiscordChannelPayload(channelId, payload);
    await sendDiscordChannelMessage(config.logChannelId, `📌 Painel de verificação enviado no canal <#${channelId}> pelo Console.`).catch(() => null);
    res.json({ ok: true, message: "Painel de verificação enviado no canal configurado.", discordMessageId: sent.message?.id || null });
  } catch (error) { next(error); }
});

app.get("/payments/status", auth, (req, res) => {
  if (!requirePaymentsAdmin(req, res)) return;
  res.json({ ok: true, payments: getPublicPaymentStatus() });
});

app.get("/discord/orders", auth, async (req, res, next) => {
  try {
    if (!requirePaymentsAdmin(req, res)) return;
    const expired = cancelExpiredDonations(req.db, 5);
    if (expired.changed) await writeDb(req.db);
    const orders = Array.isArray(req.db.discordOrders) ? req.db.discordOrders : [];
    res.json({ ok: true, orders: orders.slice(0, 100), expired: expired.count });
  } catch (error) { next(error); }
});

app.post("/discord/orders", auth, async (req, res, next) => {
  try {
    if (!requirePaymentsAdmin(req, res)) return;
    const order = createPreparedOrder(req.body || {}, req.user);
    req.db.discordOrders = [order, ...(Array.isArray(req.db.discordOrders) ? req.db.discordOrders : [])].slice(0, 100);
    await writeDb(req.db);
    res.status(201).json({ ok: true, order });
  } catch (error) {
    next(error);
  }
});

app.post("/payments/mercadopago/donation", auth, async (req, res, next) => {
  try {
    if (!requirePaymentsAdmin(req, res)) return;

    const config = getPaymentConfig().mercadoPago;
    if (!config.configured) return res.status(400).json({ error: "Mercado Pago não configurado no Render." });
    if (!config.enabled) return res.status(400).json({ error: "Mercado Pago está em modo preparado. Altere MERCADOPAGO_ENABLED=true para criar link de doação." });

    const order = createPreparedOrder({ ...(req.body || {}), provider: "mercadopago", currency: "BRL", source: "manual_console" }, req.user);
    if (!order.amount) return res.status(400).json({ error: "Informe um valor de doação válido." });

    order.status = "aguardando_doacao";
    order.donationStatus = "aguardando_doacao";
    order.paymentStatus = "preference_created";
    order.note = "Link de doação Mercado Pago criado. Key ainda não será gerada automaticamente nesta etapa.";

    const preference = await createMercadoPagoPreference(order, config);
    order.mpPreferenceId = preference.id || null;
    order.externalReference = order.id;
    order.paymentUrl = preference.init_point || preference.sandbox_init_point || null;
    order.sandboxPaymentUrl = preference.sandbox_init_point || null;
    order.mpRawStatus = preference.status || null;
    order.updatedAt = nowIso();

    req.db.discordOrders = [order, ...(Array.isArray(req.db.discordOrders) ? req.db.discordOrders : [])].slice(0, 100);
    await writeDb(req.db);

    res.status(201).json({ ok: true, order, paymentUrl: order.paymentUrl });
  } catch (error) {
    const config = getPaymentConfig().mercadoPago;
    const diagnostic = error.mpDiagnostic || mercadoPagoErrorDiagnostic(error, config, error.mpPayload || {});
    appendSystemLog({
      level: "warning",
      origin: "api.payments.mercadopago.donation",
      message: error.message || "Falha ao criar link de doação Mercado Pago.",
      userId: req.user?.id || null,
      username: req.user?.username || null,
      context: diagnostic
    }).catch(() => null);
    res.status(error.status || 500).json({
      error: error.message || "Falha ao criar link de doação Mercado Pago.",
      code: diagnostic.mercadoPagoCode || null,
      diagnostic
    });
  }
});

app.post("/webhooks/mercadopago", async (req, res) => {
  const config = getPaymentConfig().mercadoPago;
  if (!config.enabled || !config.configured) {
    await appendSystemLog({
      level: "info",
      origin: "api.webhook.mercadopago",
      message: "Webhook Mercado Pago recebido em modo preparado/desativado.",
      context: { enabled: config.enabled, configured: config.configured, body: req.body || null }
    }).catch(() => null);
    return res.status(202).json({ ok: true, ignored: true, reason: "mercadopago_disabled_or_unconfigured" });
  }

  try {
    const paymentId = String(req.body?.data?.id || req.body?.id || req.query?.id || "").trim();
    const eventType = String(req.body?.type || req.query?.type || "").trim();
    const action = String(req.body?.action || "").trim();
    if (!paymentId) {
      await appendSystemLog({
        level: "info",
        origin: "api.webhook.mercadopago",
        message: "Webhook Mercado Pago recebido sem payment id.",
        context: { eventType, action, body: req.body || null }
      }).catch(() => null);
      return res.status(202).json({ ok: true, received: true, message: "Webhook recebido sem payment id." });
    }

    const payment = await fetchMercadoPagoPayment(paymentId, config);
    const externalReference = String(payment.external_reference || payment.metadata?.upsystem_order_id || "").trim();
    const db = await readDb();
    const order = findDonationOrder(db, externalReference);

    await appendSystemLog({
      level: order ? "info" : "warning",
      origin: "api.webhook.mercadopago",
      message: order ? "Webhook Mercado Pago vinculado à doação." : "Webhook Mercado Pago sem doação vinculada.",
      context: {
        eventType,
        action,
        paymentId,
        externalReference,
        paymentStatus: payment.status || null,
        matched: Boolean(order)
      }
    }).catch(() => null);

    let finalized = null;
    if (order) {
      order.paymentId = String(payment.id || paymentId);
      order.paymentStatus = String(payment.status || "unknown");
      order.mpStatusDetail = String(payment.status_detail || "");
      order.updatedAt = nowIso();

      if (payment.status === "approved") {
        finalized = await finalizeApprovedDonation(db, order, payment);
      } else {
        order.status = "aguardando_doacao";
        order.donationStatus = "aguardando_doacao";
        db.discordOrders = [order, ...ensureDiscordOrderArray(db).filter((item) => item.id !== order.id)].slice(0, 100);
      }

      await writeDb(db);
    }

    return res.status(202).json({
      ok: true,
      received: true,
      paymentId,
      externalReference,
      matched: Boolean(order),
      status: payment.status || null,
      keyGenerated: Boolean(finalized?.key),
      deliveryStatus: finalized?.order?.deliveryStatus || null
    });
  } catch (error) {
    await appendSystemLog({
      level: "warning",
      origin: "api.webhook.mercadopago",
      message: error.message || "Falha ao processar webhook Mercado Pago.",
      context: { body: req.body || null, status: error.status || null }
    }).catch(() => null);
    return res.status(202).json({ ok: false, received: true, error: error.message || "Falha ao processar webhook." });
  }
});

app.post("/webhooks/paypal", async (req, res) => {
  const config = getPaymentConfig().paypal;
  if (!config.enabled || !config.configured) {
    await appendSystemLog({
      level: "info",
      origin: "api.webhook.paypal",
      message: "Webhook PayPal recebido em modo preparado/desativado.",
      context: { enabled: config.enabled, configured: config.configured }
    }).catch(() => null);
    return res.status(202).json({ ok: true, ignored: true, reason: "paypal_disabled_or_unconfigured" });
  }
  return res.status(202).json({ ok: true, received: true, message: "Webhook PayPal preparado para implementação de confirmação automática." });
});


let discordBotStarted = false;
let discordClient = null;

async function startDiscordBot() {
  const configDb = await readDb().catch(() => null);
  const config = getDiscordConfig(configDb);
  if (discordBotStarted || !config.enabled) return;
  discordBotStarted = true;

  if (!config.configured) {
    console.log("Discord habilitado, mas configuração incompleta no Render.");
    return;
  }

  let discord;
  try {
    discord = require("discord.js");
  } catch (error) {
    console.log("discord.js não instalado. Comandos Discord não serão iniciados.");
    await appendSystemLog({
      level: "warning",
      origin: "api.discord.bot",
      message: "discord.js não instalado. Instale a dependência para ativar comandos Discord.",
      context: { error: error.message }
    }).catch(() => null);
    return;
  }

  const { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder, AttachmentBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, StringSelectMenuBuilder, ChannelType, PermissionFlagsBits } = discord;

  const commands = [
    new SlashCommandBuilder()
      .setName("doar")
      .setDescription("Mostra orientação para usar o painel fixo de doação com Pix QR Code.")
  ].map((command) => command.toJSON());

  const rest = new REST({ version: "10" }).setToken(config.token);
  try {
    await rest.put(Routes.applicationGuildCommands(config.clientId, config.guildId), { body: commands });
    console.log("Comandos Discord registrados para o servidor configurado.");
  } catch (error) {
    console.error("Falha ao registrar comandos Discord:", error);
    await appendSystemLog({
      level: "warning",
      origin: "api.discord.commands",
      message: error.message || "Falha ao registrar comandos Discord.",
      context: { status: error.status || null }
    }).catch(() => null);
  }

  discordClient = new Client({ intents: [GatewayIntentBits.Guilds] });

  discordClient.once("ready", () => {
    console.log(`Discord bot conectado como ${discordClient.user?.tag || "bot"}.`);
  });

  discordClient.on("interactionCreate", async (interaction) => {
    const mpConfig = getPaymentConfig().mercadoPago;

    async function createDonationForInteraction(plan, sourceInteraction) {
      if (!mpConfig.enabled || !mpConfig.configured) {
        throw new Error("As doações Mercado Pago ainda não estão ativas.");
      }
      const amount = defaultDonationAmount(plan);
      const email = `discord-${sourceInteraction.user.id}@upsystem.local`;
      const db = await readDb();
      const order = createPreparedOrder({
        provider: "mercadopago",
        currency: "BRL",
        plan,
        amount,
        customerEmail: email,
        discordUserId: sourceInteraction.user.id,
        discordUsername: sourceInteraction.user.username,
        discordDisplayName: sourceInteraction.member?.displayName || sourceInteraction.user.globalName || sourceInteraction.user.username,
        discordChannelId: sourceInteraction.channelId,
        discordGuildId: sourceInteraction.guildId
      }, { username: "discord" });

      order.status = "aguardando_doacao";
      order.donationStatus = "aguardando_doacao";
      order.paymentStatus = "pix_created";
      order.externalReference = order.id;
      order.note = "Doação criada pelo painel Discord. Key será entregue após confirmação automática.";

      const payment = await createMercadoPagoPixPayment(order, mpConfig);
      const transactionData = payment?.point_of_interaction?.transaction_data || {};
      order.paymentId = String(payment.id || "");
      order.paymentStatus = String(payment.status || "pending");
      order.pixQrCode = transactionData.qr_code || null;
      order.pixQrCodeBase64 = transactionData.qr_code_base64 || null;
      order.pixTicketUrl = transactionData.ticket_url || null;
      order.paymentUrl = transactionData.ticket_url || null;
      order.updatedAt = nowIso();
      return { db, order };
    }

    async function sendPixToValidationChannel(channel, order) {
      const lines = [
        `Olá <@${order.discordUserId}>. Sua doação foi criada.`,
        `Plano: **${donationPlanLabel(order.plan)}**`,
        `Valor: **R$ ${Number(order.amount).toFixed(2)}**`,
        "Status: aguardando confirmação da doação",
        "",
        "**Pagamento padrão: Pix QR Code**",
        order.pixQrCode ? `Pix copia e cola:\n\`${truncateDiscordText(order.pixQrCode, 900)}\`` : "Pix copia e cola indisponível no retorno do Mercado Pago.",
        order.pixTicketUrl ? `Link alternativo Mercado Pago: ${order.pixTicketUrl}` : "",
        "",
        "Após a confirmação, a key será enviada por DM. Se sua DM estiver bloqueada, ela aparecerá neste canal antes da exclusão automática."
      ].filter(Boolean);
      const files = [];
      if (order.pixQrCodeBase64) {
        try { files.push(new AttachmentBuilder(Buffer.from(order.pixQrCodeBase64, "base64"), { name: "upsystem-pix-qrcode.png" })); } catch (_) {}
      }
      await channel.send({ content: truncateDiscordText(lines.join("\n"), 1900), files });
    }

    function memberHasDonationAccess(member, config) {
      const allowed = [config.userRoleId, config.roleClientesId, config.roleParceiroId, config.roleAdmiroId, config.roleDevId].filter(Boolean);
      if (!allowed.length) return true;
      return allowed.some((roleId) => member?.roles?.cache?.has(roleId));
    }

    try {
      if (interaction.isButton() && interaction.customId === "upsystem_verify_user") {
        const config = getDiscordConfig(await readDb().catch(() => null));
        if (!config.userRoleId) return interaction.reply({ content: "Cargo de verificação não configurado. Avise um administrador.", ephemeral: true });
        const member = interaction.member || await interaction.guild?.members.fetch(interaction.user.id).catch(() => null);
        if (!member) return interaction.reply({ content: "Não foi possível localizar seu membro no servidor.", ephemeral: true });
        if (memberHasDonationAccess(member, config)) return interaction.reply({ content: "Você já está verificado.", ephemeral: true });
        await member.roles.add(config.userRoleId, "UpSysteM verificação por botão");
        await sendDiscordChannelMessage(config.logChannelId, `✅ Usuário verificado: <@${interaction.user.id}> recebeu o cargo user.`).catch(() => null);
        return interaction.reply({ content: "Verificação concluída. Você já pode usar o botão Doar.", ephemeral: true });
      }

      if (interaction.isButton() && interaction.customId === "upsystem_donate_start") {
        const config = getDiscordConfig(await readDb().catch(() => null));
        if (config.userRoleId) {
          const member = interaction.member || await interaction.guild?.members.fetch(interaction.user.id).catch(() => null);
          const verified = memberHasDonationAccess(member, config);
          if (!verified) {
            const where = config.verifyChannelId ? ` Acesse <#${config.verifyChannelId}> e clique em Verificar.` : " Faça a verificação no canal indicado pelo servidor.";
            return interaction.reply({ content: `Você precisa se verificar antes de doar.${where}`, ephemeral: true });
          }
        }
        const row = new ActionRowBuilder().addComponents(
          new StringSelectMenuBuilder()
            .setCustomId("upsystem_donation_plan")
            .setPlaceholder("Escolha o plano")
            .addOptions([
              { label: "Semanal", value: "weekly", description: "Key de acesso semanal" },
              { label: "Mensal", value: "monthly", description: "Key de acesso mensal" }
            ])
        );
        return interaction.reply({ content: "Selecione o plano para gerar o Pix de doação.", components: [row], ephemeral: true });
      }

      if (interaction.isStringSelectMenu() && interaction.customId === "upsystem_donation_plan") {
        await interaction.deferReply({ ephemeral: true });
        const plan = normalizeDonationPlan(interaction.values?.[0] || "monthly");
        const config = getDiscordConfig(await readDb().catch(() => null));
        const guild = interaction.guild;
        if (!guild) throw new Error("Servidor Discord não disponível para criar canal de validação.");
        const channelName = `validacao-${discordSafeName(interaction.user.username)}-${Date.now().toString().slice(-5)}`;
        const overwrites = [
          { id: guild.roles.everyone.id, deny: [PermissionFlagsBits.ViewChannel] },
          { id: interaction.user.id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory] }
        ];
        if (config.staffRoleId) overwrites.push({ id: config.staffRoleId, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory] });
        const validationChannel = await guild.channels.create({
          name: channelName,
          type: ChannelType.GuildText,
          parent: config.validationCategoryId || null,
          permissionOverwrites: overwrites,
          topic: `UpSysteM validação de doação · usuário ${interaction.user.id}`
        });

        const { db, order } = await createDonationForInteraction(plan, interaction);
        order.validationChannelId = validationChannel.id;
        order.validationChannelName = validationChannel.name;
        db.discordOrders = [order, ...ensureDiscordOrderArray(db)].slice(0, 100);
        await writeDb(db);
        await sendPixToValidationChannel(validationChannel, order);
        await interaction.editReply({ content: `Sala de validação criada: <#${validationChannel.id}>. Conclua a doação por Pix nesse canal.` });
        await sendDiscordChannelMessage(config.logChannelId, `🟡 Nova doação criada pelo painel. Usuário: <@${interaction.user.id}> · Plano: ${donationPlanLabel(plan)} · Canal: <#${validationChannel.id}> · Status: aguardando_doacao`).catch(() => null);
        return;
      }

      if (interaction.isChatInputCommand() && interaction.commandName === "doar") {
        await interaction.reply({ content: "Use o painel fixo no canal de doações e clique em **Doar** para abrir a validação por Pix QR Code.", ephemeral: true });
        return;
      }
    } catch (error) {
      await appendSystemLog({
        level: "warning",
        origin: "api.discord.interaction",
        message: error.message || "Falha em interação Discord.",
        context: { status: error.status || null, customId: interaction.customId || null, command: interaction.commandName || null }
      }).catch(() => null);
      const content = "Não foi possível iniciar a doação agora. O administrador foi avisado para verificar a integração.";
      if (interaction.deferred || interaction.replied) await interaction.editReply({ content, components: [] }).catch(() => null);
      else await interaction.reply({ content, ephemeral: true }).catch(() => null);
    }
  });

  discordClient.on("error", (error) => {
    appendSystemLog({
      level: "warning",
      origin: "api.discord.bot",
      message: error.message || "Erro no bot Discord."
    }).catch(() => null);
  });

  try {
    await discordClient.login(config.token);
  } catch (error) {
    console.error("Falha ao conectar Discord bot:", error);
    await appendSystemLog({
      level: "warning",
      origin: "api.discord.login",
      message: error.message || "Falha ao conectar Discord bot."
    }).catch(() => null);
  }
}

app.delete("/system-logs", auth, async (req, res, next) => {
  try {
    if (!canReadSystemLogs(req.user)) return res.status(403).json({ error: "Sem permissão." });
    await clearSystemLogs();
    res.json({ ok: true });
  } catch (error) {
    next(error);
  }
});

app.get("/backup/export", auth, (req, res) => {
  if (req.user.role !== "adm") return res.status(403).json({ error: "Apenas Admin pode exportar dados." });

  res.json({
    exportedAt: nowIso(),
    source: "upsystem-api",
    version: "1.1.0",
    users: req.db.users || [],
    activationKeys: req.db.activationKeys || [],
    sites: req.db.sites || [],
    meta: {
      totalUsers: (req.db.users || []).length,
      totalKeys: (req.db.activationKeys || []).length
    }
  });
});

app.post("/backup/import", auth, (req, res) => {
  if (req.user.role !== "adm") return res.status(403).json({ error: "Apenas Admin pode importar dados." });

  const incomingUsers = Array.isArray(req.body.users) ? req.body.users : [];
  const incomingKeys = Array.isArray(req.body.activationKeys) ? req.body.activationKeys : Array.isArray(req.body.keys) ? req.body.keys : [];
  const incomingSites = Array.isArray(req.body.sites) ? req.body.sites : [];

  let importedUsers = 0;
  let importedKeys = 0;
  let importedSites = 0;

  const currentAdminId = req.user.id;
  const usersByKey = new Map();

  for (const existing of req.db.users || []) {
    usersByKey.set(existing.id || existing.username, existing);
  }

  for (const imported of incomingUsers) {
    if (!imported || !imported.username) continue;

    const importedIsCurrentAdmin =
      imported.id === currentAdminId ||
      imported.username === req.user.username ||
      imported.id === "admin-root";

    if (importedIsCurrentAdmin) {
      continue;
    }

    usersByKey.set(imported.id || imported.username, {
      ...imported,
      updatedAt: nowIso()
    });
    importedUsers++;
  }

  const keysByCode = new Map((req.db.activationKeys || []).map((key) => [key.code, key]));
  for (const key of incomingKeys) {
    if (!key || !key.code) continue;
    keysByCode.set(key.code, key);
    importedKeys++;
  }

  const sitesById = new Map((req.db.sites || []).map((site) => [site.id, site]));
  for (const site of incomingSites) {
    if (!site || !site.id) continue;
    sitesById.set(site.id, site);
    importedSites++;
  }

  req.db.users = Array.from(usersByKey.values());
  req.db.activationKeys = Array.from(keysByCode.values());
  if (incomingSites.length) req.db.sites = Array.from(sitesById.values());

  writeDb(req.db);

  res.json({
    ok: true,
    importedUsers,
    importedKeys,
    importedSites,
    totalUsers: req.db.users.length,
    totalKeys: req.db.activationKeys.length
  });
});


app.use((err, req, res, next) => {
  console.error(err);

  appendSystemLog({
    level: "error",
    origin: "api",
    message: err.message || "Erro interno na API.",
    stack: err.stack || "",
    context: {
      method: req.method,
      path: req.path,
      status: err.status || 500
    },
    username: req.user?.username || null,
    userId: req.user?.id || null,
    clientVersion: req.get("X-UpSystem-Version") || "",
    createdAt: nowIso()
  }).catch(() => null);

  res.status(err.status || 500).json({ error: err.message || "Erro interno." });
});

app.listen(PORT, () => {
  console.log(`UpSysteM API online na porta ${PORT}`);
  startDiscordBot().catch((error) => {
    console.error("Falha ao iniciar bot Discord:", error);
    appendSystemLog({
      level: "warning",
      origin: "api.discord.start",
      message: error.message || "Falha ao iniciar bot Discord."
    }).catch(() => null);
  });
});
