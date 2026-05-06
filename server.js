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
  res.setHeader("X-UpSystem-API", "1.0.8");

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
    res.json({ ok: true, service: "UpSysteM API", version: "1.0.8", database: "postgresql" });
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
  const mercadoPago = {
    enabled: envBool("MERCADOPAGO_ENABLED", false),
    accessTokenPresent: Boolean(envText("MERCADOPAGO_ACCESS_TOKEN")),
    webhookSecretPresent: Boolean(envText("MERCADOPAGO_WEBHOOK_SECRET")),
    mode: envText("MERCADOPAGO_MODE") || "production",
    configured: Boolean(envText("MERCADOPAGO_ACCESS_TOKEN"))
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
    message: "Doações preparadas para Mercado Pago e PayPal. Nenhuma key é gerada automaticamente nesta etapa."
  };
}

function getPublicPaymentStatus(config = getPaymentConfig()) {
  return {
    mercadoPago: {
      enabled: config.mercadoPago.enabled,
      configured: config.mercadoPago.configured,
      accessTokenConfigured: config.mercadoPago.accessTokenPresent,
      webhookSecretConfigured: config.mercadoPago.webhookSecretPresent,
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

function createPreparedOrder(body = {}, user = null) {
  const provider = normalizePaymentProvider(String(body.provider || body.paymentProvider || "mercadopago").toLowerCase());
  const plan = normalizeDonationPlan(String(body.plan || "monthly").toLowerCase());
  const currency = String(body.currency || (provider === "paypal" ? "USD" : "BRL")).toUpperCase().slice(0, 10);
  const amount = normalizeDonationAmount(body.amount);
  return {
    id: makeId("donation"),
    source: "discord_donation",
    status: "preparada",
    donationStatus: "preparada",
    provider,
    plan,
    currency,
    amount,
    discordUserId: String(body.discordUserId || "").slice(0, 80) || null,
    discordUsername: String(body.discordUsername || "").slice(0, 120) || null,
    customerEmail: String(body.customerEmail || "").slice(0, 180) || null,
    paymentId: null,
    paymentStatus: "not_created",
    paymentUrl: null,
    keyCode: null,
    note: "Doação preparada. A geração automática da key será ativada em etapa posterior.",
    createdBy: user?.username || null,
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

function getDiscordConfig() {
  const enabled = String(process.env.DISCORD_ENABLED || "false").toLowerCase() === "true";
  const clientId = String(process.env.DISCORD_CLIENT_ID || "").trim();
  const guildId = String(process.env.DISCORD_GUILD_ID || "").trim();
  const salesChannelId = String(process.env.DISCORD_SALES_CHANNEL_ID || "").trim();
  const logChannelId = String(process.env.DISCORD_LOG_CHANNEL_ID || "").trim();
  const token = String(process.env.DISCORD_BOT_TOKEN || "").trim();
  const configured = Boolean(clientId && guildId && salesChannelId && logChannelId && token);

  return {
    enabled,
    configured,
    clientId,
    guildId,
    salesChannelId,
    logChannelId,
    token,
    tokenPresent: Boolean(token)
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
    logChannelId: config.logChannelId || null,
    mode: config.enabled ? "ready_to_connect" : "prepared_disabled",
    message: config.enabled
      ? "Discord configurado para futura ativação. Nenhum comando de doação foi iniciado nesta versão."
      : "Discord preparado, mas desativado por DISCORD_ENABLED=false."
  };
}

app.get("/discord/status", auth, (req, res) => {
  if (!requireDiscordAdmin(req, res)) return;
  const config = getDiscordConfig();
  res.json({ ok: true, discord: getPublicDiscordStatus(config) });
});

app.post("/discord/test", auth, async (req, res, next) => {
  try {
    if (!requireDiscordAdmin(req, res)) return;

    const config = getDiscordConfig();
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


app.get("/payments/status", auth, (req, res) => {
  if (!requirePaymentsAdmin(req, res)) return;
  res.json({ ok: true, payments: getPublicPaymentStatus() });
});

app.get("/discord/orders", auth, (req, res) => {
  if (!requirePaymentsAdmin(req, res)) return;
  const orders = Array.isArray(req.db.discordOrders) ? req.db.discordOrders : [];
  res.json({ ok: true, orders: orders.slice(0, 100) });
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

    const order = createPreparedOrder({ ...(req.body || {}), provider: "mercadopago", currency: "BRL" }, req.user);
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
    appendSystemLog({
      level: "warning",
      origin: "api.payments.mercadopago.donation",
      message: error.message || "Falha ao criar link de doação Mercado Pago.",
      userId: req.user?.id || null,
      username: req.user?.username || null,
      context: { status: error.status || null, details: error.details || null }
    }).catch(() => null);
    next(error);
  }
});

app.post("/webhooks/mercadopago", async (req, res) => {
  const config = getPaymentConfig().mercadoPago;
  if (!config.enabled || !config.configured) {
    await appendSystemLog({
      level: "info",
      origin: "api.webhook.mercadopago",
      message: "Webhook Mercado Pago recebido em modo preparado/desativado.",
      context: { enabled: config.enabled, configured: config.configured }
    }).catch(() => null);
    return res.status(202).json({ ok: true, ignored: true, reason: "mercadopago_disabled_or_unconfigured" });
  }

  try {
    const paymentId = String(req.body?.data?.id || req.body?.id || req.query?.id || "").trim();
    if (!paymentId) return res.status(202).json({ ok: true, received: true, message: "Webhook recebido sem payment id." });

    const payment = await fetchMercadoPagoPayment(paymentId, config);
    const externalReference = String(payment.external_reference || payment.metadata?.upsystem_order_id || "").trim();
    const db = await readDb();
    const order = findDonationOrder(db, externalReference);

    if (order) {
      order.paymentId = String(payment.id || paymentId);
      order.paymentStatus = String(payment.status || "unknown");
      order.mpStatusDetail = String(payment.status_detail || "");
      order.updatedAt = nowIso();

      if (payment.status === "approved") {
        order.status = "doacao_confirmada";
        order.donationStatus = "doacao_confirmada";
        order.paidAt = payment.date_approved || nowIso();
        order.note = "Doação confirmada pelo Mercado Pago. Key ainda não foi gerada automaticamente nesta etapa.";
      } else {
        order.status = "aguardando_doacao";
        order.donationStatus = "aguardando_doacao";
      }

      db.discordOrders = [order, ...db.discordOrders.filter((item) => item.id !== order.id)].slice(0, 100);
      await writeDb(db);
    }

    return res.status(202).json({ ok: true, received: true, paymentId, externalReference, matched: Boolean(order) });
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
    version: "1.0.8",
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
});
