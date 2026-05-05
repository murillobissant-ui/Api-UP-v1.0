require("dotenv").config();

const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const {
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
} = require("./storage");

const app = express();
const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

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

function normalizeRole(role) {
  return ["usuario", "parceiro", "dev"].includes(role) ? role : "usuario";
}

function normalizeAccess(accessType) {
  return ["weekly", "monthly", "lifetime"].includes(accessType) ? accessType : "weekly";
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

  if (key.keyExpiresAt && new Date(key.keyExpiresAt).getTime() < Date.now()) {
    const err = new Error("Key expirada. Solicite uma nova key ao administrador.");
    err.status = 400;
    throw err;
  }
}

async function redeemKeyForUser(db, key, user, passwordHash = null, name = null) {
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

app.get("/health", (req, res) => {
  res.json({ ok: true, service: "UpSysteM API", version: "4.2.0" });
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
      user = await redeemKeyForUser(db, key, existing, passwordHash, name);
    } else {
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

    const updated = await redeemKeyForUser(db, key, user);
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

    const role = current.role === "adm" ? (req.body.role || "usuario") : "usuario";
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
      user.permissions = current.role === "adm" ? (req.body.permissions || defaultPermissions(role)) : ["control_repost"];
      user.accountLimit = role === "parceiro" ? normalizeLimit(req.body.accountLimit ?? user.accountLimit ?? 3) : null;
      user.updatedAt = nowIso();
      if (req.body.password) user.passwordHash = await bcrypt.hash(String(req.body.password), 10);
    } else {
      if (!req.body.password) return res.status(400).json({ error: "Informe uma senha inicial." });

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
        permissions: current.role === "adm" ? (req.body.permissions || defaultPermissions(role)) : ["control_repost"],
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

app.delete("/users/:id", auth, requirePermission("user_delete"), (req, res) => {
  const db = req.db;
  if (req.user.role !== "adm") return res.status(403).json({ error: "Apenas Admin pode excluir usuários." });

  const target = db.users.find((u) => u.id === req.params.id);
  if (!target) return res.json({ ok: true });

  if (target.role === "adm" || target.username === "admin" || target.id === req.user.id) {
    return res.status(403).json({ error: "Este usuário não pode ser excluído." });
  }

  db.users = db.users.filter((u) => u.id !== req.params.id);
  writeDb(db);
  res.json({ ok: true });
});

app.get("/keys", auth, (req, res) => {
  const keys = visibleKeys(req.db, req.user).map((key) => {
    const expired = key.keyExpiresAt && new Date(key.keyExpiresAt).getTime() < Date.now();
    return {
      ...key,
      status: key.status === "used" ? "used" : key.status === "replaced" ? "replaced" : expired ? "expired" : "available"
    };
  });

  res.json({ keys });
});

app.post("/keys", auth, requirePermission("user_create"), (req, res, next) => {
  try {
    const db = req.db;
    const current = req.user;

    if (current.role === "parceiro") assertPartnerLimit(db, current, true);

    const role = current.role === "adm" ? normalizeRole(req.body.role) : "usuario";
    const accessType = current.role === "adm" ? normalizeAccess(req.body.accessType) : (req.body.accessType === "lifetime" ? "monthly" : normalizeAccess(req.body.accessType));
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
      permissions: defaultPermissions(role),
      note: String(req.body.note || "").slice(0, 120),
      customerFirstName: String(req.body.customerFirstName || "").trim().slice(0, 80),
      customerLastName: String(req.body.customerLastName || "").trim().slice(0, 80),
      customerEmail: String(req.body.customerEmail || "").trim().slice(0, 120),
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

  req.db.logs.push(log);
  req.db.logs = req.db.logs.slice(-5000);
  writeDb(req.db);
  res.json({ log });
});

app.get("/logs", auth, (req, res) => {
  const validLogs = (req.db.logs || []).filter((log) => log.username && log.username !== "sem-usuario");
  if (req.user.role === "adm") return res.json({ logs: validLogs.slice(-1000) });
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

app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.message || "Erro interno." });
});

app.listen(PORT, () => {
  console.log(`UpSysteM API online na porta ${PORT}`);
});
