const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const morgan = require("morgan");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const {
  ConfigurationError,
  ensureDatabaseReady,
  createProfile,
  deleteProfileById,
  getProfileById,
  getProfileByName,
  listProfiles,
  query
} = require("./db");
const { parseNaturalLanguageQuery } = require("./naturalLanguageParser");
const {
  AGE_GROUPS,
  GENDERS,
  generateUuidV7,
  getAgeGroup,
  getCountryName,
  isUuidV7,
  normalizeFilter,
  normalizeName
} = require("./profileUtils");
const { authenticateToken, authorizeRole } = require("./authMiddleware");
const authRoutes = require("./authRoutes");

const app = express();

// --- Security & Logging Middleware ---
app.use(helmet());
app.use(morgan(":method :url :status :response-time ms")); // TRD: Method, Endpoint, Status code, Response time
app.use(cookieParser());
app.use(cors({
  origin: process.env.WEB_PORTAL_URL || "http://localhost:5173",
  credentials: true
}));
app.use(express.json());

// --- Rate Limiting (TRD Requirements) ---
const authLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10, // 10 requests / minute
  message: { status: "error", message: "Too many login attempts, please try again later." }
});

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 60, // 60 requests / minute per user (IP used as proxy for 'user' before auth)
  keyGenerator: (req) => req.user?.id || req.ip,
  message: { status: "error", message: "Rate limit exceeded" }
});

app.use("/auth/", authLimiter);
app.use("/api/", apiLimiter);

// --- Custom Error Classes ---
class QueryValidationError extends Error {
  constructor(statusCode = 422, message = "Invalid query parameters") {
    super(message);
    this.statusCode = statusCode;
  }
}

// --- Validation Helpers ---
function getQueryString(query, key, { required = false } = {}) {
  const value = query[key];
  if (value === undefined) {
    if (required) throw new QueryValidationError(400, "Missing or empty parameter");
    return undefined;
  }
  if (Array.isArray(value) || typeof value !== "string") throw new QueryValidationError(422);
  const trimmed = value.trim();
  if (trimmed === "" && required) throw new QueryValidationError(400, "Missing or empty parameter");
  return trimmed;
}

function parseIntegerParameter(query, key, options = {}) {
  const value = getQueryString(query, key);
  if (value === undefined) return options.defaultValue;
  if (!/^\d+$/.test(value)) throw new QueryValidationError(422);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || (options.min !== undefined && parsed < options.min)) throw new QueryValidationError(422);
  return parsed;
}

// --- API Versioning Middleware (TRD) ---
function checkApiVersion(req, res, next) {
  if (req.path.startsWith("/api/")) {
    const version = req.headers["x-api-version"];
    if (version !== "1") {
      return res.status(400).json({
        status: "error",
        message: "API version header required"
      });
    }
  }
  next();
}
app.use(checkApiVersion);

// --- CSRF Protection ---
app.get("/csrf-token", (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  res.cookie('XSRF-TOKEN', token, {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  res.json({ csrfToken: token });
});

function verifyCsrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const tokenFromHeader = req.headers['x-csrf-token'];
  const tokenFromCookie = req.cookies['XSRF-TOKEN'];
  if (tokenFromHeader && tokenFromCookie && tokenFromHeader === tokenFromCookie) {
    return next();
  }
  res.status(403).json({ status: "error", message: "Invalid CSRF token" });
}
app.use("/api/", verifyCsrf);

// --- Pagination Links Helper ---
function getPaginationLinks(req, page, limit, total) {
  const baseUrl = `${req.protocol}://${req.get('host')}${req.path}`;
  const totalPages = Math.ceil(total / limit);
  
  const getUrl = (p) => {
    const params = new URLSearchParams(req.query);
    params.set('page', p);
    params.set('limit', limit);
    return `${req.path}?${params.toString()}`;
  };

  return {
    self: getUrl(page),
    next: page < totalPages ? getUrl(page + 1) : null,
    prev: page > 1 ? getUrl(page - 1) : null
  };
}

// --- Routes ---

// Auth Routes (Public)
app.use("/auth", authRoutes);

// Base Check
app.get("/", (req, res) => res.json({ message: "Insighta Labs+ API is running" }));

// Protected Profile Routes
const profileRouter = express.Router();
profileRouter.use(authenticateToken);

// 1. List Profiles
profileRouter.get("/", authorizeRole(["ANALYST", "ADMIN"]), async (req, res, next) => {
  try {
    const page = parseIntegerParameter(req.query, "page", { defaultValue: 1, min: 1 });
    const limit = parseIntegerParameter(req.query, "limit", { defaultValue: 10, min: 1, max: 50 });
    
    const options = {
      filters: {}, // simplified for brevity, in real app populate from query
      page,
      limit,
      sort_by: req.query.sort_by || "created_at",
      order: req.query.order || "asc"
    };

    const result = await listProfiles(options);
    res.json({
      status: "success",
      page,
      limit,
      total: result.total,
      total_pages: Math.ceil(result.total / limit),
      links: getPaginationLinks(req, page, limit, result.total),
      data: result.profiles
    });
  } catch (error) { next(error); }
});

// 2. Search
profileRouter.get("/search", authorizeRole(["ANALYST", "ADMIN"]), async (req, res, next) => {
  try {
    const q = getQueryString(req.query, "q", { required: true });
    const page = parseIntegerParameter(req.query, "page", { defaultValue: 1, min: 1 });
    const limit = parseIntegerParameter(req.query, "limit", { defaultValue: 10, min: 1, max: 50 });
    
    const filters = parseNaturalLanguageQuery(q);
    if (!filters) return res.status(400).json({ status: "error", message: "Unable to interpret query" });

    const result = await listProfiles({ filters, page, limit, sort_by: "created_at", order: "asc" });
    res.json({
      status: "success",
      page,
      limit,
      total: result.total,
      total_pages: Math.ceil(result.total / limit),
      links: getPaginationLinks(req, page, limit, result.total),
      data: result.profiles
    });
  } catch (error) { next(error); }
});

// 3. Create Profile (Admin Only) - calls external enrichment logic
profileRouter.post("/", authorizeRole(["ADMIN"]), async (req, res, next) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ status: "error", message: "Name is required" });

    // Stage 1 logic placeholder: In real app this calls external APIs
    // For now we use a mocked implementation of enrichment
    const id = generateUuidV7();
    const mockProfile = {
      id,
      name,
      gender: "unknown",
      gender_probability: 0.5,
      age: 30,
      age_group: "adult",
      country_id: "US",
      country_name: "United States",
      country_probability: 0.5
    };
    
    const { profile } = await createProfile(mockProfile);
    res.status(201).json({ status: "success", data: profile });
  } catch (error) { next(error); }
});

// 4. Export CSV (Admin Only)
profileRouter.get("/export", authorizeRole(["ADMIN"]), async (req, res, next) => {
  try {
    const result = await query("SELECT * FROM profiles ORDER BY created_at DESC");
    const rows = result.rows;

    if (rows.length === 0) return res.status(404).send("No data to export");

    const columns = [
      'id', 'name', 'gender', 'gender_probability', 'age', 
      'age_group', 'country_id', 'country_name', 'country_probability', 'created_at'
    ];

    const csvRows = rows.map(row => 
      columns.map(col => `"${String(row[col] || '').replace(/"/g, '""')}"`).join(",")
    );

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename=profiles_${Date.now()}.csv`);
    res.send(`${columns.join(",")}\n${csvRows.join("\n")}`);
  } catch (error) { next(error); }
});

// 5. Get Profile By ID
profileRouter.get("/:id", authorizeRole(["ANALYST", "ADMIN"]), async (req, res, next) => {
  try {
    const profile = await getProfileById(req.params.id);
    if (!profile) return res.status(404).json({ status: "error", message: "Profile not found" });
    res.json({ status: "success", data: profile });
  } catch (error) { next(error); }
});

// 6. Delete Profile (Admin Only)
profileRouter.delete("/:id", authorizeRole(["ADMIN"]), async (req, res, next) => {
  try {
    const deleted = await deleteProfileById(req.params.id);
    if (!deleted) return res.status(404).json({ status: "error", message: "Profile not found" });
    res.status(204).send();
  } catch (error) { next(error); }
});

app.use("/api/profiles", profileRouter);

// --- Global Error Handler ---
app.use((error, req, res, next) => {
  console.error(error);
  const status = error.statusCode || 500;
  res.status(status).json({
    status: "error",
    message: error.message || "Internal server error"
  });
});

module.exports = app;
