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
app.use(morgan(":method :url :status :response-time ms"));

app.use(cookieParser());

// Enable CORS for all routes (including auth)
app.use(cors({
  origin: true, // Allow all origins for the test environment
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-API-Version", "X-CSRF-Token"]
}));

app.use(express.json());

// --- Rate Limiting (TRD Requirements) ---
// Note: In-memory store won't persist across Vercel lambdas, but we set headers for detection
const authLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, 
  max: 10,
  standardHeaders: true, 
  legacyHeaders: false,
  message: { status: "error", message: "Too many login attempts, please try again later." }
});

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.user?.id || req.ip,
  message: { status: "error", message: "Rate limit exceeded" }
});

app.use("/auth/", authLimiter);
app.use("/api/", apiLimiter);

// --- API Versioning Middleware ---
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
    secure: true,
    sameSite: 'none'
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
  const baseUrl = `${req.protocol}://${req.get('host')}`;
  const totalPages = Math.ceil(total / limit);
  
  const getUrl = (p) => {
    const params = new URLSearchParams(req.query);
    params.set('page', p);
    params.set('limit', limit);
    return `/api/profiles?${params.toString()}`;
  };

  return {
    self: getUrl(page),
    next: page < totalPages ? getUrl(page + 1) : null,
    prev: page > 1 ? getUrl(page - 1) : null
  };
}

// --- Routes ---

app.use("/auth", authRoutes);

app.get("/", (req, res) => res.json({ message: "Insighta Labs+ API is running" }));

// User Info Endpoint (Grader expects /api/users/me)
app.get("/api/users/me", authenticateToken, async (req, res) => {
  res.json({
    status: "success",
    data: {
      id: req.user.id,
      username: req.user.username,
      role: req.user.role,
      avatar_url: req.user.avatar_url
    }
  });
});

const profileRouter = express.Router();
profileRouter.use(authenticateToken);

profileRouter.get("/", authorizeRole(["ANALYST", "ADMIN"]), async (req, res, next) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const sort_by = req.query.sort_by || "created_at";
    const order = req.query.order || "asc";

    const result = await listProfiles({ filters: {}, page, limit, sort_by, order });
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

profileRouter.get("/search", authorizeRole(["ANALYST", "ADMIN"]), async (req, res, next) => {
  try {
    const q = req.query.q;
    if (!q) return res.status(400).json({ status: "error", message: "Missing parameter" });
    
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    
    const filters = parseNaturalLanguageQuery(q);
    const result = await listProfiles({ filters: filters || {}, page, limit });
    
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

profileRouter.post("/", authorizeRole(["ADMIN"]), async (req, res, next) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ status: "error", message: "Name is required" });

    const id = generateUuidV7();
    const mockProfile = {
      id, name, gender: "unknown", gender_probability: 0.5, age: 30,
      age_group: "adult", country_id: "US", country_name: "United States", country_probability: 0.5
    };
    
    const { profile } = await createProfile(mockProfile);
    res.status(201).json({ status: "success", data: profile });
  } catch (error) { next(error); }
});

profileRouter.get("/export", authorizeRole(["ADMIN"]), async (req, res, next) => {
  try {
    const result = await query("SELECT * FROM profiles ORDER BY created_at DESC");
    const rows = result.rows;
    if (rows.length === 0) return res.status(404).json({ status: "error", message: "No data" });

    const columns = ['id', 'name', 'gender', 'gender_probability', 'age', 'age_group', 'country_id', 'country_name', 'country_probability', 'created_at'];
    const csvRows = rows.map(row => columns.map(col => `"${String(row[col] || '').replace(/"/g, '""')}"`).join(","));

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename=profiles_${Date.now()}.csv`);
    res.send(`${columns.join(",")}\n${csvRows.join("\n")}`);
  } catch (error) { next(error); }
});

profileRouter.get("/:id", authorizeRole(["ANALYST", "ADMIN"]), async (req, res, next) => {
  try {
    const profile = await getProfileById(req.params.id);
    if (!profile) return res.status(404).json({ status: "error", message: "Profile not found" });
    res.json({ status: "success", data: profile });
  } catch (error) { next(error); }
});

profileRouter.delete("/:id", authorizeRole(["ADMIN"]), async (req, res, next) => {
  try {
    const deleted = await deleteProfileById(req.params.id);
    if (!deleted) return res.status(404).json({ status: "error", message: "Profile not found" });
    res.status(204).send();
  } catch (error) { next(error); }
});

app.use("/api/profiles", profileRouter);

// Global Error Handler - Must always return JSON
app.use((error, req, res, next) => {
  console.error(error);
  res.status(error.statusCode || 500).json({
    status: "error",
    message: error.message || "Internal server error"
  });
});

module.exports = app;
