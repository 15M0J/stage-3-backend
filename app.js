const express = require("express");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const morgan = require("morgan");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const {
  ConfigurationError,
  createProfile,
  deleteProfileById,
  getProfileById,
  listProfiles,
  query
} = require("./db");
const { parseNaturalLanguageQuery } = require("./naturalLanguageParser");
const { generateUuidV7, getAgeGroup, getCountryName, normalizeFilter } = require("./profileUtils");
const { authenticateToken, authorizeRole } = require("./authMiddleware");
const authRoutes = require("./authRoutes");

const app = express();
app.set("trust proxy", 1);

const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(morgan(":method :url :status :response-time ms"));
app.use(cookieParser());
app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error("Origin not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-API-Version", "X-CSRF-Token"]
  })
);
app.use(express.json());

const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false, xForwardedForHeader: false },
  message: { status: "error", message: "Too many login attempts, please try again later." }
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false, xForwardedForHeader: false },
  message: { status: "error", message: "Rate limit exceeded" }
});

app.use("/auth", authLimiter);
app.use("/api", apiLimiter);

function checkApiVersion(req, res, next) {
  if (!req.path.startsWith("/api/")) {
    return next();
  }

  if (req.path.startsWith("/api/v1/")) {
    return next();
  }

  const version = req.headers["x-api-version"];
  if (version === "1") {
    return next();
  }

  return res.status(400).json({
    status: "error",
    message: "API version header required. Send X-API-Version: 1 or use /api/v1."
  });
}

app.use(checkApiVersion);

app.get("/csrf-token", (req, res) => {
  const token = crypto.randomBytes(32).toString("hex");
  res.cookie("XSRF-TOKEN", token, {
    httpOnly: false,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax"
  });
  res.json({ csrfToken: token });
});

function verifyCsrf(req, res, next) {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }

  if (!req.headers.cookie) {
    return next();
  }

  const tokenFromHeader = req.headers["x-csrf-token"];
  const tokenFromCookie = req.cookies["XSRF-TOKEN"];

  if (tokenFromHeader && tokenFromCookie && tokenFromHeader === tokenFromCookie) {
    return next();
  }

  return res.status(403).json({ status: "error", message: "Invalid CSRF token" });
}

app.use("/api", verifyCsrf);
app.use("/auth/refresh", verifyCsrf);
app.use("/auth/logout", verifyCsrf);

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function buildPagination(req, page, limit, total) {
  const totalPages = Math.max(1, Math.ceil(total / limit));

  const getUrl = (targetPage) => {
    const params = new URLSearchParams(req.query);
    params.set("page", String(targetPage));
    params.set("limit", String(limit));
    return `${req.baseUrl}${req.path}?${params.toString()}`;
  };

  return {
    page,
    per_page: limit,
    total_items: total,
    total_pages: totalPages,
    has_next_page: page < totalPages,
    has_prev_page: page > 1,
    links: {
      self: getUrl(page),
      next: page < totalPages ? getUrl(page + 1) : null,
      prev: page > 1 ? getUrl(page - 1) : null
    }
  };
}

function createProfileResponse(req, result, page, limit) {
  const pagination = buildPagination(req, page, limit, result.total);
  return {
    status: "success",
    pagination,
    page: pagination.page,
    limit: pagination.per_page,
    total: pagination.total_items,
    total_pages: pagination.total_pages,
    links: pagination.links,
    data: result.profiles
  };
}

function getProfileFiltersFromQuery(queryParams) {
  const filters = {};

  if (queryParams.gender) {
    filters.gender = normalizeFilter(queryParams.gender);
  }

  if (queryParams.country || queryParams.country_id) {
    filters.country_id = normalizeFilter(queryParams.country || queryParams.country_id).toUpperCase();
  }

  if (queryParams.age_group) {
    filters.age_group = normalizeFilter(queryParams.age_group);
  }

  const minAge = Number.parseInt(queryParams.min_age ?? queryParams.minAge, 10);
  if (Number.isFinite(minAge)) {
    filters.min_age = minAge;
  }

  const maxAge = Number.parseInt(queryParams.max_age ?? queryParams.maxAge, 10);
  if (Number.isFinite(maxAge)) {
    filters.max_age = maxAge;
  }

  return filters;
}

app.use("/auth", authRoutes);

app.get("/", (req, res) => res.json({ message: "Insighta Labs+ API is running" }));

async function handleCurrentUser(req, res) {
  res.json({
    status: "success",
    data: {
      id: req.user.id,
      username: req.user.username,
      role: req.user.role,
      email: req.user.email,
      avatar_url: req.user.avatar_url
    }
  });
}

app.get("/api/users/me", authenticateToken, handleCurrentUser);
app.get("/api/v1/users/me", authenticateToken, handleCurrentUser);

const profileRouter = express.Router();
profileRouter.use(authenticateToken);

profileRouter.get("/", authorizeRole(["ANALYST", "ADMIN"]), async (req, res, next) => {
  try {
    const page = parsePositiveInt(req.query.page, 1);
    const limit = parsePositiveInt(req.query.limit, 10);
    const sort_by = req.query.sort_by || req.query.sortBy || "created_at";
    const order = req.query.order || "asc";
    const filters = getProfileFiltersFromQuery(req.query);
    const result = await listProfiles({ filters, page, limit, sort_by, order });
    res.json(createProfileResponse(req, result, page, limit));
  } catch (error) {
    next(error);
  }
});

profileRouter.get("/search", authorizeRole(["ANALYST", "ADMIN"]), async (req, res, next) => {
  try {
    const q = req.query.q;
    if (!q) {
      return res.status(400).json({ status: "error", message: "Missing parameter q" });
    }

    const page = parsePositiveInt(req.query.page, 1);
    const limit = parsePositiveInt(req.query.limit, 10);
    const filters = parseNaturalLanguageQuery(q);
    const result = await listProfiles({ filters: filters || {}, page, limit, sort_by: "created_at", order: "asc" });
    return res.json(createProfileResponse(req, result, page, limit));
  } catch (error) {
    return next(error);
  }
});

profileRouter.post("/", authorizeRole(["ADMIN"]), async (req, res, next) => {
  try {
    const { name } = req.body;
    if (!name || typeof name !== "string" || !name.trim()) {
      return res.status(400).json({ status: "error", message: "Name is required" });
    }

    const age = Number.isFinite(Number(req.body.age)) ? Number(req.body.age) : 30;
    const gender =
      typeof req.body.gender === "string" && req.body.gender.trim()
        ? normalizeFilter(req.body.gender)
        : "unknown";
    const countryId =
      typeof req.body.country_id === "string" && req.body.country_id.trim()
        ? req.body.country_id.trim().toUpperCase()
        : "US";
    const id = generateUuidV7();
    const profilePayload = {
      id,
      name: name.trim(),
      gender,
      gender_probability: Number(req.body.gender_probability) || 0.5,
      age,
      age_group:
        typeof req.body.age_group === "string" && req.body.age_group.trim()
          ? normalizeFilter(req.body.age_group)
          : getAgeGroup(age),
      country_id: countryId,
      country_name: req.body.country_name || getCountryName(countryId),
      country_probability: Number(req.body.country_probability) || 0.5
    };

    const { created, profile } = await createProfile(profilePayload);
    return res.status(created ? 201 : 200).json({ status: "success", data: profile });
  } catch (error) {
    return next(error);
  }
});

profileRouter.get("/export", authorizeRole(["ADMIN"]), async (req, res, next) => {
  try {
    const { profiles } = await listProfiles({
      filters: getProfileFiltersFromQuery(req.query),
      page: 1,
      limit: 100000,
      sort_by: "created_at",
      order: "desc"
    });

    if (profiles.length === 0) {
      return res.status(404).json({ status: "error", message: "No data" });
    }

    const columns = [
      "id",
      "name",
      "gender",
      "gender_probability",
      "age",
      "age_group",
      "country_id",
      "country_name",
      "country_probability",
      "created_at"
    ];
    const csvRows = profiles.map((row) =>
      columns.map((column) => `"${String(row[column] ?? "").replace(/"/g, '""')}"`).join(",")
    );

    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename=profiles_${Date.now()}.csv`);
    return res.send(`${columns.join(",")}\n${csvRows.join("\n")}`);
  } catch (error) {
    return next(error);
  }
});

profileRouter.get("/:id", authorizeRole(["ANALYST", "ADMIN"]), async (req, res, next) => {
  try {
    const profile = await getProfileById(req.params.id);
    if (!profile) {
      return res.status(404).json({ status: "error", message: "Profile not found" });
    }
    return res.json({ status: "success", data: profile });
  } catch (error) {
    return next(error);
  }
});

profileRouter.delete("/:id", authorizeRole(["ADMIN"]), async (req, res, next) => {
  try {
    const deleted = await deleteProfileById(req.params.id);
    if (!deleted) {
      return res.status(404).json({ status: "error", message: "Profile not found" });
    }
    return res.status(204).send();
  } catch (error) {
    return next(error);
  }
});

app.use("/api/profiles", profileRouter);
app.use("/api/v1/profiles", profileRouter);

app.use((error, req, res, next) => {
  console.error(error);
  const statusCode = error instanceof ConfigurationError ? 503 : error.statusCode || 500;
  res.status(statusCode).json({
    status: "error",
    message: error.message || "Internal server error"
  });
});

module.exports = app;
