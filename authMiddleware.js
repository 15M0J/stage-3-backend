const jwt = require("jsonwebtoken");
const { query } = require("./db");

const JWT_SECRET = process.env.JWT_SECRET || "super-secret-key-change-me";

function authenticateToken(req, res, next) {
  // We check two places for the token: 
  // 1. The 'Authorization' header (used by CLI)
  // 2. Cookies (used by the Web Portal)
  let token = req.cookies?.accessToken;

  const authHeader = req.headers["authorization"];
  if (authHeader && authHeader.startsWith("Bearer ")) {
    token = authHeader.split(" ")[1];
  }

  if (!token) {
    return res.status(401).json({
      status: "error",
      message: "Authentication required"
    });
  }

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(401).json({
        status: "error",
        message: "Invalid or expired token"
      });
    }

    // TRD: Check if user is active
    const userResult = await query("SELECT is_active, email FROM users WHERE id = $1", [decoded.id]);
    const user = userResult.rows[0];

    if (!user || !user.is_active) {
      return res.status(403).json({
        status: "error",
        message: "Forbidden: Account is inactive"
      });
    }

    req.user = { ...decoded, is_active: user.is_active, email: user.email };
    next();
  });
}

function authorizeRole(roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({
        status: "error",
        message: "Insufficient permissions"
      });
    }
    next();
  };
}

module.exports = {
  authenticateToken,
  authorizeRole,
  JWT_SECRET
};
