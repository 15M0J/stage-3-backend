const app = require("../app");
const { ensureDatabaseReady } = require("../db");

// Initialize database tables on cold start
let dbReady = ensureDatabaseReady().catch(err => {
  console.error("DB init failed:", err.message);
});

module.exports = async (req, res) => {
  await dbReady;
  return app(req, res);
};
