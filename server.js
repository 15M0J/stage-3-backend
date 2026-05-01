const app = require("./app");
const { ensureDatabaseReady } = require("./db");

const PORT = process.env.PORT || 3000;

ensureDatabaseReady()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Failed to start server:", error.message);
    process.exit(1);
  });
