const express = require("express");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { findOrCreateUser, saveRefreshToken, deleteRefreshToken, findRefreshToken } = require("./db");
const { JWT_SECRET } = require("./authMiddleware");

const router = express.Router();

const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI || "http://localhost:3000/auth/github/callback";

// Helper to generate tokens
function generateTokens(user) {
  const payload = {
    id: user.id,
    username: user.username,
    role: user.role
  };

  // TRD: Access token 3 minutes, Refresh token 5 minutes
  const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: "3m" });
  const refreshToken = crypto.randomBytes(40).toString("hex");

  return { accessToken, refreshToken };
}

// 1. Initial redirect to GitHub
router.get("/github", (req, res) => {
  const { code_challenge, state } = req.query;
  let githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${GITHUB_CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=user:email`;
  
  if (code_challenge) {
    githubAuthUrl += `&code_challenge=${code_challenge}&code_challenge_method=S256`;
  }
  if (state) {
    githubAuthUrl += `&state=${state}`;
  }
  
  res.redirect(githubAuthUrl);
});

// 2. Token Exchange / Callback
router.post("/token", async (req, res) => {
  const { code, code_verifier, redirect_uri } = req.body;

  if (!code) {
    return res.status(400).json({ status: "error", message: "Code is required" });
  }

  try {
    const params = {
      client_id: GITHUB_CLIENT_ID,
      client_secret: GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: redirect_uri || REDIRECT_URI
    };

    if (code_verifier) {
      params.code_verifier = code_verifier;
    }

    const tokenResponse = await axios.post(
      "https://github.com/login/oauth/access_token",
      params,
      { headers: { Accept: "application/json" } }
    );

    if (tokenResponse.data.error) {
      return res.status(400).json({ 
        status: "error", 
        message: tokenResponse.data.error_description || tokenResponse.data.error 
      });
    }

    const githubToken = tokenResponse.data.access_token;

    // Get User Info from GitHub
    const userResponse = await axios.get("https://api.github.com/user", {
      headers: { Authorization: `Bearer ${githubToken}` }
    });

    const { id: github_id, login: username, email, avatar_url } = userResponse.data;

    // Find or Create user
    const user = await findOrCreateUser({ github_id: String(github_id), username, email, avatar_url });

    if (!user.is_active) {
      return res.status(403).json({ status: "error", message: "Account is inactive" });
    }

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);

    // Save refresh token
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + 5); // 5 minutes per TRD
    await saveRefreshToken(user.id, refreshToken, expiresAt);

    // Set cookies for web
    res.cookie("accessToken", accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 3 * 60 * 1000
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 5 * 60 * 1000
    });

    res.json({
      status: "success",
      data: {
        access_token: accessToken,
        refresh_token: refreshToken,
        user: { username: user.username, role: user.role, avatar_url: user.avatar_url }
      }
    });
  } catch (error) {
    console.error("Token Exchange Error:", error.response?.data || error.message);
    res.status(500).json({ status: "error", message: "Authentication failed" });
  }
});

// Callback endpoint (receives code, client side then calls /token)
router.get("/github/callback", (req, res) => {
  const { code, state } = req.query;
  if (!code) return res.status(400).send("Authorization code missing");

  // Show a success message and the code for CLI/Web to capture
  res.send(`
    <html>
      <body style="font-family: sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; background: #0f172a; color: white;">
        <div style="text-align: center; background: #1e293b; padding: 2rem; border-radius: 1rem;">
          <h1>Authentication Successful</h1>
          <p>You can now close this window.</p>
          <div style="display:none" id="code">${code}</div>
        </div>
      </body>
    </html>
  `);
});

// 3. Refresh Token
router.post("/refresh", async (req, res) => {
  const refreshToken = req.body.refresh_token || req.cookies?.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ status: "error", message: "Refresh token missing" });
  }

  const storedToken = await findRefreshToken(refreshToken);
  if (!storedToken) {
    return res.status(401).json({ status: "error", message: "Invalid or expired refresh token" });
  }

  if (!storedToken.is_active) {
    return res.status(403).json({ status: "error", message: "Account is inactive" });
  }

  // Invalidate old token immediately (TRD requirement)
  await deleteRefreshToken(refreshToken);

  const user = { id: storedToken.user_id, username: storedToken.username, role: storedToken.role };
  const { accessToken, refreshToken: newRefreshToken } = generateTokens(user);

  // Save new refresh token
  const expiresAt = new Date();
  expiresAt.setMinutes(expiresAt.getMinutes() + 5);
  await saveRefreshToken(user.id, newRefreshToken, expiresAt);

  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 3 * 60 * 1000
  });

  res.cookie("refreshToken", newRefreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 5 * 60 * 1000
  });

  res.json({ 
    status: "success", 
    access_token: accessToken, 
    refresh_token: newRefreshToken 
  });
});

// 4. Logout
router.post("/logout", async (req, res) => {
  const refreshToken = req.body.refresh_token || req.cookies?.refreshToken;
  if (refreshToken) {
    await deleteRefreshToken(refreshToken);
  }
  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");
  res.json({ status: "success", message: "Logged out" });
});

module.exports = router;
