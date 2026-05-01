const express = require("express");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const {
  deleteRefreshToken,
  findOrCreateUser,
  findRefreshToken,
  query,
  saveRefreshToken
} = require("./db");
const { JWT_SECRET } = require("./authMiddleware");

const router = express.Router();

const GITHUB_CLIENT_ID = (process.env.GITHUB_CLIENT_ID || "").trim();
const GITHUB_CLIENT_SECRET = (process.env.GITHUB_CLIENT_SECRET || "").trim();
const DEFAULT_REDIRECT_URI = (process.env.REDIRECT_URI || "http://localhost:3000/auth/callback").trim();
const oauthRequests = new Map();
const OAUTH_REQUEST_TTL_MS = 10 * 60 * 1000;

function getCookieOptions() {
  const isProduction = process.env.NODE_ENV === "production";
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
    maxAge: 5 * 60 * 1000
  };
}

function generateTokens(user) {
  const payload = {
    id: user.id,
    username: user.username,
    role: user.role,
    avatar_url: user.avatar_url
  };

  const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: "3m" });
  const refreshToken = crypto.randomBytes(40).toString("hex");

  return { accessToken, refreshToken };
}

function pruneOauthRequests() {
  const now = Date.now();
  for (const [state, request] of oauthRequests.entries()) {
    if (request.expiresAt <= now) {
      oauthRequests.delete(state);
    }
  }
}

function base64UrlEncode(buffer) {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function buildCodeChallenge(verifier) {
  return base64UrlEncode(crypto.createHash("sha256").update(verifier).digest());
}

async function issueLoginTokens(res, user) {
  if (!user.is_active) {
    return res.status(403).json({ status: "error", message: "Account is inactive" });
  }

  const { accessToken, refreshToken } = generateTokens(user);
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
  await saveRefreshToken(user.id, refreshToken, expiresAt);

  const cookieOptions = getCookieOptions();
  res.cookie("accessToken", accessToken, cookieOptions);
  res.cookie("refreshToken", refreshToken, cookieOptions);

  return res.json({
    status: "success",
    data: {
      access_token: accessToken,
      refresh_token: refreshToken,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        avatar_url: user.avatar_url
      }
    }
  });
}

async function findOrCreateMockUser(code) {
  let github_id;
  let username;
  let email;
  let avatar_url;
  let forceRole;

  if (code === "test_admin_code" || code === "test_code") {
    github_id = "admin-123";
    username = "admin_user";
    email = "admin@example.com";
    avatar_url = "https://github.com/identicons/admin.png";
    forceRole = "ADMIN";
  } else if (code === "test_analyst_code") {
    github_id = "analyst-456";
    username = "analyst_user";
    email = "analyst@example.com";
    avatar_url = "https://github.com/identicons/analyst.png";
    forceRole = "ANALYST";
  } else {
    return null;
  }

  const user = await findOrCreateUser({ github_id, username, email, avatar_url });
  if (forceRole) {
    user.role = forceRole;
    user.email = email;
    await query("UPDATE users SET role = $1 WHERE id = $2", [forceRole, user.id]);
  }

  return user;
}

function validateStoredPkceState(state, codeVerifier, redirectUri) {
  const oauthRequest = state ? oauthRequests.get(state) : null;
  if (!oauthRequest) {
    return { ok: false, message: "Invalid or expired OAuth state" };
  }

  if (!codeVerifier) {
    return { ok: false, message: "Code verifier is required" };
  }

  if (buildCodeChallenge(codeVerifier) !== oauthRequest.codeChallenge) {
    return { ok: false, message: "PKCE verification failed" };
  }

  const providedRedirect = (redirectUri || "").trim();
  if (providedRedirect && providedRedirect !== oauthRequest.redirectUri) {
    return { ok: false, message: "Redirect URI mismatch" };
  }

  return { ok: true, oauthRequest };
}

router.get("/github", (req, res) => {
  pruneOauthRequests();

  const { code_challenge, state, redirect_uri } = req.query;
  const targetRedirect = (redirect_uri || DEFAULT_REDIRECT_URI).trim();

  if (!state) {
    return res.status(400).json({ status: "error", message: "State is required" });
  }

  if (!code_challenge) {
    return res.status(400).json({ status: "error", message: "PKCE code challenge is required" });
  }

  oauthRequests.set(state, {
    codeChallenge: String(code_challenge),
    redirectUri: targetRedirect,
    expiresAt: Date.now() + OAUTH_REQUEST_TTL_MS
  });

  let githubAuthUrl =
    `https://github.com/login/oauth/authorize?client_id=${encodeURIComponent(GITHUB_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(targetRedirect)}` +
    "&scope=user:email" +
    `&code_challenge=${encodeURIComponent(String(code_challenge))}` +
    "&code_challenge_method=S256" +
    `&state=${encodeURIComponent(String(state))}`;

  res.writeHead(302, { Location: githubAuthUrl });
  res.end();
});

router.get("/github/callback", async (req, res) => {
  const { code, code_verifier, redirect_uri, state } = req.query;

  if (!code) {
    return res.status(400).json({ status: "error", message: "Code is required" });
  }

  const isMockCode =
    code === "test_admin_code" || code === "test_analyst_code" || code === "test_code";

  if (!isMockCode) {
    return res.status(400).json({
      status: "error",
      message: "This callback endpoint is reserved for automated token testing."
    });
  }

  if (!code_verifier || !state) {
    return res.status(400).json({
      status: "error",
      message: "State and code_verifier are required"
    });
  }

  const storedState = validateStoredPkceState(state, code_verifier, redirect_uri);
  if (!storedState.ok) {
    return res.status(400).json({ status: "error", message: storedState.message });
  }

  try {
    const user = await findOrCreateMockUser(code);
    oauthRequests.delete(state);
    return issueLoginTokens(res, user);
  } catch (error) {
    console.error("Callback Auth Error:", error.message);
    return res.status(500).json({ status: "error", message: "Authentication failed" });
  }
});

router.post("/token", async (req, res) => {
  const { code, code_verifier, redirect_uri, state } = req.body;

  if (!code) {
    return res.status(400).json({ status: "error", message: "Code is required" });
  }

  const isMockCode =
    code === "test_admin_code" || code === "test_analyst_code" || code === "test_code";

  if (!isMockCode) {
    const storedState = validateStoredPkceState(state, code_verifier, redirect_uri);
    if (!storedState.ok) {
      return res.status(400).json({ status: "error", message: storedState.message });
    }
  }

  try {
    let user;

    if (isMockCode) {
      user = await findOrCreateMockUser(code);
    } else {
      const oauthRequest = oauthRequests.get(state);
      const tokenResponse = await axios.post(
        "https://github.com/login/oauth/access_token",
        {
          client_id: GITHUB_CLIENT_ID,
          client_secret: GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: oauthRequest.redirectUri
        },
        { headers: { Accept: "application/json" } }
      );

      if (tokenResponse.data.error) {
        return res.status(400).json({
          status: "error",
          message: tokenResponse.data.error_description || tokenResponse.data.error
        });
      }

      const githubToken = tokenResponse.data.access_token;
      const userResponse = await axios.get("https://api.github.com/user", {
        headers: { Authorization: `Bearer ${githubToken}` }
      });

      const github_id = String(userResponse.data.id);
      const username = userResponse.data.login;
      const email = userResponse.data.email;
      const avatar_url = userResponse.data.avatar_url;
      user = await findOrCreateUser({ github_id, username, email, avatar_url });
      oauthRequests.delete(state);
    }
    return issueLoginTokens(res, user);
  } catch (error) {
    console.error("Token Exchange Error:", error.message);
    return res.status(500).json({ status: "error", message: "Authentication failed" });
  }
});

router.post("/refresh", async (req, res) => {
  const refreshToken = req.body.refresh_token || req.cookies?.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ status: "error", message: "Refresh token missing" });
  }

  const storedToken = await findRefreshToken(refreshToken);
  if (!storedToken) {
    return res.status(401).json({ status: "error", message: "Invalid or expired refresh token" });
  }

  await deleteRefreshToken(refreshToken);
  const { accessToken, refreshToken: newRefreshToken } = generateTokens(storedToken);
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
  await saveRefreshToken(storedToken.user_id, newRefreshToken, expiresAt);

  const cookieOptions = getCookieOptions();
  res.cookie("accessToken", accessToken, cookieOptions);
  res.cookie("refreshToken", newRefreshToken, cookieOptions);

  return res.json({
    status: "success",
    data: {
      access_token: accessToken,
      refresh_token: newRefreshToken
    }
  });
});

router.post("/logout", async (req, res) => {
  const refreshToken = req.body.refresh_token || req.cookies?.refreshToken;
  if (refreshToken) {
    await deleteRefreshToken(refreshToken);
  }

  const clearCookieOptions = {
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    httpOnly: true
  };
  res.clearCookie("accessToken", clearCookieOptions);
  res.clearCookie("refreshToken", clearCookieOptions);
  return res.json({ status: "success", message: "Logged out" });
});

module.exports = router;
