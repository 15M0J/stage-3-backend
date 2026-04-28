# Insighta Labs+ Backend (Stage 3)

Insighta Labs+ is a secure Profile Intelligence System designed for demographic analysis. This version (Stage 3) introduces robust authentication, role-based access control, and cross-platform integration.

## 🏗 System Architecture

The system follows a modular monolithic architecture:
- **Express.js API**: Handles requests, authentication, and business logic.
- **PostgreSQL Database**: Persistent storage for profiles, users, and refresh tokens.
- **GitHub OAuth**: Third-party identity provider for secure login.
- **Interfaces**: CLI Tool (Node.js) and Web Portal (React/Vite).

## 🔐 Authentication Flow (GitHub OAuth with PKCE)

We implement the Proof Key for Code Exchange (PKCE) extension to secure the OAuth flow for both the CLI and Web Portal.

1.  **Initiation**: The client generates a `code_verifier` and a `code_challenge`.
2.  **Authorization**: The user is redirected to GitHub with the `code_challenge`.
3.  **Callback**: GitHub redirects back with an authorization `code`.
4.  **Exchange**: The client sends the `code` and `code_verifier` to our `/api/v1/auth/token` endpoint.
5.  **Validation**: The backend exchanges these with GitHub using the `client_secret` and verifies the PKCE handshake.
6.  **Issuance**: The backend issues a short-lived **Access Token** (JWT) and a long-lived **Refresh Token**.

## 🎫 Token Handling Approach

-   **Access Tokens**: JWTs with a 15-minute expiry, stored in HTTP-only cookies (Web) or memory (CLI).
-   **Refresh Tokens**: Opaque tokens stored in the database with a 7-day expiry. Used to rotate and issue new access tokens via `/api/v1/auth/refresh`.
-   **Security**: HTTP-only, Secure, and SameSite=Strict cookies prevent XSS and some CSRF attacks.

## 🛡 Role Enforcement Logic

We use a declarative middleware (`authorizeRole`) to enforce permissions:
-   **ANALYST**: Can list and search profiles.
-   **ADMIN**: Can list, search, export (CSV), and delete profiles.
-   Roles are embedded in the JWT payload and verified on every request. The first user to register via GitHub is automatically assigned the `ADMIN` role.

## 🔍 Natural Language Parsing Approach

The `naturalLanguageParser.js` utilizes a rule-based engine to translate human queries into structured filters:
-   **Entity Recognition**: Identifies countries, genders, and age keywords.
-   **Context Mapping**: Maps "males" to `gender='male'`, "Nigeria" to `country_id='NG'`, etc.
-   **Fuzzy Probabilities**: Leverages Stage 2 enrichment data to filter by confidence scores.

## 💻 CLI Usage

1.  **Install**: `npm install -g .`
2.  **Login**: `insighta login` (Opens browser, handles PKCE callback automatically).
3.  **Search**: `insighta search "females from Nigeria"`
4.  **List**: `insighta profiles --page 1 --limit 10`

## 🌐 Web Portal

The web portal includes:
-   **CSRF Protection**: Every state-changing request requires a valid `X-CSRF-Token` header.
-   **Real-time Search**: Instant feedback using natural language queries.
-   **Responsive Design**: Premium UI built with Tailwind CSS and Framer Motion.
