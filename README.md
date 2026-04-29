# Insighta Labs+ Backend (Stage 3)

Insighta Labs+ is a secure Profile Intelligence System designed for demographic analysis. This version (Stage 3) introduces robust authentication, role-based access control, and cross-platform integration.

## 🏗 System Architecture

The system is built as a modular Node.js API with the following components:
- **Express.js Framework**: Provides the core routing and middleware engine.
- **PostgreSQL Database**: Stores user identities, demographic profiles, and secure session tokens.
- **GitHub OAuth 2.0**: Handles external identity verification.
- **Interfaces**:
  - **CLI**: A globally installable command-line tool.
  - **Web Portal**: A secure React-based dashboard.

## 🔐 Authentication Flow (GitHub OAuth with PKCE)

We implement the Proof Key for Code Exchange (PKCE) flow to ensure secure token exchange:
1.  **Authorization Request**: The client (CLI or Web) redirects the user to `/auth/github` with a `code_challenge` and `state`.
2.  **User Consent**: The user authenticates with GitHub.
3.  **Redirection**: GitHub redirects back to the callback URL with an authorization `code`.
4.  **Token Exchange**: The client sends the `code` and the original `code_verifier` to `/auth/token`.
5.  **Verification**: The backend verifies the PKCE handshake with GitHub and issues a short-lived **Access Token** (JWT) and an opaque **Refresh Token**.

## 🎫 Token Handling Approach

-   **Access Tokens**: 3-minute expiry. Contains user `id`, `username`, and `role`.
-   **Refresh Tokens**: 5-minute expiry. Stored in the database and rotated (invalidated) immediately upon use to prevent replay attacks.
-   **Storage**: 
    - **Web**: HTTP-only, Secure, SameSite=None cookies.
    - **CLI**: Secure local storage at `~/.insighta/credentials.json`.

## 🛡 Role Enforcement Logic

Permissions are managed via a structured middleware approach:
-   **ANALYST**: Read-only access to `/api/profiles` and search.
-   **ADMIN**: Full CRUD access, including profile creation, deletion, and CSV export.
-   **Dynamic Assignment**: The first user to register in the system is automatically promoted to `ADMIN`.

## 🔍 Natural Language Parsing Approach

Queries are processed via a rule-based parsing engine that translates text into SQL filters:
-   **Keyword Mapping**: "males" -> `gender = 'male'`, "Nigeria" -> `country_id = 'NG'`.
-   **Heuristic Extraction**: Extracts age ranges and demographic groupings.
-   **Fuzzy Matching**: Matches query intent against stored profile data with confidence thresholds.

## 💻 CLI Usage

1.  **Installation**: `npm install -g .`
2.  **Commands**:
    - `insighta login`: Initiates the PKCE flow.
    - `insighta profiles list`: Lists all profiles with optional filters.
    - `insighta profiles search <query>`: Natural language search.
    - `insighta profiles export`: Generates a CSV in the current directory.

## ⚙️ CI/CD & Deployment

-   **CI**: GitHub Actions runs on every PR to `main` (Linting, Build checks).
-   **Deployment**: Hosted on Vercel with automatic deployments.
-   **Security**: Includes Rate Limiting (10/min auth, 60/min api) and CSRF protection.
