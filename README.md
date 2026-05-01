# Insighta Labs+ Backend

Stage 3 extends the Stage 2 Profile Intelligence System into a secure multi-client platform. The backend remains the system of record for profiles, authentication, authorization, pagination, search, and exports. The CLI and web portal both integrate with the same API and token lifecycle.

## System Architecture

- `Express` provides the API surface and middleware pipeline.
- `PostgreSQL` stores profiles, users, and refresh tokens.
- `GitHub OAuth` is used for identity, with PKCE for both CLI and browser sign-in flows.
- `JWT access tokens` are used for short-lived API access.
- `Opaque refresh tokens` are stored server-side and rotated on every refresh.
- `Role middleware` enforces `ADMIN` and `ANALYST` permissions across protected endpoints.
- `Natural language parsing` converts human search text into profile filters before querying PostgreSQL.

## Authentication Flow

### Browser flow

1. The web portal generates a PKCE verifier/challenge pair and a unique OAuth `state`.
2. The browser is redirected to `GET /auth/github` with `code_challenge`, `state`, and its callback URL.
3. The backend stores the pending OAuth request and redirects the user to GitHub.
4. GitHub returns the browser to the web callback page.
5. The callback page posts `code`, `code_verifier`, `state`, and `redirect_uri` to `POST /auth/token`.
6. The backend validates the stored `state`, recomputes the PKCE challenge from the verifier, exchanges the code with GitHub, and issues local access and refresh tokens.
7. The browser stores tokens in HTTP-only cookies and uses a CSRF token for mutating requests.

### CLI flow

1. The CLI generates a PKCE verifier/challenge and starts a local callback listener on `127.0.0.1:3333`.
2. The CLI opens the browser against `GET /auth/github` with the local callback URL.
3. GitHub redirects back to the CLI callback.
4. The CLI exchanges the returned code with `POST /auth/token`.
5. Credentials are written to `~/.insighta/credentials.json`.

## Token Handling Approach

- Access tokens expire after `3 minutes`.
- Refresh tokens expire after `5 minutes`.
- Refresh tokens are persisted in PostgreSQL and deleted immediately when rotated or logged out.
- Web clients use secure cookies:
  - `httpOnly: true`
  - `sameSite: none` in production, `lax` locally
  - `secure: true` in production
- CLI credentials are stored locally at `~/.insighta/credentials.json`.
- The web client automatically attempts `/auth/refresh` after a `401`.
- The CLI also attempts refresh automatically before requiring a new login.

## Role Enforcement Logic

- `ANALYST`
  - Can read `/api/v1/profiles`
  - Can access `/api/v1/profiles/search`
  - Can read `/api/v1/profiles/:id`
- `ADMIN`
  - Inherits analyst access
  - Can create profiles
  - Can delete profiles
  - Can export profile data as CSV
- The first created user is promoted to `ADMIN`. Later users default to `ANALYST`.
- Every protected route passes through both authentication and role middleware.

## API Versioning And Pagination

- Versioning is available in two compatible forms:
  - URL-based: `/api/v1/...`
  - Header-based compatibility: `/api/...` with `X-API-Version: 1`
- Collection endpoints return a `pagination` object with:
  - `page`
  - `per_page`
  - `total_items`
  - `total_pages`
  - `has_next_page`
  - `has_prev_page`
  - `links`

## Natural Language Parsing Approach

The parser is intentionally rule-based and deterministic:

- gender terms such as `male`, `female`, `men`, `women`
- age phrases such as `between 20 and 30`, `older than 50`, `young`
- age-group terms such as `child`, `teenager`, `adult`, `senior`
- country extraction through the country lookup table

The resulting filter object is passed into the same query path used by normal filtered listing, which keeps search behavior aligned with the rest of the API.

## CLI Usage

From the CLI repo:

```bash
npm install -g .
insighta login
insighta whoami
insighta profiles list --page 1 --limit 10
insighta profiles search "young females from Nigeria"
insighta profiles create --name "Ada"
insighta profiles export
```

You can point the CLI at a deployed backend with:

```bash
INSIGHTA_API_URL=https://your-backend-url insighta login
```

## Security Controls

- `helmet` for secure headers
- `morgan` request logging
- rate limiting:
  - `/auth/*`: 10 requests per minute
  - `/api/*`: 60 requests per minute
- CSRF protection for cookie-backed mutating requests
- role checks on every protected endpoint
- refresh-token rotation to reduce replay risk

## Main Endpoints

- `GET /auth/github`
- `POST /auth/token`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /csrf-token`
- `GET /api/v1/users/me`
- `GET /api/v1/profiles`
- `GET /api/v1/profiles/search`
- `GET /api/v1/profiles/:id`
- `POST /api/v1/profiles`
- `DELETE /api/v1/profiles/:id`
- `GET /api/v1/profiles/export`
