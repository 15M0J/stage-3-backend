const { Pool } = require("pg");
const { getCountryName } = require("./profileUtils");

class ConfigurationError extends Error {}

const connectionString =
  process.env.backend_practice_DATABASE_URL ||
  process.env.backend_practice_POSTGRES_URL ||
  process.env.DATABASE_URL ||
  process.env.POSTGRES_URL;
const shouldUseSsl =
  connectionString &&
  !connectionString.includes("localhost") &&
  !connectionString.includes("127.0.0.1");

const pool = connectionString
  ? new Pool({
      connectionString,
      ssl: shouldUseSsl ? { rejectUnauthorized: false } : false
    })
  : null;

let databaseReadyPromise;

const PROFILE_COLUMNS = `
  id,
  name,
  gender,
  gender_probability,
  age,
  age_group,
  country_id,
  country_name,
  country_probability,
  created_at
`;

function formatProfile(row) {
  if (!row) {
    return null;
  }

  return {
    id: row.id,
    name: row.name,
    gender: row.gender,
    gender_probability: Number(row.gender_probability),
    age: Number(row.age),
    age_group: row.age_group,
    country_id: row.country_id,
    country_name: row.country_name || getCountryName(row.country_id),
    country_probability: Number(row.country_probability),
    created_at: new Date(row.created_at).toISOString()
  };
}

async function query(text, values = []) {
  if (!pool) {
    throw new ConfigurationError(
      "Database is not configured. Set DATABASE_URL or POSTGRES_URL."
    );
  }

  return pool.query(text, values);
}

async function backfillCountryNames() {
  const result = await query(
    "SELECT id, country_id FROM profiles WHERE country_name IS NULL OR country_name = ''"
  );

  await Promise.all(
    result.rows.map((row) =>
      query("UPDATE profiles SET country_name = $1 WHERE id = $2", [
        getCountryName(row.country_id),
        row.id
      ])
    )
  );
}

async function ensureDatabaseReady() {
  if (!databaseReadyPromise) {
    databaseReadyPromise = (async () => {
      await query(`
        CREATE TABLE IF NOT EXISTS users (
          id UUID PRIMARY KEY,
          github_id VARCHAR NOT NULL UNIQUE,
          email VARCHAR,
          username VARCHAR NOT NULL,
          avatar_url VARCHAR,
          role VARCHAR NOT NULL CHECK (role IN ('ADMIN', 'ANALYST')) DEFAULT 'ANALYST',
          is_active BOOLEAN NOT NULL DEFAULT true,
          last_login_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
      `);

      await query(`
        CREATE TABLE IF NOT EXISTS refresh_tokens (
          token VARCHAR PRIMARY KEY,
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at TIMESTAMPTZ NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
      `);

      await query(`
        CREATE TABLE IF NOT EXISTS profiles (
          id UUID PRIMARY KEY,
          name VARCHAR NOT NULL UNIQUE,
          gender VARCHAR NOT NULL,
          gender_probability DOUBLE PRECISION NOT NULL,
          age INT NOT NULL,
          age_group VARCHAR NOT NULL,
          country_id VARCHAR(2) NOT NULL,
          country_name VARCHAR NOT NULL,
          country_probability DOUBLE PRECISION NOT NULL,
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
      `);

      await query("ALTER TABLE profiles ADD COLUMN IF NOT EXISTS country_name VARCHAR");
      await query("ALTER TABLE profiles DROP COLUMN IF EXISTS sample_size");
      await query("ALTER TABLE profiles ALTER COLUMN name TYPE VARCHAR");
      await query("ALTER TABLE profiles ALTER COLUMN gender TYPE VARCHAR");
      await query("ALTER TABLE profiles ALTER COLUMN age_group TYPE VARCHAR");
      await query("ALTER TABLE profiles ALTER COLUMN country_id TYPE VARCHAR(2)");
      await query("ALTER TABLE profiles ALTER COLUMN created_at SET DEFAULT now()");

      await backfillCountryNames();
      await query("ALTER TABLE profiles ALTER COLUMN country_name SET NOT NULL");

      await query("CREATE INDEX IF NOT EXISTS idx_users_github_id ON users (github_id)");
      await query("CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens (user_id)");

      await query("CREATE INDEX IF NOT EXISTS idx_profiles_gender ON profiles (gender)");
      await query("CREATE INDEX IF NOT EXISTS idx_profiles_age_group ON profiles (age_group)");
      await query("CREATE INDEX IF NOT EXISTS idx_profiles_country_id ON profiles (country_id)");
      await query("CREATE INDEX IF NOT EXISTS idx_profiles_age ON profiles (age)");
      await query(
        "CREATE INDEX IF NOT EXISTS idx_profiles_gender_probability ON profiles (gender_probability)"
      );
      await query(
        "CREATE INDEX IF NOT EXISTS idx_profiles_country_probability ON profiles (country_probability)"
      );
      await query("CREATE INDEX IF NOT EXISTS idx_profiles_created_at ON profiles (created_at)");
    })().catch((error) => {
      databaseReadyPromise = null;
      throw error;
    });
  }

  return databaseReadyPromise;
}

async function getProfileByName(name) {
  const result = await query(
    `SELECT ${PROFILE_COLUMNS} FROM profiles WHERE name = $1 LIMIT 1`,
    [name]
  );

  return formatProfile(result.rows[0]);
}

async function getProfileById(id) {
  const result = await query(
    `SELECT ${PROFILE_COLUMNS} FROM profiles WHERE id = $1 LIMIT 1`,
    [id]
  );

  return formatProfile(result.rows[0]);
}

function buildProfileWhereClause(filters, values) {
  const clauses = [];

  if (filters.gender) {
    values.push(filters.gender);
    clauses.push(`gender = $${values.length}`);
  }

  if (filters.country_id) {
    values.push(filters.country_id);
    clauses.push(`country_id = $${values.length}`);
  }

  if (filters.age_group) {
    values.push(filters.age_group);
    clauses.push(`age_group = $${values.length}`);
  }

  if (filters.min_age !== undefined) {
    values.push(filters.min_age);
    clauses.push(`age >= $${values.length}`);
  }

  if (filters.max_age !== undefined) {
    values.push(filters.max_age);
    clauses.push(`age <= $${values.length}`);
  }

  if (filters.min_gender_probability !== undefined) {
    values.push(filters.min_gender_probability);
    clauses.push(`gender_probability >= $${values.length}`);
  }

  if (filters.min_country_probability !== undefined) {
    values.push(filters.min_country_probability);
    clauses.push(`country_probability >= $${values.length}`);
  }

  return clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
}

async function listProfiles(options) {
  const allowedSortColumns = new Set([
    "created_at",
    "name",
    "age",
    "gender",
    "country_id",
    "country_name",
    "age_group"
  ]);
  const values = [];
  const whereClause = buildProfileWhereClause(options.filters, values);
  const sortBy = allowedSortColumns.has(options.sort_by) ? options.sort_by : "created_at";
  const order = String(options.order).toLowerCase() === "desc" ? "DESC" : "ASC";
  const limit = options.limit;
  const offset = (options.page - 1) * options.limit;

  const countResult = await query(
    `SELECT COUNT(*)::int AS total FROM profiles ${whereClause}`,
    values
  );

  values.push(limit);
  const limitPlaceholder = `$${values.length}`;
  values.push(offset);
  const offsetPlaceholder = `$${values.length}`;

  const result = await query(
    `
      SELECT ${PROFILE_COLUMNS}
      FROM profiles
      ${whereClause}
      ORDER BY ${sortBy} ${order}, id ASC
      LIMIT ${limitPlaceholder}
      OFFSET ${offsetPlaceholder}
    `,
    values
  );

  return {
    total: Number(countResult.rows[0]?.total ?? 0),
    profiles: result.rows.map(formatProfile)
  };
}

async function createProfile(profile) {
  const result = await query(
    `
      INSERT INTO profiles (
        id,
        name,
        gender,
        gender_probability,
        age,
        age_group,
        country_id,
        country_name,
        country_probability,
        created_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, COALESCE($10, now()))
      ON CONFLICT (name) DO NOTHING
      RETURNING ${PROFILE_COLUMNS}
    `,
    [
      profile.id,
      profile.name,
      profile.gender,
      profile.gender_probability,
      profile.age,
      profile.age_group,
      profile.country_id,
      profile.country_name || getCountryName(profile.country_id),
      profile.country_probability,
      profile.created_at || null
    ]
  );

  if (result.rows[0]) {
    return {
      created: true,
      profile: formatProfile(result.rows[0])
    };
  }

  return {
    created: false,
    profile: await getProfileByName(profile.name)
  };
}

async function upsertProfiles(profiles) {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    let upserted = 0;
    const batchSize = 500;

    for (let start = 0; start < profiles.length; start += batchSize) {
      const batch = profiles.slice(start, start + batchSize);
      const values = [];
      const rows = batch.map((profile, index) => {
        const parameterOffset = index * 10;
        values.push(
          profile.id,
          profile.name,
          profile.gender,
          profile.gender_probability,
          profile.age,
          profile.age_group,
          profile.country_id,
          profile.country_name || getCountryName(profile.country_id),
          profile.country_probability,
          profile.created_at || null
        );

        return `($${parameterOffset + 1}, $${parameterOffset + 2}, $${parameterOffset + 3}, $${parameterOffset + 4}, $${parameterOffset + 5}, $${parameterOffset + 6}, $${parameterOffset + 7}, $${parameterOffset + 8}, $${parameterOffset + 9}, COALESCE($${parameterOffset + 10}, now()))`;
      });

      await client.query(
        `
          INSERT INTO profiles (
            id,
            name,
            gender,
            gender_probability,
            age,
            age_group,
            country_id,
            country_name,
            country_probability,
            created_at
          )
          VALUES ${rows.join(", ")}
          ON CONFLICT (name) DO UPDATE SET
            gender = EXCLUDED.gender,
            gender_probability = EXCLUDED.gender_probability,
            age = EXCLUDED.age,
            age_group = EXCLUDED.age_group,
            country_id = EXCLUDED.country_id,
            country_name = EXCLUDED.country_name,
            country_probability = EXCLUDED.country_probability
        `,
        values
      );
      upserted += batch.length;
    }

    await client.query("COMMIT");
    return upserted;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

async function findOrCreateUser({ github_id, username, email, avatar_url }) {
  // First, try to find the user
  const existing = await query(
    `SELECT * FROM users WHERE github_id = $1 LIMIT 1`,
    [github_id]
  );

  if (existing.rows[0]) {
    // Update last login
    await query(
      "UPDATE users SET last_login_at = now(), avatar_url = $1, username = $2, email = $3 WHERE id = $4",
      [avatar_url, username, email, existing.rows[0].id]
    );
    return { ...existing.rows[0], avatar_url, username, email };
  }

  const id = require("./profileUtils").generateUuidV7();
  const userCountResult = await query("SELECT COUNT(*)::int AS count FROM users");
  const isFirstUser = userCountResult.rows[0].count === 0;
  const role = isFirstUser ? "ADMIN" : "ANALYST";

  const result = await query(
    `INSERT INTO users (id, github_id, username, email, avatar_url, role, last_login_at)
     VALUES ($1, $2, $3, $4, $5, $6, now())
     RETURNING *`,
    [id, github_id, username, email, avatar_url, role]
  );

  return result.rows[0];
}

async function saveRefreshToken(user_id, token, expires_at) {
  await query(
    `INSERT INTO refresh_tokens (token, user_id, expires_at)
     VALUES ($1, $2, $3)`,
    [token, user_id, expires_at]
  );
}

async function deleteRefreshToken(token) {
  await query("DELETE FROM refresh_tokens WHERE token = $1", [token]);
}

async function findRefreshToken(token) {
  const result = await query(
    `SELECT rt.*, u.role, u.username, u.is_active, u.avatar_url
     FROM refresh_tokens rt
     JOIN users u ON rt.user_id = u.id
     WHERE rt.token = $1 AND rt.expires_at > now()
     LIMIT 1`,
    [token]
  );
  return result.rows[0];
}

async function deleteProfileById(id) {
  const result = await query(
    "DELETE FROM profiles WHERE id = $1 RETURNING id",
    [id]
  );

  return Boolean(result.rows[0]);
}

module.exports = {
  ConfigurationError,
  createProfile,
  deleteProfileById,
  ensureDatabaseReady,
  getProfileById,
  getProfileByName,
  listProfiles,
  query,
  upsertProfiles,
  findOrCreateUser,
  saveRefreshToken,
  deleteRefreshToken,
  findRefreshToken
};
