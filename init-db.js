require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function init() {
  const client = await pool.connect();
  try {
    console.log('Connecting to database...');
    
    // Create Users table
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE,
        password VARCHAR(255),
        surname VARCHAR(255),
        othername VARCHAR(255),
        email VARCHAR(255) UNIQUE,
        phone VARCHAR(20),
        role VARCHAR(50)
      );
    `);
    await client.query('ALTER TABLE users ALTER COLUMN password DROP DEFAULT;');
    console.log('Users table created or exists.');

    // Insert default admin if not exists
    await client.query(`
      INSERT INTO users (username, password, surname, othername, role)
      VALUES ('JMS', 'Apata', 'Admin', 'Jasola', 'admin')
      ON CONFLICT (username) DO UPDATE
      SET role = 'admin',
          surname = COALESCE(users.surname, EXCLUDED.surname),
          othername = COALESCE(users.othername, EXCLUDED.othername);
    `);
    console.log('Default admin user checked.');

    await client.query(`
      CREATE TABLE IF NOT EXISTS classes (
        id SERIAL PRIMARY KEY,
        class_name VARCHAR(100) NOT NULL,
        section VARCHAR(100) NOT NULL,
        class_teacher VARCHAR(255) REFERENCES users(username),
        stream VARCHAR(20),
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        UNIQUE (class_name, section)
      );
    `);
    await client.query('ALTER TABLE classes ADD COLUMN IF NOT EXISTS stream VARCHAR(20);');
    await client.query('ALTER TABLE classes ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;');

    // Create Subjects table (refined)
    await client.query(`
      CREATE TABLE IF NOT EXISTS subjects (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255),
        class_name VARCHAR(50),
        stream VARCHAR(20),
        is_active BOOLEAN NOT NULL DEFAULT TRUE
      );
    `);
    await client.query('ALTER TABLE subjects ADD COLUMN IF NOT EXISTS stream VARCHAR(20);');
    await client.query('ALTER TABLE subjects ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;');
    console.log('Subjects table created or exists.');

    // Create Learners table
    await client.query(`
      CREATE TABLE IF NOT EXISTS learners (
        id SERIAL PRIMARY KEY,
        surname VARCHAR(255),
        othername VARCHAR(255),
        gender VARCHAR(20),
        class_name VARCHAR(50),
        admission_number VARCHAR(100) UNIQUE,
        date_of_birth DATE
      );
    `);
    await client.query('ALTER TABLE learners ADD COLUMN IF NOT EXISTS class_id INTEGER REFERENCES classes(id);');
    await client.query(`
      INSERT INTO classes (class_name, section)
      SELECT DISTINCT class_name, 'General'
      FROM learners
      WHERE class_name IS NOT NULL AND BTRIM(class_name) <> ''
      ON CONFLICT (class_name, section) DO NOTHING;
    `);
    await client.query(`
      UPDATE learners l
      SET class_id = c.id
      FROM classes c
      WHERE l.class_id IS NULL AND c.class_name = l.class_name AND c.section = 'General';
    `);
    console.log('Learners table created or exists.');

    // Create Results table
    await client.query(`
      CREATE TABLE IF NOT EXISTS results (
        id SERIAL PRIMARY KEY,
        class_name VARCHAR(50),
        subject VARCHAR(255),
        term VARCHAR(50),
        session_year VARCHAR(50)
      );
    `);
    console.log('Results table created or exists.');

    // Create Allocations table
    await client.query(`
      CREATE TABLE IF NOT EXISTS allocations (
        id SERIAL PRIMARY KEY,
        teacher_username VARCHAR(255) REFERENCES users(username),
        subject_name VARCHAR(255),
        subject_id INTEGER REFERENCES subjects(id),
        class_id INTEGER REFERENCES classes(id)
      );
    `);
    await client.query('ALTER TABLE allocations ADD COLUMN IF NOT EXISTS subject_id INTEGER REFERENCES subjects(id);');
    await client.query('ALTER TABLE allocations ADD COLUMN IF NOT EXISTS class_id INTEGER REFERENCES classes(id);');
    await client.query('DROP INDEX IF EXISTS allocations_teacher_subject_unique;');
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS allocations_teacher_class_subject_unique
      ON allocations (teacher_username, class_id, subject_id)
      WHERE subject_id IS NOT NULL AND class_id IS NOT NULL;
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS learner_results (
        id SERIAL PRIMARY KEY,
        learner_id INTEGER NOT NULL REFERENCES learners(id) ON DELETE CASCADE,
        class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
        subject_id INTEGER NOT NULL REFERENCES subjects(id),
        term VARCHAR(50) NOT NULL,
        session_year VARCHAR(50) NOT NULL,
        ca1 NUMERIC(5,2) NOT NULL CHECK (ca1 >= 0 AND ca1 <= 100),
        ca2 NUMERIC(5,2) NOT NULL CHECK (ca2 >= 0 AND ca2 <= 100),
        exam NUMERIC(5,2) NOT NULL CHECK (exam >= 0 AND exam <= 100),
        updated_by VARCHAR(255) REFERENCES users(username),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (learner_id, subject_id, term, session_year)
      );
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS learner_comments (
        id SERIAL PRIMARY KEY,
        learner_id INTEGER NOT NULL REFERENCES learners(id) ON DELETE CASCADE,
        class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
        term VARCHAR(50) NOT NULL,
        session_year VARCHAR(50) NOT NULL,
        comment TEXT NOT NULL DEFAULT '',
        principal_comment TEXT,
        teacher_comment TEXT,
        updated_by VARCHAR(255) REFERENCES users(username),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (learner_id, term, session_year)
      );
    `);
    await client.query(`
      ALTER TABLE learner_comments ADD COLUMN IF NOT EXISTS principal_comment TEXT;
      ALTER TABLE learner_comments ADD COLUMN IF NOT EXISTS teacher_comment TEXT;
      UPDATE learner_comments
      SET principal_comment = comment
      WHERE principal_comment IS NULL AND BTRIM(comment) <> '';
      UPDATE learner_comments SET principal_comment = '' WHERE principal_comment IS NULL;
      UPDATE learner_comments SET teacher_comment = '' WHERE teacher_comment IS NULL;
      ALTER TABLE learner_comments ALTER COLUMN principal_comment SET DEFAULT '';
      ALTER TABLE learner_comments ALTER COLUMN principal_comment SET NOT NULL;
      ALTER TABLE learner_comments ALTER COLUMN teacher_comment SET DEFAULT '';
      ALTER TABLE learner_comments ALTER COLUMN teacher_comment SET NOT NULL;
      ALTER TABLE learner_comments
        DROP CONSTRAINT IF EXISTS learner_comments_learner_id_term_session_year_key;
      CREATE UNIQUE INDEX IF NOT EXISTS learner_comments_learner_class_term_session_unique
      ON learner_comments (learner_id, class_id, term, session_year);
      CREATE TABLE IF NOT EXISTS learner_behaviors (
        id SERIAL PRIMARY KEY,
        learner_id INTEGER NOT NULL REFERENCES learners(id) ON DELETE CASCADE,
        class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
        term VARCHAR(50) NOT NULL,
        session_year VARCHAR(50) NOT NULL,
        ratings JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_by VARCHAR(255) REFERENCES users(username),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (learner_id, class_id, term, session_year)
      );
    `);
    console.log('Allocations table created or exists.');

    console.log('Database initialization complete!');
  } catch (err) {
    console.error('Error initializing database:', err);
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

init();
