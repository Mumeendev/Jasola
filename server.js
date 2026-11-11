const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;
const scrypt = promisify(crypto.scrypt);
const tokenSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

if (!process.env.SESSION_SECRET) {
  console.warn('SESSION_SECRET is not set; logins will expire when the server restarts.');
}

app.use(cors({ origin: '*' }));
app.use(express.json({ limit: '1mb' }));
app.use((req, res, next) => {
  const protectedPaths = ['/server.js', '/init-db.js', '/package.json', '/package-lock.json'];
  if (protectedPaths.includes(req.path) || req.path.startsWith('/node_modules/')) {
    return res.sendStatus(404);
  }
  next();
});
app.use(express.static(path.join(__dirname)));
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
let isDatabaseConnected = false;

pool.on('error', (err) => {
  console.error('Unexpected error on idle database client:', err);
  isDatabaseConnected = false;
});

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = await scrypt(password, salt, 64);
  return `scrypt$${salt}$${derivedKey.toString('hex')}`;
}

async function verifyPassword(password, storedPassword) {
  if (!storedPassword) return false;
  if (!storedPassword.startsWith('scrypt$')) return storedPassword === password;

  const [, salt, storedHash] = storedPassword.split('$');
  if (!salt || !storedHash) return false;
  const actualHash = await scrypt(password, salt, 64);
  const expectedHash = Buffer.from(storedHash, 'hex');
  return actualHash.length === expectedHash.length &&
    crypto.timingSafeEqual(actualHash, expectedHash);
}

function createToken(user) {
  const payload = Buffer.from(JSON.stringify({
    username: user.username,
    exp: Date.now() + 8 * 60 * 60 * 1000
  })).toString('base64url');
  const signature = crypto.createHmac('sha256', tokenSecret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

async function requireAuth(req, res, next) {
  const [payload, signature] = (req.get('authorization') || '').replace(/^Bearer\s+/i, '').split('.');
  if (!payload || !signature) {
    return res.status(401).json({ error: 'Please log in to continue.' });
  }

  let claims;
  try {
    const expected = crypto.createHmac('sha256', tokenSecret).update(payload).digest();
    const received = Buffer.from(signature, 'base64url');
    if (expected.length !== received.length || !crypto.timingSafeEqual(expected, received)) {
      return res.status(401).json({ error: 'Invalid login session.' });
    }

    claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if (!claims.username || !Number.isFinite(claims.exp) || claims.exp <= Date.now()) {
      return res.status(401).json({ error: 'Login session expired.' });
    }
  } catch (err) {
    return res.status(401).json({ error: 'Invalid login session.' });
  }
  try {
    const result = await pool.query(
      'SELECT username, role FROM users WHERE username = $1',
      [claims.username]
    );
    if (!result.rows.length) {
      return res.status(401).json({ error: 'User account not found.' });
    }
    req.user = result.rows[0];
    next();
  } catch (err) {
    console.error('Checking the authenticated user failed:', err);
    res.status(500).json({ error: 'Unable to verify login session.' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'You do not have permission to perform this action.' });
    }
    next();
  };
}

function isSeniorSecondaryClass(className) {
  return /senior\s+secondary|(?:^|\b)sss?\s*[-.]?\s*[1-3]\b/i.test(className);
}

function subjectCategoryForClass(className) {
  if (/junior\s+secondary|(?:^|\b)jss?\s*[-.]?\s*[1-3]\b/i.test(className)) {
    return 'Junior Secondary';
  }
  if (isSeniorSecondaryClass(className) || /secondary/i.test(className)) {
    return 'Secondary';
  }
  if (/primary|(?:^|\b)pry\s*[-.]?\s*[1-6]\b/i.test(className)) return 'Primary';
  if (/creche|nursery|kindergarten|(?:^|\b)kg\s*[-.]?\s*[1-3]\b/i.test(className)) return 'Creche';
  return null;
}

function isSubjectAllowedForClass(subject, classRow) {
  if (subject.stream && subject.stream !== classRow.stream) return false;
  const category = subjectCategoryForClass(classRow.class_name);
  if (category === 'Junior Secondary' && subject.class_name === 'Secondary') return true;
  return !category || !subject.class_name || subject.class_name === category;
}

function teacherUsernameFromOthername(othername) {
  return othername.trim().toLocaleLowerCase().replace(/[^\p{L}\p{N}]+/gu, '.').replace(/^\.+|\.+$/g, '');
}

const subjectStreams = new Set(['Science', 'Arts', 'Commercial']);
const behaviorSkills = ['Attentiveness', 'Punctuality', 'Neatness', 'Leadership'];
const behaviorRatings = new Set(['Excellent', 'Very Good', 'Good', 'Fair', 'Poor']);

async function initializeDatabase() {
  const client = await pool.connect();
  try {
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
      ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(255) UNIQUE;
      ALTER TABLE users ADD COLUMN IF NOT EXISTS password VARCHAR(255);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS surname VARCHAR(255);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS othername VARCHAR(255);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(255);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(20);
      ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(50);
      ALTER TABLE users ALTER COLUMN password DROP DEFAULT;

      CREATE TABLE IF NOT EXISTS classes (
        id SERIAL PRIMARY KEY,
        class_name VARCHAR(100) NOT NULL,
        section VARCHAR(100) NOT NULL,
        class_teacher VARCHAR(255) REFERENCES users(username),
        stream VARCHAR(20),
        UNIQUE (class_name, section)
      );
      ALTER TABLE classes ADD COLUMN IF NOT EXISTS stream VARCHAR(20);

      CREATE TABLE IF NOT EXISTS subjects (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255),
        class_name VARCHAR(50),
        stream VARCHAR(20),
        is_active BOOLEAN NOT NULL DEFAULT TRUE
      );
      ALTER TABLE subjects ADD COLUMN IF NOT EXISTS name VARCHAR(255);
      ALTER TABLE subjects ADD COLUMN IF NOT EXISTS class_name VARCHAR(50);
      ALTER TABLE subjects ADD COLUMN IF NOT EXISTS stream VARCHAR(20);
      ALTER TABLE subjects ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE;

      CREATE TABLE IF NOT EXISTS learners (
        id SERIAL PRIMARY KEY,
        surname VARCHAR(255),
        othername VARCHAR(255),
        gender VARCHAR(20),
        class_name VARCHAR(50),
        admission_number VARCHAR(100) UNIQUE,
        date_of_birth DATE
      );
      ALTER TABLE learners ADD COLUMN IF NOT EXISTS surname VARCHAR(255);
      ALTER TABLE learners ADD COLUMN IF NOT EXISTS othername VARCHAR(255);
      ALTER TABLE learners ADD COLUMN IF NOT EXISTS gender VARCHAR(20);
      ALTER TABLE learners ADD COLUMN IF NOT EXISTS class_name VARCHAR(50);
      ALTER TABLE learners ADD COLUMN IF NOT EXISTS admission_number VARCHAR(100);
      ALTER TABLE learners ADD COLUMN IF NOT EXISTS date_of_birth DATE;
      ALTER TABLE learners ADD COLUMN IF NOT EXISTS class_id INTEGER REFERENCES classes(id);

      CREATE TABLE IF NOT EXISTS results (
        id SERIAL PRIMARY KEY,
        class_name VARCHAR(50),
        subject VARCHAR(255),
        term VARCHAR(50),
        session_year VARCHAR(50)
      );
      ALTER TABLE results ADD COLUMN IF NOT EXISTS class_name VARCHAR(50);
      ALTER TABLE results ADD COLUMN IF NOT EXISTS subject VARCHAR(255);
      ALTER TABLE results ADD COLUMN IF NOT EXISTS term VARCHAR(50);
      ALTER TABLE results ADD COLUMN IF NOT EXISTS session_year VARCHAR(50);

      CREATE TABLE IF NOT EXISTS allocations (
        id SERIAL PRIMARY KEY,
        teacher_username VARCHAR(255) REFERENCES users(username),
        subject_name VARCHAR(255)
      );
      ALTER TABLE allocations ADD COLUMN IF NOT EXISTS teacher_username VARCHAR(255);
      ALTER TABLE allocations ADD COLUMN IF NOT EXISTS subject_name VARCHAR(255);
      ALTER TABLE allocations ADD COLUMN IF NOT EXISTS subject_id INTEGER REFERENCES subjects(id);
      ALTER TABLE allocations ADD COLUMN IF NOT EXISTS class_id INTEGER REFERENCES classes(id);
      DROP INDEX IF EXISTS allocations_teacher_subject_unique;
      CREATE UNIQUE INDEX IF NOT EXISTS allocations_teacher_class_subject_unique
        ON allocations (teacher_username, class_id, subject_id)
        WHERE class_id IS NOT NULL AND subject_id IS NOT NULL;

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
    await client.query(`
      INSERT INTO users (username, password, surname, othername, role)
      VALUES ('JMS', 'Apata', 'Admin', 'Jasola', 'admin')
      ON CONFLICT (username) DO UPDATE
      SET role = 'admin',
          surname = COALESCE(users.surname, EXCLUDED.surname),
          othername = COALESCE(users.othername, EXCLUDED.othername);
    `);
    isDatabaseConnected = true;
  } catch (err) {
    isDatabaseConnected = false;
    console.error('Database initialization failed:', err);
    throw err;
  } finally {
    client.release();
  }
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true, database: isDatabaseConnected ? 'connected' : 'disconnected' });
});

app.post('/api/login', async (req, res) => {
  const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }

  try {
    const result = await pool.query('SELECT username, password, role FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user || !(await verifyPassword(password, user.password))) {
      return res.status(401).json({ success: false, message: 'Invalid username or password.' });
    }

    if (!user.password.startsWith('scrypt$')) {
      await pool.query('UPDATE users SET password = $1 WHERE username = $2', [
        await hashPassword(password), username
      ]);
    }
    res.json({
      success: true,
      token: createToken(user),
      user: { username: user.username, role: user.role }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ success: false, error: 'Unable to log in right now.' });
  }
});

app.use('/api', (req, res, next) => {
  if (req.path === '/health' || req.path === '/login') return next();
  return requireAuth(req, res, next);
});

app.post('/api/change-password', async (req, res) => {
  const newPassword = typeof req.body.newPassword === 'string' ? req.body.newPassword : '';
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }
  try {
    await pool.query('UPDATE users SET password = $1 WHERE username = $2', [
      await hashPassword(newPassword), req.user.username
    ]);
    res.json({ success: true });
  } catch (err) {
    console.error('Password change failed:', err);
    res.status(500).json({ error: 'Unable to change password.' });
  }
});

app.get('/api/users', requireRole('admin'), async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT username, surname, othername, email, phone, role FROM users ORDER BY surname, othername'
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Loading users failed:', err);
    res.status(500).json({ error: 'Unable to load users.' });
  }
});

app.get('/api/user/:username', async (req, res) => {
  if (req.user.role !== 'admin' && req.user.username !== req.params.username) {
    return res.status(403).json({ error: 'You can only view your own profile.' });
  }
  try {
    const result = await pool.query(
      'SELECT username, surname, othername, email, phone, role FROM users WHERE username = $1',
      [req.params.username]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'User not found.' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Loading profile failed:', err);
    res.status(500).json({ error: 'Unable to load profile.' });
  }
});

app.post('/api/users', requireRole('admin'), async (req, res) => {
  const { surname, othername, email, phone, role } = req.body;
  if (![surname, othername, email, phone, role].every((value) => typeof value === 'string' && value.trim())) {
    return res.status(400).json({ error: 'Surname, other name, email, phone, and role are required.' });
  }
  if (!['admin', 'teacher', 'student', 'parent'].includes(role)) {
    return res.status(400).json({ error: 'Invalid user role.' });
  }
  const username = role === 'teacher'
    ? teacherUsernameFromOthername(othername)
    : email.trim().split('@')[0].toLowerCase();
  if (!username) {
    return res.status(400).json({ error: 'The other name must contain letters or numbers to create a teacher username.' });
  }
  try {
    await pool.query(
      `INSERT INTO users (username, password, surname, othername, email, phone, role)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [username, role === 'teacher' ? await hashPassword(surname.trim()) : null,
        surname.trim(), othername.trim(), email.trim().toLowerCase(), phone.trim(), role]
    );
    res.status(201).json({ success: true, username });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'That email or username is already registered.' });
    }
    console.error('Creating user failed:', err);
    res.status(500).json({ error: 'Unable to create user.' });
  }
});

app.delete('/api/users/:username', requireRole('admin'), async (req, res) => {
  const username = req.params.username;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const user = await client.query(
      'SELECT role FROM users WHERE username = $1 FOR UPDATE',
      [username]
    );
    if (!user.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'User not found.' });
    }
    if (user.rows[0].role === 'admin') {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'Administrator accounts cannot be removed.' });
    }
    await client.query('UPDATE allocations SET teacher_username = NULL WHERE teacher_username = $1', [username]);
    await client.query('UPDATE classes SET class_teacher = NULL WHERE class_teacher = $1', [username]);
    await client.query('UPDATE learner_results SET updated_by = NULL WHERE updated_by = $1', [username]);
    await client.query('UPDATE learner_comments SET updated_by = NULL WHERE updated_by = $1', [username]);
    await client.query('UPDATE learner_behaviors SET updated_by = NULL WHERE updated_by = $1', [username]);
    await client.query('DELETE FROM users WHERE username = $1', [username]);
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Removing user failed:', err);
    res.status(500).json({ error: 'Unable to remove user.' });
  } finally {
    client.release();
  }
});

app.post('/api/teachers/:username/credentials', requireRole('admin'), async (req, res) => {
  const currentUsername = req.params.username;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const teacher = await client.query(
      "SELECT username, surname, othername FROM users WHERE username = $1 AND role = 'teacher' FOR UPDATE",
      [currentUsername]
    );
    if (!teacher.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Teacher not found.' });
    }
    const allocation = await client.query(
      'SELECT 1 FROM allocations WHERE teacher_username = $1 AND subject_id IS NOT NULL AND class_id IS NOT NULL LIMIT 1',
      [currentUsername]
    );
    if (!allocation.rows.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Allocate at least one subject to this teacher first.' });
    }
    const { surname, othername } = teacher.rows[0];
    if (!surname || !surname.trim() || !othername || !othername.trim()) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Add the teacher surname and other names before creating login details.' });
    }
    const username = teacherUsernameFromOthername(othername);
    if (!username) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'The teacher other names cannot be used as a username.' });
    }
    const result = await client.query(
      `SELECT 1 FROM users WHERE username = $1 AND username <> $2`,
      [username, currentUsername]
    );
    if (result.rows.length) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: `The username "${username}" is already in use. Change the teacher's other names or username first.` });
    }
    const password = surname.trim();
    const passwordHash = await hashPassword(password);
    await client.query('UPDATE allocations SET teacher_username = $1 WHERE teacher_username = $2', [username, currentUsername]);
    await client.query('UPDATE classes SET class_teacher = $1 WHERE class_teacher = $2', [username, currentUsername]);
    await client.query('UPDATE learner_results SET updated_by = $1 WHERE updated_by = $2', [username, currentUsername]);
    await client.query(
      `UPDATE users SET username = $1, password = $2
       WHERE username = $3 AND role = 'teacher'`,
      [username, passwordHash, currentUsername]
    );
    await client.query('COMMIT');
    res.json({ success: true, username, password });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Creating teacher credentials failed:', err);
    res.status(500).json({ error: 'Unable to generate teacher credentials.' });
  } finally {
    client.release();
  }
});

app.put('/api/teachers/:username/password', requireRole('admin'), async (req, res) => {
  const username = req.params.username;
  const newPassword = typeof req.body.newPassword === 'string' ? req.body.newPassword : '';
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }
  try {
    const result = await pool.query(
      `UPDATE users SET password = $1 WHERE username = $2 AND role = 'teacher'
       RETURNING username`,
      [await hashPassword(newPassword), username]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Teacher not found.' });
    res.json({ success: true });
  } catch (err) {
    console.error('Changing teacher password failed:', err);
    res.status(500).json({ error: 'Unable to change teacher password.' });
  }
});

app.get('/api/teachers', requireRole('admin'), async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT username, surname, othername FROM users WHERE role = 'teacher' ORDER BY surname, othername"
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Loading teachers failed:', err);
    res.status(500).json({ error: 'Unable to load teachers.' });
  }
});

app.get('/api/classes', async (req, res) => {
  try {
    const result = req.user.role === 'teacher'
      ? await pool.query(
        `SELECT DISTINCT c.id, c.class_name, c.section, c.class_teacher, c.stream
         FROM classes c JOIN allocations a ON a.class_id = c.id
         WHERE a.teacher_username = $1 ORDER BY c.class_name, c.section`,
        [req.user.username]
      )
      : await pool.query('SELECT id, class_name, section, class_teacher, stream FROM classes ORDER BY class_name, section');
    res.json(result.rows);
  } catch (err) {
    console.error('Loading classes failed:', err);
    res.status(500).json({ error: 'Unable to load classes.' });
  }
});

app.post('/api/classes', requireRole('admin'), async (req, res) => {
  const className = typeof req.body.className === 'string' ? req.body.className.trim() : '';
  const section = typeof req.body.section === 'string' ? req.body.section.trim() : '';
  const classTeacher = typeof req.body.classTeacher === 'string' ? req.body.classTeacher.trim() : '';
  const stream = typeof req.body.stream === 'string' ? req.body.stream.trim() : '';
  if (!className || !section || !classTeacher) {
    return res.status(400).json({ error: 'Class name, section, and class teacher are required.' });
  }
  if (isSeniorSecondaryClass(className) && !subjectStreams.has(stream)) {
    return res.status(400).json({ error: 'Select Science, Arts, or Commercial for a senior secondary class.' });
  }
  if (stream && !isSeniorSecondaryClass(className)) {
    return res.status(400).json({ error: 'Science, Arts, and Commercial streams are only for senior secondary classes.' });
  }
  if (stream && !subjectStreams.has(stream)) {
    return res.status(400).json({ error: 'Select a valid senior secondary stream.' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO classes (class_name, section, class_teacher, stream)
       SELECT $1, $2, username, $4 FROM users WHERE username = $3 AND role = 'teacher'
       RETURNING id, class_name, section, class_teacher, stream`,
      [className, section, classTeacher, stream || null]
    );
    if (!result.rows.length) return res.status(400).json({ error: 'Select a valid teacher account.' });
    res.status(201).json({ success: true, class: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'That class and section already exist.' });
    console.error('Creating class failed:', err);
    res.status(500).json({ error: 'Unable to create class.' });
  }
});

app.get('/api/teachers/:username/subjects', requireRole('admin'), async (req, res) => {
  try {
    const teacher = await pool.query(
      "SELECT 1 FROM users WHERE username = $1 AND role = 'teacher'",
      [req.params.username]
    );
    if (!teacher.rows.length) return res.status(404).json({ error: 'Teacher not found.' });
    const result = await pool.query(
      `SELECT a.class_id, a.subject_id
       FROM allocations a JOIN subjects s ON s.id = a.subject_id
       WHERE a.teacher_username = $1 AND s.is_active = TRUE
         AND a.subject_id IS NOT NULL AND a.class_id IS NOT NULL`,
      [req.params.username]
    );
    res.json({
      allocations: result.rows.map((row) => ({ classId: row.class_id, subjectId: row.subject_id })),
      subjectIds: result.rows.map((row) => row.subject_id)
    });
  } catch (err) {
    console.error('Loading teacher allocations failed:', err);
    res.status(500).json({ error: 'Unable to load teacher subject allocations.' });
  }
});

app.get('/api/subjects', async (req, res) => {
  try {
    if (req.query.catalog === '1') {
      if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Only administrators can view the subject catalog.' });
      }
      const catalog = await pool.query(
        'SELECT id, name, class_name, stream FROM subjects WHERE is_active = TRUE ORDER BY class_name, stream NULLS FIRST, name'
      );
      return res.json(catalog.rows);
    }
    const result = req.user.role === 'teacher'
      ? await pool.query(
        `SELECT DISTINCT s.id, s.name, s.class_name, s.stream, a.class_id,
                c.class_name AS allocated_class_name, c.section, c.stream AS allocated_stream
         FROM subjects s
         JOIN allocations a ON a.subject_id = s.id
         JOIN classes c ON c.id = a.class_id
         WHERE a.teacher_username = $1 AND s.is_active = TRUE
           AND (s.stream IS NULL OR s.stream = c.stream)
         ORDER BY s.class_name, s.name`,
        [req.user.username]
      )
      : await pool.query(
        `SELECT DISTINCT s.id, s.name, s.class_name, s.stream, a.class_id,
                c.class_name AS allocated_class_name, c.section, c.stream AS allocated_stream
         FROM subjects s
         JOIN allocations a ON a.subject_id = s.id
         JOIN classes c ON c.id = a.class_id
         WHERE s.is_active = TRUE AND (s.stream IS NULL OR s.stream = c.stream)
         ORDER BY c.class_name, c.section, s.name`
      );
    res.json(result.rows.filter((subject) => isSubjectAllowedForClass(
      { class_name: subject.class_name, stream: subject.stream },
      { class_name: subject.allocated_class_name, stream: subject.allocated_stream }
    )));
  } catch (err) {
    console.error('Loading subjects failed:', err);
    res.status(500).json({ error: 'Unable to load subjects.' });
  }
});

app.post('/api/subjects', requireRole('admin'), async (req, res) => {
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
  const className = typeof req.body.className === 'string' ? req.body.className.trim() : '';
  const stream = typeof req.body.stream === 'string' ? req.body.stream.trim() : '';
  if (!name || !['Creche', 'Primary', 'Junior Secondary', 'Secondary'].includes(className)) {
    return res.status(400).json({ error: 'Subject and a valid category are required.' });
  }
  if (stream && (className !== 'Secondary' || !subjectStreams.has(stream))) {
    return res.status(400).json({ error: 'Choose a valid stream for a secondary subject.' });
  }
  try {
    const result = await pool.query(
      'INSERT INTO subjects (name, class_name, stream) VALUES ($1, $2, $3) RETURNING id, name, class_name, stream',
      [name, className, stream || null]
    );
    res.status(201).json({ success: true, subject: result.rows[0] });
  } catch (err) {
    console.error('Creating subject failed:', err);
    res.status(500).json({ error: 'Unable to create subject.' });
  }
});

app.delete('/api/subjects/:id', requireRole('admin'), async (req, res) => {
  const subjectId = Number(req.params.id);
  if (!Number.isInteger(subjectId) || subjectId <= 0) {
    return res.status(400).json({ error: 'Select a valid subject.' });
  }
  try {
    const result = await pool.query(
      'UPDATE subjects SET is_active = FALSE WHERE id = $1 AND is_active = TRUE RETURNING id',
      [subjectId]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Active subject not found.' });
    res.json({ success: true });
  } catch (err) {
    console.error('Archiving subject failed:', err);
    res.status(500).json({ error: 'Unable to remove subject from the active catalog.' });
  }
});

app.get('/api/learners', requireRole('admin', 'teacher'), async (req, res) => {
  const classId = Number(req.query.classId);
  if (!Number.isInteger(classId) || classId <= 0) {
    return res.status(400).json({ error: 'Select a valid class.' });
  }
  try {
    if (req.user.role === 'teacher') {
      const allocation = await pool.query(
        'SELECT 1 FROM allocations WHERE teacher_username = $1 AND class_id = $2 LIMIT 1',
        [req.user.username, classId]
      );
      if (!allocation.rows.length) {
        return res.status(403).json({ error: 'You are not assigned to this class.' });
      }
    }
    const result = await pool.query(
      `SELECT id, surname, othername, admission_number, class_id, class_name
       FROM learners WHERE class_id = $1 ORDER BY surname, othername`,
      [classId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Loading learners failed:', err);
    res.status(500).json({ error: 'Unable to load learners.' });
  }
});

app.post('/api/learners', requireRole('admin'), async (req, res) => {
  const { surname, othername, gender, dob } = req.body;
  const classId = Number(req.body.classId);
  const admissionNumber = req.body.admissionNumber || null;
  if (!Number.isInteger(classId) || classId <= 0 ||
      ![surname, othername, gender].every((value) => typeof value === 'string' && value.trim())) {
    return res.status(400).json({ error: 'Learner name, gender, and a valid class are required.' });
  }
  try {
    const classResult = await pool.query('SELECT class_name FROM classes WHERE id = $1', [classId]);
    if (!classResult.rows.length) return res.status(400).json({ error: 'Select a valid class.' });
    await pool.query(
      `INSERT INTO learners (surname, othername, gender, class_name, class_id, admission_number, date_of_birth)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [surname.trim(), othername.trim(), gender, classResult.rows[0].class_name, classId, admissionNumber, dob || null]
    );
    res.status(201).json({ success: true });
  } catch (err) {
    console.error('Creating learner failed:', err);
    res.status(500).json({ error: 'Unable to register learner.' });
  }
});

app.delete('/api/learners/:id', requireRole('admin'), async (req, res) => {
  const learnerId = Number(req.params.id);
  if (!Number.isInteger(learnerId) || learnerId <= 0) {
    return res.status(400).json({ error: 'Select a valid learner.' });
  }
  try {
    const result = await pool.query('DELETE FROM learners WHERE id = $1 RETURNING id', [learnerId]);
    if (!result.rows.length) return res.status(404).json({ error: 'Learner not found.' });
    res.json({ success: true });
  } catch (err) {
    console.error('Deleting learner failed:', err);
    res.status(500).json({ error: 'Unable to remove learner.' });
  }
});

app.get('/api/result-sheet', requireRole('admin', 'teacher'), async (req, res) => {
  const classId = Number(req.query.classId);
  const subjectId = Number(req.query.subjectId);
  const { term, sessionYear } = req.query;
  if (!Number.isInteger(classId) || !Number.isInteger(subjectId) ||
      typeof term !== 'string' || typeof sessionYear !== 'string') {
    return res.status(400).json({ error: 'Select a class, subject, term, and session.' });
  }
  try {
    const allocation = req.user.role === 'teacher'
      ? await pool.query(
        'SELECT 1 FROM allocations WHERE teacher_username = $1 AND class_id = $2 AND subject_id = $3',
        [req.user.username, classId, subjectId]
      )
      : await pool.query(
        'SELECT 1 FROM allocations WHERE class_id = $1 AND subject_id = $2',
        [classId, subjectId]
      );
    if (!allocation.rows.length) {
      return res.status(403).json({ error: 'This subject is not allocated to the selected class and teacher.' });
    }
    const classResult = await pool.query(
      'SELECT class_name, section, stream FROM classes WHERE id = $1',
      [classId]
    );
    if (!classResult.rows.length) return res.status(404).json({ error: 'Class not found.' });
    const subject = await pool.query('SELECT id, name, class_name, stream, is_active FROM subjects WHERE id = $1', [subjectId]);
    if (!subject.rows.length) return res.status(404).json({ error: 'Subject not found.' });
    if (!subject.rows[0].is_active) return res.status(409).json({ error: 'This subject has been archived and cannot receive new results.' });
    if (!isSubjectAllowedForClass(subject.rows[0], classResult.rows[0])) {
      return res.status(400).json({ error: 'This subject is not available for the selected class stream.' });
    }
    const learners = await pool.query(
      `SELECT l.id AS learner_id, l.surname, l.othername, l.admission_number,
              r.ca1, r.ca2, r.exam
       FROM learners l
       LEFT JOIN learner_results r
         ON r.learner_id = l.id AND r.subject_id = $2 AND r.term = $3 AND r.session_year = $4
       WHERE l.class_id = $1
       ORDER BY l.surname, l.othername`,
      [classId, subjectId, term, sessionYear]
    );
    res.json({
      class: classResult.rows[0],
      subject: subject.rows[0],
      learners: learners.rows
    });
  } catch (err) {
    console.error('Loading result sheet failed:', err);
    res.status(500).json({ error: 'Unable to load the learner result sheet.' });
  }
});

app.put('/api/result-sheet', requireRole('admin', 'teacher'), async (req, res) => {
  const classId = Number(req.body.classId);
  const subjectId = Number(req.body.subjectId);
  const { term, sessionYear, rows } = req.body;
  if (!Number.isInteger(classId) || !Number.isInteger(subjectId) ||
      typeof term !== 'string' || !term.trim() ||
      typeof sessionYear !== 'string' || !sessionYear.trim() ||
      !Array.isArray(rows) ||
      rows.some((row) => !row || typeof row !== 'object' || Array.isArray(row))) {
    return res.status(400).json({ error: 'Class, subject, term, session, and score rows are required.' });
  }
  const isScore = (value, maximum) =>
    (typeof value === 'number' || (typeof value === 'string' && value.trim() !== '')) &&
    Number.isFinite(Number(value)) && Number(value) >= 0 && Number(value) <= maximum;
  if (rows.some((row) =>
    !isScore(row.ca1, 20) || !isScore(row.ca2, 20) || !isScore(row.exam, 60)
  )) {
    return res.status(400).json({ error: 'CA1 and CA2 scores must be 0–20; exam scores must be 0–60.' });
  }
  const normalizedRows = rows.map((row) => ({
    learnerId: Number(row.learnerId),
    ca1: Number(row.ca1),
    ca2: Number(row.ca2),
    exam: Number(row.exam)
  }));
  if (normalizedRows.some((row) => !Number.isInteger(row.learnerId) || row.learnerId <= 0)) {
    return res.status(400).json({ error: 'Each score row must identify a valid learner.' });
  }
  if (new Set(normalizedRows.map((row) => row.learnerId)).size !== normalizedRows.length) {
    return res.status(400).json({ error: 'A learner appears more than once in the score sheet.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const allocation = req.user.role === 'teacher'
      ? await client.query(
        'SELECT 1 FROM allocations WHERE teacher_username = $1 AND class_id = $2 AND subject_id = $3',
        [req.user.username, classId, subjectId]
      )
      : await client.query(
        'SELECT 1 FROM allocations WHERE class_id = $1 AND subject_id = $2',
        [classId, subjectId]
      );
    if (!allocation.rows.length) {
      await client.query('ROLLBACK');
      return res.status(403).json({ error: 'This subject is not allocated to the selected class and teacher.' });
    }
    const classResult = await client.query('SELECT 1 FROM classes WHERE id = $1', [classId]);
    if (!classResult.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Class not found.' });
    }
    const subject = await client.query('SELECT is_active FROM subjects WHERE id = $1', [subjectId]);
    if (!subject.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Subject not found.' });
    }
    if (!subject.rows[0].is_active) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'This subject has been archived and cannot receive new results.' });
    }
    const classDetails = await client.query('SELECT class_name, stream FROM classes WHERE id = $1', [classId]);
    const subjectDetails = await client.query('SELECT class_name, stream FROM subjects WHERE id = $1', [subjectId]);
    if (!isSubjectAllowedForClass(subjectDetails.rows[0], classDetails.rows[0])) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'This subject is not available for the selected class stream.' });
    }
    const classLearners = await client.query(
      'SELECT id FROM learners WHERE class_id = $1',
      [classId]
    );
    const learnerIds = new Set(classLearners.rows.map((learner) => learner.id));
    if (normalizedRows.some((row) => !learnerIds.has(row.learnerId))) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Every learner must belong to the selected class.' });
    }

    for (const row of normalizedRows) {
      await client.query(
        `INSERT INTO learner_results
          (learner_id, class_id, subject_id, term, session_year, ca1, ca2, exam, updated_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (learner_id, subject_id, term, session_year)
         DO UPDATE SET class_id = EXCLUDED.class_id, ca1 = EXCLUDED.ca1,
           ca2 = EXCLUDED.ca2, exam = EXCLUDED.exam, updated_by = EXCLUDED.updated_by,
           updated_at = NOW()`,
        [row.learnerId, classId, subjectId, term.trim(), sessionYear.trim(),
          row.ca1, row.ca2, row.exam, req.user.username]
      );
    }
    await client.query('COMMIT');
    res.json({ success: true, saved: normalizedRows.length });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Saving result sheet failed:', err);
    res.status(500).json({ error: 'Unable to save learner scores.' });
  } finally {
    client.release();
  }
});

app.get('/api/report-cards', requireRole('admin', 'teacher'), async (req, res) => {
  const classId = Number(req.query.classId);
  const { term, sessionYear } = req.query;
  if (!Number.isInteger(classId) || classId <= 0 ||
      typeof term !== 'string' || !term.trim() ||
      typeof sessionYear !== 'string' || !sessionYear.trim()) {
    return res.status(400).json({ error: 'Select a class, term, and session.' });
  }
  try {
    if (req.user.role === 'teacher') {
      const allocation = await pool.query(
        'SELECT 1 FROM allocations WHERE teacher_username = $1 AND class_id = $2 LIMIT 1',
        [req.user.username, classId]
      );
      if (!allocation.rows.length) {
        return res.status(403).json({ error: 'You are not assigned to this class.' });
      }
    }

    const classResult = await pool.query(
      `SELECT c.id, c.class_name, c.section, c.class_teacher, c.stream,
              u.surname AS teacher_surname, u.othername AS teacher_othername
       FROM classes c LEFT JOIN users u ON u.username = c.class_teacher
       WHERE c.id = $1`,
      [classId]
    );
    if (!classResult.rows.length) return res.status(404).json({ error: 'Class not found.' });

    const learnersResult = await pool.query(
      `SELECT id, surname, othername, admission_number
       FROM learners WHERE class_id = $1 ORDER BY surname, othername`,
      [classId]
    );
    const subjectsResult = req.user.role === 'teacher'
      ? await pool.query(
        `SELECT DISTINCT s.id, s.name, s.class_name, s.stream
         FROM allocations a
         JOIN subjects s ON s.id = a.subject_id
         JOIN classes c ON c.id = a.class_id
         WHERE a.class_id = $1 AND a.teacher_username = $2
           AND (s.stream IS NULL OR s.stream = c.stream)
         ORDER BY s.name`,
        [classId, req.user.username]
      )
      : await pool.query(
        `SELECT DISTINCT s.id, s.name, s.class_name, s.stream
         FROM allocations a
         JOIN subjects s ON s.id = a.subject_id
         JOIN classes c ON c.id = a.class_id
         WHERE a.class_id = $1
           AND (s.stream IS NULL OR s.stream = c.stream)
         ORDER BY s.name`,
        [classId]
      );
    const scoresResult = req.user.role === 'teacher'
      ? await pool.query(
        `SELECT lr.learner_id, lr.subject_id, lr.ca1, lr.ca2, lr.exam
         FROM learner_results lr
         JOIN allocations a ON a.class_id = lr.class_id AND a.subject_id = lr.subject_id
         JOIN subjects s ON s.id = lr.subject_id
         JOIN classes c ON c.id = lr.class_id
         WHERE lr.class_id = $1 AND lr.term = $2 AND lr.session_year = $3
           AND (s.stream IS NULL OR s.stream = c.stream)
           AND a.teacher_username = $4`,
        [classId, term, sessionYear, req.user.username]
      )
      : await pool.query(
        `SELECT lr.learner_id, lr.subject_id, lr.ca1, lr.ca2, lr.exam
         FROM learner_results lr
         JOIN subjects s ON s.id = lr.subject_id
         JOIN classes c ON c.id = lr.class_id
         WHERE lr.class_id = $1 AND lr.term = $2 AND lr.session_year = $3
           AND (s.stream IS NULL OR s.stream = c.stream)`,
        [classId, term, sessionYear]
      );
    const commentsResult = await pool.query(
      `SELECT learner_id, principal_comment, teacher_comment
       FROM learner_comments
       WHERE class_id = $1 AND term = $2 AND session_year = $3`,
      [classId, term.trim(), sessionYear.trim()]
    );
    const behaviorsResult = await pool.query(
      `SELECT learner_id, ratings
       FROM learner_behaviors
       WHERE class_id = $1 AND term = $2 AND session_year = $3`,
      [classId, term.trim(), sessionYear.trim()]
    );
    const allowedSubjects = subjectsResult.rows.filter((subject) =>
      isSubjectAllowedForClass(subject, classResult.rows[0])
    );
    const allowedSubjectIds = new Set(allowedSubjects.map((subject) => subject.id));
    res.json({
      class: classResult.rows[0],
      learners: learnersResult.rows,
      subjects: allowedSubjects,
      scores: scoresResult.rows.filter((score) => allowedSubjectIds.has(score.subject_id)),
      comments: commentsResult.rows,
      behaviors: behaviorsResult.rows,
      behaviorSkills
    });
  } catch (err) {
    console.error('Loading report cards failed:', err);
    res.status(500).json({ error: 'Unable to load report cards.' });
  }
});

app.get('/api/learner-comments', requireRole('admin', 'teacher'), async (req, res) => {
  const classId = Number(req.query.classId);
  const { term, sessionYear } = req.query;
  const commentType = req.query.type;
  if (!Number.isInteger(classId) || classId <= 0 ||
      typeof term !== 'string' || !term.trim() ||
      typeof sessionYear !== 'string' || !sessionYear.trim() ||
      !['principal', 'teacher'].includes(commentType)) {
    return res.status(400).json({ error: 'Select a class, term, and session.' });
  }
  if ((commentType === 'principal' && req.user.role !== 'admin') ||
      (commentType === 'teacher' && req.user.role !== 'teacher')) {
    return res.status(403).json({ error: 'You cannot manage this type of comment.' });
  }
  const commentColumn = commentType === 'principal' ? 'principal_comment' : 'teacher_comment';
  try {
    if (req.user.role === 'teacher') {
      const allocation = await pool.query(
        'SELECT 1 FROM allocations WHERE teacher_username = $1 AND class_id = $2 LIMIT 1',
        [req.user.username, classId]
      );
      if (!allocation.rows.length) return res.status(403).json({ error: 'You are not assigned to this class.' });
    }
    const classExists = await pool.query('SELECT 1 FROM classes WHERE id = $1', [classId]);
    if (!classExists.rows.length) return res.status(404).json({ error: 'Class not found.' });
    const result = await pool.query(
      `SELECT l.id AS learner_id, l.surname, l.othername, l.admission_number,
              COALESCE(lc.${commentColumn}, '') AS comment
       FROM learners l
       LEFT JOIN learner_comments lc
         ON lc.learner_id = l.id AND lc.class_id = $1 AND lc.term = $2 AND lc.session_year = $3
       WHERE l.class_id = $1
       ORDER BY l.surname, l.othername`,
      [classId, term.trim(), sessionYear.trim()]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Loading learner comments failed:', err);
    res.status(500).json({ error: 'Unable to load learner comments.' });
  }
});

app.put('/api/learner-comments', requireRole('admin', 'teacher'), async (req, res) => {
  const classId = Number(req.body.classId);
  const { term, sessionYear, comments } = req.body;
  const commentType = req.body.type;
  if (!Number.isInteger(classId) || classId <= 0 ||
      typeof term !== 'string' || !term.trim() ||
      typeof sessionYear !== 'string' || !sessionYear.trim() ||
      !['principal', 'teacher'].includes(commentType) ||
      !Array.isArray(comments) ||
      comments.some((item) => !item || typeof item !== 'object' ||
        !Number.isInteger(Number(item.learnerId)) || Number(item.learnerId) <= 0 ||
        typeof item.comment !== 'string' || item.comment.length > 2000)) {
    return res.status(400).json({ error: 'Class, term, session, and valid learner comments are required.' });
  }
  if ((commentType === 'principal' && req.user.role !== 'admin') ||
      (commentType === 'teacher' && req.user.role !== 'teacher')) {
    return res.status(403).json({ error: 'You cannot save this type of comment.' });
  }
  const commentColumn = commentType === 'principal' ? 'principal_comment' : 'teacher_comment';
  const rows = comments.map((item) => ({
    learnerId: Number(item.learnerId),
    comment: item.comment.trim()
  }));
  if (new Set(rows.map((item) => item.learnerId)).size !== rows.length) {
    return res.status(400).json({ error: 'A learner appears more than once in the comment list.' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const classResult = await client.query('SELECT 1 FROM classes WHERE id = $1', [classId]);
    if (!classResult.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Class not found.' });
    }
    if (req.user.role === 'teacher') {
      const allocation = await client.query(
        'SELECT 1 FROM allocations WHERE teacher_username = $1 AND class_id = $2 LIMIT 1',
        [req.user.username, classId]
      );
      if (!allocation.rows.length) {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'You are not assigned to this class.' });
      }
    }
    const learners = await client.query('SELECT id FROM learners WHERE class_id = $1', [classId]);
    const learnerIds = new Set(learners.rows.map((learner) => learner.id));
    if (rows.some((row) => !learnerIds.has(row.learnerId))) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Every commented learner must belong to the selected class.' });
    }
    for (const row of rows) {
      await client.query(
        `INSERT INTO learner_comments
           (learner_id, class_id, term, session_year, ${commentColumn}, updated_by)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (learner_id, class_id, term, session_year)
         DO UPDATE SET class_id = EXCLUDED.class_id, ${commentColumn} = EXCLUDED.${commentColumn},
           updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
        [row.learnerId, classId, term.trim(), sessionYear.trim(), row.comment, req.user.username]
      );
    }
    await client.query('COMMIT');
    res.json({ success: true, saved: rows.length });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Saving learner comments failed:', err);
    res.status(500).json({ error: 'Unable to save learner comments.' });
  } finally {
    client.release();
  }
});

app.get('/api/learner-behaviors', requireRole('admin', 'teacher'), async (req, res) => {
  const classId = Number(req.query.classId);
  const { term, sessionYear } = req.query;
  if (!Number.isInteger(classId) || classId <= 0 ||
      typeof term !== 'string' || !term.trim() ||
      typeof sessionYear !== 'string' || !sessionYear.trim()) {
    return res.status(400).json({ error: 'Select a class, term, and session.' });
  }
  try {
    if (req.user.role === 'teacher') {
      const allocation = await pool.query(
        'SELECT 1 FROM allocations WHERE teacher_username = $1 AND class_id = $2 LIMIT 1',
        [req.user.username, classId]
      );
      if (!allocation.rows.length) return res.status(403).json({ error: 'You are not assigned to this class.' });
    }
    const classExists = await pool.query('SELECT 1 FROM classes WHERE id = $1', [classId]);
    if (!classExists.rows.length) return res.status(404).json({ error: 'Class not found.' });
    const result = await pool.query(
      `SELECT l.id AS learner_id, l.surname, l.othername, l.admission_number,
              COALESCE(lb.ratings, '{}'::jsonb) AS ratings
       FROM learners l
       LEFT JOIN learner_behaviors lb
         ON lb.learner_id = l.id AND lb.class_id = $1 AND lb.term = $2 AND lb.session_year = $3
       WHERE l.class_id = $1
       ORDER BY l.surname, l.othername`,
      [classId, term.trim(), sessionYear.trim()]
    );
    res.json({ skills: behaviorSkills, learners: result.rows });
  } catch (err) {
    console.error('Loading learner behavioral skills failed:', err);
    res.status(500).json({ error: 'Unable to load behavioral skills.' });
  }
});

app.put('/api/learner-behaviors', requireRole('admin', 'teacher'), async (req, res) => {
  const classId = Number(req.body.classId);
  const { term, sessionYear, learners } = req.body;
  if (!Number.isInteger(classId) || classId <= 0 ||
      typeof term !== 'string' || !term.trim() ||
      typeof sessionYear !== 'string' || !sessionYear.trim() ||
      !Array.isArray(learners) ||
      learners.some((item) => !item || typeof item !== 'object' ||
        !Number.isInteger(Number(item.learnerId)) || Number(item.learnerId) <= 0 ||
        !item.ratings || typeof item.ratings !== 'object' || Array.isArray(item.ratings) ||
        Object.entries(item.ratings).some(([skill, rating]) =>
          !behaviorSkills.includes(skill) ||
          (rating !== '' && (typeof rating !== 'string' || !behaviorRatings.has(rating)))
        ))) {
    return res.status(400).json({ error: 'Class, term, session, and valid learner ratings are required.' });
  }
  const rows = learners.map((item) => ({
    learnerId: Number(item.learnerId),
    ratings: Object.fromEntries(Object.entries(item.ratings).filter(([, rating]) => rating !== ''))
  }));
  if (new Set(rows.map((item) => item.learnerId)).size !== rows.length) {
    return res.status(400).json({ error: 'A learner appears more than once in the ratings.' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const classExists = await client.query('SELECT 1 FROM classes WHERE id = $1', [classId]);
    if (!classExists.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Class not found.' });
    }
    if (req.user.role === 'teacher') {
      const allocation = await client.query(
        'SELECT 1 FROM allocations WHERE teacher_username = $1 AND class_id = $2 LIMIT 1',
        [req.user.username, classId]
      );
      if (!allocation.rows.length) {
        await client.query('ROLLBACK');
        return res.status(403).json({ error: 'You are not assigned to this class.' });
      }
    }
    const classLearners = await client.query('SELECT id FROM learners WHERE class_id = $1', [classId]);
    const learnerIds = new Set(classLearners.rows.map((learner) => learner.id));
    if (rows.some((row) => !learnerIds.has(row.learnerId))) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Every learner must belong to the selected class.' });
    }
    for (const row of rows) {
      if (!Object.keys(row.ratings).length) {
        await client.query(
          'DELETE FROM learner_behaviors WHERE learner_id = $1 AND class_id = $2 AND term = $3 AND session_year = $4',
          [row.learnerId, classId, term.trim(), sessionYear.trim()]
        );
        continue;
      }
      await client.query(
        `INSERT INTO learner_behaviors
           (learner_id, class_id, term, session_year, ratings, updated_by)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6)
         ON CONFLICT (learner_id, class_id, term, session_year)
         DO UPDATE SET class_id = EXCLUDED.class_id, ratings = EXCLUDED.ratings,
           updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
        [row.learnerId, classId, term.trim(), sessionYear.trim(),
          JSON.stringify(row.ratings), req.user.username]
      );
    }
    await client.query('COMMIT');
    res.json({ success: true, saved: rows.length });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Saving learner behavioral skills failed:', err);
    res.status(500).json({ error: 'Unable to save behavioral skills.' });
  } finally {
    client.release();
  }
});

app.get('/api/class-gradebook', requireRole('admin', 'teacher'), async (req, res) => {
  const classId = Number(req.query.classId);
  const { term, sessionYear } = req.query;
  if (!Number.isInteger(classId) || classId <= 0 ||
      typeof term !== 'string' || !term.trim() ||
      typeof sessionYear !== 'string' || !sessionYear.trim()) {
    return res.status(400).json({ error: 'Select a class, term, and session.' });
  }
  try {
    if (req.user.role === 'teacher') {
      const allocation = await pool.query(
        'SELECT 1 FROM allocations WHERE teacher_username = $1 AND class_id = $2 LIMIT 1',
        [req.user.username, classId]
      );
      if (!allocation.rows.length) {
        return res.status(403).json({ error: 'You are not assigned to this class.' });
      }
    }

    const classResult = await pool.query(
      'SELECT id, class_name, section, stream FROM classes WHERE id = $1',
      [classId]
    );
    if (!classResult.rows.length) return res.status(404).json({ error: 'Class not found.' });

    const teacherFilter = req.user.role === 'teacher' ? 'AND a.teacher_username = $2' : '';
    const subjectParams = req.user.role === 'teacher' ? [classId, req.user.username] : [classId];
    const subjectsResult = await pool.query(
      `SELECT DISTINCT s.id, s.name, s.class_name, s.stream
       FROM allocations a
       JOIN subjects s ON s.id = a.subject_id
       JOIN classes c ON c.id = a.class_id
       WHERE a.class_id = $1
         AND (s.stream IS NULL OR s.stream = c.stream)
         ${teacherFilter}
       ORDER BY s.name`,
      subjectParams
    );
    const learnersResult = await pool.query(
      `SELECT id, surname, othername, admission_number
       FROM learners WHERE class_id = $1 ORDER BY surname, othername`,
      [classId]
    );
    const scoreParams = req.user.role === 'teacher'
      ? [classId, term.trim(), sessionYear.trim(), req.user.username]
      : [classId, term.trim(), sessionYear.trim()];
    const teacherScoreFilter = req.user.role === 'teacher'
      ? 'AND a.teacher_username = $4'
      : '';
    const scoresResult = await pool.query(
      `SELECT lr.learner_id, lr.subject_id, lr.ca1, lr.ca2, lr.exam
       FROM learner_results lr
       JOIN allocations a ON a.class_id = lr.class_id AND a.subject_id = lr.subject_id
       JOIN subjects s ON s.id = lr.subject_id
       JOIN classes c ON c.id = lr.class_id
       WHERE lr.class_id = $1 AND lr.term = $2 AND lr.session_year = $3
         AND (s.stream IS NULL OR s.stream = c.stream)
         ${teacherScoreFilter}`,
      scoreParams
    );
    const allowedSubjects = subjectsResult.rows.filter((subject) =>
      isSubjectAllowedForClass(subject, classResult.rows[0])
    );
    const allowedSubjectIds = new Set(allowedSubjects.map((subject) => subject.id));
    res.json({
      class: classResult.rows[0],
      learners: learnersResult.rows,
      subjects: allowedSubjects,
      scores: scoresResult.rows.filter((score) => allowedSubjectIds.has(score.subject_id))
    });
  } catch (err) {
    console.error('Loading class gradebook failed:', err);
    res.status(500).json({ error: 'Unable to load the class gradebook.' });
  }
});

app.get('/api/results', requireRole('admin', 'teacher'), async (req, res) => {
  try {
    const result = req.user.role === 'teacher'
      ? await pool.query(
        `SELECT lr.id, c.class_name || ' - ' || c.section AS class_name,
                s.name AS subject, lr.term, lr.session_year,
                l.surname || ' ' || l.othername AS learner_name, l.admission_number,
                lr.ca1, lr.ca2, lr.exam, lr.ca1 + lr.ca2 + lr.exam AS total
         FROM learner_results lr
         JOIN classes c ON c.id = lr.class_id
         JOIN subjects s ON s.id = lr.subject_id
         JOIN learners l ON l.id = lr.learner_id
         JOIN allocations a ON a.class_id = lr.class_id AND a.subject_id = lr.subject_id
         WHERE a.teacher_username = $1
         ORDER BY lr.session_year DESC, lr.term, c.class_name, c.section, s.name, l.surname`,
        [req.user.username]
      )
      : await pool.query(
        `SELECT lr.id, c.class_name || ' - ' || c.section AS class_name,
                s.name AS subject, lr.term, lr.session_year,
                l.surname || ' ' || l.othername AS learner_name, l.admission_number,
                lr.ca1, lr.ca2, lr.exam, lr.ca1 + lr.ca2 + lr.exam AS total
         FROM learner_results lr
         JOIN classes c ON c.id = lr.class_id
         JOIN subjects s ON s.id = lr.subject_id
         JOIN learners l ON l.id = lr.learner_id
         ORDER BY lr.session_year DESC, lr.term, c.class_name, c.section, s.name, l.surname`
      );
    res.json(result.rows);
  } catch (err) {
    console.error('Loading results failed:', err);
    res.status(500).json({ error: 'Unable to load results.' });
  }
});

app.post('/api/allocate', requireRole('admin'), async (req, res) => {
  const { teacherUsername } = req.body;
  const subjectId = Number(req.body.subjectId);
  const classId = Number(req.body.classId);
  if (typeof teacherUsername !== 'string' || !Number.isInteger(subjectId) || !Number.isInteger(classId)) {
    return res.status(400).json({ error: 'A teacher, class, and valid subject are required.' });
  }
  try {
    const teacher = await pool.query(
      "SELECT 1 FROM users WHERE username = $1 AND role = 'teacher'",
      [teacherUsername]
    );
    if (!teacher.rows.length) return res.status(404).json({ error: 'Teacher not found.' });
    const subject = await pool.query('SELECT id, name, class_name, stream, is_active FROM subjects WHERE id = $1', [Number(subjectId)]);
    if (!subject.rows.length) return res.status(404).json({ error: 'Subject not found.' });
    if (!subject.rows[0].is_active) return res.status(409).json({ error: 'This subject has been archived.' });
    const classResult = await pool.query('SELECT class_name, stream FROM classes WHERE id = $1', [classId]);
    if (!classResult.rows.length) return res.status(404).json({ error: 'Class not found.' });
    if (!isSubjectAllowedForClass(subject.rows[0], classResult.rows[0])) {
      return res.status(400).json({ error: 'This subject is not available for the selected class or stream.' });
    }
    await pool.query(
      `INSERT INTO allocations (teacher_username, subject_name, subject_id, class_id)
       VALUES ($1, $2, $3, $4) ON CONFLICT (teacher_username, class_id, subject_id)
       WHERE subject_id IS NOT NULL AND class_id IS NOT NULL DO NOTHING`,
      [teacherUsername, subject.rows[0].name, subjectId, classId]
    );
    res.status(201).json({ success: true });
  } catch (err) {
    console.error('Allocating subject failed:', err);
    res.status(500).json({ error: 'Unable to allocate subject.' });
  }
});

app.put('/api/allocate', requireRole('admin'), async (req, res) => {
  const { teacherUsername, subjectIds } = req.body;
  const classId = Number(req.body.classId);
  if (
    typeof teacherUsername !== 'string' ||
    !Number.isInteger(classId) || classId <= 0 ||
    !Array.isArray(subjectIds) ||
    subjectIds.some((id) => !Number.isInteger(Number(id)) || Number(id) <= 0)
  ) {
    return res.status(400).json({ error: 'A teacher and a list of valid subjects are required.' });
  }
  const ids = [...new Set(subjectIds.map(Number))];
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const teacher = await client.query(
      "SELECT 1 FROM users WHERE username = $1 AND role = 'teacher' FOR UPDATE",
      [teacherUsername]
    );
    if (!teacher.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Teacher not found.' });
    }
    const classResult = await client.query('SELECT class_name, stream FROM classes WHERE id = $1', [classId]);
    if (!classResult.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Class not found.' });
    }
    const subjects = ids.length
      ? await client.query('SELECT id, name, class_name, stream FROM subjects WHERE id = ANY($1::int[]) AND is_active = TRUE', [ids])
      : { rows: [] };
    if (subjects.rows.length !== ids.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'One or more selected subjects do not exist.' });
    }
    if (subjects.rows.some((subject) => !isSubjectAllowedForClass(subject, classResult.rows[0]))) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'One or more selected subjects are not available for this class or stream.' });
    }

    await client.query(
      `DELETE FROM allocations a
       USING subjects s
       WHERE a.subject_id = s.id AND s.is_active = TRUE
         AND a.teacher_username = $1 AND a.class_id = $2`,
      [teacherUsername, classId]
    );
    for (const subject of subjects.rows) {
      await client.query(
        'INSERT INTO allocations (teacher_username, subject_name, subject_id, class_id) VALUES ($1, $2, $3, $4)',
        [teacherUsername, subject.name, subject.id, classId]
      );
    }
    await client.query('COMMIT');
    res.json({ success: true, classId, subjectIds: ids });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Saving teacher allocations failed:', err);
    res.status(500).json({ error: 'Unable to save teacher subject allocations.' });
  } finally {
    client.release();
  }
});

initializeDatabase()
  .catch(() => {
    console.error('Server starting without a database connection; database requests will fail until it is available.');
  })
  .finally(() => {
    app.listen(port, () => console.log(`Server listening on port ${port}`));
  });
