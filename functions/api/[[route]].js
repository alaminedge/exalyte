// Exalyte API — Complete Backend
// functions/api/[[route]].js

const JWT_SECRET = 'exalyte_prod_secret_2024_x9kLm3nR7pQw';

// ─── Crypto helpers ───────────────────────────────────────────────────────────
async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacSha256(key, data) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64url(obj) {
  return btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function signJWT(payload) {
  const header = b64url({ alg: 'HS256', typ: 'JWT' });
  const body = b64url({ ...payload, exp: Math.floor(Date.now() / 1000) + 7 * 86400 });
  const sig = await hmacSha256(JWT_SECRET, `${header}.${body}`);
  return `${header}.${body}.${sig}`;
}

async function verifyJWT(token) {
  try {
    const [h, b, s] = token.split('.');
    const expected = await hmacSha256(JWT_SECRET, `${h}.${b}`);
    if (s !== expected) return null;
    const payload = JSON.parse(atob(b.replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

// ─── CORS ─────────────────────────────────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...CORS } });
}

function err(msg, status = 400) { return json({ error: msg }, status); }

// ─── Auth middleware ──────────────────────────────────────────────────────────
async function requireAuth(request) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return null;
  return await verifyJWT(token);
}

async function requireAdmin(request, db) {
  const user = await requireAuth(request);
  if (!user) return null;
  const row = await db.prepare('SELECT * FROM users WHERE id = ?').bind(user.id).first();
  if (!row || !row.is_admin) return null;
  return row;
}

// ─── DB init ──────────────────────────────────────────────────────────────────
async function initDB(db) {
  // D1 requires each statement run separately — never use db.exec with multiple statements
  const statements = [
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      is_admin INTEGER DEFAULT 0,
      is_premium_allowed INTEGER DEFAULT 0,
      premium_until DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS batches (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS exams (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      time_limit INTEGER DEFAULT 30,
      is_premium INTEGER DEFAULT 0,
      negative_marking REAL DEFAULT 0,
      allow_practice INTEGER DEFAULT 1,
      batch_id INTEGER REFERENCES batches(id) ON DELETE SET NULL,
      live_deadline_hours INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS questions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      exam_id INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
      question_text TEXT NOT NULL,
      option_a TEXT NOT NULL,
      option_b TEXT NOT NULL,
      option_c TEXT NOT NULL,
      option_d TEXT NOT NULL,
      correct_answer TEXT NOT NULL,
      image_url TEXT
    )`,
    `CREATE TABLE IF NOT EXISTS exam_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      exam_id INTEGER NOT NULL,
      score INTEGER DEFAULT 0,
      total_questions INTEGER DEFAULT 0,
      percentage REAL DEFAULT 0,
      answers TEXT,
      submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS exam_results_stored (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      exam_id INTEGER NOT NULL,
      score INTEGER DEFAULT 0,
      total_questions INTEGER DEFAULT 0,
      percentage REAL DEFAULT 0,
      answers TEXT,
      submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      attempt_number INTEGER DEFAULT 1,
      is_first_attempt INTEGER DEFAULT 1,
      is_practice INTEGER DEFAULT 0
    )`,
    `CREATE TABLE IF NOT EXISTS premium_access (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id),
      exam_id INTEGER REFERENCES exams(id) ON DELETE CASCADE,
      batch_id INTEGER REFERENCES batches(id) ON DELETE CASCADE,
      grant_scope TEXT DEFAULT 'exam',
      granted_by INTEGER,
      granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME
    )`,
    `CREATE TABLE IF NOT EXISTS signup_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip_address TEXT NOT NULL,
      email TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
  ];

  for (const sql of statements) {
    await db.prepare(sql).run();
  }

  // Seed default admin account
  const adminHash = '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9';
  const existing = await db.prepare('SELECT id FROM users WHERE email = ?').bind('admin@exalyte.com').first();
  if (!existing) {
    await db.prepare('INSERT INTO users (name,email,password,is_admin,is_premium_allowed) VALUES (?,?,?,1,1)')
      .bind('Admin', 'admin@exalyte.com', adminHash).run();
  }
}

// ─── Premium check ────────────────────────────────────────────────────────────
async function checkPremiumAccess(db, userId, examId, isAdmin) {
  if (isAdmin) return true;
  const now = new Date().toISOString();
  const user = await db.prepare('SELECT premium_until FROM users WHERE id = ?').bind(userId).first();
  if (user && user.premium_until && user.premium_until > now) return true;
  const exam = await db.prepare('SELECT batch_id FROM exams WHERE id = ?').bind(examId).first();
  const examGrant = await db.prepare(
    `SELECT id FROM premium_access WHERE user_id=? AND exam_id=? AND grant_scope='exam' AND (expires_at IS NULL OR expires_at > ?)`
  ).bind(userId, examId, now).first();
  if (examGrant) return true;
  if (exam && exam.batch_id) {
    const batchGrant = await db.prepare(
      `SELECT id FROM premium_access WHERE user_id=? AND batch_id=? AND grant_scope='batch' AND (expires_at IS NULL OR expires_at > ?)`
    ).bind(userId, exam.batch_id, now).first();
    if (batchGrant) return true;
  }
  return false;
}

// ─── CSV Parser ───────────────────────────────────────────────────────────────
function parseCSVLine(line) {
  const fields = [];
  let cur = '', inQ = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') { inQ = !inQ; continue; }
    if (c === ',' && !inQ) { fields.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  fields.push(cur.trim());
  return fields;
}

// ─── Live status helper ───────────────────────────────────────────────────────
function getLiveStatus(exam) {
  if (!exam.live_deadline_hours || exam.live_deadline_hours === 0) {
    return { is_live: false, live_ends_at: null, live_seconds_remaining: 0 };
  }
  const created = new Date(exam.created_at).getTime();
  const liveEnds = created + exam.live_deadline_hours * 3600000;
  const now = Date.now();
  const remaining = Math.max(0, Math.floor((liveEnds - now) / 1000));
  return { is_live: now < liveEnds, live_ends_at: new Date(liveEnds).toISOString(), live_seconds_remaining: remaining };
}

// ═══════════════════════════════════════════════════════════════════════════════
// ROUTE HANDLERS
// ═══════════════════════════════════════════════════════════════════════════════

// ─── Auth ─────────────────────────────────────────────────────────────────────
async function handleSignup(request, db) {
  const { name, email, password } = await request.json();
  if (!name || !email || !password) return err('All fields required');
  if (password.length < 6) return err('Password must be at least 6 characters');
  const ip = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || '0.0.0.0';
  const existing = await db.prepare('SELECT id FROM signup_logs WHERE ip_address = ?').bind(ip).first();
  if (existing) return err('An account already exists from this device.', 403);
  const hash = await sha256(password);
  try {
    const result = await db.prepare('INSERT INTO users (name,email,password) VALUES (?,?,?) RETURNING *')
      .bind(name, email, hash).first();
    await db.prepare('INSERT INTO signup_logs (ip_address,email) VALUES (?,?)').bind(ip, email).run();
    const token = await signJWT({ id: result.id, email: result.email, is_admin: result.is_admin });
    return json({ token, user: { id: result.id, name: result.name, email: result.email, is_admin: result.is_admin } });
  } catch (e) {
    if (e.message && e.message.includes('UNIQUE')) return err('Email already in use');
    return err('Signup failed');
  }
}

async function handleLogin(request, db) {
  const { email, password } = await request.json();
  if (!email || !password) return err('Email and password required');
  const hash = await sha256(password);
  const user = await db.prepare('SELECT * FROM users WHERE email=? AND password=?').bind(email, hash).first();
  if (!user) return err('Invalid credentials', 401);
  const token = await signJWT({ id: user.id, email: user.email, is_admin: user.is_admin });
  return json({ token, user: { id: user.id, name: user.name, email: user.email, is_admin: user.is_admin } });
}

// ─── Exams ────────────────────────────────────────────────────────────────────
async function handleListExams(request, db) {
  const user = await requireAuth(request);
  const userId = user ? user.id : null;

  const exams = await db.prepare(`
    SELECT e.*, b.name as batch_name,
      (SELECT COUNT(*) FROM questions q WHERE q.exam_id = e.id) as question_count
    FROM exams e LEFT JOIN batches b ON e.batch_id = b.id
    ORDER BY e.created_at DESC
  `).all();

  const result = [];
  for (const exam of exams.results) {
    const live = getLiveStatus(exam);
    let stored_attempt = null, accessible = !exam.is_premium, can_practice = false;

    if (userId) {
      const sa = await db.prepare(
        `SELECT * FROM exam_results_stored WHERE user_id=? AND exam_id=? AND is_practice=0 AND is_first_attempt=1 LIMIT 1`
      ).bind(userId, exam.id).first();
      stored_attempt = sa || null;
      if (exam.is_premium) accessible = await checkPremiumAccess(db, userId, exam.id, user.is_admin);
      if (exam.allow_practice && !live.is_live && stored_attempt) can_practice = true;
    }

    result.push({ ...exam, ...live, stored_attempt, accessible, can_practice });
  }
  return json(result);
}

async function handleExamStatus(examId, request, db) {
  const user = await requireAuth(request);
  const exam = await db.prepare('SELECT * FROM exams WHERE id=?').bind(examId).first();
  if (!exam) return err('Exam not found', 404);
  const live = getLiveStatus(exam);
  let can_attempt_live = false, can_practice = false, has_completed_live = false;

  if (user) {
    const liveAttempt = await db.prepare(
      `SELECT id FROM exam_results_stored WHERE user_id=? AND exam_id=? AND is_practice=0 LIMIT 1`
    ).bind(user.id, examId).first();
    has_completed_live = !!liveAttempt;
    can_attempt_live = live.is_live && !has_completed_live;
    can_practice = exam.allow_practice && !live.is_live && has_completed_live;
  }

  return json({ ...live, can_attempt_live, can_practice, has_completed_live });
}

async function handleGetQuestions(examId, request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  const exam = await db.prepare('SELECT * FROM exams WHERE id=?').bind(examId).first();
  if (!exam) return err('Exam not found', 404);
  if (exam.is_premium) {
    const ok = await checkPremiumAccess(db, user.id, examId, user.is_admin);
    if (!ok) return err('Premium access required', 403);
  }
  const qs = await db.prepare(
    'SELECT id,exam_id,question_text,option_a,option_b,option_c,option_d,image_url FROM questions WHERE exam_id=?'
  ).bind(examId).all();
  return json(qs.results);
}

async function handleSubmit(examId, request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  const { answers, is_practice } = await request.json();
  const exam = await db.prepare('SELECT * FROM exams WHERE id=?').bind(examId).first();
  if (!exam) return err('Exam not found', 404);

  if (exam.is_premium) {
    const ok = await checkPremiumAccess(db, user.id, examId, user.is_admin);
    if (!ok) return err('Premium access required', 403);
  }

  const live = getLiveStatus(exam);

  if (!is_practice) {
    if (live.is_live && live.live_seconds_remaining === 0) return err('Live exam has ended');
    const existing = await db.prepare(
      `SELECT id FROM exam_results_stored WHERE user_id=? AND exam_id=? AND is_practice=0 LIMIT 1`
    ).bind(user.id, examId).first();
    if (existing) return err('You have already submitted this exam');
  } else {
    const liveAttempt = await db.prepare(
      `SELECT id FROM exam_results_stored WHERE user_id=? AND exam_id=? AND is_practice=0 LIMIT 1`
    ).bind(user.id, examId).first();
    if (!liveAttempt) return err('Complete the live exam before practicing');
  }

  const questions = await db.prepare('SELECT * FROM questions WHERE exam_id=?').bind(examId).all();
  let score = 0;
  const total = questions.results.length;
  const nm = exam.negative_marking || 0;

  for (const q of questions.results) {
    const ans = answers[q.id];
    if (ans === q.correct_answer) score += 1;
    else if (ans && nm > 0) score -= nm;
  }

  const percentage = total > 0 ? Math.round((score / total) * 10000) / 100 : 0;
  const answersJson = JSON.stringify(answers);
  const is_first = !is_practice ? 1 : 0;

  const r1 = await db.prepare(
    `INSERT INTO exam_results_stored (user_id,exam_id,score,total_questions,percentage,answers,is_first_attempt,is_practice)
     VALUES (?,?,?,?,?,?,?,?) RETURNING id`
  ).bind(user.id, examId, score, total, percentage, answersJson, is_first, is_practice ? 1 : 0).first();

  await db.prepare(
    `INSERT INTO exam_attempts (user_id,exam_id,score,total_questions,percentage,answers) VALUES (?,?,?,?,?,?)`
  ).bind(user.id, examId, score, total, percentage, answersJson).run();

  return json({ attemptId: r1.id, score, total, percentage, answers });
}

async function handleGetResult(examId, attemptId, request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  const attempt = await db.prepare(
    'SELECT * FROM exam_results_stored WHERE id=? AND user_id=? AND exam_id=?'
  ).bind(attemptId, user.id, examId).first();
  if (!attempt) return err('Result not found', 404);
  const questions = await db.prepare('SELECT * FROM questions WHERE exam_id=?').bind(examId).all();
  const exam = await db.prepare('SELECT * FROM exams WHERE id=?').bind(examId).first();
  return json({ attempt, questions: questions.results, exam });
}

// ─── Leaderboard ──────────────────────────────────────────────────────────────
async function handleLeaderboard(examId, request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  const row = await db.prepare(`
    SELECT rank, total_participants, percentage, score FROM (
      SELECT user_id, score, percentage,
        ROW_NUMBER() OVER (ORDER BY percentage DESC, submitted_at ASC) as rank,
        COUNT(*) OVER () as total_participants
      FROM exam_results_stored
      WHERE exam_id=? AND is_first_attempt=1 AND is_practice=0
    ) WHERE user_id=?
  `).bind(examId, user.id).first();
  if (!row) return json({ rank: null, total_participants: 0, percentile: null, score: null, percentage: null });
  const percentile = row.total_participants > 1
    ? Math.round((1 - (row.rank - 1) / row.total_participants) * 100)
    : 100;
  return json({ ...row, percentile });
}

// ─── History ──────────────────────────────────────────────────────────────────
async function handleHistory(request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  const rows = await db.prepare(`
    SELECT ers.*, e.name as exam_name, b.name as batch_name
    FROM exam_results_stored ers
    JOIN exams e ON ers.exam_id = e.id
    LEFT JOIN batches b ON e.batch_id = b.id
    WHERE ers.user_id=? AND ers.is_first_attempt=1 AND ers.is_practice=0
    ORDER BY ers.submitted_at DESC
  `).bind(user.id).all();

  const result = [];
  for (const r of rows.results) {
    const lb = await db.prepare(`
      SELECT rank, total_participants FROM (
        SELECT user_id, ROW_NUMBER() OVER (ORDER BY percentage DESC, submitted_at ASC) as rank,
          COUNT(*) OVER () as total_participants
        FROM exam_results_stored WHERE exam_id=? AND is_first_attempt=1 AND is_practice=0
      ) WHERE user_id=?
    `).bind(r.exam_id, user.id).first();
    const percentile = lb && lb.total_participants > 1
      ? Math.round((1 - (lb.rank - 1) / lb.total_participants) * 100) : 100;
    result.push({ ...r, rank: lb?.rank || 1, total_participants: lb?.total_participants || 1, percentile });
  }
  return json(result);
}

// ─── Batches ──────────────────────────────────────────────────────────────────
async function handleListBatches(db) {
  const rows = await db.prepare(`
    SELECT b.*, COUNT(e.id) as exam_count
    FROM batches b LEFT JOIN exams e ON e.batch_id = b.id
    GROUP BY b.id ORDER BY b.created_at DESC
  `).all();
  return json(rows.results);
}

// ─── Admin ────────────────────────────────────────────────────────────────────
async function handleAdminCreateBatch(request, db) {
  const { name, description } = await request.json();
  if (!name) return err('Name required');
  const r = await db.prepare('INSERT INTO batches (name,description) VALUES (?,?) RETURNING *')
    .bind(name, description || '').first();
  return json(r, 201);
}

async function handleAdminDeleteBatch(batchId, db) {
  await db.prepare('UPDATE exams SET batch_id=NULL WHERE batch_id=?').bind(batchId).run();
  await db.prepare('DELETE FROM batches WHERE id=?').bind(batchId).run();
  return json({ success: true });
}

async function handleAdminCreateExam(request, db) {
  const { name, description, time_limit, is_premium, negative_marking, allow_practice, batch_id, live_deadline_hours } = await request.json();
  if (!name) return err('Name required');
  const r = await db.prepare(
    `INSERT INTO exams (name,description,time_limit,is_premium,negative_marking,allow_practice,batch_id,live_deadline_hours)
     VALUES (?,?,?,?,?,?,?,?) RETURNING *`
  ).bind(name, description || '', time_limit || 30, is_premium ? 1 : 0, negative_marking || 0,
    allow_practice !== false ? 1 : 0, batch_id || null, live_deadline_hours || 0).first();
  return json(r, 201);
}

async function handleAdminUpdateExam(examId, request, db) {
  const { name, description, time_limit, is_premium, negative_marking, allow_practice, batch_id, live_deadline_hours } = await request.json();
  await db.prepare(
    `UPDATE exams SET name=?,description=?,time_limit=?,is_premium=?,negative_marking=?,allow_practice=?,batch_id=?,live_deadline_hours=? WHERE id=?`
  ).bind(name, description || '', time_limit || 30, is_premium ? 1 : 0, negative_marking || 0,
    allow_practice !== false ? 1 : 0, batch_id || null, live_deadline_hours || 0, examId).run();
  const r = await db.prepare('SELECT * FROM exams WHERE id=?').bind(examId).first();
  return json(r);
}

async function handleAdminDeleteExam(examId, db) {
  await db.prepare('DELETE FROM premium_access WHERE exam_id=?').bind(examId).run();
  await db.prepare('DELETE FROM exam_results_stored WHERE exam_id=?').bind(examId).run();
  await db.prepare('DELETE FROM exam_attempts WHERE exam_id=?').bind(examId).run();
  await db.prepare('DELETE FROM questions WHERE exam_id=?').bind(examId).run();
  await db.prepare('DELETE FROM exams WHERE id=?').bind(examId).run();
  return json({ success: true });
}

async function handleAdminGetQuestions(examId, db) {
  const qs = await db.prepare('SELECT * FROM questions WHERE exam_id=? ORDER BY id').bind(examId).all();
  return json(qs.results);
}

async function handleAdminDeleteAllQuestions(examId, db) {
  await db.prepare('DELETE FROM questions WHERE exam_id=?').bind(examId).run();
  return json({ success: true });
}

async function handleAdminDeleteQuestion(qId, db) {
  await db.prepare('DELETE FROM questions WHERE id=?').bind(qId).run();
  return json({ success: true });
}

async function handleAdminBulkQuestions(request, db) {
  const { exam_id, csv } = await request.json();
  if (!exam_id || !csv) return err('exam_id and csv required');
  const lines = csv.split('\n').map(l => l.trim()).filter(l => l);
  const start = lines[0].toLowerCase().includes('question') ? 1 : 0;
  let count = 0;
  for (let i = start; i < lines.length; i++) {
    const f = parseCSVLine(lines[i]);
    if (f.length < 6) continue;
    const [qt, oa, ob, oc, od, ca, img] = f;
    if (!['A', 'B', 'C', 'D'].includes(ca.toUpperCase())) continue;
    await db.prepare(
      'INSERT INTO questions (exam_id,question_text,option_a,option_b,option_c,option_d,correct_answer,image_url) VALUES (?,?,?,?,?,?,?,?)'
    ).bind(exam_id, qt, oa, ob, oc, od, ca.toUpperCase(), img || null).run();
    count++;
  }
  return json({ inserted: count });
}

async function handleAdminListUsers(db) {
  const rows = await db.prepare('SELECT id,name,email,is_admin,is_premium_allowed,premium_until,created_at FROM users ORDER BY created_at DESC').all();
  const result = [];
  for (const u of rows.results) {
    const grants = await db.prepare(`
      SELECT pa.*, e.name as exam_name, b.name as batch_name
      FROM premium_access pa
      LEFT JOIN exams e ON pa.exam_id = e.id
      LEFT JOIN batches b ON pa.batch_id = b.id
      WHERE pa.user_id=?
    `).bind(u.id).all();
    result.push({ ...u, premium_grants: grants.results });
  }
  return json(result);
}

async function handleAdminGrantPremium(request, db, adminId) {
  const { user_id, grant_scope, exam_id, batch_id, duration_hours } = await request.json();
  if (!user_id || !grant_scope) return err('user_id and grant_scope required');
  const expires_at = duration_hours
    ? new Date(Date.now() + duration_hours * 3600000).toISOString()
    : null;

  if (grant_scope === 'account') {
    await db.prepare('UPDATE users SET premium_until=? WHERE id=?').bind(expires_at, user_id).run();
  } else if (grant_scope === 'batch') {
    if (!batch_id) return err('batch_id required for batch scope');
    await db.prepare(
      'INSERT INTO premium_access (user_id,batch_id,grant_scope,granted_by,expires_at) VALUES (?,?,?,?,?)'
    ).bind(user_id, batch_id, 'batch', adminId, expires_at).run();
  } else {
    if (!exam_id) return err('exam_id required for exam scope');
    await db.prepare(
      'INSERT INTO premium_access (user_id,exam_id,grant_scope,granted_by,expires_at) VALUES (?,?,?,?,?)'
    ).bind(user_id, exam_id, 'exam', adminId, expires_at).run();
  }
  return json({ success: true });
}

async function handleAdminRevokePremium(request, db) {
  const { user_id, exam_id } = await request.json();
  await db.prepare('DELETE FROM premium_access WHERE user_id=? AND exam_id=?').bind(user_id, exam_id).run();
  return json({ success: true });
}

async function handleAdminRevokeAccountPremium(request, db) {
  const { user_id } = await request.json();
  await db.prepare('UPDATE users SET premium_until=NULL WHERE id=?').bind(user_id).run();
  return json({ success: true });
}

async function handleAdminResults(examId, db) {
  const query = examId
    ? `SELECT ers.*,u.name as user_name,u.email,e.name as exam_name FROM exam_results_stored ers JOIN users u ON ers.user_id=u.id JOIN exams e ON ers.exam_id=e.id WHERE ers.exam_id=? AND ers.is_first_attempt=1 AND ers.is_practice=0 ORDER BY ers.submitted_at DESC`
    : `SELECT ers.*,u.name as user_name,u.email,e.name as exam_name FROM exam_results_stored ers JOIN users u ON ers.user_id=u.id JOIN exams e ON ers.exam_id=e.id WHERE ers.is_first_attempt=1 AND ers.is_practice=0 ORDER BY ers.submitted_at DESC`;
  const rows = examId
    ? await db.prepare(query).bind(examId).all()
    : await db.prepare(query).all();
  return json(rows.results);
}

async function handleAdminDeleteResult(resultId, db) {
  await db.prepare('DELETE FROM exam_results_stored WHERE id=?').bind(resultId).run();
  return json({ success: true });
}

async function handleAdminPremiumGrants(db) {
  const rows = await db.prepare(`
    SELECT pa.*,u.name as user_name,u.email,e.name as exam_name,b.name as batch_name
    FROM premium_access pa
    JOIN users u ON pa.user_id=u.id
    LEFT JOIN exams e ON pa.exam_id=e.id
    LEFT JOIN batches b ON pa.batch_id=b.id
    ORDER BY pa.granted_at DESC
  `).all();
  return json(rows.results);
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN ROUTER
// ═══════════════════════════════════════════════════════════════════════════════
export async function onRequest(context) {
  const { request, env } = context;
  const db = env.DB;

  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  try { await initDB(db); } catch (e) { console.error('DB init error:', e); }

  const url = new URL(request.url);
  let path = url.pathname.replace(/^\/api/, '').replace(/\/$/, '') || '/';
  const method = request.method;

  // ── Auth ──
  if (path === '/auth/signup' && method === 'POST') return handleSignup(request, db);
  if (path === '/auth/login' && method === 'POST') return handleLogin(request, db);

  // ── Batches ──
  if (path === '/batches' && method === 'GET') return handleListBatches(db);

  // ── History ──
  if (path === '/history' && method === 'GET') return handleHistory(request, db);

  // ── Leaderboard ──
  const lbMatch = path.match(/^\/leaderboard\/(\d+)$/);
  if (lbMatch && method === 'GET') return handleLeaderboard(lbMatch[1], request, db);

  // ── Exams ──
  if (path === '/exams' && method === 'GET') return handleListExams(request, db);

  const examStatus = path.match(/^\/exams\/(\d+)\/status$/);
  if (examStatus && method === 'GET') return handleExamStatus(examStatus[1], request, db);

  const examQs = path.match(/^\/exams\/(\d+)\/questions$/);
  if (examQs && method === 'GET') return handleGetQuestions(examQs[1], request, db);

  const examSubmit = path.match(/^\/exams\/(\d+)\/submit$/);
  if (examSubmit && method === 'POST') return handleSubmit(examSubmit[1], request, db);

  const examResult = path.match(/^\/exams\/(\d+)\/result\/(\d+)$/);
  if (examResult && method === 'GET') return handleGetResult(examResult[1], examResult[2], request, db);

  // ── Admin ──
  const admin = await requireAdmin(request, db);

  if (path === '/admin/batches' && method === 'POST') {
    if (!admin) return err('Admin required', 403);
    return handleAdminCreateBatch(request, db);
  }
  const delBatch = path.match(/^\/admin\/batches\/(\d+)$/);
  if (delBatch && method === 'DELETE') {
    if (!admin) return err('Admin required', 403);
    return handleAdminDeleteBatch(delBatch[1], db);
  }

  if (path === '/admin/exams' && method === 'POST') {
    if (!admin) return err('Admin required', 403);
    return handleAdminCreateExam(request, db);
  }
  const adminExam = path.match(/^\/admin\/exams\/(\d+)$/);
  if (adminExam && method === 'PUT') {
    if (!admin) return err('Admin required', 403);
    return handleAdminUpdateExam(adminExam[1], request, db);
  }
  if (adminExam && method === 'DELETE') {
    if (!admin) return err('Admin required', 403);
    return handleAdminDeleteExam(adminExam[1], db);
  }

  const adminQs = path.match(/^\/admin\/questions\/(\d+)$/);
  if (adminQs && method === 'GET') {
    if (!admin) return err('Admin required', 403);
    return handleAdminGetQuestions(adminQs[1], db);
  }
  if (adminQs && method === 'DELETE') {
    if (!admin) return err('Admin required', 403);
    return handleAdminDeleteAllQuestions(adminQs[1], db);
  }

  const adminSingleQ = path.match(/^\/admin\/questions\/single\/(\d+)$/);
  if (adminSingleQ && method === 'DELETE') {
    if (!admin) return err('Admin required', 403);
    return handleAdminDeleteQuestion(adminSingleQ[1], db);
  }

  if (path === '/admin/questions/bulk' && method === 'POST') {
    if (!admin) return err('Admin required', 403);
    return handleAdminBulkQuestions(request, db);
  }

  if (path === '/admin/users' && method === 'GET') {
    if (!admin) return err('Admin required', 403);
    return handleAdminListUsers(db);
  }

  if (path === '/admin/grant-premium' && method === 'POST') {
    if (!admin) return err('Admin required', 403);
    return handleAdminGrantPremium(request, db, admin.id);
  }
  if (path === '/admin/revoke-premium' && method === 'DELETE') {
    if (!admin) return err('Admin required', 403);
    return handleAdminRevokePremium(request, db);
  }
  if (path === '/admin/revoke-account-premium' && method === 'DELETE') {
    if (!admin) return err('Admin required', 403);
    return handleAdminRevokeAccountPremium(request, db);
  }

  if (path === '/admin/results' && method === 'GET') {
    if (!admin) return err('Admin required', 403);
    return handleAdminResults(null, db);
  }
  const adminResults = path.match(/^\/admin\/results\/(\d+)$/);
  if (adminResults && method === 'GET') {
    if (!admin) return err('Admin required', 403);
    return handleAdminResults(adminResults[1], db);
  }
  if (adminResults && method === 'DELETE') {
    if (!admin) return err('Admin required', 403);
    return handleAdminDeleteResult(adminResults[1], db);
  }

  if (path === '/admin/premium-grants' && method === 'GET') {
    if (!admin) return err('Admin required', 403);
    return handleAdminPremiumGrants(db);
  }

  return err('Not found', 404);
}
