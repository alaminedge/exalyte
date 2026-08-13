// Exalyte API — Complete Backend for Cloudflare Pages
// functions/api/[[route]].js
// FULL VERSION: Sectional Exams + Marks per Question + Practice (no storage)

// ============================================================
// CRYPTO HELPERS
// ============================================================

async function sha256(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

const JWT_SECRET = 'exalyte_prod_secret_2025_x9kLm3nR7pQw';

async function hmacSha256(key, data) {
  const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(key), 
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
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

// ============================================================
// CORS & RESPONSE HELPERS
// ============================================================

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

function json(data, status = 200, cacheSeconds = 0) {
  const headers = { 'Content-Type': 'application/json', ...CORS };
  if (cacheSeconds > 0) headers['Cache-Control'] = `private, max-age=${cacheSeconds}`;
  return new Response(JSON.stringify(data), { status, headers });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// ============================================================
// AUTH MIDDLEWARE
// ============================================================

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

// ============================================================
// DATABASE INITIALIZATION
// ============================================================

let dbInitialized = false;

async function initDB(db) {
  if (dbInitialized) return;

  const statements = [
    `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT DEFAULT '')`,
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT,
      google_id TEXT DEFAULT '',
      is_admin INTEGER DEFAULT 0,
      is_banned INTEGER DEFAULT 0,
      premium_until DATETIME,
      device_fingerprint TEXT DEFAULT '',
      created_ip TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS banned_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      device_fingerprint TEXT DEFAULT '',
      ip_address TEXT DEFAULT '',
      ban_type TEXT DEFAULT 'ban',
      banned_by INTEGER,
      banned_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
      marks_per_question REAL DEFAULT 1,
      allow_practice INTEGER DEFAULT 1,
      batch_id INTEGER REFERENCES batches(id) ON DELETE SET NULL,
      live_deadline_hours INTEGER DEFAULT 0,
      results_published INTEGER DEFAULT 0,
      publish_after_hours INTEGER DEFAULT 0,
      leaderboard_enabled INTEGER DEFAULT 1,
      is_closed INTEGER DEFAULT 0,
      scheduled_at DATETIME,
      has_sections INTEGER DEFAULT 0,
      section_config TEXT DEFAULT '',
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
      image_url TEXT,
      explanation TEXT DEFAULT '',
      section TEXT DEFAULT '',
      section_order INTEGER DEFAULT 1
    )`,
    `CREATE TABLE IF NOT EXISTS exam_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      exam_id INTEGER NOT NULL,
      score INTEGER DEFAULT 0,
      total_questions INTEGER DEFAULT 0,
      percentage REAL DEFAULT 0,
      answers TEXT,
      time_taken_seconds INTEGER DEFAULT 0,
      submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS exam_results_stored (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      exam_id INTEGER NOT NULL,
      score REAL DEFAULT 0,
      total_questions INTEGER DEFAULT 0,
      percentage REAL DEFAULT 0,
      answers TEXT,
      time_taken_seconds INTEGER DEFAULT 0,
      submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      attempt_number INTEGER DEFAULT 1,
      is_first_attempt INTEGER DEFAULT 1,
      is_practice INTEGER DEFAULT 0,
      selected_sections TEXT DEFAULT ''
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
    `CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      body TEXT DEFAULT '',
      image_url TEXT,
      link_url TEXT,
      created_by INTEGER NOT NULL REFERENCES users(id),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS notification_reads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      notification_id INTEGER NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id),
      read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(notification_id, user_id)
    )`,
    `CREATE TABLE IF NOT EXISTS exam_resources (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      exam_id INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      link TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS batch_resources (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      batch_id INTEGER NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      link TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE INDEX IF NOT EXISTS idx_results_user_exam ON exam_results_stored(user_id, exam_id, is_practice, is_first_attempt)`,
    `CREATE INDEX IF NOT EXISTS idx_premium_user ON premium_access(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_questions_exam ON questions(exam_id)`,
    `CREATE INDEX IF NOT EXISTS idx_users_fp ON users(device_fingerprint)`,
    `CREATE INDEX IF NOT EXISTS idx_users_ip ON users(created_ip)`
  ];

  for (const sql of statements) {
    try { await db.prepare(sql).run(); } catch (e) {}
  }

  // ALTER TABLE — individually guarded
  try { await db.prepare(`ALTER TABLE users ADD COLUMN device_fingerprint TEXT DEFAULT ''`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE users ADD COLUMN created_ip TEXT DEFAULT ''`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE users ADD COLUMN google_id TEXT DEFAULT ''`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE exams ADD COLUMN is_closed INTEGER DEFAULT 0`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE exams ADD COLUMN scheduled_at DATETIME`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE exams ADD COLUMN has_sections INTEGER DEFAULT 0`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE exams ADD COLUMN section_config TEXT DEFAULT ''`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE exams ADD COLUMN marks_per_question REAL DEFAULT 1`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE questions ADD COLUMN section TEXT DEFAULT ''`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE questions ADD COLUMN section_order INTEGER DEFAULT 1`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE exam_results_stored ADD COLUMN selected_sections TEXT DEFAULT ''`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE exam_attempts ADD COLUMN time_taken_seconds INTEGER DEFAULT 0`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE exam_results_stored ADD COLUMN time_taken_seconds INTEGER DEFAULT 0`).run(); } catch (e) {}

  // Section index after column exists
  try { await db.prepare(`CREATE INDEX IF NOT EXISTS idx_questions_section ON questions(exam_id, section)`).run(); } catch (e) {}

  const adminHash = await sha256('Admin@2024');
  const existing = await db.prepare('SELECT id FROM users WHERE email = ?').bind('admin@exalyte.com').first();
  if (!existing) {
    await db.prepare('INSERT INTO users (name, email, password, is_admin) VALUES (?, ?, ?, 1)')
      .bind('Administrator', 'admin@exalyte.com', adminHash).run();
  }

  dbInitialized = true;
}

// ============================================================
// PREMIUM ACCESS CHECK
// ============================================================

async function checkPremiumAccess(db, userId, examId, isAdmin) {
  if (isAdmin) return true;
  const exam = await db.prepare('SELECT is_premium, batch_id FROM exams WHERE id = ?').bind(examId).first();
  if (!exam || !exam.is_premium) return true;
  const now = new Date().toISOString();
  const user = await db.prepare('SELECT premium_until FROM users WHERE id = ?').bind(userId).first();
  if (user && user.premium_until && user.premium_until > now) return true;
  const examGrant = await db.prepare(`SELECT id FROM premium_access WHERE user_id = ? AND exam_id = ? AND (expires_at IS NULL OR expires_at > ?)`).bind(userId, examId, now).first();
  if (examGrant) return true;
  if (exam.batch_id) {
    const batchGrant = await db.prepare(`SELECT id FROM premium_access WHERE user_id = ? AND batch_id = ? AND (expires_at IS NULL OR expires_at > ?)`).bind(userId, exam.batch_id, now).first();
    if (batchGrant) return true;
  }
  return false;
}

function checkPremiumAccessFast(exam, isAdmin, hasAccountPremium, userPremiumExams, userPremiumBatches) {
  if (isAdmin) return true;
  if (!exam.is_premium) return true;
  if (hasAccountPremium) return true;
  if (userPremiumExams.has(exam.id)) return true;
  if (exam.batch_id && userPremiumBatches.has(exam.batch_id)) return true;
  return false;
}

// ============================================================
// LIVE STATUS HELPER
// ============================================================

function getLiveStatus(exam) {
  if (!exam.live_deadline_hours || exam.live_deadline_hours === 0) {
    return { is_live: false, live_ends_at: null, live_seconds_remaining: 0, live_ended: true, live_starts_at: null, is_scheduled: false, seconds_until_live: 0 };
  }
  const startTime = exam.scheduled_at ? new Date(exam.scheduled_at).getTime() : new Date(exam.created_at).getTime();
  const liveEnds = startTime + exam.live_deadline_hours * 3600000;
  const now = Date.now();
  const remaining = Math.max(0, Math.floor((liveEnds - now) / 1000));
  const secondsUntilLive = Math.max(0, Math.floor((startTime - now) / 1000));
  return {
    is_live: now >= startTime && now < liveEnds,
    live_ends_at: new Date(liveEnds).toISOString(),
    live_seconds_remaining: remaining,
    live_ended: now >= liveEnds,
    live_starts_at: new Date(startTime).toISOString(),
    is_scheduled: now < startTime,
    seconds_until_live: secondsUntilLive
  };
}

function isResultsPublished(exam) {
  if (!exam.live_deadline_hours || exam.live_deadline_hours === 0) return true;
  if (exam.results_published) return true;
  const startTime = exam.scheduled_at ? new Date(exam.scheduled_at).getTime() : new Date(exam.created_at).getTime();
  const liveEndsAt = startTime + exam.live_deadline_hours * 3600000;
  if (Date.now() >= liveEndsAt) return true;
  return false;
}

// ============================================================
// AUTH ROUTES
// ============================================================

async function handleSignup(request, db) {
  const { name, email, password, fingerprint } = await request.json();
  if (!name || !email || !password) return err('All fields required');
  if (password.length < 6) return err('Password must be at least 6 characters');
  const existing = await db.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
  if (existing) return err('Email already registered');
  const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
  const fp = fingerprint || clientIP;
  const countByIP = await db.prepare('SELECT COUNT(*) as count FROM users WHERE created_ip = ?').bind(clientIP).first();
  if ((countByIP?.count || 0) >= 2) return err('Maximum 2 accounts allowed per network.', 403);
  const hash = await sha256(password);
  const result = await db.prepare('INSERT INTO users (name, email, password, device_fingerprint, created_ip) VALUES (?, ?, ?, ?, ?) RETURNING id, name, email, is_admin').bind(name, email.toLowerCase(), hash, fp, clientIP).first();
  const token = await signJWT({ id: result.id, email: result.email, is_admin: result.is_admin });
  return json({ token, user: { id: result.id, name: result.name, email: result.email, is_admin: result.is_admin } });
}

async function handleLogin(request, db) {
  const { email, password } = await request.json();
  if (!email || !password) return err('Email and password required');
  const hash = await sha256(password);
  const user = await db.prepare('SELECT * FROM users WHERE email = ? AND password = ?').bind(email.toLowerCase(), hash).first();
  if (!user) return err('Invalid credentials', 401);
  if (user.is_banned) return err('Account suspended.', 403);
  if (user.is_admin) {
    const masterKeyRow = await db.prepare('SELECT value FROM settings WHERE key = ?').bind('master_key_hash').first();
    const hasMasterKey = masterKeyRow && masterKeyRow.value;
    if (hasMasterKey) {
      const tempToken = await signJWT({ id: user.id, email: user.email, is_admin: true, temp: true, exp: Math.floor(Date.now() / 1000) + 300 });
      return json({ requires_master_key: true, temp_token: tempToken, user: { id: user.id, name: user.name, email: user.email, is_admin: true } });
    } else {
      const tempToken = await signJWT({ id: user.id, email: user.email, is_admin: true, temp: true, setup_master: true, exp: Math.floor(Date.now() / 1000) + 300 });
      return json({ setup_master_key: true, temp_token: tempToken, user: { id: user.id, name: user.name, email: user.email, is_admin: true } });
    }
  }
  const token = await signJWT({ id: user.id, email: user.email, is_admin: user.is_admin });
  return json({ token, user: { id: user.id, name: user.name, email: user.email, is_admin: user.is_admin } });
}

// ============================================================
// MASTER KEY ROUTES
// ============================================================

async function handleMasterKeyStatus(db) {
  const row = await db.prepare('SELECT value FROM settings WHERE key = ?').bind('master_key_hash').first();
  return json({ exists: !!(row && row.value) });
}

async function handleMasterKeySet(request, db) {
  const { temp_token, master_key } = await request.json();
  if (!temp_token || !master_key) return err('Missing token or master key');
  if (master_key.length < 6) return err('Master key must be at least 6 characters');
  const payload = await verifyJWT(temp_token);
  if (!payload || !payload.setup_master || !payload.is_admin) return err('Invalid session', 401);
  const hash = await sha256(master_key);
  await db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').bind('master_key_hash', hash).run();
  const token = await signJWT({ id: payload.id, email: payload.email, is_admin: true });
  return json({ success: true, token });
}

async function handleMasterKeyVerify(request, db) {
  const { temp_token, master_key } = await request.json();
  if (!temp_token || !master_key) return err('Missing token or master key');
  const payload = await verifyJWT(temp_token);
  if (!payload || !payload.temp || !payload.is_admin) return err('Invalid session', 401);
  const row = await db.prepare('SELECT value FROM settings WHERE key = ?').bind('master_key_hash').first();
  if (!row || !row.value) return err('Master key not configured', 500);
  const hash = await sha256(master_key);
  if (hash !== row.value) return err('Incorrect master key', 403);
  const token = await signJWT({ id: payload.id, email: payload.email, is_admin: true });
  return json({ success: true, token });
}

// ============================================================
// BATCH ROUTES
// ============================================================

async function handleListBatches(db) {
  const rows = await db.prepare(`SELECT b.*, COUNT(DISTINCT e.id) as exam_count FROM batches b LEFT JOIN exams e ON e.batch_id = b.id GROUP BY b.id ORDER BY b.created_at DESC`).all();
  return json(rows.results, 200, 30);
}

async function handleCreateBatch(request, db) {
  const { name, description } = await request.json();
  if (!name) return err('Name required');
  const r = await db.prepare('INSERT INTO batches (name, description) VALUES (?, ?) RETURNING *').bind(name, description || '').first();
  return json(r, 201);
}

async function handleUpdateBatch(batchId, request, db) {
  const { name, description } = await request.json();
  await db.prepare('UPDATE batches SET name = ?, description = ? WHERE id = ?').bind(name, description || '', batchId).run();
  const r = await db.prepare('SELECT * FROM batches WHERE id = ?').bind(batchId).first();
  return json(r);
}

async function handleDeleteBatch(batchId, db) {
  await db.prepare('UPDATE exams SET batch_id = NULL WHERE batch_id = ?').bind(batchId).run();
  await db.prepare('DELETE FROM batch_resources WHERE batch_id = ?').bind(batchId).run();
  await db.prepare('DELETE FROM batches WHERE id = ?').bind(batchId).run();
  return json({ success: true });
}

// ============================================================
// BATCH/EXAM RESOURCES
// ============================================================

async function handleGetBatchResources(batchId, db) {
  const resources = await db.prepare('SELECT id, title, link FROM batch_resources WHERE batch_id = ?').bind(batchId).all();
  return json(resources.results, 200, 30);
}

async function handleAddBatchResource(request, db) {
  const { batch_id, title, link } = await request.json();
  if (!batch_id || !title || !link) return err('Required fields missing');
  const result = await db.prepare('INSERT INTO batch_resources (batch_id, title, link) VALUES (?, ?, ?) RETURNING id').bind(batch_id, title, link).first();
  return json({ id: result.id }, 201);
}

async function handleDeleteBatchResource(resourceId, db) {
  await db.prepare('DELETE FROM batch_resources WHERE id = ?').bind(resourceId).run();
  return json({ success: true });
}

async function handleGetExamResources(examId, db) {
  const resources = await db.prepare('SELECT id, title, link FROM exam_resources WHERE exam_id = ?').bind(examId).all();
  return json(resources.results, 200, 30);
}

async function handleAddExamResource(request, db) {
  const { exam_id, title, link } = await request.json();
  if (!exam_id || !title || !link) return err('Required fields missing');
  const result = await db.prepare('INSERT INTO exam_resources (exam_id, title, link) VALUES (?, ?, ?) RETURNING id').bind(exam_id, title, link).first();
  return json({ id: result.id }, 201);
}

async function handleDeleteExamResource(resourceId, db) {
  await db.prepare('DELETE FROM exam_resources WHERE id = ?').bind(resourceId).run();
  return json({ success: true });
}

// ============================================================
// EXAMS ROUTES
// ============================================================

async function handleListExams(request, db) {
  const user = await requireAuth(request);
  const userId = user ? user.id : null;
  const isAdmin = user ? user.is_admin : false;
  const exams = await db.prepare(`SELECT e.*, b.name as batch_name, (SELECT COUNT(*) FROM questions q WHERE q.exam_id = e.id) as question_count FROM exams e LEFT JOIN batches b ON e.batch_id = b.id ORDER BY e.created_at DESC`).all();
  let userAttemptsMap = {};
  if (userId) {
    const attempts = await db.prepare('SELECT * FROM exam_results_stored WHERE user_id = ? AND is_practice = 0 AND is_first_attempt = 1').bind(userId).all();
    for (const a of attempts.results) userAttemptsMap[a.exam_id] = a;
  }
  const result = [];
  for (const exam of exams.results) {
    const live = getLiveStatus(exam);
    let stored_attempt = null, can_practice = false, results_visible = false;
    if (userId) {
      stored_attempt = userAttemptsMap[exam.id] || null;
      if (exam.allow_practice && !exam.is_closed) {
        if (exam.live_deadline_hours > 0) can_practice = live.live_ended;
        else can_practice = !!stored_attempt;
      }
      if (exam.live_deadline_hours > 0 && live.is_live) results_visible = false;
      else results_visible = isResultsPublished(exam);
    }
    result.push({ ...exam, ...live, stored_attempt, can_practice, results_visible, batch_id: exam.batch_id, batch_name: exam.batch_name });
  }
  return json({ exams: result }, 200, 15);
}

// ============================================================
// GET EXAM QUESTIONS — BOTH GET AND POST + SECTION VALIDATION
// ============================================================

async function handleGetExamQuestions(examId, request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  const exam = await db.prepare('SELECT * FROM exams WHERE id = ?').bind(examId).first();
  if (!exam) return err('Exam not found', 404);
  if (exam.is_closed && !user.is_admin) return err('This exam is currently closed.', 403);
  const url = new URL(request.url);
  const isPractice = url.searchParams.get('practice') === '1';
  const accessible = await checkPremiumAccess(db, user.id, examId, user.is_admin);
  if (!accessible) return err('Premium access required', 403);

  let selectedSections = [];
  if (request.method === 'POST') {
    try { const body = await request.json(); selectedSections = body.sections || []; } catch (e) {}
  }

  // Section validation for REAL exams (not practice)
  if (exam.has_sections && exam.section_config && !isPractice) {
    const config = JSON.parse(exam.section_config);
    const compulsoryGroup = config.compulsory_group || [];
    const normalGroup = config.normal_group || [];
    const selectedCompulsory = compulsoryGroup.filter(s => selectedSections.includes(s.name));
    const selectedNormal = normalGroup.filter(s => selectedSections.includes(s.name));
    const totalOptional = selectedCompulsory.length + selectedNormal.length;
    const maxOptional = config.max_optional || 2;
    const minCompulsory = config.min_from_compulsory || 1;

    if (totalOptional !== maxOptional) return err(`Select exactly ${maxOptional} optional sections.`, 400);
    if (selectedCompulsory.length < minCompulsory) return err(`Select at least ${minCompulsory} from compulsory group.`, 400);
    if (selectedCompulsory.length === maxOptional && selectedNormal.length > 0) return err('Cannot select normal sections when both compulsory sections selected.', 400);
  }

  let questions;
  if (exam.has_sections && selectedSections.length > 0) {
    const placeholders = selectedSections.map(() => '?').join(',');
    questions = await db.prepare(`SELECT id, exam_id, question_text, option_a, option_b, option_c, option_d, image_url, explanation, section, section_order FROM questions WHERE exam_id = ? AND section IN (${placeholders}) ORDER BY section_order, id`).bind(examId, ...selectedSections).all();
  } else {
    questions = await db.prepare('SELECT id, exam_id, question_text, option_a, option_b, option_c, option_d, image_url, explanation, section, section_order FROM questions WHERE exam_id = ?').bind(examId).all();
  }

  const examRes = await db.prepare('SELECT id, title, link FROM exam_resources WHERE exam_id = ?').bind(examId).all();
  return json({ exam, questions: questions.results, exam_resources: examRes.results, selected_sections: selectedSections, section_config: exam.has_sections ? JSON.parse(exam.section_config) : null });
}

// ============================================================
// SUBMIT EXAM — NORMAL GRADING + MARKS PER QUESTION + PRACTICE NO STORAGE
// ============================================================

async function handleSubmitExam(examId, request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  const { answers, is_practice, time_taken_seconds, selected_sections } = await request.json();
  const exam = await db.prepare('SELECT * FROM exams WHERE id = ?').bind(examId).first();
  if (!exam) return err('Exam not found', 404);
  if (exam.is_closed && !user.is_admin) return err('This exam is currently closed.', 403);
  const accessible = await checkPremiumAccess(db, user.id, examId, user.is_admin);
  if (!accessible) return err('Premium access required', 403);

  let questions;
  if (exam.has_sections && selected_sections && selected_sections.length > 0) {
    const placeholders = selected_sections.map(() => '?').join(',');
    questions = await db.prepare(`SELECT * FROM questions WHERE exam_id = ? AND section IN (${placeholders})`).bind(examId, ...selected_sections).all();
  } else {
    questions = await db.prepare('SELECT * FROM questions WHERE exam_id = ?').bind(examId).all();
  }

  const marksPerQ = exam.marks_per_question || 1;
  const nm = exam.negative_marking || 0;
  let score = 0, correctCount = 0, wrongCount = 0, skippedCount = 0;
  const total = questions.results.length;
  const detailedAnswers = {};

  for (const q of questions.results) {
    const rawGiven = answers[q.id] || answers[String(q.id)] || '';
    const given = rawGiven.toString().trim().toUpperCase();
    const correct = (q.correct_answer || '').toString().trim().toUpperCase();
    const isCorrect = given === correct;
    if (!given) skippedCount++;
    else if (isCorrect) { correctCount++; score += marksPerQ; }
    else { wrongCount++; if (nm > 0) score -= nm; }
    detailedAnswers[q.id] = { given, correct, isCorrect };
  }

  const maxScore = total * marksPerQ;
  const percentage = maxScore > 0 ? Math.round((Math.max(0, score) / maxScore) * 10000) / 100 : 0;
  const timeTaken = time_taken_seconds || 0;

  // PRACTICE: Return result WITHOUT storing
  if (is_practice) {
    return json({
      attemptId: 0,
      score: Math.max(0, score),
      total,
      max_score: maxScore,
      percentage,
      correct: correctCount,
      wrong: wrongCount,
      skipped: skippedCount,
      detailed: detailedAnswers,
      time_taken_seconds: timeTaken,
      is_practice: true
    });
  }

  // REAL EXAM: Store and return
  const existingFirst = await db.prepare('SELECT id FROM exam_results_stored WHERE user_id = ? AND exam_id = ? AND is_practice = 0 AND is_first_attempt = 1').bind(user.id, examId).first();
  if (existingFirst) return err('You have already taken this exam.', 403);

  const r1 = await db.prepare(`INSERT INTO exam_results_stored (user_id, exam_id, score, total_questions, percentage, answers, is_practice, is_first_attempt, time_taken_seconds, selected_sections) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`).bind(user.id, examId, Math.max(0, score), total, percentage, JSON.stringify(detailedAnswers), 0, 1, timeTaken, JSON.stringify(selected_sections || [])).first();

  await db.prepare(`INSERT INTO exam_attempts (user_id, exam_id, score, total_questions, percentage, answers, time_taken_seconds) VALUES (?, ?, ?, ?, ?, ?, ?)`).bind(user.id, examId, Math.max(0, score), total, percentage, JSON.stringify(detailedAnswers), timeTaken).run();

  return json({
    attemptId: r1.id,
    score: Math.max(0, score),
    total,
    max_score: maxScore,
    percentage,
    correct: correctCount,
    wrong: wrongCount,
    skipped: skippedCount,
    detailed: detailedAnswers,
    time_taken_seconds: timeTaken
  });
}

// ============================================================
// GET RESULT
// ============================================================

async function handleGetResult(examId, attemptId, request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  const exam = await db.prepare('SELECT * FROM exams WHERE id = ?').bind(examId).first();
  if (!exam) return err('Exam not found', 404);
  const live = getLiveStatus(exam);
  if (exam.live_deadline_hours > 0 && live.is_live) return json({ pending: true, message: 'Results available after live window ends.' });
  if (!isResultsPublished(exam)) return json({ pending: true, message: 'Results available after publication.' });
  if (attemptId == 0 || !attemptId) {
    const questions = await db.prepare('SELECT * FROM questions WHERE exam_id = ?').bind(examId).all();
    return json({ attempt: { id: 0, score: 0, total_questions: questions.results.length, percentage: 0, answers: '{}', is_practice: 1 }, questions: questions.results, exam, results_published: true });
  }
  const attempt = await db.prepare('SELECT * FROM exam_results_stored WHERE id = ? AND user_id = ? AND exam_id = ?').bind(attemptId, user.id, examId).first();
  if (!attempt) return err('Result not found', 404);
  const questions = await db.prepare('SELECT * FROM questions WHERE exam_id = ?').bind(examId).all();
  return json({ attempt: { ...attempt, answers: JSON.parse(attempt.answers || '{}') }, questions: questions.results, exam, results_published: true });
}

// ============================================================
// LEADERBOARD
// ============================================================

async function handleLeaderboard(examId, request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  const exam = await db.prepare('SELECT * FROM exams WHERE id = ?').bind(examId).first();
  if (!exam) return err('Exam not found', 404);
  if (!exam.leaderboard_enabled) return json({ disabled: true });
  if (exam.live_deadline_hours > 0 && getLiveStatus(exam).is_live) return json({ disabled: true, pending: true });
  const row = await db.prepare(`SELECT rank, total_participants, percentage, score FROM (SELECT user_id, score, percentage, ROW_NUMBER() OVER (ORDER BY percentage DESC, submitted_at ASC) as rank, COUNT(*) OVER () as total_participants FROM exam_results_stored WHERE exam_id = ? AND is_first_attempt = 1 AND is_practice = 0) WHERE user_id = ?`).bind(examId, user.id).first();
  if (!row) return json({ rank: null, total_participants: 0, percentile: null });
  const percentile = row.total_participants > 1 ? Math.round((1 - (row.rank - 1) / row.total_participants) * 100) : 100;
  return json({ ...row, percentile, disabled: false });
}

// ============================================================
// HISTORY
// ============================================================

async function handleHistory(request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  const rows = await db.prepare(`SELECT ers.*, e.name as exam_name FROM exam_results_stored ers JOIN exams e ON ers.exam_id = e.id WHERE ers.user_id = ? AND ers.is_first_attempt = 1 AND ers.is_practice = 0 ORDER BY ers.submitted_at DESC`).bind(user.id).all();
  return json(rows.results, 200, 5);
}

// ============================================================
// NOTIFICATIONS
// ============================================================

async function handleListNotifications(request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  const notifications = await db.prepare(`SELECT n.*, u.name as creator_name, CASE WHEN nr.id IS NOT NULL THEN 1 ELSE 0 END as is_read FROM notifications n JOIN users u ON n.created_by = u.id LEFT JOIN notification_reads nr ON n.id = nr.notification_id AND nr.user_id = ? ORDER BY n.created_at DESC`).bind(user.id).all();
  const unreadCount = await db.prepare('SELECT COUNT(*) as count FROM notifications n WHERE n.id NOT IN (SELECT notification_id FROM notification_reads WHERE user_id = ?)').bind(user.id).first();
  return json({ notifications: notifications.results, unread_count: unreadCount.count }, 200, 10);
}

async function handleMarkNotificationRead(notifId, request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  await db.prepare('INSERT OR IGNORE INTO notification_reads (notification_id, user_id) VALUES (?, ?)').bind(notifId, user.id).run();
  return json({ success: true });
}

// ============================================================
// ADMIN ROUTES
// ============================================================

async function handleAdminCreateExam(request, db) {
  const body = await request.json();
  if (!body.name) return err('Name required');
  const r = await db.prepare(`INSERT INTO exams (name, description, time_limit, is_premium, negative_marking, marks_per_question, allow_practice, batch_id, live_deadline_hours, results_published, publish_after_hours, leaderboard_enabled, scheduled_at, has_sections, section_config) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`)
    .bind(body.name, body.description || '', body.time_limit || 30, body.is_premium ? 1 : 0, body.negative_marking || 0, body.marks_per_question || 1, body.allow_practice !== false ? 1 : 0, body.batch_id || null, body.live_deadline_hours || 0, body.results_published ? 1 : 0, body.publish_after_hours || 0, body.leaderboard_enabled !== false ? 1 : 0, body.scheduled_at || null, body.has_sections ? 1 : 0, body.section_config || '').first();
  return json(r, 201);
}

async function handleAdminUpdateExam(examId, request, db) {
  const body = await request.json();
  await db.prepare(`UPDATE exams SET name = ?, description = ?, time_limit = ?, is_premium = ?, negative_marking = ?, marks_per_question = ?, allow_practice = ?, batch_id = ?, live_deadline_hours = ?, results_published = ?, publish_after_hours = ?, leaderboard_enabled = ?, scheduled_at = ?, has_sections = ?, section_config = ? WHERE id = ?`)
    .bind(body.name, body.description || '', body.time_limit || 30, body.is_premium ? 1 : 0, body.negative_marking || 0, body.marks_per_question || 1, body.allow_practice !== false ? 1 : 0, body.batch_id || null, body.live_deadline_hours || 0, body.results_published ? 1 : 0, body.publish_after_hours || 0, body.leaderboard_enabled !== false ? 1 : 0, body.scheduled_at || null, body.has_sections ? 1 : 0, body.section_config || '', examId).run();
  const r = await db.prepare('SELECT * FROM exams WHERE id = ?').bind(examId).first();
  return json(r);
}

async function handleAdminDeleteExam(examId, db) {
  await db.prepare('DELETE FROM exam_results_stored WHERE exam_id = ?').bind(examId).run();
  await db.prepare('DELETE FROM exam_attempts WHERE exam_id = ?').bind(examId).run();
  await db.prepare('DELETE FROM questions WHERE exam_id = ?').bind(examId).run();
  await db.prepare('DELETE FROM exam_resources WHERE exam_id = ?').bind(examId).run();
  await db.prepare('DELETE FROM exams WHERE id = ?').bind(examId).run();
  return json({ success: true });
}

async function handleAdminGetQuestions(examId, db) {
  const qs = await db.prepare('SELECT * FROM questions WHERE exam_id = ? ORDER BY section_order, id').bind(examId).all();
  return json(qs.results, 200, 10);
}

async function handleAdminDeleteAllQuestions(examId, db) {
  await db.prepare('DELETE FROM questions WHERE exam_id = ?').bind(examId).run();
  return json({ success: true });
}

async function handleAdminDeleteQuestion(qId, db) {
  await db.prepare('DELETE FROM questions WHERE id = ?').bind(qId).run();
  return json({ success: true });
}

async function handleAdminBulkQuestions(request, db) {
  const { exam_id, questions, section } = await request.json();
  if (!exam_id || !questions || !Array.isArray(questions) || !questions.length) return err('Invalid input');
  let count = 0;
  for (const q of questions) {
    const qt = q.question || q.question_text || '';
    const a = q.option_a || q.a || '';
    const b = q.option_b || q.b || '';
    const c = q.option_c || q.c || '';
    const d = q.option_d || q.d || '';
    const ans = (q.answer || q.correct_answer || '').toUpperCase();
    const img = q.image_url || q.image || null;
    const exp = q.explanation || '';
    const sec = q.section || section || '';
    if (!qt || !a || !b || !c || !d || !['A','B','C','D'].includes(ans)) continue;
    await db.prepare('INSERT INTO questions (exam_id, question_text, option_a, option_b, option_c, option_d, correct_answer, image_url, explanation, section) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(exam_id, qt, a, b, c, d, ans, img, exp, sec).run();
    count++;
  }
  return json({ inserted: count });
}

async function handleAdminListUsers(db) {
  const users = await db.prepare('SELECT id, name, email, is_admin, is_banned, premium_until, created_at FROM users ORDER BY created_at DESC').all();
  return json(users.results, 200, 15);
}

async function handleAdminGrantPremium(request, db, adminId) {
  const { user_id, grant_scope, exam_id, batch_id, duration_hours } = await request.json();
  const expires_at = duration_hours ? new Date(Date.now() + duration_hours * 3600000).toISOString() : null;
  if (grant_scope === 'account') {
    await db.prepare('UPDATE users SET premium_until = ? WHERE id = ?').bind(expires_at, user_id).run();
  } else if (grant_scope === 'batch') {
    await db.prepare('INSERT OR REPLACE INTO premium_access (user_id, batch_id, grant_scope, granted_by, expires_at) VALUES (?, ?, ?, ?, ?)').bind(user_id, batch_id, 'batch', adminId, expires_at).run();
  } else {
    await db.prepare('INSERT OR REPLACE INTO premium_access (user_id, exam_id, grant_scope, granted_by, expires_at) VALUES (?, ?, ?, ?, ?)').bind(user_id, exam_id, 'exam', adminId, expires_at).run();
  }
  return json({ success: true });
}

async function handleAdminRevokePremium(request, db) {
  const { user_id, exam_id, batch_id } = await request.json();
  if (batch_id) await db.prepare('DELETE FROM premium_access WHERE user_id = ? AND batch_id = ?').bind(user_id, batch_id).run();
  else if (exam_id) await db.prepare('DELETE FROM premium_access WHERE user_id = ? AND exam_id = ?').bind(user_id, exam_id).run();
  else await db.prepare('DELETE FROM premium_access WHERE user_id = ?').bind(user_id).run();
  return json({ success: true });
}

async function handleAdminRevokeAccountPremium(request, db) {
  const { user_id } = await request.json();
  await db.prepare('UPDATE users SET premium_until = NULL WHERE id = ?').bind(user_id).run();
  return json({ success: true });
}

async function handleAdminBanUser(userId, request, db, adminId) {
  await db.prepare('UPDATE users SET is_banned = 1 WHERE id = ?').bind(userId).run();
  return json({ success: true });
}

async function handleAdminUnbanUser(userId, request, db) {
  await db.prepare('UPDATE users SET is_banned = 0 WHERE id = ?').bind(userId).run();
  return json({ success: true });
}

async function handleAdminDeleteUser(userId, request, db, adminId) {
  await db.prepare('DELETE FROM exam_results_stored WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM exam_attempts WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM premium_access WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();
  return json({ success: true });
}

async function handleAdminToggleExam(examId, request, db) {
  const { is_closed } = await request.json();
  await db.prepare('UPDATE exams SET is_closed = ? WHERE id = ?').bind(is_closed ? 1 : 0, examId).run();
  return json({ success: true });
}

async function handleAdminResults(examId, db) {
  const query = examId
    ? `SELECT ers.*, u.name as user_name, u.email as user_email, e.name as exam_name, ROW_NUMBER() OVER (ORDER BY ers.percentage DESC) as rank FROM exam_results_stored ers JOIN users u ON ers.user_id = u.id JOIN exams e ON ers.exam_id = e.id WHERE ers.exam_id = ? AND ers.is_first_attempt = 1 AND ers.is_practice = 0`
    : `SELECT ers.*, u.name as user_name, u.email as user_email, e.name as exam_name, ROW_NUMBER() OVER (ORDER BY ers.percentage DESC) as rank FROM exam_results_stored ers JOIN users u ON ers.user_id = u.id JOIN exams e ON ers.exam_id = e.id WHERE ers.is_first_attempt = 1 AND ers.is_practice = 0`;
  const rows = examId ? await db.prepare(query).bind(examId).all() : await db.prepare(query).all();
  return json(rows.results, 200, 10);
}

async function handleAdminDownloadResults(examId, db) {
  const rows = await db.prepare(`SELECT u.name as user_name, u.email as user_email, e.name as exam_name, ers.score, ers.total_questions, ers.percentage, ers.submitted_at FROM exam_results_stored ers JOIN users u ON ers.user_id = u.id JOIN exams e ON ers.exam_id = e.id WHERE ers.exam_id = ? AND ers.is_first_attempt = 1 AND ers.is_practice = 0 ORDER BY ers.percentage DESC`).bind(examId).all();
  const results = rows.results;
  if (!results.length) return err('No results found', 404);
  let txt = 'Exam: '+results[0].exam_name+'\n\n';
  txt += 'Rank,Name,Email,Score,Percentage,Date\n';
  results.forEach((r, i) => { txt += (i+1)+','+r.user_name+','+r.email+','+r.score+'/'+r.total_questions+','+(r.percentage||0).toFixed(1)+'%,'+r.submitted_at+'\n'; });
  return new Response(txt, { status: 200, headers: { 'Content-Type': 'text/plain', 'Content-Disposition': 'attachment; filename="results.txt"', ...CORS } });
}

async function handleAdminDeleteResult(resultId, db) {
  await db.prepare('DELETE FROM exam_results_stored WHERE id = ?').bind(resultId).run();
  return json({ success: true });
}

async function handleAdminCreateNotification(request, db, adminId) {
  const { title, body, image_url, link_url } = await request.json();
  if (!title) return err('Title required');
  const r = await db.prepare('INSERT INTO notifications (title, body, image_url, link_url, created_by) VALUES (?, ?, ?, ?, ?) RETURNING *').bind(title, body || '', image_url || null, link_url || null, adminId).first();
  return json(r, 201);
}

async function handleAdminListNotifications(db) {
  const rows = await db.prepare('SELECT n.*, u.name as creator_name FROM notifications n JOIN users u ON n.created_by = u.id ORDER BY n.created_at DESC').all();
  return json(rows.results, 200, 10);
}

async function handleAdminDeleteNotification(notifId, db) {
  await db.prepare('DELETE FROM notification_reads WHERE notification_id = ?').bind(notifId).run();
  await db.prepare('DELETE FROM notifications WHERE id = ?').bind(notifId).run();
  return json({ success: true });
}

async function handleAdminPublishResults(examId, db) {
  await db.prepare('UPDATE exams SET results_published = 1 WHERE id = ?').bind(examId).run();
  return json({ success: true });
}

// ============================================================
// MAIN ROUTER
// ============================================================

export async function onRequest(context) {
  const { request, env } = context;
  const db = env.DB;
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  
  try { await initDB(db); } catch (e) { return err('Database init failed: ' + (e.message || 'unknown'), 500); }
  
  const url = new URL(request.url);
  let path = url.pathname.replace(/^\/api/, '').replace(/\/$/, '') || '/';
  const method = request.method;
  
  try {
    // AUTH
    if (path === '/auth/signup' && method === 'POST') return handleSignup(request, db);
    if (path === '/auth/login' && method === 'POST') return handleLogin(request, db);
    if (path === '/auth/master-key/status' && method === 'POST') return handleMasterKeyStatus(db);
    if (path === '/auth/master-key/set' && method === 'POST') return handleMasterKeySet(request, db);
    if (path === '/auth/master-key/verify' && method === 'POST') return handleMasterKeyVerify(request, db);
    
    // PUBLIC
    if (path === '/batches' && method === 'GET') return handleListBatches(db);
    if (path === '/exams' && method === 'GET') return handleListExams(request, db);
    
    // USER
    if (path === '/history' && method === 'GET') return handleHistory(request, db);
    
    // QUESTIONS — GET + POST
    const examQuestions = path.match(/^\/exams\/(\d+)\/questions$/);
    if (examQuestions && (method === 'GET' || method === 'POST')) return handleGetExamQuestions(examQuestions[1], request, db);
    
    const examSubmit = path.match(/^\/exams\/(\d+)\/submit$/);
    if (examSubmit && method === 'POST') return handleSubmitExam(examSubmit[1], request, db);
    
    const examResult = path.match(/^\/exams\/(\d+)\/result\/(\d+)$/);
    if (examResult && method === 'GET') return handleGetResult(examResult[1], examResult[2], request, db);
    
    const leaderboard = path.match(/^\/leaderboard\/(\d+)$/);
    if (leaderboard && method === 'GET') return handleLeaderboard(leaderboard[1], request, db);
    
    if (path === '/notifications' && method === 'GET') return handleListNotifications(request, db);
    const markRead = path.match(/^\/notifications\/(\d+)\/read$/);
    if (markRead && method === 'POST') return handleMarkNotificationRead(markRead[1], request, db);
    
    // ADMIN
    const admin = await requireAdmin(request, db);
    
    if (path === '/admin/batches' && method === 'POST') { if (!admin) return err('Admin required', 403); return handleCreateBatch(request, db); }
    const adminBatch = path.match(/^\/admin\/batches\/(\d+)$/);
    if (adminBatch && method === 'PUT') { if (!admin) return err('Admin required', 403); return handleUpdateBatch(adminBatch[1], request, db); }
    if (adminBatch && method === 'DELETE') { if (!admin) return err('Admin required', 403); return handleDeleteBatch(adminBatch[1], db); }
    
    const adminBatchResources = path.match(/^\/admin\/batches\/(\d+)\/resources$/);
    if (adminBatchResources && method === 'GET') { if (!admin) return err('Admin required', 403); return handleGetBatchResources(adminBatchResources[1], db); }
    if (path === '/admin/batch-resources' && method === 'POST') { if (!admin) return err('Admin required', 403); return handleAddBatchResource(request, db); }
    const adminBatchResource = path.match(/^\/admin\/batch-resources\/(\d+)$/);
    if (adminBatchResource && method === 'DELETE') { if (!admin) return err('Admin required', 403); return handleDeleteBatchResource(adminBatchResource[1], db); }
    
    const adminExamResources = path.match(/^\/admin\/exams\/(\d+)\/resources$/);
    if (adminExamResources && method === 'GET') { if (!admin) return err('Admin required', 403); return handleGetExamResources(adminExamResources[1], db); }
    if (path === '/admin/resources' && method === 'POST') { if (!admin) return err('Admin required', 403); return handleAddExamResource(request, db); }
    const adminExamResource = path.match(/^\/admin\/resources\/(\d+)$/);
    if (adminExamResource && method === 'DELETE') { if (!admin) return err('Admin required', 403); return handleDeleteExamResource(adminExamResource[1], db); }
    
    if (path === '/admin/exams' && method === 'POST') { if (!admin) return err('Admin required', 403); return handleAdminCreateExam(request, db); }
    const adminExam = path.match(/^\/admin\/exams\/(\d+)$/);
    if (adminExam && method === 'PUT') { if (!admin) return err('Admin required', 403); return handleAdminUpdateExam(adminExam[1], request, db); }
    if (adminExam && method === 'DELETE') { if (!admin) return err('Admin required', 403); return handleAdminDeleteExam(adminExam[1], db); }
    
    const adminToggle = path.match(/^\/admin\/exams\/(\d+)\/toggle$/);
    if (adminToggle && method === 'POST') { if (!admin) return err('Admin required', 403); return handleAdminToggleExam(adminToggle[1], request, db); }
    
    const adminDownload = path.match(/^\/admin\/results\/(\d+)\/download$/);
    if (adminDownload && method === 'GET') { if (!admin) return err('Admin required', 403); return handleAdminDownloadResults(adminDownload[1], db); }
    
    if (path === '/admin/questions/bulk' && method === 'POST') { if (!admin) return err('Admin required', 403); return handleAdminBulkQuestions(request, db); }
    const adminQs = path.match(/^\/admin\/questions\/(\d+)$/);
    if (adminQs && method === 'GET') { if (!admin) return err('Admin required', 403); return handleAdminGetQuestions(adminQs[1], db); }
    if (adminQs && method === 'DELETE') { if (!admin) return err('Admin required', 403); return handleAdminDeleteAllQuestions(adminQs[1], db); }
    
    if (path === '/admin/users' && method === 'GET') { if (!admin) return err('Admin required', 403); return handleAdminListUsers(db); }
    if (path === '/admin/grant-premium' && method === 'POST') { if (!admin) return err('Admin required', 403); return handleAdminGrantPremium(request, db, admin.id); }
    if (path === '/admin/revoke-premium' && method === 'DELETE') { if (!admin) return err('Admin required', 403); return handleAdminRevokePremium(request, db); }
    if (path === '/admin/revoke-account-premium' && method === 'DELETE') { if (!admin) return err('Admin required', 403); return handleAdminRevokeAccountPremium(request, db); }
    
    const adminBan = path.match(/^\/admin\/users\/(\d+)\/ban$/);
    if (adminBan && method === 'POST') { if (!admin) return err('Admin required', 403); return handleAdminBanUser(adminBan[1], request, db, admin.id); }
    const adminUnban = path.match(/^\/admin\/users\/(\d+)\/unban$/);
    if (adminUnban && method === 'POST') { if (!admin) return err('Admin required', 403); return handleAdminUnbanUser(adminUnban[1], request, db); }
    const adminDelUser = path.match(/^\/admin\/users\/(\d+)\/delete$/);
    if (adminDelUser && method === 'DELETE') { if (!admin) return err('Admin required', 403); return handleAdminDeleteUser(adminDelUser[1], request, db, admin.id); }
    
    if (path === '/admin/results' && method === 'GET') { if (!admin) return err('Admin required', 403); return handleAdminResults(null, db); }
    const adminResults = path.match(/^\/admin\/results\/(\d+)$/);
    if (adminResults && method === 'GET') { if (!admin) return err('Admin required', 403); return handleAdminResults(adminResults[1], db); }
    if (adminResults && method === 'DELETE') { if (!admin) return err('Admin required', 403); return handleAdminDeleteResult(adminResults[1], db); }
    
    if (path === '/admin/notifications' && method === 'POST') { if (!admin) return err('Admin required', 403); return handleAdminCreateNotification(request, db, admin.id); }
    if (path === '/admin/notifications' && method === 'GET') { if (!admin) return err('Admin required', 403); return handleAdminListNotifications(db); }
    const adminNotif = path.match(/^\/admin\/notifications\/(\d+)$/);
    if (adminNotif && method === 'DELETE') { if (!admin) return err('Admin required', 403); return handleAdminDeleteNotification(adminNotif[1], db); }
    
    const adminPublish = path.match(/^\/admin\/exams\/(\d+)\/publish$/);
    if (adminPublish && method === 'POST') { if (!admin) return err('Admin required', 403); return handleAdminPublishResults(adminPublish[1], db); }
    
    return err('Not found', 404);
  } catch (e) {
    return err('Server error: ' + (e.message || 'unknown'), 500);
  }
}
