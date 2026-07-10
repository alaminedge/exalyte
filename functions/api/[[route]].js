// Exalyte API — Complete Backend for Cloudflare Pages
// functions/api/[[route]].js

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

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...CORS } });
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

async function initDB(db) {
  const statements = [
    `CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT DEFAULT ''
    )`,
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
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
      allow_practice INTEGER DEFAULT 1,
      batch_id INTEGER REFERENCES batches(id) ON DELETE SET NULL,
      live_deadline_hours INTEGER DEFAULT 0,
      results_published INTEGER DEFAULT 0,
      publish_after_hours INTEGER DEFAULT 0,
      leaderboard_enabled INTEGER DEFAULT 1,
      is_closed INTEGER DEFAULT 0,
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
      explanation TEXT DEFAULT ''
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
      score INTEGER DEFAULT 0,
      total_questions INTEGER DEFAULT 0,
      percentage REAL DEFAULT 0,
      answers TEXT,
      time_taken_seconds INTEGER DEFAULT 0,
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
    )`
  ];

  for (const sql of statements) {
    await db.prepare(sql).run();
  }

  try { await db.prepare(`ALTER TABLE users ADD COLUMN device_fingerprint TEXT DEFAULT ''`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE users ADD COLUMN created_ip TEXT DEFAULT ''`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE exams ADD COLUMN is_closed INTEGER DEFAULT 0`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE exam_attempts ADD COLUMN time_taken_seconds INTEGER DEFAULT 0`).run(); } catch (e) {}
  try { await db.prepare(`ALTER TABLE exam_results_stored ADD COLUMN time_taken_seconds INTEGER DEFAULT 0`).run(); } catch (e) {}

  const adminHash = await sha256('Admin@2024');
  const existing = await db.prepare('SELECT id FROM users WHERE email = ?').bind('admin@exalyte.com').first();
  if (!existing) {
    await db.prepare('INSERT INTO users (name, email, password, is_admin) VALUES (?, ?, ?, 1)')
      .bind('Administrator', 'admin@exalyte.com', adminHash).run();
  }
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
  
  const examGrant = await db.prepare(
    `SELECT id FROM premium_access WHERE user_id = ? AND exam_id = ? AND (expires_at IS NULL OR expires_at > ?)`
  ).bind(userId, examId, now).first();
  if (examGrant) return true;
  
  if (exam.batch_id) {
    const batchGrant = await db.prepare(
      `SELECT id FROM premium_access WHERE user_id = ? AND batch_id = ? AND (expires_at IS NULL OR expires_at > ?)`
    ).bind(userId, exam.batch_id, now).first();
    if (batchGrant) return true;
  }
  
  return false;
}

// ============================================================
// LIVE STATUS HELPER
// ============================================================

function getLiveStatus(exam) {
  if (!exam.live_deadline_hours || exam.live_deadline_hours === 0) {
    return { is_live: false, live_ends_at: null, live_seconds_remaining: 0, live_ended: true };
  }
  const created = new Date(exam.created_at).getTime();
  const liveEnds = created + exam.live_deadline_hours * 3600000;
  const now = Date.now();
  const remaining = Math.max(0, Math.floor((liveEnds - now) / 1000));
  return {
    is_live: now < liveEnds,
    live_ends_at: new Date(liveEnds).toISOString(),
    live_seconds_remaining: remaining,
    live_ended: now >= liveEnds
  };
}

function isResultsPublished(exam) {
  if (!exam.live_deadline_hours || exam.live_deadline_hours === 0) return true;
  if (exam.results_published) return true;
  if (exam.publish_after_hours > 0) {
    const created = new Date(exam.created_at).getTime();
    const publishTime = created + exam.publish_after_hours * 3600000;
    if (Date.now() >= publishTime) return true;
  }
  const created = new Date(exam.created_at).getTime();
  const liveEndsAt = created + exam.live_deadline_hours * 3600000;
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
  
  const permBan = await db.prepare(
    'SELECT id FROM banned_users WHERE (device_fingerprint = ? OR ip_address = ?) AND ban_type = ? LIMIT 1'
  ).bind(fp, clientIP, 'delete').first();
  if (permBan) return err('Access denied. This device is permanently restricted.', 403);
  
  const countByFP = await db.prepare(
    'SELECT COUNT(*) as count FROM users WHERE device_fingerprint = ? AND device_fingerprint != ?'
  ).bind(fp, '').first();
  
  const countByIP = await db.prepare(
    'SELECT COUNT(*) as count FROM users WHERE created_ip = ?'
  ).bind(clientIP).first();
  
  const totalCount = Math.max(countByFP?.count || 0, countByIP?.count || 0);
  
  if (totalCount >= 2) {
    return err('Maximum 2 accounts allowed per device/network.', 403);
  }
  
  const hash = await sha256(password);
  const result = await db.prepare(
    'INSERT INTO users (name, email, password, device_fingerprint, created_ip) VALUES (?, ?, ?, ?, ?) RETURNING id, name, email, is_admin'
  ).bind(name, email.toLowerCase(), hash, fp, clientIP).first();
  
  const token = await signJWT({ id: result.id, email: result.email, is_admin: result.is_admin });
  return json({ token, user: { id: result.id, name: result.name, email: result.email, is_admin: result.is_admin } });
}

async function handleLogin(request, db) {
  const { email, password } = await request.json();
  if (!email || !password) return err('Email and password required');
  
  const hash = await sha256(password);
  const user = await db.prepare('SELECT id, name, email, is_admin, is_banned FROM users WHERE email = ? AND password = ?')
    .bind(email.toLowerCase(), hash).first();
  if (!user) return err('Invalid credentials', 401);
  
  if (user.is_banned) return err('Account suspended. Contact support for assistance.', 403);
  
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
  if (!payload || !payload.setup_master || !payload.is_admin) return err('Invalid or expired session', 401);
  
  const existing = await db.prepare('SELECT value FROM settings WHERE key = ?').bind('master_key_hash').first();
  if (existing && existing.value) return err('Master key already set', 403);
  
  const hash = await sha256(master_key);
  await db.prepare('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)').bind('master_key_hash', hash).run();
  
  const token = await signJWT({ id: payload.id, email: payload.email, is_admin: true });
  return json({ success: true, token, message: 'Master key set successfully' });
}

async function handleMasterKeyVerify(request, db) {
  const { temp_token, master_key } = await request.json();
  if (!temp_token || !master_key) return err('Missing token or master key');
  
  const payload = await verifyJWT(temp_token);
  if (!payload || !payload.temp || !payload.is_admin) return err('Invalid or expired session', 401);
  
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
  const rows = await db.prepare(`
    SELECT b.*, 
      COUNT(DISTINCT e.id) as exam_count,
      (SELECT COUNT(*) FROM batch_resources br WHERE br.batch_id = b.id) as resource_count
    FROM batches b 
    LEFT JOIN exams e ON e.batch_id = b.id
    GROUP BY b.id ORDER BY b.created_at DESC
  `).all();
  return json(rows.results);
}

async function handleCreateBatch(request, db) {
  const { name, description } = await request.json();
  if (!name) return err('Name required');
  const r = await db.prepare('INSERT INTO batches (name, description) VALUES (?, ?) RETURNING *')
    .bind(name, description || '').first();
  return json(r, 201);
}

async function handleUpdateBatch(batchId, request, db) {
  const { name, description } = await request.json();
  await db.prepare('UPDATE batches SET name = ?, description = ? WHERE id = ?')
    .bind(name, description || '', batchId).run();
  const r = await db.prepare('SELECT * FROM batches WHERE id = ?').bind(batchId).first();
  return json(r);
}

async function handleDeleteBatch(batchId, db) {
  await db.prepare('UPDATE exams SET batch_id = NULL WHERE batch_id = ?').bind(batchId).run();
  await db.prepare('DELETE FROM batch_resources WHERE batch_id = ?').bind(batchId).run();
  await db.prepare('DELETE FROM premium_access WHERE batch_id = ?').bind(batchId).run();
  await db.prepare('DELETE FROM batches WHERE id = ?').bind(batchId).run();
  return json({ success: true });
}

// ============================================================
// BATCH RESOURCES MANAGEMENT
// ============================================================

async function handleGetBatchResources(batchId, db) {
  const resources = await db.prepare('SELECT id, title, link FROM batch_resources WHERE batch_id = ? ORDER BY created_at DESC').bind(batchId).all();
  return json(resources.results);
}

async function handleAddBatchResource(request, db) {
  const { batch_id, title, link } = await request.json();
  if (!batch_id || !title || !link) return err('Batch ID, title, and link required');
  const result = await db.prepare('INSERT INTO batch_resources (batch_id, title, link) VALUES (?, ?, ?) RETURNING id')
    .bind(batch_id, title, link).first();
  return json({ id: result.id, message: 'Resource added' }, 201);
}

async function handleDeleteBatchResource(resourceId, db) {
  await db.prepare('DELETE FROM batch_resources WHERE id = ?').bind(resourceId).run();
  return json({ success: true });
}

// ============================================================
// EXAM RESOURCES MANAGEMENT
// ============================================================

async function handleGetExamResources(examId, db) {
  const resources = await db.prepare('SELECT id, title, link FROM exam_resources WHERE exam_id = ? ORDER BY created_at DESC').bind(examId).all();
  return json(resources.results);
}

async function handleAddExamResource(request, db) {
  const { exam_id, title, link } = await request.json();
  if (!exam_id || !title || !link) return err('Exam ID, title, and link required');
  const result = await db.prepare('INSERT INTO exam_resources (exam_id, title, link) VALUES (?, ?, ?) RETURNING id')
    .bind(exam_id, title, link).first();
  return json({ id: result.id, message: 'Resource added' }, 201);
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

  const exams = await db.prepare(`
    SELECT e.*, b.name as batch_name,
      (SELECT COUNT(*) FROM questions q WHERE q.exam_id = e.id) as question_count
    FROM exams e 
    LEFT JOIN batches b ON e.batch_id = b.id
    ORDER BY e.created_at DESC
  `).all();

  const allExamResources = await db.prepare(`
    SELECT er.*, e.id as exam_id, e.is_premium, e.batch_id
    FROM exam_resources er
    JOIN exams e ON er.exam_id = e.id
    ORDER BY er.created_at DESC
  `).all();

  const allBatchResources = await db.prepare(`
    SELECT br.*, b.id as batch_id, b.name as batch_name
    FROM batch_resources br
    JOIN batches b ON br.batch_id = b.id
    ORDER BY br.created_at DESC
  `).all();

  let userPremiumBatches = new Set();
  let userPremiumExams = new Set();
  let hasAccountPremium = false;
  
  if (userId && !isAdmin) {
    const now = new Date().toISOString();
    const userRow = await db.prepare('SELECT premium_until FROM users WHERE id = ?').bind(userId).first();
    if (userRow && userRow.premium_until && userRow.premium_until > now) {
      hasAccountPremium = true;
    }
    
    const batchGrants = await db.prepare(
      'SELECT batch_id FROM premium_access WHERE user_id = ? AND batch_id IS NOT NULL AND (expires_at IS NULL OR expires_at > ?)'
    ).bind(userId, now).all();
    for (const g of batchGrants.results) { userPremiumBatches.add(g.batch_id); }
    
    const examGrants = await db.prepare(
      'SELECT exam_id FROM premium_access WHERE user_id = ? AND exam_id IS NOT NULL AND (expires_at IS NULL OR expires_at > ?)'
    ).bind(userId, now).all();
    for (const g of examGrants.results) { userPremiumExams.add(g.exam_id); }
  }

  const examResourcesMap = {};
  for (const r of allExamResources.results) {
    const eid = r.exam_id;
    let canSee = false;
    if (isAdmin) {
      canSee = true;
    } else if (!r.is_premium) {
      canSee = true;
    } else if (hasAccountPremium || userPremiumExams.has(eid)) {
      canSee = true;
    } else if (r.batch_id && userPremiumBatches.has(r.batch_id)) {
      canSee = true;
    }
    
    if (canSee) {
      if (!examResourcesMap[eid]) examResourcesMap[eid] = [];
      examResourcesMap[eid].push({ id: r.id, title: r.title, link: r.link });
    }
  }

  const batchResourcesMap = {};
  for (const r of allBatchResources.results) {
    const bid = r.batch_id;
    const batchExams = await db.prepare(
      'SELECT id, is_premium FROM exams WHERE batch_id = ?'
    ).bind(bid).all();
    
    let canSeeBatch = false;
    
    if (isAdmin) {
      canSeeBatch = true;
    } else if (hasAccountPremium || userPremiumBatches.has(bid)) {
      canSeeBatch = true;
    } else if (batchExams.results.length > 0) {
      const allFree = batchExams.results.every(e => !e.is_premium);
      if (allFree) {
        canSeeBatch = true;
      }
    }
    
    if (canSeeBatch) {
      if (!batchResourcesMap[bid]) {
        batchResourcesMap[bid] = { id: bid, name: r.batch_name, resources: [] };
      }
      batchResourcesMap[bid].resources.push({ id: r.id, title: r.title, link: r.link });
    }
  }
  const batchResourcesList = Object.values(batchResourcesMap);

  const result = [];
  for (const exam of exams.results) {
    const live = getLiveStatus(exam);
    let stored_attempt = null, accessible = false, can_practice = false, results_visible = false;
    
    if (userId) {
      const sa = await db.prepare(
        `SELECT * FROM exam_results_stored WHERE user_id = ? AND exam_id = ? AND is_practice = 0 AND is_first_attempt = 1 LIMIT 1`
      ).bind(userId, exam.id).first();
      stored_attempt = sa || null;
      accessible = await checkPremiumAccess(db, userId, exam.id, isAdmin);
      
      if (exam.allow_practice && !exam.is_closed) {
        if (exam.live_deadline_hours > 0) {
          can_practice = live.live_ended && !!stored_attempt;
        } else {
          can_practice = !!stored_attempt;
        }
      }
      
      if (exam.live_deadline_hours > 0 && live.is_live) {
        results_visible = false;
      } else {
        results_visible = isResultsPublished(exam);
      }
    }
    
    const examResources = examResourcesMap[exam.id] || [];
    
    result.push({ 
      ...exam, ...live, 
      stored_attempt, 
      accessible, 
      can_practice, 
      results_visible,
      exam_resources: examResources,
      batch_id: exam.batch_id,
      batch_name: exam.batch_name
    });
  }
  
  return json({ exams: result, batch_resources: batchResourcesList });
}

async function handleGetExamQuestions(examId, request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  
  const exam = await db.prepare('SELECT * FROM exams WHERE id = ?').bind(examId).first();
  if (!exam) return err('Exam not found', 404);
  
  // Block if exam is closed
  if (exam.is_closed && !user.is_admin) {
    return err('This exam is currently closed.', 403);
  }
  
  const accessible = await checkPremiumAccess(db, user.id, examId, user.is_admin);
  if (!accessible) return err('Premium access required', 403);
  
  const url = new URL(request.url);
  const isPractice = url.searchParams.get('practice') === '1';
  if (isPractice && !exam.allow_practice) {
    return err('Practice mode is not available for this exam.', 403);
  }
  
  const qs = await db.prepare(
    'SELECT id, exam_id, question_text, option_a, option_b, option_c, option_d, image_url, explanation FROM questions WHERE exam_id = ?'
  ).bind(examId).all();
  
  const examRes = await db.prepare('SELECT id, title, link FROM exam_resources WHERE exam_id = ? ORDER BY created_at DESC').bind(examId).all();
  
  return json({ exam, questions: qs.results, exam_resources: examRes.results });
}

async function handleSubmitExam(examId, request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  
  const { answers, is_practice, time_taken_seconds } = await request.json();
  const exam = await db.prepare('SELECT * FROM exams WHERE id = ?').bind(examId).first();
  if (!exam) return err('Exam not found', 404);
  
  // Block if exam is closed
  if (exam.is_closed && !user.is_admin) {
    return err('This exam is currently closed.', 403);
  }
  
  const accessible = await checkPremiumAccess(db, user.id, examId, user.is_admin);
  if (!accessible) return err('Premium access required', 403);
  
  if (is_practice && !exam.allow_practice) {
    return err('Practice mode is not available for this exam.', 403);
  }
  
  const questions = await db.prepare('SELECT * FROM questions WHERE exam_id = ?').bind(examId).all();
  let score = 0;
  let correctCount = 0;
  let wrongCount = 0;
  let skippedCount = 0;
  const total = questions.results.length;
  const nm = exam.negative_marking || 0;
  const detailedAnswers = {};
  
  for (const q of questions.results) {
    const rawGiven = answers[q.id] || answers[String(q.id)] || '';
    const given = rawGiven.toString().trim().toUpperCase();
    const correct = (q.correct_answer || '').toString().trim().toUpperCase();
    const isCorrect = given === correct;
    
    if (!given) {
      skippedCount++;
    } else if (isCorrect) {
      correctCount++;
      score += 1;
    } else {
      wrongCount++;
      if (nm > 0) score -= nm;
    }
    
    detailedAnswers[q.id] = { given, correct, isCorrect };
  }
  
  const percentage = total > 0 ? Math.round((score / total) * 10000) / 100 : 0;
  const answersJson = JSON.stringify(detailedAnswers);
  const timeTaken = time_taken_seconds || 0;
  
  const existingFirst = await db.prepare(
    'SELECT id FROM exam_results_stored WHERE user_id = ? AND exam_id = ? AND is_practice = 0 AND is_first_attempt = 1'
  ).bind(user.id, examId).first();
  
  let attemptId = null;
  
  if (!is_practice && !existingFirst) {
    const r1 = await db.prepare(
      `INSERT INTO exam_results_stored (user_id, exam_id, score, total_questions, percentage, answers, is_practice, is_first_attempt, time_taken_seconds)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`
    ).bind(user.id, examId, Math.max(0, score), total, percentage, answersJson, 0, 1, timeTaken).first();
    
    await db.prepare(
      `INSERT INTO exam_attempts (user_id, exam_id, score, total_questions, percentage, answers, time_taken_seconds) VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(user.id, examId, Math.max(0, score), total, percentage, answersJson, timeTaken).run();
    
    attemptId = r1.id;
  } else if (existingFirst) {
    attemptId = existingFirst.id;
  }
  
  return json({ 
    attemptId: attemptId || 0, 
    score: Math.max(0, score), 
    total, 
    percentage,
    correct: correctCount,
    wrong: wrongCount,
    skipped: skippedCount,
    detailed: detailedAnswers,
    time_taken_seconds: timeTaken
  });
}

async function handleGetResult(examId, attemptId, request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  
  const exam = await db.prepare('SELECT * FROM exams WHERE id = ?').bind(examId).first();
  if (!exam) return err('Exam not found', 404);
  
  const live = getLiveStatus(exam);
  if (exam.live_deadline_hours > 0 && live.is_live) {
    return json({ pending: true, message: 'Results will be available after the live exam window ends.', exam_name: exam.name });
  }
  
  if (!isResultsPublished(exam)) {
    return json({ pending: true, message: 'Results will be available after publication.', exam_name: exam.name });
  }
  
  if (attemptId == 0 || !attemptId) {
    const questions = await db.prepare('SELECT * FROM questions WHERE exam_id = ?').bind(examId).all();
    return json({ 
      attempt: { id: 0, score: 0, total_questions: questions.results.length, percentage: 0, answers: '{}', is_practice: 1, time_taken_seconds: 0 }, 
      questions: questions.results, 
      exam, 
      results_published: true 
    });
  }
  
  const attempt = await db.prepare(
    'SELECT * FROM exam_results_stored WHERE id = ? AND user_id = ? AND exam_id = ?'
  ).bind(attemptId, user.id, examId).first();
  if (!attempt) return err('Result not found', 404);
  
  const questions = await db.prepare('SELECT * FROM questions WHERE exam_id = ?').bind(examId).all();
  return json({ 
    attempt: { ...attempt, answers: JSON.parse(attempt.answers || '{}') }, 
    questions: questions.results, 
    exam, 
    results_published: true 
  });
}

async function handleLeaderboard(examId, request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  
  const exam = await db.prepare('SELECT * FROM exams WHERE id = ?').bind(examId).first();
  if (!exam) return err('Exam not found', 404);
  
  if (!exam.leaderboard_enabled) return json({ disabled: true });
  
  if (exam.live_deadline_hours > 0) {
    const liveStatus = getLiveStatus(exam);
    if (liveStatus.is_live) return json({ disabled: true, pending: true });
  }
  
  const row = await db.prepare(`
    SELECT rank, total_participants, percentage, score FROM (
      SELECT user_id, score, percentage,
        ROW_NUMBER() OVER (ORDER BY percentage DESC, submitted_at ASC) as rank,
        COUNT(*) OVER () as total_participants
      FROM exam_results_stored
      WHERE exam_id = ? AND is_first_attempt = 1 AND is_practice = 0
    ) WHERE user_id = ?
  `).bind(examId, user.id).first();
  
  if (!row) return json({ rank: null, total_participants: 0, percentile: null });
  const percentile = row.total_participants > 1 ? Math.round((1 - (row.rank - 1) / row.total_participants) * 100) : 100;
  return json({ ...row, percentile, disabled: false });
}

async function handleHistory(request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  
  const rows = await db.prepare(`
    SELECT ers.*, e.name as exam_name, e.results_published, e.publish_after_hours, 
           e.live_deadline_hours, e.created_at as exam_created_at
    FROM exam_results_stored ers
    JOIN exams e ON ers.exam_id = e.id
    WHERE ers.user_id = ? AND ers.is_first_attempt = 1 AND ers.is_practice = 0
    ORDER BY ers.submitted_at DESC
  `).bind(user.id).all();
  
  const result = [];
  for (const r of rows.results) {
    const examForLive = { live_deadline_hours: r.live_deadline_hours, created_at: r.exam_created_at };
    const live = getLiveStatus(examForLive);
    
    let published;
    if (r.live_deadline_hours > 0) {
      published = live.live_ended;
      if (r.results_published) published = true;
    } else {
      published = true;
    }
    
    if (!published && r.publish_after_hours > 0) {
      const publishTime = new Date(r.exam_created_at).getTime() + r.publish_after_hours * 3600000;
      if (Date.now() >= publishTime) published = true;
    }
    
    let lb = null;
    if (published) {
      lb = await db.prepare(`
        SELECT rank, total_participants FROM (
          SELECT user_id, ROW_NUMBER() OVER (ORDER BY percentage DESC, submitted_at ASC) as rank,
            COUNT(*) OVER () as total_participants
          FROM exam_results_stored WHERE exam_id = ? AND is_first_attempt = 1 AND is_practice = 0
        ) WHERE user_id = ?
      `).bind(r.exam_id, user.id).first();
    }
    const percentile = lb && lb.total_participants > 1 ? Math.round((1 - (lb.rank - 1) / lb.total_participants) * 100) : null;
    result.push({ ...r, rank: lb?.rank || null, total_participants: lb?.total_participants || null, percentile, results_visible: published });
  }
  return json(result);
}

// ============================================================
// NOTIFICATIONS ROUTES
// ============================================================

async function handleListNotifications(request, db) {
  const user = await requireAuth(request);
  if (!user) return err('Unauthorized', 401);
  
  const notifications = await db.prepare(`
    SELECT n.*, u.name as creator_name,
      CASE WHEN nr.id IS NOT NULL THEN 1 ELSE 0 END as is_read
    FROM notifications n
    JOIN users u ON n.created_by = u.id
    LEFT JOIN notification_reads nr ON n.id = nr.notification_id AND nr.user_id = ?
    ORDER BY n.created_at DESC
  `).bind(user.id).all();
  
  const unreadCount = await db.prepare(`
    SELECT COUNT(*) as count FROM notifications n
    WHERE n.id NOT IN (SELECT notification_id FROM notification_reads WHERE user_id = ?)
  `).bind(user.id).first();
  
  return json({ notifications: notifications.results, unread_count: unreadCount.count });
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
  const { name, description, time_limit, is_premium, negative_marking, allow_practice, batch_id, live_deadline_hours, results_published, publish_after_hours, leaderboard_enabled } = await request.json();
  if (!name) return err('Name required');
  const r = await db.prepare(
    `INSERT INTO exams (name, description, time_limit, is_premium, negative_marking, allow_practice, batch_id, live_deadline_hours, results_published, publish_after_hours, leaderboard_enabled)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`
  ).bind(name, description || '', time_limit || 30, is_premium ? 1 : 0, negative_marking || 0,
    allow_practice !== false ? 1 : 0, batch_id || null, live_deadline_hours || 0,
    results_published ? 1 : 0, publish_after_hours || 0, leaderboard_enabled !== false ? 1 : 0).first();
  return json(r, 201);
}

async function handleAdminUpdateExam(examId, request, db) {
  const { name, description, time_limit, is_premium, negative_marking, allow_practice, batch_id, live_deadline_hours, results_published, publish_after_hours, leaderboard_enabled } = await request.json();
  await db.prepare(
    `UPDATE exams SET name = ?, description = ?, time_limit = ?, is_premium = ?, negative_marking = ?, allow_practice = ?, batch_id = ?, live_deadline_hours = ?, results_published = ?, publish_after_hours = ?, leaderboard_enabled = ? WHERE id = ?`
  ).bind(name, description || '', time_limit || 30, is_premium ? 1 : 0, negative_marking || 0,
    allow_practice !== false ? 1 : 0, batch_id || null, live_deadline_hours || 0,
    results_published ? 1 : 0, publish_after_hours || 0, leaderboard_enabled !== false ? 1 : 0, examId).run();
  const r = await db.prepare('SELECT * FROM exams WHERE id = ?').bind(examId).first();
  return json(r);
}

async function handleAdminDeleteExam(examId, db) {
  await db.prepare('DELETE FROM premium_access WHERE exam_id = ?').bind(examId).run();
  await db.prepare('DELETE FROM exam_results_stored WHERE exam_id = ?').bind(examId).run();
  await db.prepare('DELETE FROM exam_attempts WHERE exam_id = ?').bind(examId).run();
  await db.prepare('DELETE FROM questions WHERE exam_id = ?').bind(examId).run();
  await db.prepare('DELETE FROM exam_resources WHERE exam_id = ?').bind(examId).run();
  await db.prepare('DELETE FROM exams WHERE id = ?').bind(examId).run();
  return json({ success: true });
}

async function handleAdminGetQuestions(examId, db) {
  const qs = await db.prepare('SELECT * FROM questions WHERE exam_id = ? ORDER BY id').bind(examId).all();
  return json(qs.results);
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
  const { exam_id, questions } = await request.json();
  if (!exam_id) return err('exam_id required');
  if (!questions || !Array.isArray(questions) || questions.length === 0) return err('questions array required');
  
  let count = 0;
  for (const q of questions) {
    const question_text = q.question || q.question_text || '';
    const option_a = q.option_a || q.a || '';
    const option_b = q.option_b || q.b || '';
    const option_c = q.option_c || q.c || '';
    const option_d = q.option_d || q.d || '';
    const correct_answer = (q.answer || q.correct_answer || '').toUpperCase();
    const image_url = q.image_url || q.image || null;
    const explanation = q.explanation || '';
    
    if (!question_text) continue;
    if (!['A', 'B', 'C', 'D'].includes(correct_answer)) continue;
    if (!option_a || !option_b || !option_c || !option_d) continue;
    
    await db.prepare(
      'INSERT INTO questions (exam_id, question_text, option_a, option_b, option_c, option_d, correct_answer, image_url, explanation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(exam_id, question_text, option_a, option_b, option_c, option_d, correct_answer, image_url || null, explanation).run();
    count++;
  }
  return json({ inserted: count });
}

async function handleAdminListUsers(db) {
  const users = await db.prepare(`
    SELECT u.id, u.name, u.email, u.is_admin, u.is_banned, u.premium_until, u.created_at, u.device_fingerprint, u.created_ip
    FROM users u
    ORDER BY u.created_at DESC
  `).all();
  
  const result = [];
  for (const user of users.results) {
    const grants = await db.prepare(`
      SELECT pa.*, e.name as exam_name, b.name as batch_name
      FROM premium_access pa
      LEFT JOIN exams e ON pa.exam_id = e.id
      LEFT JOIN batches b ON pa.batch_id = b.id
      WHERE pa.user_id = ?
      ORDER BY pa.granted_at DESC
    `).bind(user.id).all();
    
    result.push({ ...user, premium_grants: grants.results });
  }
  return json(result);
}

async function handleAdminGrantPremium(request, db, adminId) {
  const { user_id, grant_scope, exam_id, batch_id, duration_hours } = await request.json();
  if (!user_id || !grant_scope) return err('user_id and grant_scope required');
  const expires_at = duration_hours ? new Date(Date.now() + duration_hours * 3600000).toISOString() : null;
  
  if (grant_scope === 'account') {
    await db.prepare('UPDATE users SET premium_until = ? WHERE id = ?').bind(expires_at, user_id).run();
  } else if (grant_scope === 'batch') {
    if (!batch_id) return err('batch_id required for batch scope');
    await db.prepare(
      `INSERT OR REPLACE INTO premium_access (user_id, batch_id, grant_scope, granted_by, expires_at) 
       VALUES (?, ?, ?, ?, ?)`
    ).bind(user_id, batch_id, 'batch', adminId, expires_at).run();
  } else {
    if (!exam_id) return err('exam_id required for exam scope');
    await db.prepare(
      `INSERT OR REPLACE INTO premium_access (user_id, exam_id, grant_scope, granted_by, expires_at) 
       VALUES (?, ?, ?, ?, ?)`
    ).bind(user_id, exam_id, 'exam', adminId, expires_at).run();
  }
  return json({ success: true });
}

async function handleAdminRevokePremium(request, db) {
  const { user_id, exam_id, batch_id } = await request.json();
  if (batch_id) {
    await db.prepare('DELETE FROM premium_access WHERE user_id = ? AND batch_id = ? AND grant_scope = ?')
      .bind(user_id, batch_id, 'batch').run();
  } else if (exam_id) {
    await db.prepare('DELETE FROM premium_access WHERE user_id = ? AND exam_id = ? AND grant_scope = ?')
      .bind(user_id, exam_id, 'exam').run();
  } else {
    await db.prepare('DELETE FROM premium_access WHERE user_id = ?').bind(user_id).run();
  }
  return json({ success: true });
}

async function handleAdminRevokeAccountPremium(request, db) {
  const { user_id } = await request.json();
  await db.prepare('UPDATE users SET premium_until = NULL WHERE id = ?').bind(user_id).run();
  return json({ success: true });
}

async function handleAdminBanUser(userId, request, db, adminId) {
  const user = await db.prepare('SELECT id, device_fingerprint, created_ip FROM users WHERE id = ?').bind(userId).first();
  if (!user) return err('User not found', 404);
  if (user.is_admin) return err('Cannot ban an admin');
  
  await db.prepare('UPDATE users SET is_banned = 1 WHERE id = ?').bind(userId).run();
  
  await db.prepare(
    'INSERT INTO banned_users (user_id, device_fingerprint, ip_address, ban_type, banned_by) VALUES (?, ?, ?, ?, ?)'
  ).bind(userId, user.device_fingerprint || '', user.created_ip || '', 'ban', adminId).run();
  
  return json({ success: true, message: 'User banned successfully. They cannot login. Data preserved.' });
}

async function handleAdminUnbanUser(userId, request, db) {
  const user = await db.prepare('SELECT id FROM users WHERE id = ?').bind(userId).first();
  if (!user) return err('User not found', 404);
  
  await db.prepare('UPDATE users SET is_banned = 0 WHERE id = ?').bind(userId).run();
  await db.prepare('DELETE FROM banned_users WHERE user_id = ? AND ban_type = ?').bind(userId, 'ban').run();
  
  return json({ success: true, message: 'User unbanned successfully. Access restored.' });
}

async function handleAdminDeleteUser(userId, request, db, adminId) {
  const user = await db.prepare('SELECT id, device_fingerprint, created_ip, is_admin FROM users WHERE id = ?').bind(userId).first();
  if (!user) return err('User not found', 404);
  if (user.is_admin) return err('Cannot delete an admin');
  
  const fp = user.device_fingerprint || '';
  const ip = user.created_ip || '';
  
  let relatedUserIds = [userId];
  
  if (fp) {
    const fpUsers = await db.prepare(
      'SELECT id FROM users WHERE device_fingerprint = ? AND device_fingerprint != ?'
    ).bind(fp, '').all();
    for (const u of fpUsers.results) {
      if (!relatedUserIds.includes(u.id)) relatedUserIds.push(u.id);
    }
  }
  
  if (ip) {
    const ipUsers = await db.prepare(
      'SELECT id FROM users WHERE created_ip = ?'
    ).bind(ip).all();
    for (const u of ipUsers.results) {
      if (!relatedUserIds.includes(u.id)) relatedUserIds.push(u.id);
    }
  }
  
  for (const uid of relatedUserIds) {
    const u = await db.prepare('SELECT is_admin FROM users WHERE id = ?').bind(uid).first();
    if (u && u.is_admin) continue;
    
    await db.prepare('DELETE FROM notification_reads WHERE user_id = ?').bind(uid).run();
    await db.prepare('DELETE FROM exam_attempts WHERE user_id = ?').bind(uid).run();
    await db.prepare('DELETE FROM exam_results_stored WHERE user_id = ?').bind(uid).run();
    await db.prepare('DELETE FROM premium_access WHERE user_id = ?').bind(uid).run();
    await db.prepare('DELETE FROM banned_users WHERE user_id = ?').bind(uid).run();
    await db.prepare('DELETE FROM users WHERE id = ?').bind(uid).run();
  }
  
  await db.prepare(
    'INSERT INTO banned_users (device_fingerprint, ip_address, ban_type, banned_by) VALUES (?, ?, ?, ?)'
  ).bind(fp, ip, 'delete', adminId).run();
  
  const count = relatedUserIds.length;
  return json({ success: true, message: `${count} account(s) permanently deleted. Device banned from future signups.` });
}

async function handleAdminToggleExam(examId, request, db) {
  const { is_closed } = await request.json();
  await db.prepare('UPDATE exams SET is_closed = ? WHERE id = ?').bind(is_closed ? 1 : 0, examId).run();
  return json({ success: true, is_closed: is_closed ? 1 : 0 });
}

async function handleAdminResults(examId, db) {
  const query = examId
    ? `SELECT ers.*, u.name as user_name, u.email as user_email, e.name as exam_name, e.time_limit,
       ROW_NUMBER() OVER (ORDER BY ers.percentage DESC, ers.submitted_at ASC) as rank
       FROM exam_results_stored ers 
       JOIN users u ON ers.user_id = u.id 
       JOIN exams e ON ers.exam_id = e.id 
       WHERE ers.exam_id = ? AND ers.is_first_attempt = 1 AND ers.is_practice = 0 
       ORDER BY ers.percentage DESC, ers.submitted_at ASC`
    : `SELECT ers.*, u.name as user_name, u.email as user_email, e.name as exam_name, e.time_limit,
       ROW_NUMBER() OVER (ORDER BY ers.percentage DESC, ers.submitted_at ASC) as rank
       FROM exam_results_stored ers 
       JOIN users u ON ers.user_id = u.id 
       JOIN exams e ON ers.exam_id = e.id 
       WHERE ers.is_first_attempt = 1 AND ers.is_practice = 0 
       ORDER BY ers.percentage DESC, ers.submitted_at ASC`;
  const rows = examId ? await db.prepare(query).bind(examId).all() : await db.prepare(query).all();
  return json(rows.results);
}

async function handleAdminDownloadResults(examId, db) {
  const rows = await db.prepare(`
    SELECT u.name as user_name, u.email as user_email, e.name as exam_name, e.time_limit,
           ers.score, ers.total_questions, ers.percentage, ers.time_taken_seconds, ers.submitted_at,
           ROW_NUMBER() OVER (ORDER BY ers.percentage DESC, ers.submitted_at ASC) as rank
    FROM exam_results_stored ers 
    JOIN users u ON ers.user_id = u.id 
    JOIN exams e ON ers.exam_id = e.id 
    WHERE ers.exam_id = ? AND ers.is_first_attempt = 1 AND ers.is_practice = 0 
    ORDER BY ers.percentage DESC, ers.submitted_at ASC
  `).bind(examId).all();
  
  const results = rows.results;
  if (!results.length) return err('No results found', 404);
  
  const examName = results[0].exam_name;
  const timeLimit = results[0].time_limit || 30;
  
  let txt = `Exam: ${examName}\n`;
  txt += `Total Time: ${timeLimit} min\n`;
  txt += `Total Participants: ${results.length}\n`;
  txt += `Date: ${new Date().toLocaleDateString()}\n`;
  txt += `${'─'.repeat(80)}\n`;
  txt += `Rank  Name                 Score    Percentage  Time Taken    Email\n`;
  txt += `${'─'.repeat(80)}\n`;
  
  for (const r of results) {
    const timeMin = (r.time_taken_seconds || 0) > 0 ? (r.time_taken_seconds / 60).toFixed(1) + ' min' : 'N/A';
    const rank = String(r.rank).padStart(4);
    const name = (r.user_name || 'Unknown').substring(0, 20).padEnd(20);
    const score = `${r.score}/${r.total_questions}`.padEnd(9);
    const pct = (r.percentage || 0).toFixed(1) + '%'.padEnd(12);
    const time = timeMin.padEnd(14);
    txt += `${rank} ${name} ${score} ${pct} ${time} ${r.email}\n`;
  }
  
  txt += `${'─'.repeat(80)}\n`;
  txt += `Generated by Exalyte Admin Panel\n`;
  
  return new Response(txt, {
    status: 200,
    headers: {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': `attachment; filename="${examName.replace(/[^a-zA-Z0-9]/g, '_')}_results.txt"`,
      ...CORS
    }
  });
}

async function handleAdminDeleteResult(resultId, db) {
  await db.prepare('DELETE FROM exam_results_stored WHERE id = ?').bind(resultId).run();
  return json({ success: true });
}

async function handleAdminCreateNotification(request, db, adminId) {
  const { title, body, image_url, link_url } = await request.json();
  if (!title) return err('Title required');
  const r = await db.prepare(
    'INSERT INTO notifications (title, body, image_url, link_url, created_by) VALUES (?, ?, ?, ?, ?) RETURNING *'
  ).bind(title, body || '', image_url || null, link_url || null, adminId).first();
  return json(r, 201);
}

async function handleAdminListNotifications(db) {
  const rows = await db.prepare(`
    SELECT n.*, u.name as creator_name,
      (SELECT COUNT(*) FROM notification_reads nr WHERE nr.notification_id = n.id) as read_count,
      (SELECT COUNT(*) FROM users) as total_users
    FROM notifications n
    JOIN users u ON n.created_by = u.id
    ORDER BY n.created_at DESC
  `).all();
  return json(rows.results);
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
  
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }
  
  await initDB(db);
  
  const url = new URL(request.url);
  let path = url.pathname.replace(/^\/api/, '').replace(/\/$/, '') || '/';
  const method = request.method;
  
  if (path === '/auth/signup' && method === 'POST') return handleSignup(request, db);
  if (path === '/auth/login' && method === 'POST') return handleLogin(request, db);
  
  if (path === '/auth/master-key/status' && method === 'POST') return handleMasterKeyStatus(db);
  if (path === '/auth/master-key/set' && method === 'POST') return handleMasterKeySet(request, db);
  if (path === '/auth/master-key/verify' && method === 'POST') return handleMasterKeyVerify(request, db);
  
  if (path === '/batches' && method === 'GET') return handleListBatches(db);
  
  if (path === '/exams' && method === 'GET') return handleListExams(request, db);
  if (path === '/history' && method === 'GET') return handleHistory(request, db);
  
  const examQuestions = path.match(/^\/exams\/(\d+)\/questions$/);
  if (examQuestions && method === 'GET') return handleGetExamQuestions(examQuestions[1], request, db);
  
  const examSubmit = path.match(/^\/exams\/(\d+)\/submit$/);
  if (examSubmit && method === 'POST') return handleSubmitExam(examSubmit[1], request, db);
  
  const examResult = path.match(/^\/exams\/(\d+)\/result\/(\d+)$/);
  if (examResult && method === 'GET') return handleGetResult(examResult[1], examResult[2], request, db);
  
  const leaderboard = path.match(/^\/leaderboard\/(\d+)$/);
  if (leaderboard && method === 'GET') return handleLeaderboard(leaderboard[1], request, db);
  
  if (path === '/notifications' && method === 'GET') return handleListNotifications(request, db);
  const markRead = path.match(/^\/notifications\/(\d+)\/read$/);
  if (markRead && method === 'POST') return handleMarkNotificationRead(markRead[1], request, db);
  
  const admin = await requireAdmin(request, db);
  
  if (path === '/admin/batches' && method === 'POST') {
    if (!admin) return err('Admin required', 403);
    return handleCreateBatch(request, db);
  }
  const adminBatch = path.match(/^\/admin\/batches\/(\d+)$/);
  if (adminBatch && method === 'PUT') {
    if (!admin) return err('Admin required', 403);
    return handleUpdateBatch(adminBatch[1], request, db);
  }
  if (adminBatch && method === 'DELETE') {
    if (!admin) return err('Admin required', 403);
    return handleDeleteBatch(adminBatch[1], db);
  }
  
  const adminBatchResources = path.match(/^\/admin\/batches\/(\d+)\/resources$/);
  if (adminBatchResources && method === 'GET') {
    if (!admin) return err('Admin required', 403);
    return handleGetBatchResources(adminBatchResources[1], db);
  }
  if (path === '/admin/batch-resources' && method === 'POST') {
    if (!admin) return err('Admin required', 403);
    return handleAddBatchResource(request, db);
  }
  const adminBatchResource = path.match(/^\/admin\/batch-resources\/(\d+)$/);
  if (adminBatchResource && method === 'DELETE') {
    if (!admin) return err('Admin required', 403);
    return handleDeleteBatchResource(adminBatchResource[1], db);
  }
  
  const adminExamResources = path.match(/^\/admin\/exams\/(\d+)\/resources$/);
  if (adminExamResources && method === 'GET') {
    if (!admin) return err('Admin required', 403);
    return handleGetExamResources(adminExamResources[1], db);
  }
  if (path === '/admin/resources' && method === 'POST') {
    if (!admin) return err('Admin required', 403);
    return handleAddExamResource(request, db);
  }
  const adminExamResource = path.match(/^\/admin\/resources\/(\d+)$/);
  if (adminExamResource && method === 'DELETE') {
    if (!admin) return err('Admin required', 403);
    return handleDeleteExamResource(adminExamResource[1], db);
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
  
  const adminToggleExam = path.match(/^\/admin\/exams\/(\d+)\/toggle$/);
  if (adminToggleExam && method === 'POST') {
    if (!admin) return err('Admin required', 403);
    return handleAdminToggleExam(adminToggleExam[1], request, db);
  }
  
  const adminDownloadResults = path.match(/^\/admin\/results\/(\d+)\/download$/);
  if (adminDownloadResults && method === 'GET') {
    if (!admin) return err('Admin required', 403);
    return handleAdminDownloadResults(adminDownloadResults[1], db);
  }
  
  if (path === '/admin/questions/bulk' && method === 'POST') {
    if (!admin) return err('Admin required', 403);
    return handleAdminBulkQuestions(request, db);
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
  
  const adminBanUser = path.match(/^\/admin\/users\/(\d+)\/ban$/);
  if (adminBanUser && method === 'POST') {
    if (!admin) return err('Admin required', 403);
    return handleAdminBanUser(adminBanUser[1], request, db, admin.id);
  }
  
  const adminUnbanUser = path.match(/^\/admin\/users\/(\d+)\/unban$/);
  if (adminUnbanUser && method === 'POST') {
    if (!admin) return err('Admin required', 403);
    return handleAdminUnbanUser(adminUnbanUser[1], request, db);
  }
  
  const adminDeleteUser = path.match(/^\/admin\/users\/(\d+)\/delete$/);
  if (adminDeleteUser && method === 'DELETE') {
    if (!admin) return err('Admin required', 403);
    return handleAdminDeleteUser(adminDeleteUser[1], request, db, admin.id);
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
  
  if (path === '/admin/notifications' && method === 'POST') {
    if (!admin) return err('Admin required', 403);
    return handleAdminCreateNotification(request, db, admin.id);
  }
  if (path === '/admin/notifications' && method === 'GET') {
    if (!admin) return err('Admin required', 403);
    return handleAdminListNotifications(db);
  }
  const adminNotif = path.match(/^\/admin\/notifications\/(\d+)$/);
  if (adminNotif && method === 'DELETE') {
    if (!admin) return err('Admin required', 403);
    return handleAdminDeleteNotification(adminNotif[1], db);
  }
  
  const adminPublish = path.match(/^\/admin\/exams\/(\d+)\/publish$/);
  if (adminPublish && method === 'POST') {
    if (!admin) return err('Admin required', 403);
    return handleAdminPublishResults(adminPublish[1], db);
  }
  
  return err('Not found', 404);
}
