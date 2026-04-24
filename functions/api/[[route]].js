// functions/api/[[route]].js
// Exalyte Cloudflare Pages Functions

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

const SECRET = 'exalyte_prod_secret_2024_x9kLm3nR7pQw';

async function signToken(payload) {
  const header = btoa(JSON.stringify({ alg:'HS256', typ:'JWT' }));
  const body = btoa(JSON.stringify(payload));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(SECRET),
    { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `${header}.${body}.${sigB64}`;
}

async function verifyToken(token) {
  try {
    const [header, body, sig] = token.split('.');
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(SECRET),
      { name:'HMAC', hash:'SHA-256' }, false, ['verify']);
    const sigBuf = Uint8Array.from(atob(sig), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBuf,
      new TextEncoder().encode(`${header}.${body}`));
    if (!valid) return null;
    const payload = JSON.parse(atob(body));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

async function getUser(request) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return null;
  return verifyToken(token);
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

async function ensureTables(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0, is_premium_allowed INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS exams (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
    description TEXT, time_limit INTEGER DEFAULT 30,
    is_premium INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, exam_id INTEGER NOT NULL,
    question_text TEXT NOT NULL, option_a TEXT NOT NULL, option_b TEXT NOT NULL,
    option_c TEXT NOT NULL, option_d TEXT NOT NULL, correct_answer TEXT NOT NULL,
    image_url TEXT, FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE)`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS exam_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
    exam_id INTEGER NOT NULL, score INTEGER DEFAULT 0,
    total_questions INTEGER DEFAULT 0, percentage REAL DEFAULT 0,
    answers TEXT, submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS premium_access (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
    exam_id INTEGER NOT NULL, granted_by INTEGER,
    granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, exam_id))`).run();
}

function parseCSVLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') { inQuotes = !inQuotes; continue; }
    if (ch === ',' && !inQuotes) { result.push(current); current = ''; continue; }
    current += ch;
  }
  result.push(current);
  return result;
}

// ═══ ROUTE HANDLERS ═══

async function handleAuth(method, path, body, db) {
  if (method === 'POST' && path === '/signup') {
    const { name, email, password } = body;
    if (!name || !email || !password) return err('All fields required');
    if (password.length < 6) return err('Password must be 6+ characters');
    const hashed = await sha256(password);
    try {
      const result = await db.prepare(
        'INSERT INTO users (name,email,password) VALUES (?,?,?)'
      ).bind(name, email.toLowerCase(), hashed).run();
      const user = await db.prepare('SELECT id,name,email,is_admin,is_premium_allowed FROM users WHERE id=?')
        .bind(result.meta.last_row_id).first();
      const token = await signToken({ id: user.id, email: user.email, is_admin: user.is_admin, exp: Date.now() + 7*24*60*60*1000 });
      return json({ token, user });
    } catch (e) {
      if (e.message.includes('UNIQUE')) return err('Email already registered');
      return err('Signup failed: ' + e.message);
    }
  }

  if (method === 'POST' && path === '/login') {
    const { email, password } = body;
    if (!email || !password) return err('Email and password required');
    const hashed = await sha256(password);
    const user = await db.prepare(
      'SELECT id,name,email,is_admin,is_premium_allowed FROM users WHERE email=? AND password=?'
    ).bind(email.toLowerCase(), hashed).first();
    if (!user) return err('Invalid email or password', 401);
    const token = await signToken({ id: user.id, email: user.email, is_admin: user.is_admin, exp: Date.now() + 7*24*60*60*1000 });
    return json({ token, user });
  }

  return err('Not found', 404);
}

async function handleExams(method, path, body, db, user) {
  if (!user) return err('Unauthorized', 401);

  // GET /api/exams/ — list accessible exams
  if (method === 'GET' && path === '/') {
    const allExams = await db.prepare('SELECT * FROM exams ORDER BY created_at DESC').all();
    const exams = [];
    for (const exam of allExams.results) {
      const qCount = await db.prepare('SELECT COUNT(*) as cnt FROM questions WHERE exam_id=?').bind(exam.id).first();
      const attempt = await db.prepare(
        'SELECT id,score,total_questions,percentage,submitted_at FROM exam_attempts WHERE user_id=? AND exam_id=? ORDER BY submitted_at DESC LIMIT 1'
      ).bind(user.id, exam.id).first();

      let accessible = !exam.is_premium;
      if (exam.is_premium && user.is_admin) accessible = true;
      if (exam.is_premium && !accessible) {
        const grant = await db.prepare('SELECT id FROM premium_access WHERE user_id=? AND exam_id=?').bind(user.id, exam.id).first();
        if (grant) accessible = true;
      }
      exams.push({ ...exam, question_count: qCount.cnt, attempt, accessible });
    }
    return json(exams);
  }

  // GET /api/exams/:id/questions
  if (method === 'GET' && path.match(/^\/\d+\/questions$/)) {
    const examId = parseInt(path.split('/')[1]);
    const exam = await db.prepare('SELECT * FROM exams WHERE id=?').bind(examId).first();
    if (!exam) return err('Exam not found', 404);
    if (exam.is_premium && !user.is_admin) {
      const grant = await db.prepare('SELECT id FROM premium_access WHERE user_id=? AND exam_id=?').bind(user.id, examId).first();
      if (!grant) return err('Premium access required', 403);
    }
    const questions = await db.prepare('SELECT * FROM questions WHERE exam_id=? ORDER BY id').bind(examId).all();
    const safeQuestions = questions.results.map(({ correct_answer, ...q }) => q);
    return json({ exam, questions: safeQuestions });
  }

  // POST /api/exams/:id/submit
  if (method === 'POST' && path.match(/^\/\d+\/submit$/)) {
    const examId = parseInt(path.split('/')[1]);
    const { answers } = body;
    if (!answers) return err('Answers required');
    const questions = await db.prepare('SELECT id,correct_answer FROM questions WHERE exam_id=?').bind(examId).all();
    if (!questions.results.length) return err('No questions found');
    let score = 0;
    const total = questions.results.length;
    const detailedAnswers = {};
    for (const q of questions.results) {
      const given = (answers[q.id] || '').toUpperCase();
      const correct = q.correct_answer.toUpperCase();
      const isCorrect = given === correct;
      if (isCorrect) score++;
      detailedAnswers[q.id] = { given, correct, isCorrect };
    }
    const percentage = Math.round((score / total) * 100);
    const result = await db.prepare(
      'INSERT INTO exam_attempts (user_id,exam_id,score,total_questions,percentage,answers) VALUES (?,?,?,?,?,?)'
    ).bind(user.id, examId, score, total, percentage, JSON.stringify(detailedAnswers)).run();
    return json({ attemptId: result.meta.last_row_id, score, total, percentage, answers: detailedAnswers });
  }

  // GET /api/exams/:id/result/:attemptId
  if (method === 'GET' && path.match(/^\/\d+\/result\/\d+$/)) {
    const parts = path.split('/');
    const examId = parseInt(parts[1]);
    const attemptId = parseInt(parts[3]);
    const attempt = await db.prepare('SELECT * FROM exam_attempts WHERE id=? AND user_id=?').bind(attemptId, user.id).first();
    if (!attempt) return err('Result not found', 404);
    const exam = await db.prepare('SELECT * FROM exams WHERE id=?').bind(examId).first();
    const questions = await db.prepare('SELECT * FROM questions WHERE exam_id=? ORDER BY id').bind(examId).all();
    return json({ attempt: { ...attempt, answers: JSON.parse(attempt.answers || '{}') }, exam, questions: questions.results });
  }

  return err('Not found', 404);
}

async function handleAdmin(method, path, body, db, user) {
  if (!user) return err('Unauthorized', 401);
  if (!user.is_admin) return err('Admin access required', 403);

  // POST /api/admin/exams — create exam
  if (method === 'POST' && path === '/exams') {
    const { name, description, time_limit, is_premium } = body;
    if (!name) return err('Exam name required');
    const result = await db.prepare(
      'INSERT INTO exams (name,description,time_limit,is_premium) VALUES (?,?,?,?)'
    ).bind(name, description || '', time_limit || 30, is_premium ? 1 : 0).run();
    return json({ id: result.meta.last_row_id, message: 'Exam created' });
  }

  // DELETE /api/admin/exams/:id
  if (method === 'DELETE' && path.match(/^\/exams\/\d+$/)) {
    const examId = parseInt(path.split('/')[2]);
    await db.prepare('DELETE FROM questions WHERE exam_id=?').bind(examId).run();
    await db.prepare('DELETE FROM exam_attempts WHERE exam_id=?').bind(examId).run();
    await db.prepare('DELETE FROM premium_access WHERE exam_id=?').bind(examId).run();
    await db.prepare('DELETE FROM exams WHERE id=?').bind(examId).run();
    return json({ message: 'Exam deleted' });
  }

  // POST /api/admin/questions/bulk — CSV upload with image_url support
  if (method === 'POST' && path === '/questions/bulk') {
    const { exam_id, csv } = body;
    if (!exam_id || !csv) return err('exam_id and csv required');
    const lines = csv.trim().split('\n').filter(l => l.trim());
    let inserted = 0;
    const errors = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      const cols = parseCSVLine(line);
      if (cols.length < 6) { errors.push(`Line ${i+1}: need at least 6 columns`); continue; }
      const [question_text, option_a, option_b, option_c, option_d, correct_answer, image_url] = cols;
      const correct = correct_answer.trim().toUpperCase();
      if (!['A','B','C','D'].includes(correct)) { errors.push(`Line ${i+1}: correct_answer must be A/B/C/D`); continue; }
      try {
        await db.prepare(
          'INSERT INTO questions (exam_id,question_text,option_a,option_b,option_c,option_d,correct_answer,image_url) VALUES (?,?,?,?,?,?,?,?)'
        ).bind(exam_id, question_text.trim(), option_a.trim(), option_b.trim(), option_c.trim(), option_d.trim(), correct, image_url ? image_url.trim() : null).run();
        inserted++;
      } catch(e) { errors.push(`Line ${i+1}: ${e.message}`); }
    }
    return json({ inserted, errors });
  }

  // GET /api/admin/users
  if (method === 'GET' && path === '/users') {
    const users = await db.prepare('SELECT id,name,email,is_admin,is_premium_allowed,created_at FROM users ORDER BY created_at DESC').all();
    return json(users.results);
  }

  // POST /api/admin/grant-premium
  if (method === 'POST' && path === '/grant-premium') {
    const { user_id, exam_id } = body;
    if (!user_id || !exam_id) return err('user_id and exam_id required');
    try {
      await db.prepare('INSERT OR IGNORE INTO premium_access (user_id,exam_id,granted_by) VALUES (?,?,?)')
        .bind(user_id, exam_id, user.id).run();
      return json({ message: 'Premium access granted' });
    } catch(e) { return err(e.message); }
  }

  // DELETE /api/admin/revoke-premium
  if (method === 'DELETE' && path === '/revoke-premium') {
    const { user_id, exam_id } = body;
    await db.prepare('DELETE FROM premium_access WHERE user_id=? AND exam_id=?').bind(user_id, exam_id).run();
    return json({ message: 'Access revoked' });
  }

  // GET /api/admin/results — all results
  if (method === 'GET' && path === '/results') {
    const results = await db.prepare(`
      SELECT ea.*, u.name as user_name, u.email as user_email, e.name as exam_name
      FROM exam_attempts ea
      JOIN users u ON ea.user_id = u.id
      JOIN exams e ON ea.exam_id = e.id
      ORDER BY ea.submitted_at DESC
    `).all();
    return json(results.results);
  }

  // GET /api/admin/results/:examId — results for specific exam
  if (method === 'GET' && path.match(/^\/results\/\d+$/)) {
    const examId = parseInt(path.split('/')[2]);
    const results = await db.prepare(`
      SELECT ea.*, u.name as user_name, u.email as user_email, e.name as exam_name
      FROM exam_attempts ea
      JOIN users u ON ea.user_id = u.id
      JOIN exams e ON ea.exam_id = e.id
      WHERE ea.exam_id = ?
      ORDER BY ea.percentage DESC, ea.submitted_at DESC
    `).bind(examId).all();
    return json(results.results);
  }

  // GET /api/admin/premium-grants
  if (method === 'GET' && path === '/premium-grants') {
    const grants = await db.prepare(`
      SELECT pa.*, u.name as user_name, u.email, e.name as exam_name
      FROM premium_access pa
      JOIN users u ON pa.user_id = u.id
      JOIN exams e ON pa.exam_id = e.id
    `).all();
    return json(grants.results);
  }

  return err('Not found', 404);
}

// ═══ MAIN ENTRY ═══

export async function onRequest(context) {
  const { request, env } = context;
  const db = env.DB;

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: CORS });
  }

  await ensureTables(db);

  const url = new URL(request.url);
  const fullPath = url.pathname.replace(/^\/api/, '');

  let body = {};
  if (['POST','PUT','DELETE'].includes(request.method)) {
    try { body = await request.json(); } catch {}
  }

  const user = await getUser(request);

  if (fullPath.startsWith('/auth/')) return handleAuth(request.method, fullPath.replace('/auth',''), body, db);
  if (fullPath.startsWith('/exams')) return handleExams(request.method, fullPath.replace('/exams','') || '/', body, db, user);
  if (fullPath.startsWith('/admin/')) return handleAdmin(request.method, fullPath.replace('/admin',''), body, db, user);

  return err('API route not found', 404);
}
