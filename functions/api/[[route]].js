// functions/api/[[route]].js
// Exalyte — Complete Backend API

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

const SECRET = 'exalyte_prod_secret_2024_x9kLm3nR7pQw';

async function signToken(payload) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify(payload));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `${header}.${body}.${sigB64}`;
}

async function verifyToken(token) {
  try {
    const [header, body, sig] = token.split('.');
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBuf = Uint8Array.from(atob(sig), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBuf, new TextEncoder().encode(`${header}.${body}`));
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
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...CORS } });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

async function ensureTables(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS batches (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS exams (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT, time_limit INTEGER DEFAULT 30, is_premium INTEGER DEFAULT 0, negative_marking REAL DEFAULT 0, allow_practice INTEGER DEFAULT 1, batch_id INTEGER, live_deadline_hours INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS questions (id INTEGER PRIMARY KEY AUTOINCREMENT, exam_id INTEGER NOT NULL, question_text TEXT NOT NULL, option_a TEXT NOT NULL, option_b TEXT NOT NULL, option_c TEXT NOT NULL, option_d TEXT NOT NULL, correct_answer TEXT NOT NULL, image_url TEXT, FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE)`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS exam_attempts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, exam_id INTEGER NOT NULL, score INTEGER DEFAULT 0, total_questions INTEGER DEFAULT 0, percentage REAL DEFAULT 0, answers TEXT, submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS exam_results_stored (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, exam_id INTEGER NOT NULL, score INTEGER DEFAULT 0, total_questions INTEGER DEFAULT 0, percentage REAL DEFAULT 0, answers TEXT, submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP, attempt_number INTEGER DEFAULT 1, is_first_attempt INTEGER DEFAULT 1, is_practice INTEGER DEFAULT 0)`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS premium_access (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, exam_id INTEGER, batch_id INTEGER, grant_scope TEXT DEFAULT 'exam', granted_by INTEGER, granted_at DATETIME DEFAULT CURRENT_TIMESTAMP, expires_at DATETIME)`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS signup_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT NOT NULL, email TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`).run();
}

function parseCSVLine(line) {
  const result = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') { inQuotes = !inQuotes; continue; }
    if (ch === ',' && !inQuotes) { result.push(current.trim()); current = ''; continue; }
    current += ch;
  }
  result.push(current.trim());
  return result;
}

async function checkPremiumAccess(db, userId, examId, userIsAdmin) {
  if (userIsAdmin) return true;
  const userData = await db.prepare('SELECT premium_until FROM users WHERE id=?').bind(userId).first();
  if (userData?.premium_until && new Date(userData.premium_until + ' UTC') > new Date()) return true;
  const grant = await db.prepare('SELECT id, expires_at FROM premium_access WHERE user_id=? AND exam_id=?').bind(userId, examId).first();
  if (grant && (!grant.expires_at || new Date(grant.expires_at + ' UTC') > new Date())) return true;
  return false;
}

// ═══ AUTH ═══
async function handleAuth(method, path, body, db, request) {
  if (method === 'POST' && path === '/signup') {
    const { name, email, password } = body;
    if (!name || !email || !password) return err('All fields required');
    if (password.length < 6) return err('Password must be 6+ characters');
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
    const existingIP = await db.prepare('SELECT id FROM signup_logs WHERE ip_address=?').bind(clientIP).first();
    if (existingIP) return err('An account already exists from this device', 403);
    const hashed = await sha256(password);
    try {
      const result = await db.prepare('INSERT INTO users (name,email,password) VALUES (?,?,?)').bind(name.trim(), email.toLowerCase().trim(), hashed).run();
      await db.prepare('INSERT INTO signup_logs (ip_address,email) VALUES (?,?)').bind(clientIP, email.toLowerCase().trim()).run();
      const user = await db.prepare('SELECT id,name,email,is_admin,is_premium_allowed,premium_until FROM users WHERE id=?').bind(result.meta.last_row_id).first();
      const token = await signToken({ id: user.id, email: user.email, is_admin: user.is_admin, exp: Date.now() + 7*24*60*60*1000 });
      return json({ token, user });
    } catch (e) {
      if (e.message.includes('UNIQUE')) return err('Email already registered');
      return err('Signup failed');
    }
  }
  if (method === 'POST' && path === '/login') {
    const { email, password } = body;
    if (!email || !password) return err('Email and password required');
    const hashed = await sha256(password);
    const user = await db.prepare('SELECT id,name,email,is_admin,is_premium_allowed,premium_until FROM users WHERE email=? AND password=?').bind(email.toLowerCase().trim(), hashed).first();
    if (!user) return err('Invalid email or password', 401);
    const token = await signToken({ id: user.id, email: user.email, is_admin: user.is_admin, exp: Date.now() + 7*24*60*60*1000 });
    return json({ token, user });
  }
  return err('Not found', 404);
}

// ═══ EXAMS ═══
async function handleExams(method, path, body, db, user) {
  if (!user) return err('Unauthorized', 401);

  if (method === 'GET' && path === '/') {
    const allExams = await db.prepare(`SELECT e.*, b.name as batch_name FROM exams e LEFT JOIN batches b ON e.batch_id = b.id ORDER BY b.name ASC, e.created_at DESC`).all();
    const exams = [];
    for (const exam of allExams.results) {
      const qCount = await db.prepare('SELECT COUNT(*) as cnt FROM questions WHERE exam_id=?').bind(exam.id).first();
      const stored = await db.prepare('SELECT id,score,total_questions,percentage,is_practice FROM exam_results_stored WHERE user_id=? AND exam_id=? AND is_first_attempt=1 AND is_practice=0 ORDER BY submitted_at DESC LIMIT 1').bind(user.id, exam.id).first();
      const isPremium = exam.is_premium === 1;
      const accessible = isPremium ? await checkPremiumAccess(db, user.id, exam.id, user.is_admin) : true;
      let isLive = false, liveEndsAt = null, liveSecondsRemaining = 0;
      if (exam.live_deadline_hours > 0) {
        const createdAt = new Date(exam.created_at + ' UTC').getTime();
        const deadline = createdAt + (exam.live_deadline_hours * 60 * 60 * 1000);
        const now = Date.now();
        if (now < deadline) { isLive = true; liveEndsAt = new Date(deadline).toISOString(); liveSecondsRemaining = Math.floor((deadline - now) / 1000); }
      }
      let canPractice = false;
      if (!isLive && stored) canPractice = true;
      exams.push({ ...exam, question_count: qCount.cnt, stored_attempt: stored, accessible, is_live: isLive, live_ends_at: liveEndsAt, live_seconds_remaining: liveSecondsRemaining, can_practice: canPractice });
    }
    return json(exams);
  }

  if (method === 'GET' && path.match(/^\/\d+\/status$/)) {
    const examId = parseInt(path.split('/')[1]);
    const exam = await db.prepare('SELECT * FROM exams WHERE id=?').bind(examId).first();
    if (!exam) return err('Exam not found', 404);
    const now = Date.now();
    const createdAt = new Date(exam.created_at + ' UTC').getTime();
    const deadline = createdAt + (exam.live_deadline_hours * 60 * 60 * 1000);
    const isLiveWindow = exam.live_deadline_hours > 0 && now < deadline;
    const hasLiveAttempt = await db.prepare('SELECT id FROM exam_results_stored WHERE user_id=? AND exam_id=? AND is_practice=0 AND is_first_attempt=1').bind(user.id, examId).first();
    return json({ exam_id: examId, is_live: isLiveWindow, live_ends_at: isLiveWindow ? new Date(deadline).toISOString() : null, live_seconds_remaining: isLiveWindow ? Math.floor((deadline - now) / 1000) : 0, can_attempt_live: isLiveWindow && !hasLiveAttempt, can_practice: !isLiveWindow && !!hasLiveAttempt, has_completed_live: !!hasLiveAttempt, live_deadline_hours: exam.live_deadline_hours });
  }

  if (method === 'GET' && path.match(/^\/\d+\/questions$/)) {
    const examId = parseInt(path.split('/')[1]);
    const exam = await db.prepare('SELECT * FROM exams WHERE id=?').bind(examId).first();
    if (!exam) return err('Exam not found', 404);
    if (exam.is_premium === 1 && !user.is_admin) { const hasAccess = await checkPremiumAccess(db, user.id, examId, user.is_admin); if (!hasAccess) return err('Premium access required', 403); }
    const questions = await db.prepare('SELECT * FROM questions WHERE exam_id=? ORDER BY id').bind(examId).all();
    const safe = questions.results.map(({ correct_answer, ...q }) => q);
    return json({ exam, questions: safe });
  }

  if (method === 'POST' && path.match(/^\/\d+\/submit$/)) {
    const examId = parseInt(path.split('/')[1]);
    const { answers, is_practice } = body;
    if (!answers) return err('Answers required');
    const exam = await db.prepare('SELECT * FROM exams WHERE id=?').bind(examId).first();
    if (!exam) return err('Exam not found', 404);
    const isPracticeMode = is_practice === true || is_practice === 1;
    const now = Date.now();
    const createdAt = new Date(exam.created_at + ' UTC').getTime();
    const deadline = createdAt + (exam.live_deadline_hours * 60 * 60 * 1000);
    const isLiveWindow = exam.live_deadline_hours > 0 && now < deadline;
    if (isPracticeMode) {
      if (isLiveWindow) { const hasLive = await db.prepare('SELECT id FROM exam_results_stored WHERE user_id=? AND exam_id=? AND is_practice=0 AND is_first_attempt=1').bind(user.id, examId).first(); if (!hasLive) return err('You must complete the live exam before practicing', 403); }
    } else {
      if (exam.live_deadline_hours > 0 && !isLiveWindow) return err('Live exam deadline has passed. Use practice mode.', 403);
      if (exam.live_deadline_hours > 0 && isLiveWindow) { const existing = await db.prepare('SELECT id FROM exam_results_stored WHERE user_id=? AND exam_id=? AND is_practice=0 AND is_first_attempt=1').bind(user.id, examId).first(); if (existing) return err('You have already attempted this live exam', 403); }
    }
    const negMark = exam.negative_marking || 0;
    const questions = await db.prepare('SELECT id,correct_answer FROM questions WHERE exam_id=?').bind(examId).all();
    if (!questions.results.length) return err('No questions found');
    let score = 0;
    const total = questions.results.length;
    const detailed = {};
    for (const q of questions.results) {
      const given = (answers[q.id] || '').toUpperCase().trim();
      const correct = q.correct_answer.toUpperCase().trim();
      const isCorrect = given === correct;
      if (isCorrect) score++;
      else if (given && !isCorrect && negMark > 0) score = Math.max(0, score - negMark);
      detailed[q.id] = { given, correct, isCorrect };
    }
    const percentage = Math.round((score / total) * 100);
    const practiceVal = isPracticeMode ? 1 : 0;
    const existingFirst = await db.prepare('SELECT id FROM exam_results_stored WHERE user_id=? AND exam_id=? AND is_first_attempt=1 AND is_practice=0').bind(user.id, examId).first();
    const isFirst = practiceVal ? 0 : (existingFirst ? 0 : 1);
    const attemptNum = await db.prepare('SELECT COUNT(*) as cnt FROM exam_results_stored WHERE user_id=? AND exam_id=?').bind(user.id, examId).first();
    const result = await db.prepare('INSERT INTO exam_results_stored (user_id,exam_id,score,total_questions,percentage,answers,attempt_number,is_first_attempt,is_practice) VALUES (?,?,?,?,?,?,?,?,?)').bind(user.id, examId, score, total, percentage, JSON.stringify(detailed), (attemptNum?.cnt||0)+1, isFirst, practiceVal).run();
    await db.prepare('INSERT INTO exam_attempts (user_id,exam_id,score,total_questions,percentage,answers) VALUES (?,?,?,?,?,?)').bind(user.id, examId, score, total, percentage, JSON.stringify(detailed)).run();
    return json({ attemptId: result.meta.last_row_id, score, total, percentage, answers: detailed, is_first_attempt: !!isFirst, is_practice: !!practiceVal });
  }

  if (method === 'GET' && path.match(/^\/\d+\/result\/\d+$/)) {
    const parts = path.split('/');
    const examId = parseInt(parts[1]), attemptId = parseInt(parts[3]);
    const attempt = await db.prepare('SELECT * FROM exam_results_stored WHERE id=? AND user_id=?').bind(attemptId, user.id).first();
    if (!attempt) return err('Result not found', 404);
    const exam = await db.prepare('SELECT * FROM exams WHERE id=?').bind(examId).first();
    const questions = await db.prepare('SELECT * FROM questions WHERE exam_id=? ORDER BY id').bind(examId).all();
    return json({ attempt: { ...attempt, answers: JSON.parse(attempt.answers || '{}') }, exam, questions: questions.results });
  }
  return err('Not found', 404);
}

// ═══ LEADERBOARD ═══
async function handleLeaderboard(method, path, db, user) {
  if (!user) return err('Unauthorized', 401);
  if (method === 'GET' && path.match(/^\/\d+$/)) {
    const examId = parseInt(path.split('/')[1]);
    const results = await db.prepare(`SELECT user_id, score, total_questions, percentage, ROW_NUMBER() OVER (ORDER BY percentage DESC, submitted_at ASC) as rank FROM exam_results_stored WHERE exam_id=? AND is_first_attempt=1 AND is_practice=0 ORDER BY percentage DESC, submitted_at ASC`).bind(examId).all();
    const totalParticipants = results.results.length;
    const userResult = results.results.find(r => r.user_id === user.id);
    if (!userResult) return json({ attempted: false, total_participants: totalParticipants });
    return json({ attempted: true, rank: userResult.rank, total_participants: totalParticipants, percentile: Math.round((1 - (userResult.rank / totalParticipants)) * 100), score: userResult.score, total_questions: userResult.total_questions, percentage: userResult.percentage, exam_id: examId });
  }
  return err('Not found', 404);
}

// ═══ HISTORY ═══
async function handleHistory(method, path, db, user) {
  if (!user) return err('Unauthorized', 401);
  if (method === 'GET' && path === '/') {
    const results = await db.prepare(`SELECT r.id as attempt_id, r.exam_id, r.score, r.total_questions, r.percentage, r.submitted_at, r.is_practice, e.name as exam_name, e.time_limit, b.name as batch_name FROM exam_results_stored r JOIN exams e ON r.exam_id = e.id LEFT JOIN batches b ON e.batch_id = b.id WHERE r.user_id=? AND r.is_first_attempt=1 AND r.is_practice=0 ORDER BY r.submitted_at DESC`).bind(user.id).all();
    const history = await Promise.all(results.results.map(async (row) => {
      const stats = await db.prepare('SELECT COUNT(*) as total_participants FROM exam_results_stored WHERE exam_id=? AND is_first_attempt=1 AND is_practice=0').bind(row.exam_id).first();
      const rankRow = await db.prepare('SELECT COUNT(*)+1 as rank FROM exam_results_stored WHERE exam_id=? AND is_first_attempt=1 AND is_practice=0 AND percentage > ?').bind(row.exam_id, row.percentage).first();
      return { ...row, rank: rankRow.rank, total_participants: stats.total_participants, percentile: Math.round((1 - (rankRow.rank / stats.total_participants)) * 100) };
    }));
    return json(history);
  }
  return err('Not found', 404);
}

// ═══ BATCHES ═══
async function handleBatches(method, path, body, db, user) {
  if (!user) return err('Unauthorized', 401);
  if (method === 'GET' && path === '/') {
    const batches = await db.prepare('SELECT b.*, COUNT(e.id) as exam_count FROM batches b LEFT JOIN exams e ON b.id = e.batch_id GROUP BY b.id ORDER BY b.name').all();
    return json(batches.results);
  }
  return err('Not found', 404);
}

// ═══ ADMIN ═══
async function handleAdmin(method, path, body, db, user) {
  if (!user) return err('Unauthorized', 401);
  if (!user.is_admin) return err('Admin access required', 403);

  if (method === 'POST' && path === '/batches') {
    const { name, description } = body;
    if (!name) return err('Batch name required');
    const result = await db.prepare('INSERT INTO batches (name, description) VALUES (?,?)').bind(name.trim(), description||'').run();
    return json({ id: result.meta.last_row_id, message: 'Batch created' });
  }
  if (method === 'DELETE' && path.match(/^\/batches\/\d+$/)) {
    const batchId = parseInt(path.split('/')[2]);
    await db.prepare('UPDATE exams SET batch_id=NULL WHERE batch_id=?').bind(batchId).run();
    await db.prepare('DELETE FROM batches WHERE id=?').bind(batchId).run();
    return json({ message: 'Batch deleted' });
  }
  if (method === 'POST' && path === '/exams') {
    const { name, description, time_limit, is_premium, negative_marking, allow_practice, batch_id, live_deadline_hours } = body;
    if (!name) return err('Exam name required');
    const result = await db.prepare('INSERT INTO exams (name,description,time_limit,is_premium,negative_marking,allow_practice,batch_id,live_deadline_hours) VALUES (?,?,?,?,?,?,?,?)').bind(name.trim(), description||'', time_limit||30, is_premium?1:0, negative_marking||0, allow_practice!==undefined?(allow_practice?1:0):1, batch_id||null, live_deadline_hours||0).run();
    return json({ id: result.meta.last_row_id, message: 'Exam created' });
  }
  if (method === 'PUT' && path.match(/^\/exams\/\d+$/)) {
    const examId = parseInt(path.split('/')[2]);
    const { name, description, time_limit, is_premium, negative_marking, allow_practice, batch_id, live_deadline_hours } = body;
    const updates = [], values = [];
    if (name !== undefined) { updates.push('name=?'); values.push(name.trim()); }
    if (description !== undefined) { updates.push('description=?'); values.push(description); }
    if (time_limit !== undefined) { updates.push('time_limit=?'); values.push(time_limit); }
    if (is_premium !== undefined) { updates.push('is_premium=?'); values.push(is_premium?1:0); }
    if (negative_marking !== undefined) { updates.push('negative_marking=?'); values.push(negative_marking); }
    if (allow_practice !== undefined) { updates.push('allow_practice=?'); values.push(allow_practice?1:0); }
    if (batch_id !== undefined) { updates.push('batch_id=?'); values.push(batch_id||null); }
    if (live_deadline_hours !== undefined) { updates.push('live_deadline_hours=?'); values.push(live_deadline_hours); }
    if (!updates.length) return err('Nothing to update');
    values.push(examId);
    await db.prepare(`UPDATE exams SET ${updates.join(',')} WHERE id=?`).bind(...values).run();
    return json({ message: 'Exam updated' });
  }
  if (method === 'DELETE' && path.match(/^\/exams\/\d+$/)) {
    const examId = parseInt(path.split('/')[2]);
    await db.prepare('DELETE FROM questions WHERE exam_id=?').bind(examId).run();
    await db.prepare('DELETE FROM exam_attempts WHERE exam_id=?').bind(examId).run();
    await db.prepare('DELETE FROM exam_results_stored WHERE exam_id=?').bind(examId).run();
    await db.prepare('DELETE FROM premium_access WHERE exam_id=?').bind(examId).run();
    await db.prepare('DELETE FROM exams WHERE id=?').bind(examId).run();
    return json({ message: 'Exam deleted' });
  }
  if (method === 'DELETE' && path.match(/^\/results\/\d+$/)) {
    await db.prepare('DELETE FROM exam_results_stored WHERE id=?').bind(parseInt(path.split('/')[2])).run();
    return json({ message: 'Result deleted' });
  }
  if (method === 'DELETE' && path.match(/^\/questions\/\d+$/)) {
    await db.prepare('DELETE FROM questions WHERE exam_id=?').bind(parseInt(path.split('/')[2])).run();
    return json({ message: 'Questions deleted' });
  }
  if (method === 'DELETE' && path.match(/^\/questions\/single\/\d+$/)) {
    await db.prepare('DELETE FROM questions WHERE id=?').bind(parseInt(path.split('/')[3])).run();
    return json({ message: 'Question deleted' });
  }
  if (method === 'GET' && path.match(/^\/questions\/\d+$/)) {
    const questions = await db.prepare('SELECT * FROM questions WHERE exam_id=? ORDER BY id').bind(parseInt(path.split('/')[2])).all();
    return json(questions.results);
  }
  if (method === 'POST' && path === '/questions/bulk') {
    const { exam_id, csv } = body;
    if (!exam_id || !csv) return err('exam_id and csv required');
    const lines = csv.trim().split('\n').filter(l => l.trim());
    let inserted = 0;
    const errors = [];
    for (let i = 0; i < lines.length; i++) {
      const cols = parseCSVLine(lines[i].trim());
      if (cols.length < 6) { errors.push(`Line ${i+1}: need 6+ columns`); continue; }
      const [qt, oa, ob, oc, od, ca, iu] = cols;
      const correct = ca.trim().toUpperCase();
      if (!['A','B','C','D'].includes(correct)) { errors.push(`Line ${i+1}: answer must be A/B/C/D`); continue; }
      try {
        await db.prepare('INSERT INTO questions (exam_id,question_text,option_a,option_b,option_c,option_d,correct_answer,image_url) VALUES (?,?,?,?,?,?,?,?)').bind(exam_id, qt.trim(), oa.trim(), ob.trim(), oc.trim(), od.trim(), correct, iu?iu.trim():null).run();
        inserted++;
      } catch(e) { errors.push(`Line ${i+1}: ${e.message}`); }
    }
    return json({ inserted, errors });
  }
  if (method === 'GET' && path === '/users') {
    const users = await db.prepare('SELECT id,name,email,is_admin,is_premium_allowed,premium_until,created_at FROM users ORDER BY created_at DESC').all();
    return json(users.results);
  }
  if (method === 'POST' && path === '/grant-premium') {
    const { user_id, exam_id, batch_id, grant_scope, duration_hours } = body;
    if (!user_id || !grant_scope) return err('user_id and grant_scope required');
    let expires_at = null;
    if (duration_hours && duration_hours > 0) { const d = new Date(Date.now() + duration_hours * 60 * 60 * 1000); expires_at = d.toISOString().replace('T',' ').substring(0,19); }
    try {
      if (grant_scope === 'account') {
        await db.prepare('UPDATE users SET premium_until=?, is_premium_allowed=1 WHERE id=?').bind(expires_at, user_id).run();
        return json({ message: 'Account-wide premium granted', expires_at });
      }
      if (grant_scope === 'batch') {
        if (!batch_id) return err('batch_id required for batch grants');
        const exams = await db.prepare('SELECT id FROM exams WHERE batch_id=?').bind(batch_id).all();
        for (const e of exams.results) {
          await db.prepare('DELETE FROM premium_access WHERE user_id=? AND exam_id=?').bind(user_id, e.id).run();
          await db.prepare('INSERT INTO premium_access (user_id,exam_id,batch_id,grant_scope,granted_by,expires_at) VALUES (?,?,?,?,?,?)').bind(user_id, e.id, batch_id, 'batch', user.id, expires_at).run();
        }
        return json({ message: `Batch access granted for ${exams.results.length} exams`, expires_at });
      }
      if (!exam_id) return err('exam_id required for exam grants');
      await db.prepare('DELETE FROM premium_access WHERE user_id=? AND exam_id=?').bind(user_id, exam_id).run();
      await db.prepare('INSERT INTO premium_access (user_id,exam_id,grant_scope,granted_by,expires_at) VALUES (?,?,?,?,?)').bind(user_id, exam_id, 'exam', user.id, expires_at).run();
      return json({ message: 'Exam access granted', expires_at });
    } catch(e) { return err(e.message); }
  }
  if (method === 'DELETE' && path === '/revoke-premium') {
    const { user_id, exam_id } = body;
    await db.prepare('DELETE FROM premium_access WHERE user_id=? AND exam_id=?').bind(user_id, exam_id).run();
    return json({ message: 'Access revoked' });
  }
  if (method === 'DELETE' && path === '/revoke-account-premium') {
    const { user_id } = body;
    await db.prepare('UPDATE users SET premium_until=NULL, is_premium_allowed=0 WHERE id=?').bind(user_id).run();
    return json({ message: 'Account premium revoked' });
  }
  if (method === 'GET' && path === '/results') {
    const results = await db.prepare(`SELECT er.*, u.name as user_name, u.email as user_email, e.name as exam_name FROM exam_results_stored er JOIN users u ON er.user_id=u.id JOIN exams e ON er.exam_id=e.id WHERE er.is_first_attempt=1 AND er.is_practice=0 ORDER BY er.submitted_at DESC`).all();
    return json(results.results);
  }
  if (method === 'GET' && path.match(/^\/results\/\d+$/)) {
    const examId = parseInt(path.split('/')[2]);
    const results = await db.prepare(`SELECT er.*, u.name as user_name, u.email as user_email, e.name as exam_name FROM exam_results_stored er JOIN users u ON er.user_id=u.id JOIN exams e ON er.exam_id=e.id WHERE er.exam_id=? AND er.is_first_attempt=1 AND er.is_practice=0 ORDER BY er.percentage DESC, er.submitted_at DESC`).bind(examId).all();
    return json(results.results);
  }
  if (method === 'GET' && path === '/premium-grants') {
    const grants = await db.prepare(`SELECT pa.*, u.name as user_name, u.email, e.name as exam_name, b.name as batch_name FROM premium_access pa JOIN users u ON pa.user_id=u.id LEFT JOIN exams e ON pa.exam_id=e.id LEFT JOIN batches b ON pa.batch_id=b.id ORDER BY pa.granted_at DESC`).all();
    return json(grants.results);
  }
  return err('Not found', 404);
}

// ═══ MAIN ═══
export async function onRequest(context) {
  const { request, env } = context;
  const db = env.DB;
  if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });
  await ensureTables(db);
  const url = new URL(request.url);
  const fullPath = url.pathname.replace(/^\/api/, '') || '/';
  let body = {};
  if (['POST','PUT','DELETE'].includes(request.method)) { try { body = await request.json(); } catch {} }
  const authUser = await getUser(request);
  if (fullPath.startsWith('/auth/')) return handleAuth(request.method, fullPath.replace('/auth',''), body, db, request);
  if (fullPath.startsWith('/admin/')) return handleAdmin(request.method, fullPath.replace('/admin',''), body, db, authUser);
  if (fullPath.startsWith('/leaderboard/')) return handleLeaderboard(request.method, fullPath.replace('/leaderboard',''), db, authUser);
  if (fullPath.startsWith('/history')) return handleHistory(request.method, fullPath.replace('/history',''), db, authUser);
  if (fullPath.startsWith('/batches')) return handleBatches(request.method, fullPath.replace('/batches',''), body, db, authUser);
  if (fullPath.startsWith('/exams')) return handleExams(request.method, fullPath.replace('/exams','')||'/', body, db, authUser);
  return err('API route not found', 404);
}
