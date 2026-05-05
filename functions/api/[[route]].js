// functions/api/[[route]].js
// Exalyte — Cloudflare Pages Functions — Complete Backend
// All routes, no compression, fully documented

// ═══════════════ UTILITIES ═══════════════

async function sha256(text) {
  const buffer = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(text)
  );
  const hashArray = Array.from(new Uint8Array(buffer));
  const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
  return hashHex;
}

const JWT_SECRET = 'exalyte_prod_secret_2024_x9kLm3nR7pQw';

async function signToken(payload) {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify(payload));

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(JWT_SECRET),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(`${header}.${body}`)
  );

  const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));

  return `${header}.${body}.${signatureBase64}`;
}

async function verifyToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const [header, body, signature] = parts;

    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(JWT_SECRET),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const signatureBytes = Uint8Array.from(atob(signature), character => character.charCodeAt(0));

    const isValid = await crypto.subtle.verify(
      'HMAC',
      key,
      signatureBytes,
      new TextEncoder().encode(`${header}.${body}`)
    );

    if (!isValid) {
      return null;
    }

    const payload = JSON.parse(atob(body));

    if (payload.exp && Date.now() > payload.exp) {
      return null;
    }

    return payload;
  } catch (error) {
    return null;
  }
}

async function getUser(request) {
  const authorizationHeader = request.headers.get('Authorization') || '';
  const token = authorizationHeader.replace('Bearer ', '').trim();

  if (!token) {
    return null;
  }

  return verifyToken(token);
}

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...CORS_HEADERS,
    },
  });
}

function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}

function parseCSVLine(line) {
  const result = [];
  let current = '';
  let insideQuotes = false;

  for (let index = 0; index < line.length; index++) {
    const character = line[index];

    if (character === '"') {
      insideQuotes = !insideQuotes;
      continue;
    }

    if (character === ',' && !insideQuotes) {
      result.push(current.trim());
      current = '';
      continue;
    }

    current += character;
  }

  result.push(current.trim());

  return result;
}

// ═══════════════ DATABASE SETUP ═══════════════

async function ensureDatabaseTables(db) {
  // Users table
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      is_admin INTEGER DEFAULT 0,
      is_premium_allowed INTEGER DEFAULT 0,
      premium_until DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  // Batches table (exam groups/folders)
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS batches (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  // Exams table
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS exams (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      time_limit INTEGER DEFAULT 30,
      is_premium INTEGER DEFAULT 0,
      negative_marking REAL DEFAULT 0,
      allow_practice INTEGER DEFAULT 1,
      batch_id INTEGER,
      live_deadline_hours INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (batch_id) REFERENCES batches(id) ON DELETE SET NULL
    )
  `).run();

  // Questions table
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS questions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      exam_id INTEGER NOT NULL,
      question_text TEXT NOT NULL,
      option_a TEXT NOT NULL,
      option_b TEXT NOT NULL,
      option_c TEXT NOT NULL,
      option_d TEXT NOT NULL,
      correct_answer TEXT NOT NULL,
      image_url TEXT,
      FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE
    )
  `).run();

  // Exam attempts table (all attempts for logging)
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS exam_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      exam_id INTEGER NOT NULL,
      score INTEGER DEFAULT 0,
      total_questions INTEGER DEFAULT 0,
      percentage REAL DEFAULT 0,
      answers TEXT,
      submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  // Exam results stored table (first attempts + practice tracking)
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS exam_results_stored (
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
    )
  `).run();

  // Premium access table (per-exam and per-batch grants)
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS premium_access (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      exam_id INTEGER,
      batch_id INTEGER,
      grant_scope TEXT DEFAULT 'exam',
      granted_by INTEGER,
      granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (exam_id) REFERENCES exams(id) ON DELETE CASCADE,
      FOREIGN KEY (batch_id) REFERENCES batches(id) ON DELETE CASCADE
    )
  `).run();

  // Signup logs table (IP tracking for account limiting)
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS signup_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip_address TEXT NOT NULL,
      email TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();
}

// ═══════════════ PREMIUM ACCESS CHECKER ═══════════════

async function checkPremiumAccess(db, userId, examId, userIsAdmin) {
  // Admins always have access
  if (userIsAdmin) {
    return true;
  }

  // Check account-wide premium
  const userData = await db.prepare(
    'SELECT premium_until FROM users WHERE id = ?'
  ).bind(userId).first();

  if (userData && userData.premium_until) {
    const expiryDate = new Date(userData.premium_until + ' UTC');
    const now = new Date();

    if (expiryDate > now) {
      return true;
    }
  }

  // Check per-exam and per-batch grants
  const grant = await db.prepare(
    'SELECT id, expires_at FROM premium_access WHERE user_id = ? AND exam_id = ?'
  ).bind(userId, examId).first();

  if (grant) {
    if (!grant.expires_at) {
      return true;
    }

    const grantExpiry = new Date(grant.expires_at + ' UTC');
    const now = new Date();

    if (grantExpiry > now) {
      return true;
    }
  }

  return false;
}

// ═══════════════ AUTH HANDLERS ═══════════════

async function handleAuth(method, path, body, db, request) {
  // POST /api/auth/signup
  if (method === 'POST' && path === '/signup') {
    const { name, email, password } = body;

    if (!name || !email || !password) {
      return errorResponse('All fields are required');
    }

    if (password.length < 6) {
      return errorResponse('Password must be at least 6 characters');
    }

    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

    // Check if this IP already has an account
    const existingIPAccount = await db.prepare(
      'SELECT id FROM users WHERE id IN (SELECT id FROM users WHERE email IN (SELECT email FROM signup_logs WHERE ip_address = ?))'
    ).bind(clientIP).first();

    if (existingIPAccount) {
      return errorResponse('An account already exists from this device', 403);
    }

    const hashedPassword = await sha256(password);

    try {
      const result = await db.prepare(
        'INSERT INTO users (name, email, password) VALUES (?, ?, ?)'
      ).bind(name.trim(), email.toLowerCase().trim(), hashedPassword).run();

      // Log the signup for IP tracking
      await db.prepare(
        'INSERT INTO signup_logs (ip_address, email) VALUES (?, ?)'
      ).bind(clientIP, email.toLowerCase().trim()).run();

      const user = await db.prepare(
        'SELECT id, name, email, is_admin, is_premium_allowed, premium_until FROM users WHERE id = ?'
      ).bind(result.meta.last_row_id).first();

      const token = await signToken({
        id: user.id,
        email: user.email,
        is_admin: user.is_admin,
        exp: Date.now() + (7 * 24 * 60 * 60 * 1000)
      });

      return jsonResponse({ token, user });
    } catch (error) {
      if (error.message && error.message.includes('UNIQUE')) {
        return errorResponse('Email is already registered');
      }
      return errorResponse('Signup failed. Please try again.');
    }
  }

  // POST /api/auth/login
  if (method === 'POST' && path === '/login') {
    const { email, password } = body;

    if (!email || !password) {
      return errorResponse('Email and password are required');
    }

    const hashedPassword = await sha256(password);

    const user = await db.prepare(
      'SELECT id, name, email, is_admin, is_premium_allowed, premium_until FROM users WHERE email = ? AND password = ?'
    ).bind(email.toLowerCase().trim(), hashedPassword).first();

    if (!user) {
      return errorResponse('Invalid email or password', 401);
    }

    const token = await signToken({
      id: user.id,
      email: user.email,
      is_admin: user.is_admin,
      exp: Date.now() + (7 * 24 * 60 * 60 * 1000)
    });

    return jsonResponse({ token, user });
  }

  return errorResponse('Route not found', 404);
}

// ═══════════════ EXAM HANDLERS ═══════════════

async function handleExams(method, path, body, db, user) {
  if (!user) {
    return errorResponse('Unauthorized', 401);
  }

  // GET /api/exams/ — List all exams for dashboard
  if (method === 'GET' && path === '/') {
    const allExams = await db.prepare(`
      SELECT
        e.*,
        b.name as batch_name
      FROM exams e
      LEFT JOIN batches b ON e.batch_id = b.id
      ORDER BY b.name ASC, e.created_at DESC
    `).all();

    const exams = [];

    for (const exam of allExams.results) {
      const questionCount = await db.prepare(
        'SELECT COUNT(*) as count FROM questions WHERE exam_id = ?'
      ).bind(exam.id).first();

      const storedAttempt = await db.prepare(
        'SELECT id, score, total_questions, percentage, is_practice FROM exam_results_stored WHERE user_id = ? AND exam_id = ? AND is_first_attempt = 1 AND is_practice = 0 ORDER BY submitted_at DESC LIMIT 1'
      ).bind(user.id, exam.id).first();

      const isPremium = exam.is_premium === 1;
      const accessible = isPremium ? await checkPremiumAccess(db, user.id, exam.id, user.is_admin) : true;

      // Calculate live exam status
      let isLive = false;
      let liveEndsAt = null;
      let liveSecondsRemaining = 0;

      if (exam.live_deadline_hours > 0) {
        const createdAt = new Date(exam.created_at + ' UTC').getTime();
        const deadline = createdAt + (exam.live_deadline_hours * 60 * 60 * 1000);
        const now = Date.now();

        if (now < deadline) {
          isLive = true;
          liveEndsAt = new Date(deadline).toISOString();
          liveSecondsRemaining = Math.floor((deadline - now) / 1000);
        }
      }

      // Check if practice is available
      let canPractice = false;
      if (!isLive && storedAttempt) {
        canPractice = true;
      }

      exams.push({
        ...exam,
        question_count: questionCount.count,
        stored_attempt: storedAttempt,
        accessible: accessible,
        is_live: isLive,
        live_ends_at: liveEndsAt,
        live_seconds_remaining: liveSecondsRemaining,
        can_practice: canPractice
      });
    }

    return jsonResponse(exams);
  }

  // GET /api/exams/:id/status — Check if user can take live exam or practice
  if (method === 'GET' && path.match(/^\/\d+\/status$/)) {
    const examId = parseInt(path.split('/')[1]);
    const exam = await db.prepare('SELECT * FROM exams WHERE id = ?').bind(examId).first();

    if (!exam) {
      return errorResponse('Exam not found', 404);
    }

    const now = Date.now();
    const createdAt = new Date(exam.created_at + ' UTC').getTime();
    const deadline = createdAt + (exam.live_deadline_hours * 60 * 60 * 1000);
    const isLiveWindow = exam.live_deadline_hours > 0 && now < deadline;

    const hasLiveAttempt = await db.prepare(
      'SELECT id FROM exam_results_stored WHERE user_id = ? AND exam_id = ? AND is_practice = 0 AND is_first_attempt = 1'
    ).bind(user.id, examId).first();

    const canPractice = !isLiveWindow && !!hasLiveAttempt;
    const canAttemptLive = isLiveWindow && !hasLiveAttempt;

    return jsonResponse({
      exam_id: examId,
      is_live: isLiveWindow,
      live_ends_at: isLiveWindow ? new Date(deadline).toISOString() : null,
      live_seconds_remaining: isLiveWindow ? Math.floor((deadline - now) / 1000) : 0,
      can_attempt_live: canAttemptLive,
      can_practice: canPractice,
      has_completed_live: !!hasLiveAttempt,
      live_deadline_hours: exam.live_deadline_hours
    });
  }

  // GET /api/exams/:id/questions — Get questions for taking an exam
  if (method === 'GET' && path.match(/^\/\d+\/questions$/)) {
    const examId = parseInt(path.split('/')[1]);
    const exam = await db.prepare('SELECT * FROM exams WHERE id = ?').bind(examId).first();

    if (!exam) {
      return errorResponse('Exam not found', 404);
    }

    // Check premium access
    if (exam.is_premium === 1 && !user.is_admin) {
      const hasAccess = await checkPremiumAccess(db, user.id, examId, user.is_admin);
      if (!hasAccess) {
        return errorResponse('Premium access required for this exam', 403);
      }
    }

    const questions = await db.prepare(
      'SELECT * FROM questions WHERE exam_id = ? ORDER BY id'
    ).bind(examId).all();

    // Remove correct_answer from the response
    const safeQuestions = questions.results.map(question => {
      const { correct_answer, ...rest } = question;
      return rest;
    });

    return jsonResponse({
      exam: exam,
      questions: safeQuestions
    });
  }

  // POST /api/exams/:id/submit — Submit exam answers
  if (method === 'POST' && path.match(/^\/\d+\/submit$/)) {
    const examId = parseInt(path.split('/')[1]);
    const { answers, is_practice } = body;

    if (!answers) {
      return errorResponse('Answers are required');
    }

    const exam = await db.prepare('SELECT * FROM exams WHERE id = ?').bind(examId).first();

    if (!exam) {
      return errorResponse('Exam not found', 404);
    }

    const isPracticeMode = is_practice === true || is_practice === 1;
    const now = Date.now();
    const createdAt = new Date(exam.created_at + ' UTC').getTime();
    const deadline = createdAt + (exam.live_deadline_hours * 60 * 60 * 1000);
    const isLiveWindow = exam.live_deadline_hours > 0 && now < deadline;

    // Validate access based on mode
    if (isPracticeMode) {
      if (isLiveWindow) {
        const hasLiveAttempt = await db.prepare(
          'SELECT id FROM exam_results_stored WHERE user_id = ? AND exam_id = ? AND is_practice = 0 AND is_first_attempt = 1'
        ).bind(user.id, examId).first();

        if (!hasLiveAttempt) {
          return errorResponse('You must complete the live exam before practicing', 403);
        }
      }
    } else {
      // Live exam mode validation
      if (exam.live_deadline_hours > 0 && !isLiveWindow) {
        return errorResponse('The live exam deadline has passed. Please use practice mode.', 403);
      }

      if (exam.live_deadline_hours > 0 && isLiveWindow) {
        const existingLiveAttempt = await db.prepare(
          'SELECT id FROM exam_results_stored WHERE user_id = ? AND exam_id = ? AND is_practice = 0 AND is_first_attempt = 1'
        ).bind(user.id, examId).first();

        if (existingLiveAttempt) {
          return errorResponse('You have already attempted this live exam', 403);
        }
      }
    }

    const negativeMarking = exam.negative_marking || 0;
    const questions = await db.prepare(
      'SELECT id, correct_answer FROM questions WHERE exam_id = ?'
    ).bind(examId).all();

    if (!questions.results.length) {
      return errorResponse('No questions found for this exam');
    }

    let score = 0;
    const totalQuestions = questions.results.length;
    const detailedAnswers = {};

    for (const question of questions.results) {
      const givenAnswer = (answers[question.id] || '').toUpperCase().trim();
      const correctAnswer = question.correct_answer.toUpperCase().trim();
      const isCorrect = givenAnswer === correctAnswer;

      if (isCorrect) {
        score++;
      } else if (givenAnswer && !isCorrect && negativeMarking > 0) {
        score = Math.max(0, score - negativeMarking);
      }

      detailedAnswers[question.id] = {
        given: givenAnswer,
        correct: correctAnswer,
        isCorrect: isCorrect
      };
    }

    const percentage = Math.round((score / totalQuestions) * 100);
    const practiceValue = isPracticeMode ? 1 : 0;

    // Check if this is the first non-practice attempt
    const existingFirstAttempt = await db.prepare(
      'SELECT id FROM exam_results_stored WHERE user_id = ? AND exam_id = ? AND is_first_attempt = 1 AND is_practice = 0'
    ).bind(user.id, examId).first();

    const isFirstAttempt = practiceValue ? 0 : (existingFirstAttempt ? 0 : 1);

    // Count existing attempts for numbering
    const attemptCount = await db.prepare(
      'SELECT COUNT(*) as count FROM exam_results_stored WHERE user_id = ? AND exam_id = ?'
    ).bind(user.id, examId).first();

    const attemptNumber = (attemptCount?.count || 0) + 1;

    // Store the result
    const result = await db.prepare(`
      INSERT INTO exam_results_stored
        (user_id, exam_id, score, total_questions, percentage, answers, attempt_number, is_first_attempt, is_practice)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      user.id,
      examId,
      score,
      totalQuestions,
      percentage,
      JSON.stringify(detailedAnswers),
      attemptNumber,
      isFirstAttempt,
      practiceValue
    ).run();

    // Also log in exam_attempts for audit
    await db.prepare(`
      INSERT INTO exam_attempts (user_id, exam_id, score, total_questions, percentage, answers)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      user.id,
      examId,
      score,
      totalQuestions,
      percentage,
      JSON.stringify(detailedAnswers)
    ).run();

    return jsonResponse({
      attemptId: result.meta.last_row_id,
      score: score,
      total: totalQuestions,
      percentage: percentage,
      answers: detailedAnswers,
      is_first_attempt: !!isFirstAttempt,
      is_practice: !!practiceValue
    });
  }

  // GET /api/exams/:id/result/:attemptId — Get detailed result
  if (method === 'GET' && path.match(/^\/\d+\/result\/\d+$/)) {
    const parts = path.split('/');
    const examId = parseInt(parts[1]);
    const attemptId = parseInt(parts[3]);

    const attempt = await db.prepare(
      'SELECT * FROM exam_results_stored WHERE id = ? AND user_id = ?'
    ).bind(attemptId, user.id).first();

    if (!attempt) {
      return errorResponse('Result not found', 404);
    }

    const exam = await db.prepare('SELECT * FROM exams WHERE id = ?').bind(examId).first();
    const questions = await db.prepare(
      'SELECT * FROM questions WHERE exam_id = ? ORDER BY id'
    ).bind(examId).all();

    return jsonResponse({
      attempt: {
        ...attempt,
        answers: JSON.parse(attempt.answers || '{}')
      },
      exam: exam,
      questions: questions.results
    });
  }

  return errorResponse('Route not found', 404);
}

// ═══════════════ LEADERBOARD HANDLER ═══════════════

async function handleLeaderboard(method, path, db, user) {
  if (!user) {
    return errorResponse('Unauthorized', 401);
  }

  // GET /api/leaderboard/:examId — Get user's rank for an exam
  if (method === 'GET' && path.match(/^\/\d+$/)) {
    const examId = parseInt(path.split('/')[1]);

    // Get all first attempts for this exam, ordered by percentage
    const allResults = await db.prepare(`
      SELECT
        user_id,
        score,
        total_questions,
        percentage,
        ROW_NUMBER() OVER (ORDER BY percentage DESC, submitted_at ASC) as rank
      FROM exam_results_stored
      WHERE exam_id = ? AND is_first_attempt = 1 AND is_practice = 0
      ORDER BY percentage DESC, submitted_at ASC
    `).bind(examId).all();

    const totalParticipants = allResults.results.length;
    const userResult = allResults.results.find(row => row.user_id === user.id);

    if (!userResult) {
      return jsonResponse({
        attempted: false,
        total_participants: totalParticipants
      });
    }

    const percentile = totalParticipants > 0
      ? Math.round((1 - (userResult.rank / totalParticipants)) * 100)
      : 100;

    return jsonResponse({
      attempted: true,
      rank: userResult.rank,
      total_participants: totalParticipants,
      percentile: percentile,
      score: userResult.score,
      total_questions: userResult.total_questions,
      percentage: userResult.percentage,
      exam_id: examId
    });
  }

  return errorResponse('Route not found', 404);
}

// ═══════════════ HISTORY HANDLER ═══════════════

async function handleHistory(method, path, db, user) {
  if (!user) {
    return errorResponse('Unauthorized', 401);
  }

  // GET /api/history — Get all exams user has participated in with rankings
  if (method === 'GET' && path === '/') {
    const results = await db.prepare(`
      SELECT
        r.id as attempt_id,
        r.exam_id,
        r.score,
        r.total_questions,
        r.percentage,
        r.submitted_at,
        r.is_practice,
        e.name as exam_name,
        e.time_limit,
        b.name as batch_name
      FROM exam_results_stored r
      JOIN exams e ON r.exam_id = e.id
      LEFT JOIN batches b ON e.batch_id = b.id
      WHERE r.user_id = ? AND r.is_first_attempt = 1 AND r.is_practice = 0
      ORDER BY r.submitted_at DESC
    `).bind(user.id).all();

    // For each exam, calculate rank and total participants
    const historyWithRankings = await Promise.all(
      results.results.map(async (row) => {
        // Count total participants for this exam
        const participantStats = await db.prepare(`
          SELECT COUNT(*) as total_participants
          FROM exam_results_stored
          WHERE exam_id = ? AND is_first_attempt = 1 AND is_practice = 0
        `).bind(row.exam_id).first();

        // Find user's rank (how many scored higher)
        const rankData = await db.prepare(`
          SELECT COUNT(*) + 1 as rank
          FROM exam_results_stored
          WHERE exam_id = ? AND is_first_attempt = 1 AND is_practice = 0 AND percentage > ?
        `).bind(row.exam_id, row.percentage).first();

        const totalParticipants = participantStats.total_participants;
        const userRank = rankData.rank;

        const percentile = totalParticipants > 0
          ? Math.round((1 - (userRank / totalParticipants)) * 100)
          : 100;

        return {
          attempt_id: row.attempt_id,
          exam_id: row.exam_id,
          exam_name: row.exam_name,
          batch_name: row.batch_name,
          score: row.score,
          total_questions: row.total_questions,
          percentage: row.percentage,
          submitted_at: row.submitted_at,
          time_limit: row.time_limit,
          rank: userRank,
          total_participants: totalParticipants,
          percentile: percentile
        };
      })
    );

    return jsonResponse(historyWithRankings);
  }

  return errorResponse('Route not found', 404);
}

// ═══════════════ BATCH HANDLERS ═══════════════

async function handleBatches(method, path, body, db, user) {
  if (!user) {
    return errorResponse('Unauthorized', 401);
  }

  // GET /api/batches — List all batches with exam count
  if (method === 'GET' && path === '/') {
    const batches = await db.prepare(`
      SELECT
        b.*,
        COUNT(e.id) as exam_count
      FROM batches b
      LEFT JOIN exams e ON b.id = e.batch_id
      GROUP BY b.id
      ORDER BY b.name ASC
    `).all();

    return jsonResponse(batches.results);
  }

  return errorResponse('Route not found', 404);
}

// ═══════════════ ADMIN HANDLERS ═══════════════

async function handleAdmin(method, path, body, db, user) {
  if (!user) {
    return errorResponse('Unauthorized', 401);
  }

  if (!user.is_admin) {
    return errorResponse('Admin access required', 403);
  }

  // ═══════════ BATCH MANAGEMENT ═══════════

  // POST /api/admin/batches — Create a new batch
  if (method === 'POST' && path === '/batches') {
    const { name, description } = body;

    if (!name) {
      return errorResponse('Batch name is required');
    }

    const result = await db.prepare(
      'INSERT INTO batches (name, description) VALUES (?, ?)'
    ).bind(name.trim(), description || '').run();

    return jsonResponse({
      id: result.meta.last_row_id,
      message: 'Batch created successfully'
    });
  }

  // DELETE /api/admin/batches/:id — Delete a batch
  if (method === 'DELETE' && path.match(/^\/batches\/\d+$/)) {
    const batchId = parseInt(path.split('/')[2]);

    // Unlink exams from this batch
    await db.prepare(
      'UPDATE exams SET batch_id = NULL WHERE batch_id = ?'
    ).bind(batchId).run();

    // Delete the batch
    await db.prepare('DELETE FROM batches WHERE id = ?').bind(batchId).run();

    return jsonResponse({ message: 'Batch deleted successfully' });
  }

  // ═══════════ EXAM MANAGEMENT ═══════════

  // POST /api/admin/exams — Create a new exam
  if (method === 'POST' && path === '/exams') {
    const {
      name,
      description,
      time_limit,
      is_premium,
      negative_marking,
      allow_practice,
      batch_id,
      live_deadline_hours
    } = body;

    if (!name) {
      return errorResponse('Exam name is required');
    }

    const result = await db.prepare(`
      INSERT INTO exams
        (name, description, time_limit, is_premium, negative_marking, allow_practice, batch_id, live_deadline_hours)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      name.trim(),
      description || '',
      time_limit || 30,
      is_premium ? 1 : 0,
      negative_marking || 0,
      allow_practice !== undefined ? (allow_practice ? 1 : 0) : 1,
      batch_id || null,
      live_deadline_hours || 0
    ).run();

    return jsonResponse({
      id: result.meta.last_row_id,
      message: 'Exam created successfully'
    });
  }

  // PUT /api/admin/exams/:id — Update an exam
  if (method === 'PUT' && path.match(/^\/exams\/\d+$/)) {
    const examId = parseInt(path.split('/')[2]);
    const {
      name,
      description,
      time_limit,
      is_premium,
      negative_marking,
      allow_practice,
      batch_id,
      live_deadline_hours
    } = body;

    const updateFields = [];
    const updateValues = [];

    if (name !== undefined) {
      updateFields.push('name = ?');
      updateValues.push(name.trim());
    }

    if (description !== undefined) {
      updateFields.push('description = ?');
      updateValues.push(description);
    }

    if (time_limit !== undefined) {
      updateFields.push('time_limit = ?');
      updateValues.push(time_limit);
    }

    if (is_premium !== undefined) {
      updateFields.push('is_premium = ?');
      updateValues.push(is_premium ? 1 : 0);
    }

    if (negative_marking !== undefined) {
      updateFields.push('negative_marking = ?');
      updateValues.push(negative_marking);
    }

    if (allow_practice !== undefined) {
      updateFields.push('allow_practice = ?');
      updateValues.push(allow_practice ? 1 : 0);
    }

    if (batch_id !== undefined) {
      updateFields.push('batch_id = ?');
      updateValues.push(batch_id || null);
    }

    if (live_deadline_hours !== undefined) {
      updateFields.push('live_deadline_hours = ?');
      updateValues.push(live_deadline_hours);
    }

    if (updateFields.length === 0) {
      return errorResponse('No fields to update');
    }

    updateValues.push(examId);

    await db.prepare(
      `UPDATE exams SET ${updateFields.join(', ')} WHERE id = ?`
    ).bind(...updateValues).run();

    return jsonResponse({ message: 'Exam updated successfully' });
  }

  // DELETE /api/admin/exams/:id — Delete an exam
  if (method === 'DELETE' && path.match(/^\/exams\/\d+$/)) {
    const examId = parseInt(path.split('/')[2]);

    await db.prepare('DELETE FROM questions WHERE exam_id = ?').bind(examId).run();
    await db.prepare('DELETE FROM exam_attempts WHERE exam_id = ?').bind(examId).run();
    await db.prepare('DELETE FROM exam_results_stored WHERE exam_id = ?').bind(examId).run();
    await db.prepare('DELETE FROM premium_access WHERE exam_id = ?').bind(examId).run();
    await db.prepare('DELETE FROM exams WHERE id = ?').bind(examId).run();

    return jsonResponse({ message: 'Exam deleted successfully' });
  }

  // ═══════════ QUESTION MANAGEMENT ═══════════

  // GET /api/admin/questions/:examId — Get all questions for an exam
  if (method === 'GET' && path.match(/^\/questions\/\d+$/)) {
    const examId = parseInt(path.split('/')[2]);

    const questions = await db.prepare(
      'SELECT * FROM questions WHERE exam_id = ? ORDER BY id'
    ).bind(examId).all();

    return jsonResponse(questions.results);
  }

  // DELETE /api/admin/questions/:examId — Delete all questions for an exam
  if (method === 'DELETE' && path.match(/^\/questions\/\d+$/)) {
    const examId = parseInt(path.split('/')[2]);

    await db.prepare('DELETE FROM questions WHERE exam_id = ?').bind(examId).run();

    return jsonResponse({ message: 'All questions deleted successfully' });
  }

  // DELETE /api/admin/questions/single/:id — Delete a single question
  if (method === 'DELETE' && path.match(/^\/questions\/single\/\d+$/)) {
    const questionId = parseInt(path.split('/')[3]);

    await db.prepare('DELETE FROM questions WHERE id = ?').bind(questionId).run();

    return jsonResponse({ message: 'Question deleted successfully' });
  }

  // POST /api/admin/questions/bulk — Upload questions via CSV
  if (method === 'POST' && path === '/questions/bulk') {
    const { exam_id, csv } = body;

    if (!exam_id || !csv) {
      return errorResponse('Exam ID and CSV data are required');
    }

    const lines = csv.trim().split('\n').filter(line => line.trim());
    let inserted = 0;
    const errors = [];

    for (let index = 0; index < lines.length; index++) {
      const line = lines[index].trim();

      if (!line) {
        continue;
      }

      const columns = parseCSVLine(line);

      if (columns.length < 6) {
        errors.push(`Line ${index + 1}: Need at least 6 columns (question, A, B, C, D, answer)`);
        continue;
      }

      const [questionText, optionA, optionB, optionC, optionD, correctAnswer, imageUrl] = columns;
      const answer = correctAnswer.trim().toUpperCase();

      if (!['A', 'B', 'C', 'D'].includes(answer)) {
        errors.push(`Line ${index + 1}: Answer must be A, B, C, or D — got "${answer}"`);
        continue;
      }

      try {
        await db.prepare(`
          INSERT INTO questions
            (exam_id, question_text, option_a, option_b, option_c, option_d, correct_answer, image_url)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          exam_id,
          questionText.trim(),
          optionA.trim(),
          optionB.trim(),
          optionC.trim(),
          optionD.trim(),
          answer,
          imageUrl ? imageUrl.trim() : null
        ).run();

        inserted++;
      } catch (error) {
        errors.push(`Line ${index + 1}: ${error.message}`);
      }
    }

    return jsonResponse({
      inserted: inserted,
      errors: errors
    });
  }

  // ═══════════ USER MANAGEMENT ═══════════

  // GET /api/admin/users — List all users
  if (method === 'GET' && path === '/users') {
    const users = await db.prepare(`
      SELECT id, name, email, is_admin, is_premium_allowed, premium_until, created_at
      FROM users
      ORDER BY created_at DESC
    `).all();

    return jsonResponse(users.results);
  }

  // ═══════════ PREMIUM ACCESS MANAGEMENT ═══════════

  // POST /api/admin/grant-premium — Grant premium access (exam, batch, or account level)
  if (method === 'POST' && path === '/grant-premium') {
    const { user_id, exam_id, batch_id, grant_scope, duration_hours } = body;

    if (!user_id) {
      return errorResponse('User ID is required');
    }

    if (!grant_scope || !['exam', 'batch', 'account'].includes(grant_scope)) {
      return errorResponse('Grant scope must be "exam", "batch", or "account"');
    }

    let expiresAt = null;

    if (duration_hours && duration_hours > 0) {
      const expiryDate = new Date(Date.now() + duration_hours * 60 * 60 * 1000);
      expiresAt = expiryDate.toISOString().replace('T', ' ').substring(0, 19);
    }

    try {
      if (grant_scope === 'account') {
        // Account-wide premium — update the users table directly
        await db.prepare(
          'UPDATE users SET premium_until = ?, is_premium_allowed = 1 WHERE id = ?'
        ).bind(expiresAt, user_id).run();

        return jsonResponse({
          message: 'Account-wide premium access granted successfully',
          expires_at: expiresAt
        });
      }

      if (grant_scope === 'batch') {
        // Batch-level premium — grant access to all exams in the batch
        if (!batch_id) {
          return errorResponse('Batch ID is required for batch-level grants');
        }

        const batchExams = await db.prepare(
          'SELECT id FROM exams WHERE batch_id = ?'
        ).bind(batch_id).all();

        if (!batchExams.results.length) {
          return errorResponse('No exams found in this batch');
        }

        for (const exam of batchExams.results) {
          // Remove any existing grant for this user + exam
          await db.prepare(
            'DELETE FROM premium_access WHERE user_id = ? AND exam_id = ?'
          ).bind(user_id, exam.id).run();

          // Insert new grant
          await db.prepare(`
            INSERT INTO premium_access
              (user_id, exam_id, batch_id, grant_scope, granted_by, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
          `).bind(user_id, exam.id, batch_id, 'batch', user.id, expiresAt).run();
        }

        return jsonResponse({
          message: `Batch access granted for ${batchExams.results.length} exam(s)`,
          expires_at: expiresAt
        });
      }

      if (grant_scope === 'exam') {
        // Single exam premium
        if (!exam_id) {
          return errorResponse('Exam ID is required for exam-level grants');
        }

        // Remove existing grant
        await db.prepare(
          'DELETE FROM premium_access WHERE user_id = ? AND exam_id = ?'
        ).bind(user_id, exam_id).run();

        // Insert new grant
        await db.prepare(`
          INSERT INTO premium_access
            (user_id, exam_id, grant_scope, granted_by, expires_at)
          VALUES (?, ?, ?, ?, ?)
        `).bind(user_id, exam_id, 'exam', user.id, expiresAt).run();

        return jsonResponse({
          message: 'Exam access granted successfully',
          expires_at: expiresAt
        });
      }
    } catch (error) {
      return errorResponse(error.message);
    }
  }

  // DELETE /api/admin/revoke-premium — Revoke exam-level premium access
  if (method === 'DELETE' && path === '/revoke-premium') {
    const { user_id, exam_id } = body;

    if (!user_id || !exam_id) {
      return errorResponse('User ID and Exam ID are required');
    }

    await db.prepare(
      'DELETE FROM premium_access WHERE user_id = ? AND exam_id = ?'
    ).bind(user_id, exam_id).run();

    return jsonResponse({ message: 'Exam access revoked successfully' });
  }

  // DELETE /api/admin/revoke-account-premium — Revoke account-wide premium
  if (method === 'DELETE' && path === '/revoke-account-premium') {
    const { user_id } = body;

    if (!user_id) {
      return errorResponse('User ID is required');
    }

    await db.prepare(
      'UPDATE users SET premium_until = NULL, is_premium_allowed = 0 WHERE id = ?'
    ).bind(user_id).run();

    return jsonResponse({ message: 'Account-wide premium access revoked successfully' });
  }

  // ═══════════ RESULTS MANAGEMENT ═══════════

  // GET /api/admin/results — Get all results
  if (method === 'GET' && path === '/results') {
    const results = await db.prepare(`
      SELECT
        er.*,
        u.name as user_name,
        u.email as user_email,
        e.name as exam_name
      FROM exam_results_stored er
      JOIN users u ON er.user_id = u.id
      JOIN exams e ON er.exam_id = e.id
      WHERE er.is_first_attempt = 1 AND er.is_practice = 0
      ORDER BY er.submitted_at DESC
    `).all();

    return jsonResponse(results.results);
  }

  // GET /api/admin/results/:examId — Get results for a specific exam
  if (method === 'GET' && path.match(/^\/results\/\d+$/)) {
    const examId = parseInt(path.split('/')[2]);

    const results = await db.prepare(`
      SELECT
        er.*,
        u.name as user_name,
        u.email as user_email,
        e.name as exam_name
      FROM exam_results_stored er
      JOIN users u ON er.user_id = u.id
      JOIN exams e ON er.exam_id = e.id
      WHERE er.exam_id = ? AND er.is_first_attempt = 1 AND er.is_practice = 0
      ORDER BY er.percentage DESC, er.submitted_at DESC
    `).bind(examId).all();

    return jsonResponse(results.results);
  }

  // DELETE /api/admin/results/:id — Delete a result
  if (method === 'DELETE' && path.match(/^\/results\/\d+$/)) {
    const resultId = parseInt(path.split('/')[2]);

    await db.prepare('DELETE FROM exam_results_stored WHERE id = ?').bind(resultId).run();

    return jsonResponse({ message: 'Result deleted successfully' });
  }

  // GET /api/admin/premium-grants — Get all premium grants
  if (method === 'GET' && path === '/premium-grants') {
    const grants = await db.prepare(`
      SELECT
        pa.*,
        u.name as user_name,
        u.email,
        e.name as exam_name,
        b.name as batch_name
      FROM premium_access pa
      JOIN users u ON pa.user_id = u.id
      LEFT JOIN exams e ON pa.exam_id = e.id
      LEFT JOIN batches b ON pa.batch_id = b.id
      ORDER BY pa.granted_at DESC
    `).all();

    return jsonResponse(grants.results);
  }

  return errorResponse('Route not found', 404);
}

// ═══════════════ MAIN REQUEST HANDLER ═══════════════

export async function onRequest(context) {
  const { request, env } = context;
  const database = env.DB;

  // Handle CORS preflight requests
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: CORS_HEADERS });
  }

  // Ensure all tables exist
  await ensureDatabaseTables(database);

  // Parse the request URL and path
  const url = new URL(request.url);
  const fullPath = url.pathname.replace(/^\/api/, '') || '/';

  // Parse request body for POST, PUT, DELETE
  let body = {};

  if (['POST', 'PUT', 'DELETE'].includes(request.method)) {
    try {
      body = await request.json();
    } catch (error) {
      body = {};
    }
  }

  // Get authenticated user
  const authenticatedUser = await getUser(request);

  // ═══════════ ROUTE MATCHING ═══════════

  // Auth routes
  if (fullPath.startsWith('/auth/')) {
    const authPath = fullPath.replace('/auth', '');
    return handleAuth(request.method, authPath, body, database, request);
  }

  // Admin routes
  if (fullPath.startsWith('/admin/')) {
    const adminPath = fullPath.replace('/admin', '');
    return handleAdmin(request.method, adminPath, body, database, authenticatedUser);
  }

  // Leaderboard routes
  if (fullPath.startsWith('/leaderboard/')) {
    const leaderboardPath = fullPath.replace('/leaderboard', '');
    return handleLeaderboard(request.method, leaderboardPath, database, authenticatedUser);
  }

  // History routes
  if (fullPath.startsWith('/history')) {
    const historyPath = fullPath.replace('/history', '');
    return handleHistory(request.method, historyPath, database, authenticatedUser);
  }

  // Batch routes
  if (fullPath.startsWith('/batches')) {
    const batchPath = fullPath.replace('/batches', '');
    return handleBatches(request.method, batchPath, body, database, authenticatedUser);
  }

  // Exam routes
  if (fullPath.startsWith('/exams')) {
    const examPath = fullPath.replace('/exams', '') || '/';
    return handleExams(request.method, examPath, body, database, authenticatedUser);
  }

  // 404 for unmatched routes
  return errorResponse('API route not found', 404);
}
