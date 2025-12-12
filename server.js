// server.js - Final Working Version

// --- 1. SETUP & IMPORTS ---
const https = require('https');
const fs = require('fs');
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const querystring = require('querystring'); // Needed for Clever API fix
const axios = require('axios'); // Needed for API calls

// Fix for "Base64 is not defined" error in older passport-clever
const btoa = (text) => Buffer.from(text, 'binary').toString('base64');
global.Base64 = { encode: btoa };

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const CleverStrategy = require('passport-clever').Strategy;
const db = require('./db');

const app = express();

// --- 2. CONFIGURATION ---
app.set('view engine', 'ejs');

// Setup Session
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// --- 3. PASSPORT STRATEGY ---
passport.use(new CleverStrategy({
    clientID: process.env.CLEVER_CLIENT_ID,
    clientSecret: process.env.CLEVER_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/clever/callback",
    passReqToCallback: true
},
function(req, accessToken, refreshToken, profile, done) {
    // 1. SAVE TOKEN & DISTRICT ID (Vital for API Sync)
    profile.token = accessToken;
    profile.districtId = (profile.data && profile.data.district) ? profile.data.district : profile.district;

    // 2. DETERMINE ROLE
    // Default to what Clever says...
    let userRole = (profile.data && profile.data.type) ? profile.data.type : (profile.type || 'student');

    // ...Unless it is YOU (The Super Admin Override)
    if (profile.email === 'katie.gardner+demo@clever.com') {
        console.log("⚡️ SUPER ADMIN LOGGED IN ⚡️");
        userRole = 'district_admin';
    }

    // 3. GET NAME
    let firstName = "Unknown";
    let lastName = "User";
    if (profile.name) {
         firstName = profile.name.first || "Unknown";
         lastName = profile.name.last || "User";
    }

    const cleverId = profile.data ? profile.data.id : profile.id;

    // 4. CHECK/SAVE USER TO DB
    const user = db.prepare('SELECT * FROM users WHERE cleverId = ?').get(cleverId);

    if (!user) {
        console.log(`Creating new user: ${firstName} ${lastName} (${userRole})`);
        const insert = db.prepare('INSERT INTO users (cleverId, name, role) VALUES (?, ?, ?)');
        insert.run(cleverId, `${firstName} ${lastName}`, userRole);
    } else {
        console.log(`User found in DB: ${user.name}`);
    }

    return done(null, profile);
}));

// Serialize User (Cookie Storage)
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// --- 4. ROUTES ---

// Home Page
app.get('/', (req, res) => {
    res.render('index', { user: req.user });
});

// Login Button
app.get('/login/clever', passport.authenticate('clever'));

// Callback (After Login)
app.get('/auth/clever/callback',
    passport.authenticate('clever', { failureRedirect: '/' }),
    (req, res) => {
        // Redirect based on the ROLE we determined earlier
        const role = (req.user.data && req.user.data.type === 'district_admin') || req.user.email === 'katie.gardner+demo@clever.com' ? 'district_admin' : 'student';
        
        if (role === 'district_admin') {
            res.redirect('/admin');
        } else {
            res.redirect('/dashboard');
        }
    }
);

// Student / Teacher / Admin Dashboard with multi-role + role toggle
app.get('/dashboard', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');

  // ID from the OAuth profile (may be a role ID in some cases)
  const profileId  = req.user.data ? req.user.data.id : req.user.id;
  const loginEmail = (req.user.email || '').toLowerCase();

  let cleverId = null;
  let dbUser   = null;

  // --- 1) Resolve canonical cleverId via email, preferring IDs used in enrollments ---
  if (loginEmail) {
    const candidates = db.prepare(
      'SELECT * FROM users WHERE lower(email) = ?'
    ).all(loginEmail);

    if (candidates.length === 1) {
      dbUser   = candidates[0];
      cleverId = dbUser.cleverId;
    } else if (candidates.length > 1) {
      const hasEnrollmentStmt = db.prepare(
        'SELECT 1 FROM enrollments WHERE userId = ? LIMIT 1'
      );

      for (const cand of candidates) {
        const found = hasEnrollmentStmt.get(cand.cleverId);
        if (found) {
          dbUser   = cand;
          cleverId = cand.cleverId;
          break;
        }
      }

      if (!dbUser) {
        dbUser   = candidates[0];
        cleverId = dbUser.cleverId;
      }
    }
  }

  // Fallback: use profileId directly if email lookup failed
  if (!cleverId) {
    cleverId = profileId;
    dbUser = dbUser || db.prepare(
      'SELECT * FROM users WHERE cleverId = ?'
    ).get(cleverId);
  }

  // --- 2) Load all roles for this user from user_roles ---
  const roleRows = db.prepare(
    'SELECT role FROM user_roles WHERE userId = ?'
  ).all(cleverId);

  const roles = roleRows.map(r => r.role);
  const primaryRole = dbUser ? (dbUser.role || 'student') : 'student';

  // --- 3) Decide active role: URL param wins if valid, else priority order ---
  const requestedRole = req.query.role;
  const rolePriority = [
    'district_admin',
    'school_admin',
    'teacher',
    'student',
    'contact',
    'unknown'
  ];

  let activeRole;

  if (requestedRole && roles.includes(requestedRole)) {
    activeRole = requestedRole;
  } else if (roles.length) {
    activeRole = rolePriority.find(r => roles.includes(r)) || roles[0];
  } else {
    activeRole = primaryRole;
  }

    // --- 4) Schools this user is associated with ---
  const userSchools = db.prepare(`
    SELECT s.cleverId, s.name
    FROM user_schools us
    JOIN schools s ON s.cleverId = us.schoolId
    WHERE us.userId = ?
    ORDER BY s.name
  `).all(cleverId);

  // Map of all schools by Clever ID (for class cards)
  const allSchools = db.prepare(`
    SELECT cleverId, name
    FROM schools
  `).all();

  const schoolById = {};
  allSchools.forEach(s => {
    schoolById[s.cleverId] = s.name;
  });

  console.log(
    '🔎 Dashboard login profileId:',
    profileId,
    'canonical cleverId:',
    cleverId,
    'email:',
    loginEmail,
    'roles:',
    roles,
    'activeRole:',
    activeRole
  );

  let classes = [];

  // Shared prepared statements
  const studentsForSectionStmt = db.prepare(`
    SELECT u.name, u.email, u.cleverId
    FROM enrollments e
    JOIN users u ON u.cleverId = e.userId
    WHERE e.sectionId = ? AND e.role = 'student'
    ORDER BY u.name
  `);

  const teachersForSectionStmt = db.prepare(`
    SELECT u.name, u.email, u.cleverId
    FROM enrollments e
    JOIN users u ON u.cleverId = e.userId
    WHERE e.sectionId = ? AND e.role = 'teacher'
    ORDER BY u.name
  `);

  if (activeRole === 'teacher') {
    // ----- TEACHER VIEW: only their sections + students -----
    const teacherSectionsStmt = db.prepare(`
      SELECT s.cleverId AS sectionId, s.name AS sectionName, s.schoolId
      FROM sections s
      JOIN enrollments e ON e.sectionId = s.cleverId
      WHERE e.userId = ? AND e.role = 'teacher'
      ORDER BY s.name
    `);

    const sections = teacherSectionsStmt.all(cleverId);
    console.log('📚 Teacher sections found:', sections.length);

    classes = sections.map(sec => ({
      id: sec.sectionId,
      name: sec.sectionName || 'Untitled Section',
      schoolId: sec.schoolId,
      schoolName: schoolById[sec.schoolId] || null,
      students: studentsForSectionStmt.all(sec.sectionId)
    }));

  } else if (activeRole === 'school_admin') {
    
    // ----- SCHOOL ADMIN VIEW: all sections in their schools -----
    const schoolIds = new Set(userSchools.map(s => s.cleverId));
    console.log('🏫 School admin schools:', [...schoolIds]);

    const allSections = db.prepare(`
      SELECT cleverId AS sectionId, name AS sectionName, schoolId
      FROM sections
    `).all();

    const sections = allSections.filter(sec => schoolIds.has(sec.schoolId));
    console.log('📚 School admin sections found:', sections.length);

    classes = sections.map(sec => ({
      id: sec.sectionId,
      name: sec.sectionName || 'Untitled Section',
      schoolId: sec.schoolId,
      schoolName: schoolById[sec.schoolId] || null,
      students: studentsForSectionStmt.all(sec.sectionId),
      teachers: teachersForSectionStmt.all(sec.sectionId)
    }));

  } else if (activeRole === 'district_admin') {
    // ----- DISTRICT ADMIN VIEW: all sections in the district -----
    const sections = db.prepare(`
      SELECT cleverId AS sectionId, name AS sectionName, schoolId
      FROM sections
      ORDER BY name
    `).all();

    console.log('📚 District admin sections found:', sections.length);

    classes = sections.map(sec => ({
      id: sec.sectionId,
      name: sec.sectionName || 'Untitled Section',
      schoolId: sec.schoolId,
      schoolName: schoolById[sec.schoolId] || null,
      students: studentsForSectionStmt.all(sec.sectionId),
      teachers: teachersForSectionStmt.all(sec.sectionId)
    }));

  } else {
    // ----- STUDENT VIEW: only their sections + teachers -----
    const studentSectionsStmt = db.prepare(`
      SELECT s.cleverId AS sectionId, s.name AS sectionName, s.schoolId
      FROM sections s
      JOIN enrollments e ON e.sectionId = s.cleverId
      WHERE e.userId = ? AND e.role = 'student'
      ORDER BY s.name
    `);

    const sections = studentSectionsStmt.all(cleverId);
    console.log('📚 Student sections found:', sections.length);

    classes = sections.map(sec => ({
      id: sec.sectionId,
      name: sec.sectionName || 'Untitled Section',
      schoolId: sec.schoolId,
      schoolName: schoolById[sec.schoolId] || null,
      teachers: teachersForSectionStmt.all(sec.sectionId)
    }));
  }

  // --- 5) Render dashboard ---
  res.render('dashboard', {
    user: req.user,
    dbUser,
    roles,           // all roles this user has (for toggle)
    activeRole,      // what they’re currently “acting as”
    role: activeRole, // alias so existing EJS using `role` still works
    userSchools,
    classes
  });
});

// Admin Dashboard
app.get('/admin', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');

  // Check for Admin Role (or Super Admin Email)
  const isSuperAdmin  = req.user.email === 'katie.gardner+demo@clever.com';
  const isCleverAdmin = req.user.data && req.user.data.type === 'district_admin';

  if (!isCleverAdmin && !isSuperAdmin) {
    return res.send("Access Denied: You are not an Admin!");
  }

  // Fetch all users to show the list
  const allUsers = db.prepare('SELECT * FROM users').all();
  res.render('admin', { user: req.user, allUsers });
});

// --- 5. UPLOAD ROUTE (Manual CSV) ---
app.post('/admin/upload', upload.single('roster'), (req, res) => {
  if (!req.isAuthenticated()) return res.send("Access Denied");
  if (!req.file) return res.status(400).send('No file uploaded.');

  try {
    const fileContent = fs.readFileSync(req.file.path, 'utf-8');
    const rows = fileContent.split('\n');
    let count = 0;

    const findByEmail = db.prepare('SELECT * FROM users WHERE lower(email) = lower(?)');
    const insert = db.prepare('INSERT INTO users (cleverId, name, role, email) VALUES (?, ?, ?, ?)');

    rows.forEach((row, index) => {
      if (index === 0 || !row.trim()) return; // skip header / empty
      const cols = row.split(',');
      if (!cols[0]) return;

      const name = cols[0].trim();
      const role = cols[1] ? cols[1].trim() : null;
      const email = cols[2] ? cols[2].trim() : null;

      if (!email) return; // we only dedupe by email, so skip rows with none

      const existing = findByEmail.get(email);
      if (existing) {
        // already have this email, skip
        return;
      }

      const fakeId = 'manual_' + Date.now() + '_' + index;

      try {
        insert.run(fakeId, name, role, email);
        count++;
      } catch (e) {
        console.error('CSV insert error:', e.message);
      }
    });

    fs.unlinkSync(req.file.path);
    res.send(`<h1>Success!</h1><p>Uploaded ${count} new users.</p><a href="/admin">Back to Dashboard</a>`);
  } catch (error) {
    console.error('CSV upload error:', error);
    res.status(500).send("Error processing file.");
  }
});


// Helper: fetch ALL pages from a Clever v3 collection endpoint
// pathWithQuery example: "/users?limit=100" or "/sections?limit=100"
async function fetchAllCleverRecords(districtToken, pathWithQuery) {
  let url = `https://api.clever.com/v3.0${pathWithQuery}`;
  const all = [];

  while (url) {
    const resp = await axios.get(url, {
      headers: { Authorization: `Bearer ${districtToken}` }
    });

    const body = resp.data;
    if (Array.isArray(body.data)) {
      all.push(...body.data);
    }

    const nextLink = Array.isArray(body.links)
      ? body.links.find(l => l.rel === 'next')
      : null;

    url = nextLink ? `https://api.clever.com${nextLink.uri}` : null;
  }

  return all;
}

// 6. The "Auto-Sync" Feature – users + sections + schools + local enrollments + multi-role
app.post('/admin/sync', async (req, res) => {
  if (!req.isAuthenticated()) return res.send("Access Denied");

  const isSuperAdmin  = req.user.email === 'katie.gardner+demo@clever.com';
  const isCleverAdmin = req.user.data && req.user.data.type === 'district_admin';

  if (!isSuperAdmin && !isCleverAdmin) {
    return res.send("Access Denied: You are not an Admin!");
  }

  console.log("🔶🔶🔶 VERSION CHECK: V12 (USERS + SECTIONS + SCHOOLS + ENROLLMENTS) 🔶🔶🔶");
  console.log("⚡️ Starting Sync...");

  try {
    // ----- 1) Get district-app token -----
    const clientId     = process.env.CLEVER_CLIENT_ID.trim();
    const clientSecret = process.env.CLEVER_CLIENT_SECRET.trim();
    const basicAuth    = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');

    const distId = req.user.districtId || '60ca3110e378a7cd8bdc0c45';

    const tokensResp = await axios.get('https://clever.com/oauth/tokens', {
      headers: { Authorization: `Basic ${basicAuth}` },
      params:  { owner_type: 'district', district: distId }
    });

    console.log("Raw /oauth/tokens response:", JSON.stringify(tokensResp.data, null, 2));

    const tokens = tokensResp.data.data || [];
    if (!tokens.length) {
      return res.send(`No district tokens found for district ${distId}`);
    }

    const districtToken = String(tokens[0].access_token || tokens[0].token).trim();
    console.log("✅ Obtained District-App Token:", districtToken.slice(0, 8) + "…");

    // ----- 2) Pull all users + sections + schools -----
    console.log("📥 Fetching all users via /users...");
    const users = await fetchAllCleverRecords(districtToken, '/users?limit=100');

    console.log("📥 Fetching all sections via /sections...");
    const sections = await fetchAllCleverRecords(districtToken, '/sections?limit=100');

    console.log("📥 Fetching all schools via /schools...");
    const schools = await fetchAllCleverRecords(districtToken, '/schools?limit=100');

    console.log("✅ Finished fetching from Clever");

    // ----- 3) Insert/update schools -----
    const insertSchool = db.prepare(`
      INSERT OR REPLACE INTO schools (cleverId, name)
      VALUES (?, ?)
    `);

    let schoolInsertCount = 0;
    for (const record of schools) {
      const s = record.data;
      try {
        insertSchool.run(s.id, s.name || 'Unnamed School');
        schoolInsertCount++;
      } catch (err) {
        console.error(`Error inserting school ${s.id}:`, err.message);
      }
    }
    console.log(`✅ Inserted/updated ${schoolInsertCount} schools`);

    // ----- 4) Insert/update users + user_roles + user_schools -----
    const insertUser = db.prepare(`
      INSERT OR IGNORE INTO users (cleverId, name, role, email)
      VALUES (?, ?, ?, ?)
    `);

    const insertUserRole = db.prepare(`
      INSERT OR IGNORE INTO user_roles (userId, role)
      VALUES (?, ?)
    `);

    const insertUserSchool = db.prepare(`
      INSERT OR IGNORE INTO user_schools (userId, schoolId)
      VALUES (?, ?)
    `);

    // Reset mapping tables each sync
    db.exec(`DELETE FROM user_roles; DELETE FROM user_schools;`);

    let userInsertCount = 0;

    function classifyUserRole(u) {
      const r = u.roles || {};
      if (r.district_admin) return 'district_admin';
      if (r.staff)         return 'school_admin';
      if (r.teacher)       return 'teacher';
      if (r.student)       return 'student';
      if (r.contact)       return 'contact';
      return 'unknown';
    }

    for (const record of users) {
      const u = record.data;
      const name  = `${u.name?.first || ''} ${u.name?.last || ''}`.trim() || 'Unknown User';
      const email = u.email || 'no-email@test.com';
      const role  = classifyUserRole(u);

      try {
        insertUser.run(u.id, name, role, email);
        userInsertCount++;
      } catch (err) {
        console.error(`Error inserting user ${u.id}:`, err.message);
      }

      const roles = u.roles || {};
      if (roles.district_admin) insertUserRole.run(u.id, 'district_admin');
      if (roles.staff)          insertUserRole.run(u.id, 'school_admin');
      if (roles.teacher)        insertUserRole.run(u.id, 'teacher');
      if (roles.student)        insertUserRole.run(u.id, 'student');
      if (roles.contact)        insertUserRole.run(u.id, 'contact');

      // Map to schools
      const schoolIds = new Set();

      if (roles.student && Array.isArray(roles.student.schools)) {
        roles.student.schools.forEach(id => schoolIds.add(id));
      }
      if (roles.teacher && Array.isArray(roles.teacher.schools)) {
        roles.teacher.schools.forEach(id => schoolIds.add(id));
      }
      if (roles.staff && Array.isArray(roles.staff.schools)) {
        roles.staff.schools.forEach(id => schoolIds.add(id));
      }

      schoolIds.forEach(sid => {
        try {
          insertUserSchool.run(u.id, sid);
        } catch (err) {
          console.error(`Error linking user ${u.id} to school ${sid}:`, err.message);
        }
      });
    }

    console.log(`✅ Inserted/updated ${userInsertCount} users`);

    // ----- 5) Insert sections -----
    const insertSection = db.prepare(`
      INSERT OR REPLACE INTO sections (cleverId, name, schoolId)
      VALUES (?, ?, ?)
    `);

    let sectionInsertCount = 0;

    for (const record of sections) {
      const s = record.data;
      try {
        insertSection.run(s.id, s.name || 'Untitled Section', s.school || null);
        sectionInsertCount++;
      } catch (err) {
        console.error(`Error inserting section ${s.id}:`, err.message);
      }
    }

    console.log(`✅ Inserted/updated ${sectionInsertCount} sections`);

    // ----- 6) Build enrollments -----
    const insertEnrollment = db.prepare(`
      INSERT OR REPLACE INTO enrollments (cleverId, sectionId, userId, role)
      VALUES (?, ?, ?, ?)
    `);

    let enrollmentCount = 0;

    for (const record of sections) {
      const s = record.data;
      const sectionId = s.id;

      // Students
      for (const stu of (s.students || [])) {
        const id = `sec_${sectionId}_stu_${stu}`;
        insertEnrollment.run(id, sectionId, stu, 'student');
        enrollmentCount++;
      }

      // Teachers
      const teacherSet = new Set();
      if (s.teacher) teacherSet.add(s.teacher);
      (s.teachers || []).forEach(t => teacherSet.add(t));

      for (const tch of teacherSet) {
        const id = `sec_${sectionId}_tch_${tch}`;
        insertEnrollment.run(id, sectionId, tch, 'teacher');
        enrollmentCount++;
      }
    }

    console.log(`✅ Built ${enrollmentCount} enrollments`);

    // ----- 7) Summary -----
    res.send(`
      <h1>Sync Complete!</h1>
      <ul>
        <li><b>Total Users:</b> ${users.length}</li>
        <li><b>Total Sections:</b> ${sections.length}</li>
        <li><b>Total Schools:</b> ${schools.length}</li>
        <li><b>Total Enrollments:</b> ${enrollmentCount}</li>
      </ul>
      <p><b>DB Inserts:</b> ${userInsertCount} users, ${sectionInsertCount} sections, ${schoolInsertCount} schools</p>
      <a href="/admin">Back to Dashboard</a>
    `);
  } catch (err) {
    console.error("Sync Error:", err.response?.data || err.message);
    res.send(
      `Sync failed: ${err.message}<br><pre>${JSON.stringify(err.response?.data, null, 2)}</pre>`
    );
  }
});


// Start Server
app.listen(3000, () => console.log('App running on http://localhost:3000'));