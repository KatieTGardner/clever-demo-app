// server.js - Clever LMS Connect Reference Implementation
// Supports: Canvas, Schoology, and Google Classroom

// --- 1. SETUP & IMPORTS ---
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const CleverStrategy = require('passport-clever').Strategy;
const axios = require('axios');
const jwt = require('jsonwebtoken'); // For LTI 1.3 Handshake
const multer = require('multer');
const fs = require('fs');
const db = require('./db');
require('dotenv').config();

const upload = multer({ dest: 'uploads/' });

// Fix for "Base64 is not defined" error in older passport-clever
const btoa = (text) => Buffer.from(text, 'binary').toString('base64');
global.Base64 = { encode: btoa };

const app = express();

// --- 2. CONFIGURATION & MIDDLEWARE ---
app.set('view engine', 'ejs');
app.use(express.json()); 
app.use(express.urlencoded({ extended: true })); // Required for LTI POST bodies

app.use(session({
    secret: process.env.SESSION_SECRET || 'clever-lms-secret',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// --- 3. PASSPORT STRATEGY (OAuth for Standard/Google Login) ---
passport.use(new CleverStrategy({
    clientID: process.env.CLEVER_CLIENT_ID,
    clientSecret: process.env.CLEVER_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/clever/callback",
    passReqToCallback: true
},
function(req, accessToken, refreshToken, profile, done) {
    // Save Token & District ID for later API calls
    profile.token = accessToken;
    profile.districtId = (profile.data && profile.data.district) ? profile.data.district : profile.district;

    const cleverId = profile.data ? profile.data.id : profile.id;
    const email = (profile.email || '').toLowerCase();
    
    // Determine Role
    let userRole = (profile.data && profile.data.type) ? profile.data.type : (profile.type || 'student');
    if (profile.email === 'katie.gardner+demo@clever.com') userRole = 'district_admin';

    // Save/Update User in local DB
    const user = db.prepare('SELECT * FROM users WHERE cleverId = @cleverId').get({ cleverId });
    if (!user) {
        const firstName = profile.name?.first || "Unknown";
        const lastName = profile.name?.last || "User";
        const insert = db.prepare('INSERT INTO users (cleverId, name, role, email) VALUES (?, ?, ?, ?)');
        insert.run(cleverId, `${firstName} ${lastName}`, userRole, email);
    }

    return done(null, profile);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// --- 4. LMS CONNECT: LTI 1.3 LAUNCH HANDLER ---
// This endpoint handles the "Deep Link" launch from Canvas or Schoology
app.post('/auth/lti/launch', async (req, res) => {
    const idToken = req.body.id_token;
    if (!idToken) return res.status(400).send("Missing LTI ID Token");

    try {
        // Decode the LTI Claim provided by Clever
        const decoded = jwt.decode(idToken); 
        const customClaims = decoded['https://purl.imsglobal.org/spec/lti/claim/custom'];
        
        const cleverUserId = customClaims.clever_user_id;
        const cleverSectionId = customClaims.clever_section_id;

        // Find the user in our local DB synced from Clever
        const user = db.prepare('SELECT * FROM users WHERE cleverId = ?').get(cleverUserId);
        
        if (!user) return res.status(404).send("User not found. Please ensure district has synced.");

        req.login(user, (err) => {
            if (err) return res.redirect('/');
            // Launch into the dashboard with the specific Section Context
            res.redirect(`/dashboard?sectionId=${cleverSectionId}&lms_launch=true`);
        });
    } catch (err) {
        console.error("LTI Launch Error:", err);
        res.status(500).send("LMS Launch Handshake Failed");
    }
});

// --- 5. STANDARD ROUTES ---

app.get('/', (req, res) => {
    res.render('index', { user: req.user });
});

app.get('/login/clever', passport.authenticate('clever'));

app.get('/auth/clever/callback',
    passport.authenticate('clever', { failureRedirect: '/' }),
    (req, res) => {
        const role = (req.user.data && req.user.data.type === 'district_admin') || req.user.email === 'katie.gardner+demo@clever.com' ? 'district_admin' : 'student';
        res.redirect(role === 'district_admin' ? '/admin' : '/dashboard');
    }
);

app.get('/dashboard', (req, res) => {
    if (!req.isAuthenticated()) return res.redirect('/');
    
    const cleverId = req.user.data ? req.user.data.id : req.user.id;
    
    // ... (Your existing role-switching and class-loading logic goes here) ...
    // Note: Use req.query.sectionId to highlight a specific class if launched from LMS
    
    res.render('dashboard', { 
        user: req.user,
        activeRole: 'teacher', // Example
        classes: [] // Simplified for template
    });
});

// --- 6. LMS SYNC HELPER (THE "UNIVERSAL" PUSH) ---
app.post('/api/lms/sync-assignment', async (req, res) => {
    if (!req.isAuthenticated()) return res.status(401).send("Unauthorized");

    const { sectionId, title, points, dueDate } = req.body;
    
    try {
        // 1. Get the district token (In a real app, store this in your DB during /admin/sync)
        // For this template, we assume it's available or provided
        const districtToken = req.user.token; 

        // 2. Use Clever v3.1 for Universal LMS Sync
        const url = `https://api.clever.com/v3.1/sections/${sectionId}/assignments`;
        
        const response = await axios.post(url, {
            name: title,
            points_possible: points || 100,
            due_at: dueDate, // Should be ISO String
            status: "published"
        }, {
            headers: { Authorization: `Bearer ${districtToken}` }
        });

        res.json({ success: true, data: response.data });
    } catch (err) {
        console.error("LMS Sync Failed:", err.response?.data || err.message);
        res.status(500).json({ success: false, error: err.message });
    }
});

// --- 7. ADMIN & SYNC LOGIC (Rostering) ---

async function fetchAllCleverRecords(districtToken, pathWithQuery) {
    // Update to v3.1 for LMS data parity
    let url = `https://api.clever.com/v3.1${pathWithQuery}`;
    const all = [];
    while (url) {
        const resp = await axios.get(url, { headers: { Authorization: `Bearer ${districtToken}` } });
        all.push(...(resp.data.data || []));
        const next = resp.data.links?.find(l => l.rel === 'next');
        url = next ? `https://api.clever.com${next.uri}` : null;
    }
    return all;
}

app.post('/admin/sync', async (req, res) => {
    // ... (Your existing Sync logic here, now using v3.1 as per fetchAllCleverRecords) ...
    res.send("Sync Processed - Upgraded to v3.1");
});

// Start Server
app.listen(3000, () => console.log('🚀 LMS Connect Template running on http://localhost:3000'));
