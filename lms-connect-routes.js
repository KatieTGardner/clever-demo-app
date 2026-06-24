// lms-connect-routes.js
// Drop-in LMS Connect integration for Schoology
// Mounts on your existing Express app via: app.use(require('./lms-connect-routes'))

const express = require('express');
const axios = require('axios');
const router = express.Router();

// ─── Config ──────────────────────────────────────────────────────────────────
const CLEVER_API = 'https://api.clever.com/lms/v1';

// ─── Helpers ─────────────────────────────────────────────────────────────────

// Pull the district-app token the same way your sync route does
async function getDistrictToken(user) {
  const clientId     = process.env.CLEVER_CLIENT_ID.trim();
  const clientSecret = process.env.CLEVER_CLIENT_SECRET.trim();
  const basicAuth    = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  const distId       = user.districtId || '60ca3110e378a7cd8bdc0c45';

  const resp = await axios.get('https://clever.com/oauth/tokens', {
    headers: { Authorization: `Basic ${basicAuth}` },
    params:  { owner_type: 'district', district: distId }
  });

  const tokens = resp.data.data || [];
  if (!tokens.length) throw new Error(`No district token found for district ${distId}`);
  return String(tokens[0].access_token || tokens[0].token).trim();
}

// Unified LMS Connect API caller
async function lmsRequest(method, path, token, body = null) {
  const config = {
    method,
    url: `${CLEVER_API}${path}`,
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json'
    }
  };
  if (body) config.data = body;

  const resp = await axios(config);
  return resp.data;
}

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.isAuthenticated()) return res.redirect('/');
  next();
}

function requireTeacherOrAdmin(req, res, next) {
  const role = req.session?.activeRole || req.user?.data?.type || 'student';
  const allowed = ['teacher', 'school_admin', 'district_admin'];
  // Also allow super admin
  if (req.user?.email === 'katie.gardner+demo@clever.com') return next();
  if (allowed.includes(role)) return next();
  return res.status(403).render('lms/error', {
    user: req.user,
    message: 'Only teachers and admins can do that.'
  });
}

// ─── DISTRICT STATUS ──────────────────────────────────────────────────────────

// GET /lms/status
// Shows whether the district's Schoology connection is active
router.get('/lms/status', requireAuth, async (req, res) => {
  try {
    const token    = await getDistrictToken(req.user);
    const distId   = req.user.districtId || '60ca3110e378a7cd8bdc0c45';
    const data     = await lmsRequest('GET', `/districts/${distId}`, token);

    res.render('lms/status', {
      user: req.user,
      status: data
    });
  } catch (err) {
    console.error('LMS status error:', err.response?.data || err.message);
    res.render('lms/error', {
      user: req.user,
      message: err.response?.data?.message || err.message
    });
  }
});

// ─── ASSIGNMENTS ──────────────────────────────────────────────────────────────

// GET /lms/sections/:sectionId/assignments
// Teacher: see all assignments they created; Student: see assignments for their section
router.get('/lms/sections/:sectionId/assignments', requireAuth, async (req, res) => {
  const { sectionId } = req.params;
  try {
    const token = await getDistrictToken(req.user);
    const data  = await lmsRequest('GET', `/sections/${sectionId}/assignments`, token);

    res.render('lms/assignments', {
      user: req.user,
      sectionId,
      assignments: data.data || [],
      role: req.session?.activeRole || req.user?.data?.type || 'student'
    });
  } catch (err) {
    console.error('List assignments error:', err.response?.data || err.message);
    res.render('lms/error', {
      user: req.user,
      message: err.response?.data?.message || err.message
    });
  }
});

// GET /lms/sections/:sectionId/assignments/new
// Teacher: form to create a new assignment
router.get('/lms/sections/:sectionId/assignments/new', requireAuth, requireTeacherOrAdmin, (req, res) => {
  res.render('lms/assignment-form', {
    user: req.user,
    sectionId: req.params.sectionId,
    assignment: null, // null = create mode
    error: null
  });
});

// POST /lms/sections/:sectionId/assignments
// Teacher: create an assignment via LMS Connect
router.post('/lms/sections/:sectionId/assignments', requireAuth, requireTeacherOrAdmin, express.urlencoded({ extended: true }), async (req, res) => {
  const { sectionId } = req.params;
  const { title, description, due, max_points } = req.body;

  const body = {
    title,
    description: description || undefined,
    due: due || undefined,
    max_points: max_points ? parseInt(max_points, 10) : undefined
  };

  // Strip undefined keys so we don't send nulls to the API
  Object.keys(body).forEach(k => body[k] === undefined && delete body[k]);

  try {
    const token = await getDistrictToken(req.user);
    await lmsRequest('POST', `/sections/${sectionId}/assignments`, token, body);
    res.redirect(`/lms/sections/${sectionId}/assignments`);
  } catch (err) {
    console.error('Create assignment error:', err.response?.data || err.message);
    res.render('lms/assignment-form', {
      user: req.user,
      sectionId,
      assignment: req.body,
      error: err.response?.data?.message || err.message
    });
  }
});

// GET /lms/sections/:sectionId/assignments/:assignmentId
// View a single assignment + its submissions (teacher) or just the assignment (student)
router.get('/lms/sections/:sectionId/assignments/:assignmentId', requireAuth, async (req, res) => {
  const { sectionId, assignmentId } = req.params;
  const role = req.session?.activeRole || req.user?.data?.type || 'student';

  try {
    const token      = await getDistrictToken(req.user);
    const assignment = await lmsRequest('GET', `/sections/${sectionId}/assignments/${assignmentId}`, token);

    let submissions = [];
    if (['teacher', 'school_admin', 'district_admin'].includes(role) || req.user?.email === 'katie.gardner+demo@clever.com') {
      const subData  = await lmsRequest('GET', `/sections/${sectionId}/assignments/${assignmentId}/submissions`, token);
      submissions    = subData.data || [];
    }

    res.render('lms/assignment-detail', {
      user: req.user,
      sectionId,
      assignment: assignment.data || assignment,
      submissions,
      role
    });
  } catch (err) {
    console.error('Get assignment error:', err.response?.data || err.message);
    res.render('lms/error', {
      user: req.user,
      message: err.response?.data?.message || err.message
    });
  }
});

// GET /lms/sections/:sectionId/assignments/:assignmentId/edit
// Teacher: edit form for an existing assignment
router.get('/lms/sections/:sectionId/assignments/:assignmentId/edit', requireAuth, requireTeacherOrAdmin, async (req, res) => {
  const { sectionId, assignmentId } = req.params;
  try {
    const token      = await getDistrictToken(req.user);
    const assignment = await lmsRequest('GET', `/sections/${sectionId}/assignments/${assignmentId}`, token);

    res.render('lms/assignment-form', {
      user: req.user,
      sectionId,
      assignment: assignment.data || assignment,
      error: null
    });
  } catch (err) {
    res.render('lms/error', {
      user: req.user,
      message: err.response?.data?.message || err.message
    });
  }
});

// POST /lms/sections/:sectionId/assignments/:assignmentId/edit  (PATCH under the hood)
// Teacher: update an assignment
router.post('/lms/sections/:sectionId/assignments/:assignmentId/edit', requireAuth, requireTeacherOrAdmin, express.urlencoded({ extended: true }), async (req, res) => {
  const { sectionId, assignmentId } = req.params;
  const { title, description, due, max_points } = req.body;

  const body = {
    title,
    description: description || undefined,
    due: due || undefined,
    max_points: max_points ? parseInt(max_points, 10) : undefined
  };
  Object.keys(body).forEach(k => body[k] === undefined && delete body[k]);

  try {
    const token = await getDistrictToken(req.user);
    await lmsRequest('PATCH', `/sections/${sectionId}/assignments/${assignmentId}`, token, body);
    res.redirect(`/lms/sections/${sectionId}/assignments/${assignmentId}`);
  } catch (err) {
    console.error('Update assignment error:', err.response?.data || err.message);
    res.render('lms/assignment-form', {
      user: req.user,
      sectionId,
      assignment: { ...req.body, id: assignmentId },
      error: err.response?.data?.message || err.message
    });
  }
});

// POST /lms/sections/:sectionId/assignments/:assignmentId/delete  (DELETE under the hood)
// Teacher: delete an assignment
router.post('/lms/sections/:sectionId/assignments/:assignmentId/delete', requireAuth, requireTeacherOrAdmin, async (req, res) => {
  const { sectionId, assignmentId } = req.params;
  try {
    const token = await getDistrictToken(req.user);
    await lmsRequest('DELETE', `/sections/${sectionId}/assignments/${assignmentId}`, token);
    res.redirect(`/lms/sections/${sectionId}/assignments`);
  } catch (err) {
    console.error('Delete assignment error:', err.response?.data || err.message);
    res.render('lms/error', {
      user: req.user,
      message: err.response?.data?.message || err.message
    });
  }
});

// ─── SUBMISSIONS ──────────────────────────────────────────────────────────────

// GET /lms/sections/:sectionId/assignments/:assignmentId/submissions
// Teacher: view all submissions for an assignment
router.get('/lms/sections/:sectionId/assignments/:assignmentId/submissions', requireAuth, requireTeacherOrAdmin, async (req, res) => {
  const { sectionId, assignmentId } = req.params;
  try {
    const token = await getDistrictToken(req.user);
    const data  = await lmsRequest('GET', `/sections/${sectionId}/assignments/${assignmentId}/submissions`, token);

    res.render('lms/submissions', {
      user: req.user,
      sectionId,
      assignmentId,
      submissions: data.data || []
    });
  } catch (err) {
    console.error('View submissions error:', err.response?.data || err.message);
    res.render('lms/error', {
      user: req.user,
      message: err.response?.data?.message || err.message
    });
  }
});

// GET /lms/sections/:sectionId/assignments/:assignmentId/submissions/:userId
// Teacher: view a single student's submission
router.get('/lms/sections/:sectionId/assignments/:assignmentId/submissions/:userId', requireAuth, requireTeacherOrAdmin, async (req, res) => {
  const { sectionId, assignmentId, userId } = req.params;
  try {
    const token      = await getDistrictToken(req.user);
    const submission = await lmsRequest('GET', `/sections/${sectionId}/assignments/${assignmentId}/submissions/${userId}`, token);

    res.render('lms/submission-detail', {
      user: req.user,
      sectionId,
      assignmentId,
      userId,
      submission: submission.data || submission,
      error: null
    });
  } catch (err) {
    console.error('Get submission error:', err.response?.data || err.message);
    res.render('lms/error', {
      user: req.user,
      message: err.response?.data?.message || err.message
    });
  }
});

// POST /lms/sections/:sectionId/assignments/:assignmentId/submissions/:userId  (PATCH under the hood)
// Teacher: grade or update a submission's state
router.post('/lms/sections/:sectionId/assignments/:assignmentId/submissions/:userId', requireAuth, requireTeacherOrAdmin, express.urlencoded({ extended: true }), async (req, res) => {
  const { sectionId, assignmentId, userId } = req.params;
  const { state, score, comment } = req.body;

  // LMS Connect requires state to move through: submitted -> returned
  // You cannot skip to returned without submitted first (enforced by Schoology)
  const body = {
    state:   state   || undefined,
    score:   score   ? parseFloat(score) : undefined,
    comment: comment || undefined
  };
  Object.keys(body).forEach(k => body[k] === undefined && delete body[k]);

  try {
    const token = await getDistrictToken(req.user);
    await lmsRequest('PATCH', `/sections/${sectionId}/assignments/${assignmentId}/submissions/${userId}`, token, body);
    res.redirect(`/lms/sections/${sectionId}/assignments/${assignmentId}/submissions/${userId}`);
  } catch (err) {
    console.error('Update submission error:', err.response?.data || err.message);

    // Re-render the form with the error so the user knows what went wrong
    try {
      const token      = await getDistrictToken(req.user);
      const submission = await lmsRequest('GET', `/sections/${sectionId}/assignments/${assignmentId}/submissions/${userId}`, token);
      res.render('lms/submission-detail', {
        user: req.user,
        sectionId,
        assignmentId,
        userId,
        submission: submission.data || submission,
        error: err.response?.data?.message || err.message
      });
    } catch (_) {
      res.render('lms/error', {
        user: req.user,
        message: err.response?.data?.message || err.message
      });
    }
  }
});

module.exports = router;
