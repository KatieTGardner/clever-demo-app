const Database = require('better-sqlite3');
const db = new Database('school.db');

// Main users table

db.exec(`
  -- Users
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cleverId TEXT UNIQUE,
    name TEXT,
    role TEXT,
    email TEXT
  );

  -- Sections
  CREATE TABLE IF NOT EXISTS sections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cleverId TEXT UNIQUE,
    name TEXT,
    schoolId TEXT
  );

  -- Enrollments (section <-> user)
  CREATE TABLE IF NOT EXISTS enrollments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cleverId TEXT UNIQUE,
    sectionId TEXT,
    userId TEXT,
    role TEXT
  );

  -- Per-user roles (multi-role)
  CREATE TABLE IF NOT EXISTS user_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId TEXT,
    role TEXT,
    UNIQUE(userId, role)
  );

  -- Schools
  CREATE TABLE IF NOT EXISTS schools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cleverId TEXT UNIQUE,
    name TEXT
  );

  -- Mapping: which schools a user belongs to
  CREATE TABLE IF NOT EXISTS user_schools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId TEXT,
    schoolId TEXT,
    UNIQUE(userId, schoolId)
  );
`);


// SECTIONS TABLE
db.exec(`
  CREATE TABLE IF NOT EXISTS sections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cleverId TEXT UNIQUE,
    name TEXT,
    schoolId TEXT
  );
`);

// ENROLLMENTS TABLE
db.exec(`
  CREATE TABLE IF NOT EXISTS enrollments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cleverId TEXT UNIQUE,
    sectionId TEXT,
    userId TEXT,
    role TEXT
  );
`);



console.log("Database initialized!");
module.exports = db;
