# Clever Demo App
By: Katie Gardner 

A lightweight Node.js + Express application demonstrating **Clever SSO**, **Data API v3 rostering**, and **role-based dashboards** for students, teachers, school admins, and district admins.

Features:
- Clever OAuth login  
- District sync (users, schools, sections, enrollments)  
- Teacher & student dashboards  
- School admin + district admin views  
- Multi-role switching  
- CSV upload + duplicate cleanup  
- SQLite local storage  

---

## Requirements

- Node.js (v18+ recommended)  
- A Clever **Sandbox District**  
- A Clever **Demo App** installed in that district with:
  - OAuth enabled  
  - Data API permissions  
  - Redirect URI:  
    ```
    http://localhost:3000/auth/clever/callback
    ```

---

## Setup

### 1. Install Node.js
Download at https://nodejs.org  
Verify:
```bash
node -v
npm -v
```

### 2. Install dependencies
```bash
npm install
```

### 3. Create `.env`
Create a file named `.env` in the project root:
```
CLEVER_CLIENT_ID=your_client_id
CLEVER_CLIENT_SECRET=your_client_secret
SESSION_SECRET=choose_any_random_string
```
Find your Client ID / Secret in the Clever Demo App settings.

---

## Running the App
Start the server:
```bash
node server.js
```
Open in your browser:
```
http://localhost:3000
```
Log in using any Clever Sandbox user (student, teacher, admin, etc.).

---

## Syncing Rosters
District admins can visit:
```
/admin
```
From there you can:
- Run **Sync Now** (pull from Clever API v3)  
- Upload CSV users  
- Clean up duplicate records  

Data is stored in `school.db` (SQLite).

---

## Dashboards
Different roles see different data:

| Role | Dashboard |
|------|-----------|
| Student | Their sections + teachers |
| Teacher | Their sections + student rosters |
| School Admin | All sections and students in their school(s) |
| District Admin | All district data + admin tools |

Multi-role users can toggle roles.

---

## Database
SQLite tables auto-created:
- `users`
- `schools`
- `sections`
- `enrollments`
- `user_roles`
- `user_schools`

View with:
```bash
sqlite3 school.db
.tables
```