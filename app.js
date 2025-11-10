// app.js
// Demo intentionally-vulnerable dorm rental app
// RUN ONLY IN ISOLATED TEST ENVIRONMENT
// npm init -y
// npm i express sqlite3 body-parser cookie-parser multer

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
// Serve uploads folder directly (insecure if untrusted files are uploaded)
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Simple disk storage for file uploads (no validation)
const upload = multer({ dest: 'uploads/' });

const DB_FILE = 'demo.db';
if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, '');
}
const db = new sqlite3.Database(DB_FILE);

// Initialize DB
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT, -- stored in plaintext: VULNERABLE
    is_admin INTEGER DEFAULT 0
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS listings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER,
    title TEXT,
    description TEXT,
    price INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    listing_id INTEGER,
    user_id INTEGER,
    nights INTEGER
  )`);
  // seed
  db.run(`INSERT OR IGNORE INTO users (id, username, password, is_admin) VALUES (1, 'admin', 'admin123', 1)`);
  db.run(`INSERT OR IGNORE INTO users (id, username, password, is_admin) VALUES (2, 'alice', 'password', 0)`);
  db.run(`INSERT OR IGNORE INTO listings (id, owner_id, title, description, price)
          VALUES (1, 1, 'Cheap dorm near uni', '<b>Great place</b>', 120)`);
});

// ---------- Helpers (very naive/insecure session) ----------
function setAuthCookie(res, userId) {
  // insecure: cookie not HttpOnly, no signature
  res.cookie('user_id', String(userId), { maxAge: 24*3600*1000 });
}

function getCurrentUser(req, cb) {
  const uid = parseInt(req.cookies.user_id || '0', 10);
  if (!uid) return cb(null);
  db.get(`SELECT id, username, is_admin FROM users WHERE id = ${uid}`, (err, row) => {
    if (err) return cb(null);
    cb(row);
  });
}

// ---------- Routes ----------

// Home - show listings with unsanitized interpolation => XSS risk
app.get('/', (req, res) => {
  db.all('SELECT * FROM listings', (err, rows) => {
    let html = `<h1>Dorm listings</h1><a href="/login">Login</a> | <a href="/register">Register</a><ul>`;
    rows.forEach(r => {
      // UNSAFE: description inserted raw (XSS)
      html += `<li><a href="/listing/${r.id}">${r.title}</a> - ${r.description} - ${r.price} THB</li>`;
    });
    html += `</ul>`;
    res.send(html);
  });
});

// Vulnerable search endpoint: SQL injection via string concatenation
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  // VULNERABLE: direct concatenation into SQL
  const sql = `SELECT * FROM listings WHERE title LIKE '%${q}%' OR description LIKE '%${q}%'`;
  db.all(sql, (err, rows) => {
    if (err) return res.send('error');
    let html = `<h2>Search results for "${q}"</h2><ul>`;
    rows.forEach(r => html += `<li>${r.title} - ${r.description}</li>`);
    html += `</ul>`;
    res.send(html);
  });
});

// Listing view
app.get('/listing/:id', (req, res) => {
  const id = req.params.id;
  // VULNERABLE: no input validation but uses parameter placeholder? here we still use a template literal to show pattern
  db.get(`SELECT * FROM listings WHERE id = ${id}`, (err, row) => {
    if (!row) return res.send('not found');
    res.send(`<h1>${row.title}</h1><p>${row.description}</p><p>Price: ${row.price}</p>
      <form method="POST" action="/book">
        <input type="hidden" name="listing_id" value="${row.id}">
        Nights: <input name="nights" value="1"><button>Book</button>
      </form>`);
  });
});

// Booking (no auth check) => broken access control
app.post('/book', (req, res) => {
  const listing_id = req.body.listing_id;
  const nights = parseInt(req.body.nights || '1', 10);
  // get user id from cookie but no check if present
  const uid = parseInt(req.cookies.user_id || '0', 10) || 0;
  db.run(`INSERT INTO bookings (listing_id, user_id, nights) VALUES (${listing_id}, ${uid}, ${nights})`, function(err) {
    if (err) return res.send('error booking');
    res.send('booked (might be anonymous)'); // allows anonymous bookings
  });
});

// Registration - stores plaintext password (insecure)
app.get('/register', (req, res) => {
  res.send(`<form method="POST"><input name="username"><input name="password"><button>Register</button></form>`);
});
app.post('/register', (req, res) => {
  const u = req.body.username;
  const p = req.body.password;
  // VULNERABLE: storing password as plaintext, no validation
  db.run(`INSERT INTO users (username, password) VALUES ('${u}', '${p}')`, function(err) {
    if (err) return res.send('error or user exists');
    setAuthCookie(res, this.lastID);
    res.redirect('/');
  });
});

// Login (naive)
app.get('/login', (req, res) => {
  res.send(`<form method="POST"><input name="username"><input name="password"><button>Login</button></form>`);
});
app.post('/login', (req, res) => {
  const u = req.body.username;
  const p = req.body.password;
  // VULNERABLE: SQL injection possible because using naive string concatenation
  db.get(`SELECT id FROM users WHERE username = '${u}' AND password = '${p}'`, (err, row) => {
    if (row) {
      setAuthCookie(res, row.id);
      res.redirect('/');
    } else {
      res.send('bad creds');
    }
  });
});

// Admin-only page (but no strong auth checks)
app.get('/admin/listings', (req, res) => {
  getCurrentUser(req, (user) => {
    // BROKEN ACL: checks user.is_admin but attacker could tamper cookie to set user_id=1 (admin)
    if (!user || !user.is_admin) return res.status(403).send('forbidden');
    db.all('SELECT * FROM listings', (err, rows) => {
      let html = '<h1>Admin Listings</h1><ul>';
      rows.forEach(r => html += `<li>${r.id}: ${r.title} <a href="/admin/delete/${r.id}">Delete</a></li>`);
      html += '</ul>';
      res.send(html);
    });
  });
});

// Admin delete (no CSRF protection and no confirmation)
app.get('/admin/delete/:id', (req, res) => {
  const id = req.params.id;
  db.run(`DELETE FROM listings WHERE id = ${id}`, (err) => {
    res.send('deleted');
  });
});

// File upload for listing images (no file type checks -> arbitrary files can be uploaded and served)
app.get('/upload', (req, res) => {
  res.send(`<form enctype="multipart/form-data" method="POST">
    <input type="file" name="file"><input name="title"><button>Upload</button></form>`);
});
app.post('/upload', upload.single('file'), (req, res) => {
  // VULNERABLE: no validation, file saved to uploads/ and served statically
  const title = req.body.title || 'Untitled';
  // store a listing referencing the uploaded filename (no sanitization)
  db.run(`INSERT INTO listings (owner_id, title, description, price) VALUES (1, '${title}', 'Uploaded file: ${req.file.filename}', 100)`, function() {
    res.send(`uploaded as ${req.file.filename} - accessible at /uploads/${req.file.filename}`);
  });
});

app.listen(3000, () => console.log('Vulnerable demo running on http://localhost:3000'));
