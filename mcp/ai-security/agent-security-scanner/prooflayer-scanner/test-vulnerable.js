// test-vulnerable.js - Sample file with vulnerabilities for testing

const express = require('express');
const mysql = require('mysql');
const app = express();

// VULNERABILITY 1: Hardcoded secret
const API_KEY = 'sk_live_1234567890abcdef';

// VULNERABILITY 2: SQL injection
app.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = 'SELECT * FROM users WHERE id = ' + userId; // SQL injection
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// VULNERABILITY 3: XSS
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  res.send('<h1>Results for: ' + searchTerm + '</h1>'); // XSS vulnerability
});

// VULNERABILITY 4: Command injection
app.post('/backup', (req, res) => {
  const filename = req.body.filename;
  require('child_process').exec('tar -czf backup.tar.gz ' + filename);
});

app.listen(3000);
