const express = require('express');
const mysql = require('mysql2');
const escape = require('escape-html');

const router = express.Router();
const db = mysql.createPool({ host: 'localhost', user: 'app', database: 'main' });

router.get('/search', (req, res) => {
    const term = req.query.q || '';
    const query = `SELECT * FROM users WHERE name LIKE '%${term}%'`;
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json(results);
    });
});

router.get('/find', (req, res) => {
    const id = req.query.id || '';
    db.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json(results[0] || null);
    });
});

router.get('/profile', (req, res) => {
    const name = req.query.name || '';
    res.send(`
        <html>
        <body>
            <h1>Welcome, ${name}</h1>
        </body>
        </html>
    `);
});

router.get('/card', (req, res) => {
    const name = req.query.name || '';
    res.send(`
        <html>
        <body>
            <div class="card">${escape(name)}</div>
        </body>
        </html>
    `);
});

router.get('/data', (req, res) => {
    const input = req.query.input || '';
    res.json({ received: input });
});

module.exports = router;

