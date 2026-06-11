const express = require('express');
const path = require('path');
const fs = require('fs');
const { execSync, spawn } = require('child_process');

const router = express.Router();
const UPLOAD_DIR = '/var/uploads';

router.get('/download', (req, res) => {
    const filename = req.query.name || '';
    const filepath = path.join(UPLOAD_DIR, filename);
    res.sendFile(filepath);
});

router.get('/get', (req, res) => {
    const filename = req.query.name || '';
    const filepath = path.resolve(UPLOAD_DIR, filename);
    const base = path.resolve(UPLOAD_DIR);
    
    if (!filepath.startsWith(base + path.sep)) {
        return res.status(403).send('Forbidden');
    }
    
    if (!fs.existsSync(filepath)) {
        return res.status(404).send('Not found');
    }
    
    res.sendFile(filepath);
});

router.post('/convert', (req, res) => {
    const input = req.body.input || '';
    const output = req.body.output || '';
    execSync(`convert ${input} ${output}`);
    res.send('OK');
});

router.post('/resize', (req, res) => {
    const filename = req.body.filename || '';
    const size = req.body.size || '100x100';
    
    if (!/^[a-zA-Z0-9_-]+\.[a-z]+$/.test(filename)) {
        return res.status(400).send('Invalid filename');
    }
    
    if (!/^\d+x\d+$/.test(size)) {
        return res.status(400).send('Invalid size');
    }
    
    const child = spawn('convert', [
        '-resize', size,
        path.join(UPLOAD_DIR, filename),
        path.join('/tmp', filename)
    ]);
    
    child.on('close', (code) => {
        res.send(code === 0 ? 'OK' : 'Error');
    });
});

module.exports = router;

