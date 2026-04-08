// Intentionally Vulnerable Node.js Test File
// DO NOT USE IN PRODUCTION

const fs = require('fs');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const mysql = require('mysql');
const { exec } = require('child_process');
const express = require('express');
const xml2js = require('xml2js');
const app = express();

app.use(express.json());

// ===============================
// Hardcoded Password
// ===============================
const DB_PASSWORD = "admin123";

// ===============================
// Unsafe DB Connection String Building
// ===============================
const connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: DB_PASSWORD,
    database: "testdb"
});

// Connection without timeout
connection.connect();

// ===============================
// Unsafe SQL Query Construction
// ===============================
app.get('/user', (req, res) => {
    const username = req.query.username;
    // Use parameterized query to prevent SQL injection
    const query = "SELECT * FROM users WHERE username = ?";
    connection.query(query, [username], function (err, results) {
        if (err) {
            // Don't expose internal error details to the client
            res.status(500).send({ error: 'Database query failed' });
            return;
        }
        res.send(results);
    });
});

// ===============================
// File Creation without permissions
// ===============================
function createFile() {
    fs.writeFileSync('/tmp/test.txt', "Sensitive Data"); // Hardcoded path
}

// Improper File Permissions
fs.writeFileSync('/tmp/public.txt', "data", { mode: 0o777 });

// File Deletion without checking existence
fs.unlinkSync('/tmp/old.txt');

// FileWriter without encoding
const stream = fs.createWriteStream('/tmp/log.txt');
stream.write("log entry");

// ===============================
// Insecure Logging of Sensitive Info
// ===============================
function login(password) {
    console.log("User password:", password); // Sensitive data exposure
}

// ===============================
// Weak Hashing + Deprecated Algorithm
// ===============================
function weakHash(data) {
    return crypto.createHash('md5').update(data).digest('hex');
}

// ===============================
// Weak Encryption Mode + Non-random IV
// ===============================
function weakEncryption() {
    const key = crypto.randomBytes(16);
    const iv = Buffer.alloc(16, 0); // Non-random IV
    const cipher = crypto.createCipheriv('aes-128-ecb', key, iv); // Weak mode ECB
    cipher.update("secret", 'utf8', 'hex');
}

// ===============================
// Weak Random
// ===============================
function weakRandom() {
    return Math.random(); // Weak random
}

// ===============================
// Insecure Exception Handling
// ===============================
try {
    throw new Error("Test error");
} catch (e) {
    console.log(e.stack); // Exposes stack trace
}

// ===============================
// Unsafe Cookie (no HttpOnly, no Domain)
// ===============================
app.get('/setcookie', (req, res) => {
    res.cookie("sessionId", "12345"); // Insecure cookie
    res.send("Cookie set");
});

// ===============================
// Potential XSS
// ===============================
app.get('/xss', (req, res) => {
    const input = req.query.input;
    res.send("<html>" + input + "</html>");
});

// ===============================
// Unsafe Redirect
// ===============================
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    res.redirect(url);
});

// ===============================
// Unsafe Path Handling
// ===============================
app.get('/readfile', (req, res) => {
    const filename = req.query.name;
    const content = fs.readFileSync('/uploads/' + filename);
    res.send(content);
});

// ===============================
// Unsafe Deserialization
// ===============================
app.post('/deserialize', (req, res) => {
    const obj = JSON.parse(req.body.data); // Unsafe deserialization
    res.send(obj);
});

// ===============================
// Potential XXE
// ===============================
function parseXML(xmlData) {
    const parser = new xml2js.Parser({ explicitEntities: true });
    parser.parseString(xmlData, function (err, result) {
        console.log(result);
    });
}

// ===============================
// Potential SSRF
// ===============================
app.get('/fetch', (req, res) => {
    const target = req.query.url;
    http.get(target, response => {
        response.pipe(res);
    });
});

// ===============================
// REST Call without timeout & error handler
// ===============================
function restCall() {
    http.get("http://example.com", (res) => {
        console.log("Status:", res.statusCode); // No validation
    });
}

// ===============================
// Ignoring SSL Hostname Verification
// ===============================
const insecureAgent = new https.Agent({
    rejectUnauthorized: false
});

https.get("https://example.com", { agent: insecureAgent }, (res) => {
    console.log(res.statusCode);
});

// ===============================
// Unsafe OS Command Generation
// ===============================
function runCommand(userInput) {
    exec("ls " + userInput, (err, stdout, stderr) => {
        console.log(stdout);
    });
}

// ===============================
// Incorrect String Comparison
// ===============================
function checkUser(input) {
    if (input == "admin") {
        console.log("Admin logged in");
    }
}

// ===============================
// Sensitive Data Exposure
// ===============================
app.get('/debug', (req, res) => {
    res.send(process.env); // Exposes environment variables
});

// ===============================
// Unsafe Thread Termination (simulated)
// ===============================
process.exit(); // Forceful termination

// ===============================
// Resource Leak (no close)
// ===============================
const fileHandle = fs.openSync('/tmp/resource.txt', 'w');

// ===============================
// Start Server
// ===============================
app.listen(3000, () => {
    console.log("Vulnerable app running on port 3000");
});
