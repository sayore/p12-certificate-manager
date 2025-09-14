require('dotenv').config();
const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const path = require('path');
const fs = require('fs');
const basicAuth = require('express-basic-auth');
const helmet = require('helmet');
const cors = require('cors');

const app = express();

// --- Services importieren ---
const caService = require('./services/caService');
const x509Service = require('./services/x509Service');
const pgpService = require('./services/pgpService');
const { runTest } = require('./util/tests');
const { getJob } = require('./services/job-manager');

// --- Konfiguration ---
const PORT = process.env.PORT || 3000;

// --- Grundlegende Middleware (sicher für alle Routen) ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- View Engine ---
app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));

function getCommonNameBySerial(caName, serial) {
    const db = x509Service.parseCaDatabase(caName);
    const cert = db.find(c => c.serial === serial);
    if (!cert) throw new Error('Certificate not found for this serial.');
    return cert.commonName;
}

// =======================================================
// --- ÖFFENTLICHE ROUTEN (OHNE AUTHENTIFIZIERUNG) ---
// =======================================================
// Diese müssen VOR allen sicherheitsrelevanten Middlewares stehen.
app.get('/ca/:caName/crl.pem', (req, res) => {
    const crlFile = path.join(caService.caBaseDir, req.params.caName, 'crl.pem');
    if (fs.existsSync(crlFile)) {
        res.setHeader('Content-Type', 'application/pkix-crl');
        res.sendFile(crlFile);
    } else {
        res.status(404).send('CRL not found.');
    }
});

app.get('/ca/:caName/ca.crt', (req, res) => {
    const caCertFile = path.join(caService.caBaseDir, req.params.caName, 'ca.crt');
    if (fs.existsSync(caCertFile)) {
        res.setHeader('Content-Type', 'application/x-x509-ca-cert');
        res.sendFile(caCertFile);
    } else {
        res.status(404).send('CA certificate not found.');
    }
});

app.get('/ca/:caName/pgp/:fingerprint/pub', async (req, res) => {
    const { caName, fingerprint } = req.params;
    try {
        const publicKey = await pgpService.getPgpPublicKey(caName, fingerprint);
        res.setHeader('Content-Type', 'text/plain');
        res.send(publicKey);
    } catch (error) {
        res.status(500).send(`Could not retrieve public key: ${error.message}`);
    }
});

app.post('/api/ca/:caName/generate-pgp', async (req, res) => { // 1. Route als `async` deklarieren
    const { caName } = req.params;
    const { name, email, password } = req.body;
    try {
        if (!password) throw new Error('A password is required.');
        const job = await pgpService.generatePgpKey(caName, name, email, password); // 2. Auf das Ergebnis warten
        res.status(202).json({ 
            message: 'PGP key generation started.',
            jobId: job.id,
            statusUrl: `/jobs/${job.id}/status`
        });
    } catch (error) {
        res.status(500).json({ error: `Failed to start PGP key generation: ${error.message}` });
    }
});

app.get('/jobs/:jobId/status', (req, res) => {
    const job = getJob(req.params.jobId);
    if (!job) {
        return res.status(404).json({ error: 'Job not found.' });
    }
    res.json({
        jobId: job.id,
        status: job.status,
        error: job.error
    });
});

// =======================================================
// --- GESICHERTE ROUTEN - SETUP DER MIDDLEWARE ---
// =======================================================
// Ab hier werden Sicherheits-Header, Sessions und Authentifizierung für alle folgenden Routen aktiviert.

app.use(cors());
app.use(helmet());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // In Produktion auf 'true' setzen, wenn HTTPS verwendet wird.
}));
app.use(flash());
app.use((req, res, next) => {
    res.locals.message = req.flash('success');
    res.locals.error = req.flash('error');
    next();
});

const webAuth = basicAuth({
    users: { [process.env.ADMIN_USER]: process.env.ADMIN_PASSWORD },
    challenge: true,
    realm: 'CA Master Control',
});
app.use(webAuth);


// =======================================================
// --- GESICHERTE ROUTEN - DEFINITIONEN ---
// =======================================================

// Hauptseite
app.get('/', (req, res) => {
    const cas = caService.listCAs();
    res.render('index', { cas });
});

// CA-spezifische Aktionen
app.post('/create-ca', async (req, res) => { // 1. Fügen Sie `async` hier hinzu
    const { caName, caPassword, country, state, locality, organization } = req.body;
    try {
        if (!caPassword) throw new Error('CA Password is required.');
        // 2. Fügen Sie `await` hier hinzu, um auf das Ergebnis zu warten
        await caService.createCA(caName, caPassword, { country, state, locality, organization }); 
        req.flash('success', `CA "${caName}" wurde erfolgreich erstellt!`);
    } catch (error) {
        req.flash('error', `Fehler beim Erstellen der CA: ${error.message}`);
    }
    res.redirect('/');
});

app.get('/ca/:caName', async (req, res) => {
    const { caName } = req.params;
    try {
        const x509Certs = x509Service.parseCaDatabase(caName);
        const pgpKeys = await pgpService.listPgpKeys(caName); // PGP-Schlüssel laden
        res.render('ca_dashboard', { caName, x509Certs, pgpKeys }); // An das Template übergeben
    } catch (error) {
        req.flash('error', `Fehler beim Laden des Dashboards: ${error.message}`);
        res.redirect('/');
    }
});

// X.509 Aktionen
app.post('/ca/:caName/issue-client', async (req, res) => {
    const { caName } = req.params;
    const { commonName, caPassword } = req.body;
    try {
        const result = await x509Service.issueClientCert(caName, caPassword, commonName);
        req.flash('success', `Client-Zertifikat für "${commonName}" (Serial: ${result.serial}) erfolgreich ausgestellt.`);
    } catch (error) {
        req.flash('error', `Fehler beim Ausstellen des Client-Zertifikats: ${error.message}`);
    }
    res.redirect(`/ca/${caName}`);
});

app.post('/ca/:caName/issue-server', async (req, res) => {
    const { caName } = req.params;
    const { commonName, altNames, caPassword } = req.body;
    try {
        const result = await x509Service.issueServerCert(caName, caPassword, commonName, altNames);
        req.flash('success', `Server-Zertifikat für "${commonName}" (Serial: ${result.serial}) erfolgreich ausgestellt.`);
    } catch (error) {
        req.flash('error', `Fehler beim Ausstellen des Server-Zertifikats: ${error.message}`);
    }
    res.redirect(`/ca/${caName}`);
});

app.post('/ca/:caName/revoke-x509', async (req, res) => {
    const { caName } = req.params;
    const { serial, caPassword } = req.body;
    try {
        await x509Service.revokeCert(caName, caPassword, serial);
        req.flash('success', `Zertifikat mit der Seriennummer ${serial} wurde widerrufen.`);
    } catch (error) {
        req.flash('error', `Fehler beim Widerrufen des Zertifikats: ${error.message}`);
    }
    res.redirect(`/ca/${caName}`);
});

// PGP Aktionen für das WEB-UI
app.post('/ca/:caName/generate-pgp', async (req, res) => {
    const { caName } = req.params;
    const { name, email, password } = req.body;
    try {
        if (!password) throw new Error('A password is required.');
        // Diese Funktion startet den Job, aber wir warten hier nicht auf das Ergebnis
        pgpService.generatePgpKey(caName, name, email, password);
        // Wir setzen eine Erfolgsmeldung, die "wird erstellt" sagt
        req.flash('success', `PGP-Schlüsselerstellung für "${name} <${email}>" wurde gestartet.`);
    } catch (error) {
        req.flash('error', `Fehler beim Starten der PGP-Schlüsselerstellung: ${error.message}`);
    }
    // Leite sofort um, damit das UI nicht blockiert
    res.redirect(`/ca/${caName}`);
});

app.get('/ca/:caName/pgp/:fingerprint/pub', async (req, res) => {
    const { caName, fingerprint } = req.params;
    try {
        const publicKey = await pgpService.getPgpPublicKey(caName, fingerprint);
        res.setHeader('Content-Type', 'text/plain');
        res.send(publicKey);
    } catch (error) {
        res.status(500).send(`Could not retrieve public key: ${error.message}`);
    }
});

// API für Code-Snippets
app.get('/api/ca/:caName/snippets/:commonName', (req, res) => {
    const { caName, commonName } = req.params;
    const { verify } = req.query;
    const certPath = `/etc/ssl/${caName}/${commonName}.crt`;
    const keyPath = `/etc/ssl/${caName}/${commonName}.key`;
    const caPath = `/etc/ssl/${caName}/ca.crt`;
    const crlPath = `/etc/ssl/${caName}/crl.pem`;
    let nginxVerifyBlock = '';
    if (verify === 'on' || verify === 'optional') {
        nginxVerifyBlock = `\n    # Client-Zertifikats-Verifizierung\n    ssl_client_certificate ${caPath};\n    ssl_verify_client      ${verify};\n    ssl_verify_depth       2;\n    ssl_crl                ${crlPath};`;
    }
    const nginxSnippet = `server {\n    listen 443 ssl http2;\n    server_name ${commonName};\n\n    ssl_certificate         ${certPath};\n    ssl_certificate_key     ${keyPath};\n    \n    # Empfohlene Sicherheitseinstellungen\n    ssl_protocols           TLSv1.2 TLSv1.3;\n    ssl_prefer_server_ciphers on;${nginxVerifyBlock}\n\n    # ... Ihre restliche Konfiguration\n}`;
    let apacheVerifyBlock = '';
    if (verify === 'on' || verify === 'optional') {
        const apacheVerifyLevel = verify === 'on' ? 'require' : 'optional';
        apacheVerifyBlock = `\n    # Client-Zertifikats-Verifizierung\n    SSLCACertificateFile      ${caPath}\n    SSLCARevocationFile     ${crlPath}\n    SSLVerifyClient         ${apacheVerifyLevel}\n    SSLVerifyDepth          2`;
    }
    const apacheSnippet = `<VirtualHost *:443>\n    ServerName ${commonName}\n\n    SSLEngine on\n    SSLCertificateFile      ${certPath}\n    SSLCertificateKeyFile   ${keyPath}${apacheVerifyBlock}\n\n    # ... Ihre restliche Konfiguration\n</VirtualHost>`;
    res.json({ nginx: nginxSnippet.trim(), apache: apacheSnippet.trim() });
});

app.post('/ca/:caName/download/x509/:serial/p12', (req, res) => {
    try {
        const { caName, serial } = req.params;
        // Das CA-Passwort wird hier nicht benötigt, ist aber für die Zukunft reserviert
        const commonName = getCommonNameBySerial(caName, serial);
        const p12File = path.join(caService.caBaseDir, caName, 'issued', commonName, `${commonName}.p12`);

        if (fs.existsSync(p12File)) {
            res.download(p12File); // res.download kümmert sich um die richtigen Header
        } else {
            req.flash('error', '.p12-Datei nicht gefunden. Möglicherweise wurde sie vor der Implementierung dieser Funktion erstellt.');
            res.redirect(`/ca/${caName}`);
        }
    } catch (error) {
        req.flash('error', `Download-Fehler: ${error.message}`);
        res.redirect(`/ca/${req.params.caName}`);
    }
});

app.post('/ca/:caName/download/x509/:serial/zip', (req, res) => {
    try {
        const { caName, serial } = req.params;
        const commonName = getCommonNameBySerial(caName, serial);

        const issuedDir = path.join(caService.caBaseDir, caName, 'issued', commonName);
        const certFile = path.join(issuedDir, `${commonName}.crt`);
        const keyFile = path.join(issuedDir, `${commonName}.key`);
        const caCertFile = path.join(caService.caBaseDir, caName, 'ca.crt');

        if (!fs.existsSync(certFile) || !fs.existsSync(keyFile)) {
             req.flash('error', 'Zertifikatsdateien nicht gefunden.');
             return res.redirect(`/ca/${caName}`);
        }

        const archive = archiver('zip', { zlib: { level: 9 } });
        
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename=${commonName}.zip`);

        archive.pipe(res);
        archive.file(certFile, { name: `${commonName}.crt` });
        archive.file(keyFile, { name: `${commonName}.key` });
        archive.file(caCertFile, { name: 'ca.crt' });
        archive.finalize();

    } catch (error) {
        req.flash('error', `ZIP-Erstellungsfehler: ${error.message}`);
        res.redirect(`/ca/${req.params.caName}`);
    }
});

// =======================================================
// --- SERVERSTART UND TEST-AUSFÜHRUNG ---
// =======================================================
app.listen(PORT, () => {
    console.log(`CA Master Server running on http://localhost:${PORT}`);

    setTimeout(async () => {
        runTest("e2e")
    }, 200); 
});