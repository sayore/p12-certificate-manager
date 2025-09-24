const logger = require('./util/logger');


const chalk = require("chalk");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const flash = require('connect-flash');
const path = require('path');
const fs = require('fs');
const basicAuth = require('express-basic-auth');
const helmet = require('helmet');
const cors = require('cors');
const archiver = require('archiver');

const app = express();

let isTesting = false;
app.post('/testing/start', (req, res) => {
    isTesting = true;
    logger.log(chalk.yellow.bold('\n--- Test-Modus aktiviert. Eingehender Web-Traffic wird blockiert. ---'));
    res.status(200).send('Test mode activated.');
});

app.post('/testing/end', (req, res) => {
    isTesting = false;
    logger.log(chalk.green.bold('--- Test-Modus beendet. Server ist wieder voll erreichbar. ---'));
    res.status(200).send('Test mode deactivated.');
});
logger.addLevel("route")
app.use((req, res, next) => {
  
    logger.route(req.query)
    if (isTesting && !req.headers['x-test-secret']) {
        return res.status(503).send('Server is in test mode.');
    }
    next();
});

// --- Services importieren ---
const caService = require('./services/caService');
const x509Service = require('./services/x509Service');
const pgpService = require('./services/pgpService');
const { runTest } = require('./util/tests');
const { getJob } = require('./services/job-manager');
const { decrypt } = require('./services/utils');

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
    // KORREKTUR: Wir trimmen beide Werte und vergleichen sie case-insensitiv.
    const cert = db.find(c => c.serial.trim().toLowerCase() === serial.trim().toLowerCase());
    if (!cert) return null;
    // KORREKTUR: Wir geben den getrimmten Common Name zurück.
    return cert.commonName.trim();
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
    const { name, email, password, caPassword } = req.body; 
    try {
        if (!password || !caPassword) {
            throw new Error('A PGP password and the CA password are required.');
        }
        const job = await pgpService.generatePgpKey(caName, name, email, password, caPassword);
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
const apiAuth = basicAuth({
    users: { [process.env.ADMIN_USER]: process.env.ADMIN_PASSWORD },
});


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
        const pgpKeys = await pgpService.listPgpKeys(caName);
        // NEU: 'activePage' übergeben, damit das Menü den richtigen Link markiert
        res.render('ca_dashboard', { caName, x509Certs, pgpKeys, activePage: 'dashboard' });
    } catch (error) {
        req.flash('error', `Fehler beim Laden des Dashboards: ${error.message}`);
        res.redirect('/');
    }
});

// NEU: Route für die X.509-Management-Seite
app.get('/ca/:caName/x509', async (req, res) => {
    const { caName } = req.params;
    try {
        const x509Certs = x509Service.parseCaDatabase(caName);
        res.render('ca_x509', { caName, x509Certs, activePage: 'x509' });
    } catch (error) {
        req.flash('error', `Fehler beim Laden der X.509-Seite: ${error.message}`);
        res.redirect(`/ca/${caName}`);
    }
});

// NEU: Route für die PGP-Management-Seite
app.get('/ca/:caName/pgp', async (req, res) => {
    const { caName } = req.params;
    try {
        const pgpKeys = await pgpService.listPgpKeys(caName);
        res.render('ca_pgp', { caName, pgpKeys, activePage: 'pgp' });
    } catch (error) {
        req.flash('error', `Fehler beim Laden der PGP-Seite: ${error.message}`);
        res.redirect(`/ca/${caName}`);
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

app.post('/ca/:caName/issue-cert', async (req, res) => {
    const { caName } = req.params;
    const { certType, commonName, altNames, caPassword } = req.body;

    try {
        if (certType === 'client') {
            await x509Service.issueClientCert(caName, caPassword, commonName);
            req.flash('success', `Client-Zertifikat für "${commonName}" erfolgreich ausgestellt.`);
        } else if (certType === 'server') {
            await x509Service.issueServerCert(caName, caPassword, commonName, altNames);
            req.flash('success', `Server-Zertifikat für "${commonName}" erfolgreich ausgestellt.`);
        } else {
            throw new Error('Ungültiger Zertifikatstyp.');
        }
    } catch (error) {
        req.flash('error', `Fehler beim Ausstellen des Zertifikats: ${error.message}`);
    }
    res.redirect(`/ca/${req.params.caName}/x509`); 
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
    const { name, email, password, caPassword } = req.body;
    try {
         if (!password || !caPassword) throw new Error('PGP-Passwort und CA-Passwort werden benötigt.');
        pgpService.generatePgpKey(caName, name, email, password, caPassword);
        req.flash('success', `PGP-Schlüsselerstellung wurde gestartet.`);
    } catch (error) {
        req.flash('error', `Fehler beim Starten der PGP-Schlüsselerstellung: ${error.message}`);
    }
    // Leite sofort um, damit das UI nicht blockiert
    res.redirect(`/ca/${req.params.caName}/pgp`);
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

app.get('/ca/:caName/download/x509/:serial/p12', webAuth, (req, res) => {
    const { caName, serial } = req.params;
    try {
        const commonName = getCommonNameBySerial(caName, serial);
        if (!commonName) {
            throw new Error('Zertifikat mit dieser Seriennummer nicht in der Datenbank gefunden.');
        }

        // Der Pfad zur .p12-Datei
        const p12File = path.join(caService.caBaseDir, caName, 'issued', commonName, `${commonName}.p12`);

        if (fs.existsSync(p12File)) {
            // res.download() kümmert sich um alles Weitere
            return res.download(p12File);
        } else {
            throw new Error('.p12-Datei auf dem Dateisystem nicht gefunden. Wurde sie korrekt erstellt?');
        }
    } catch (error) {
        logger.error("P12 Download Error:", error);
        return res.status(500).render('error_page', {
            caName: req.params.caName,
            errorMessage: `Download-Fehler: ${error.message}`,
            activePage: 'x509'
        });
    }
});

app.post('/ca/:caName/pgp/:fingerprint/download-private', async (req, res) => {
    const { caName, fingerprint } = req.params;
    const { caPassword } = req.body;
    try {
        if (!caPassword) throw new Error('CA-Passwort ist erforderlich.');

        // Die Logik zum Finden und Entschlüsseln des Passworts ist identisch zu oben
        const keyInfo = (await pgpService.listPgpKeys(caName)).find(k => k.fingerprint === fingerprint);
        if (!keyInfo) throw new Error('Schlüssel nicht gefunden.');
        
        const emailMatch = keyInfo.uids[0].match(/<([^>]+)>/);
        const email = emailMatch ? emailMatch[1] : null;
        let secretFile = path.join(caService.caBaseDir, caName, 'gpg', `${fingerprint}.secret`);
        if (!fs.existsSync(secretFile) && email) {
            secretFile = path.join(caService.caBaseDir, caName, 'gpg', `${email}.secret`);
        }
        if (!fs.existsSync(secretFile)) {
            throw new Error('Passwort-Datei (.secret) nicht gefunden.');
        }

        const encryptedPassword = fs.readFileSync(secretFile, 'utf-8');
        const decryptedPgpPassword = decrypt(encryptedPassword, caPassword);

        // Exportiere den privaten Schlüssel mit dem entschlüsselten Passwort
        const privateKeyBlock = await pgpService.exportPgpPrivateKey(caName, fingerprint, decryptedPgpPassword);

        // Sende den Schlüssel als Datei-Download
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Content-Disposition', `attachment; filename="${fingerprint}.private.asc"`);
        res.send(privateKeyBlock);

    } catch (error) {
        logger.error(`Download failed for PGP private key ${fingerprint}:`, error.message);
        // Wir rendern die Fehlerseite mit klarem Feedback.
        // Status 422: Unprocessable Entity - Die Anfrage war syntaktisch korrekt,
        // konnte aber aufgrund semantischer Fehler (falsches Passwort) nicht verarbeitet werden.
        res.status(422).render('error_page', {
            caName: caName,
            errorMessage: `Fehler beim Export des privaten Schlüssels. Ist das CA-Passwort korrekt? (Details: ${error.message})`,
            // Setzen Sie die activePage, damit das Seitenmenü korrekt bleibt
            activePage: 'pgp' 
        });
    }
});

app.post('/ca/:caName/pgp/:fingerprint/show-password', async (req, res) => {
    const { caName, fingerprint } = req.params;
    const { caPassword } = req.body;
    try {
        if (!caPassword) throw new Error('CA-Passwort ist erforderlich.');

        // 1. Finde den Schlüssel, um die .secret-Datei zu lokalisieren
        const keyInfo = (await pgpService.listPgpKeys(caName)).find(k => k.fingerprint === fingerprint);
        if (!keyInfo) throw new Error('Schlüssel nicht gefunden.');

        // 2. Finde die Secret-Datei (primär nach Fingerprint, fallback auf E-Mail)
        const emailMatch = keyInfo.uids[0].match(/<([^>]+)>/);
        const email = emailMatch ? emailMatch[1] : null;
        let secretFile = path.join(caService.caBaseDir, caName, 'gpg', `${fingerprint}.secret`);
        if (!fs.existsSync(secretFile) && email) {
            secretFile = path.join(caService.caBaseDir, caName, 'gpg', `${email}.secret`);
        }
        if (!fs.existsSync(secretFile)) {
            throw new Error('Passwort-Datei (.secret) für diesen Schlüssel nicht gefunden.');
        }

        // 3. Entschlüssle das Passwort
        const encryptedPassword = fs.readFileSync(secretFile, 'utf-8');
        const decryptedPassword = decrypt(encryptedPassword, caPassword);

        // 4. Zeige es als Flash-Nachricht an
        req.flash('success', `Passwort für Schlüssel ${fingerprint.substring(0, 16)}... lautet: ${decryptedPassword}`);
    } catch (error) {
        req.flash('error', `Passwort konnte nicht abgerufen werden. Ist das CA-Passwort korrekt? (${error.message})`);
    }
    res.redirect(`/ca/${caName}/pgp`);
});

app.get('/ca/:caName/download/x509/:serial/zip', webAuth, (req, res) => {
    const { caName, serial } = req.params;

    try {
        const commonName = getCommonNameBySerial(caName, serial);
        if (!commonName) {
            throw new Error('Zertifikat mit dieser Seriennummer nicht in der Datenbank gefunden.');
        }

        const issuedDir = path.join(caService.caBaseDir, caName, 'issued', commonName);
        const certFile = path.join(issuedDir, `${commonName}.crt`);
        const keyFile = path.join(issuedDir, `${commonName}.key`);
        const caCertFile = path.join(caService.caBaseDir, caName, 'ca.crt');
        
        const certExists = fs.existsSync(certFile);
        const keyExists = fs.existsSync(keyFile);
        const caCertExists = fs.existsSync(caCertFile);

        if (!certExists || !keyExists || !caCertExists) {
             throw new Error('Eine oder mehrere Zertifikatsdateien wurden auf dem Dateisystem nicht gefunden.');
        }

        const archive = archiver('zip', { zlib: { level: 9 } });
        
        archive.on('error', function(err) { throw err; });

        const sanitizedCommonName = commonName.replace(/[^a-zA-Z0-9\.\-\_]/g, '_');

        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename=${commonName.replace(/[^a-zA-Z0-9\.\-\_]/g, '_')}.zip`);
        
        archive.pipe(res);
        archive.file(certFile, { name: `${sanitizedCommonName}_${serial}.crt` });
        archive.file(keyFile, { name: `${sanitizedCommonName}_${serial}.key` });
        archive.file(caCertFile, { name: 'ca.crt' });

        return archive.finalize();

    } catch (error) {
        return res.status(500).render('error_page', {
            caName: req.params.caName,
            errorMessage: `ZIP-Erstellungsfehler: ${error.message}`,
            activePage: 'x509'
        });
    }
});

// =======================================================
// --- SERVERSTART UND TEST-AUSFÜHRUNG ---
// =======================================================
app.listen(PORT, () => {
    logger.log(`CA Master Server running on http://localhost:${PORT}`);
    if (process.env.RUN_TESTS === 'true') {

        logger.pauseDefaultOutput()
        const collector = logger.createCollector()

        runTest("e2e").then(()=>{
          collector.print()
        }).catch(e => {
            logger.error('Test runner process failed:', e);
            // Wichtig: Sorge dafür, dass der Server bei einem Fehler im Test beendet wird
            process.exit(1); 
        });
        
    }
});