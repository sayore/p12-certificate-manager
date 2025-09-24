const fs = require('fs');
const path = require('path');
const { runCommand } = require('./utils');
const logger = require('../util/logger');

const caBaseDir = path.join(__dirname, '..', 'multi_ca_files');

// Stellt sicher, dass das Hauptverzeichnis existiert
if (!fs.existsSync(caBaseDir)) {
    fs.mkdirSync(caBaseDir);
}

async function createCA(caName, password, details) {
    if (!caName || !/^[a-zA-Z0-9_-]+$/.test(caName)) {
        throw new Error('Invalid CA name. Only letters, numbers, underscore, and hyphen are allowed.');
    }

    const caDir = path.join(caBaseDir, caName);
    if (fs.existsSync(caDir)) throw new Error('CA with this name already exists.');

    // Ordnerstruktur anlegen
    ['certs', 'crl', 'newcerts', 'private', 'gpg'].forEach(dir => {
        fs.mkdirSync(path.join(caDir, dir), { recursive: true });
    });

    const openSslCnfPath = path.join(caDir, 'openssl.cnf');
    const cnfTemplatePath = path.join(__dirname, '..', 'openssl.template.cnf');

    if (!fs.existsSync(cnfTemplatePath)) {
        throw new Error(`Template file not found at ${cnfTemplatePath}`);
    }

    const cnfTemplate = fs.readFileSync(cnfTemplatePath, 'utf-8');
    const cnfContent = cnfTemplate
        .replace(/{{CA_NAME}}/g, caName)
        .replace(/{{COUNTRY}}/g, details.country || 'DE')
        .replace(/{{STATE}}/g, details.state || 'N/A')
        .replace(/{{LOCALITY}}/g, details.locality || 'N/A')
        .replace(/{{ORGANIZATION}}/g, details.organization || caName);
        
    fs.writeFileSync(openSslCnfPath, cnfContent);
    
    // Sicherheitsprüfung: Existiert die Datei wirklich, bevor wir weitermachen?
    if (!fs.existsSync(openSslCnfPath)) {
        throw new Error(`Failed to write OpenSSL config to ${openSslCnfPath}`);
    }

    // Initialisiere die restlichen benötigten Dateien
    fs.writeFileSync(path.join(caDir, 'index.txt'), '');
    fs.writeFileSync(path.join(caDir, 'serial'), '1000');
    fs.writeFileSync(path.join(caDir, 'crlnumber'), '1000');

    const caKey = path.join(caDir, 'private', 'ca.key');
    const caCert = path.join(caDir, 'ca.crt');
    
    const env = { CA_PASS: password };

    // Generiere Schlüssel und Zertifikat.
    await runCommand(`openssl genrsa -aes256 -out "${caKey}" -passout env:CA_PASS 4096`, env);
    await runCommand(`openssl req -config "${openSslCnfPath}" -key "${caKey}" -new -x509 -days 3650 -sha256 -extensions v3_ca -out "${caCert}" -passin env:CA_PASS -subj "/CN=${caName}"`, env);

    // Initialisiere das GPG-Verzeichnis
    //const gpgHome = path.join(caDir, 'gpg');
    //await runCommand(`gpg --homedir "${gpgHome}" --list-keys`);
}

function listCAs() {
    if (!fs.existsSync(caBaseDir)) return [];
    return fs.readdirSync(caBaseDir, { withFileTypes: true })
        .filter(dirent => dirent.isDirectory())
        .map(dirent => ({ name: dirent.name }));
}

module.exports = { createCA, listCAs, caBaseDir };