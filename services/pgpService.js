const fs = require('fs');
const path = require('path');
const { runCommand } = require('./utils');
const { caBaseDir } = require('./caService');
const { runJob } = require('./job-manager');

async function generatePgpKey(caName, name, email, password) {
    const gpgHome = path.join(caBaseDir, caName, 'gpg');
    const paramFile = path.join(gpgHome, 'gpg-params.txt');
    
    const params = `
        Key-Type: RSA
        Key-Length: 4096
        Subkey-Type: RSA
        Subkey-Length: 4096
        Name-Real: ${name}
        Name-Email: ${email}
        Expire-Date: 1y
        Passphrase: ${password}
        %commit
    `;
    fs.writeFileSync(paramFile, params);

    const env = { GNUPGHOME: gpgHome };
    
    // Wir starten den Job und geben das Job-Objekt sofort zurück. KEIN await!
    const job = runJob(`gpg --batch --pinentry-mode loopback --full-generate-key "${paramFile}"`, env, gpgHome);
    
    // Die temporäre Datei wird jetzt im Job-Handler gelöscht, wenn er fertig ist.
    // Aber für diese simple Version lassen wir sie erstmal.

    return job;
}

async function listPgpKeys(caName) {
    const gpgHome = path.join(caBaseDir, caName, 'gpg');
    const env = { GNUPGHOME: gpgHome };
    try {
        // Der Befehl wird um --with-fingerprint erweitert, um die fpr-Zeile zu garantieren
        const output = await runCommand(`gpg --list-keys --with-colons --with-fingerprint`, env, gpgHome);
        
        const keys = [];
        let currentKey = null;

        output.split('\n').forEach(line => {
            const parts = line.split(':');
            const type = parts[0];

            if (type === 'pub') {
                // Wenn ein vorheriger Schlüssel existiert, diesen zur Liste hinzufügen
                if (currentKey) {
                    keys.push(currentKey);
                }
                // Einen neuen Schlüssel beginnen
                currentKey = {
                    fingerprint: '', // Wird von der 'fpr'-Zeile befüllt
                    created: new Date(parseInt(parts[5]) * 1000).toLocaleDateString(),
                    expires: parts[6] ? new Date(parseInt(parts[6]) * 1000).toLocaleDateString() : 'Never',
                    uids: []
                };
            }

            if (type === 'fpr' && currentKey) {
                // Den Fingerabdruck zum aktuellen Schlüssel hinzufügen
                currentKey.fingerprint = parts[9];
            }

            if (type === 'uid' && currentKey) {
                // Die Benutzer-ID zum aktuellen Schlüssel hinzufügen
                currentKey.uids.push(parts[9].replace(/\\x3c/g, '<').replace(/\\x3e/g, '>'));
            }
        });

        // Den letzten verarbeiteten Schlüssel hinzufügen
        if (currentKey && currentKey.fingerprint) {
            keys.push(currentKey);
        }

        return keys;
    } catch (error) {
        if (error.message.includes('No public key') || error.message.includes('kein öffentlicher Schlüssel gefunden')) return [];
        throw error;
    }
}

async function getPgpPublicKey(caName, fingerprint) {
    const gpgHome = path.join(caBaseDir, caName, 'gpg');
    const env = { GNUPGHOME: gpgHome };
    // Die entscheidende Option wird hier hinzugefügt
    const command = `gpg --armor --export-options export-local-sigs --export ${fingerprint}`;
    return await runCommand(command, env, gpgHome);
}

module.exports = { generatePgpKey, listPgpKeys, getPgpPublicKey };