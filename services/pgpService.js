const fs = require('fs');
const path = require('path');
const { caBaseDir } = require('./caService');
const { runJob } = require('./job-manager');
const { runCommand, encrypt, decrypt } = require('./utils'); 
const logger = require('../util/logger');

async function generatePgpKey(caName, name, email, pgpPassword, caPassword, onComplete=()=>{}) {
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
        Passphrase: ${pgpPassword}
        %commit
    `;
    fs.writeFileSync(paramFile, params);

    const encryptedPassword = encrypt(pgpPassword, caPassword);
    const env = { GNUPGHOME: gpgHome };

    // --- NEUE LOGIK: Die onComplete-Funktion definieren ---
    const onJobComplete = (completedJob) => {
        // Aufräumen: Die Parameterdatei wird nicht mehr benötigt
        if (fs.existsSync(paramFile)) {
            fs.unlinkSync(paramFile);
        }

        // Nur fortfahren, wenn der Job erfolgreich war
        if (completedJob.status !== 'running') {
            logger.error(`GPG key generation job ${completedJob.id} failed, not saving secret.`);
            return;
        }

        // Jetzt, da der Job fertig ist, können wir den Fingerabdruck des NEUEN Schlüssels finden.
        // GPG gibt bei --full-generate-key oft den neuen Fingerabdruck in stderr/stdout aus.
        const output = completedJob.output;
        const fingerprintMatch = output.match(/gpg: key ([A-F0-9]{40}) marked as ultimately trusted/);
        
        if (fingerprintMatch && fingerprintMatch[1]) {
            const fingerprint = fingerprintMatch[1];
            logger.log(`Successfully extracted fingerprint ${fingerprint} for new PGP key.`);
            const secretFile = path.join(gpgHome, `${fingerprint}.secret`);
            fs.writeFileSync(secretFile, encryptedPassword);
        } else {
            // Fallback: Wenn wir den Fingerprint nicht parsen können.
            // Dies ist ein Risiko, aber besser als nichts.
            logger.warn(`Could not parse fingerprint from GPG output for job ${completedJob.id}. Saving secret with email as name.`);
            const secretFile = path.join(gpgHome, `${email}.secret`);
            fs.writeFileSync(secretFile, encryptedPassword);
        }
    };

    // --- ÄNDERUNG: Wir übergeben die onComplete-Funktion an runJob ---
    const job = runJob(
        `gpg --batch --pinentry-mode loopback --full-generate-key "${paramFile}"`, 
        env, 
        gpgHome,
        onJobComplete // Hier wird der Callback übergeben
    );
    
    // Die .secret-Datei wird hier NICHT mehr geschrieben.
    return job;
}

// ... (Rest der Datei, insbesondere listPgpKeys, anpassen, damit es mit fingerprint.secret umgehen kann)

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

/**
 * Exportiert einen privaten PGP-Schlüssel.
 * Benötigt das Passwort des Schlüssels selbst, um ihn zu entsperren.
 * @param {string} caName - Der Name der CA.
 * @param {string} fingerprint - Der Fingerabdruck des zu exportierenden Schlüssels.
 * @param {string} pgpPassword - Das Passwort des PGP-Schlüssels.
 * @returns {Promise<string>} Der private Schlüssel im ASCII-Armor-Format.
 */
async function exportPgpPrivateKey(caName, fingerprint, pgpPassword) {
    const gpgHome = path.join(caBaseDir, caName, 'gpg');
    const env = { GNUPGHOME: gpgHome };
    
    // Der Befehl nutzt --pinentry-mode loopback und --passphrase, um GPG nicht-interaktiv
    // das Passwort für den zu exportierenden Schlüssel zu übergeben.
    const command = `gpg --pinentry-mode loopback --passphrase "${pgpPassword}" --armor --export-secret-keys ${fingerprint}`;

    return await runCommand(command, env, gpgHome);
}

module.exports = { generatePgpKey, listPgpKeys, getPgpPublicKey, exportPgpPrivateKey };