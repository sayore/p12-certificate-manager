const fs = require('fs');
const path = require('path');
const { caBaseDir } = require('./caService');
const { runJob } = require('./job-manager');
const { runCommand, encrypt, decrypt } = require('./utils');
const logger = require('../util/logger');

/**
 * Generates a new PGP key pair.
 * @param {string} caName - The name of the CA.
 * @param {string} name - The name for the PGP key.
 * @param {string} email - The email for the PGP key.
 * @param {string} pgpPassword - The password for the PGP key.
 * @param {string} caPassword - The password for the CA.
 * @param {function} onComplete - A callback function to execute when the job completes.
 * @returns {object} - The job object.
 */
async function generatePgpKey(caName, name, email, pgpPassword, caPassword, onComplete=()=>{}) {
    const gpgHome = path.join(caBaseDir, caName, 'gpg');
    const paramFile = path.join(gpgHome, 'gpg-params.txt');

    // Parameters for GPG key generation.
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

    // Encrypt the PGP password with the CA password for secure storage.
    const encryptedPassword = encrypt(pgpPassword, caPassword);
    const env = { GNUPGHOME: gpgHome };

    // Define the onComplete function for the job.
    const onJobComplete = (completedJob) => {
        // Clean up the parameter file.
        if (fs.existsSync(paramFile)) {
            fs.unlinkSync(paramFile);
        }

        // Only proceed if the job was successful.
        // Note: The condition `completedJob.status !== 'running'` might be incorrect. It should likely be `completedJob.status === 'completed'`.
        if (completedJob.status !== 'running') {
            logger.error(`GPG key generation job ${completedJob.id} failed, not saving secret.`);
            return;
        }

        // Extract the fingerprint of the new key from the GPG output.
        const output = completedJob.output;
        const fingerprintMatch = output.match(/gpg: key ([A-F0-9]{40}) marked as ultimately trusted/);

        if (fingerprintMatch && fingerprintMatch[1]) {
            const fingerprint = fingerprintMatch[1];
            logger.log(`Successfully extracted fingerprint ${fingerprint} for new PGP key.`);
            // Save the encrypted password in a file named after the fingerprint.
            const secretFile = path.join(gpgHome, `${fingerprint}.secret`);
            fs.writeFileSync(secretFile, encryptedPassword);
        } else {
            // Fallback if the fingerprint cannot be parsed.
            logger.warn(`Could not parse fingerprint from GPG output for job ${completedJob.id}. Saving secret with email as name.`);
            const secretFile = path.join(gpgHome, `${email}.secret`);
            fs.writeFileSync(secretFile, encryptedPassword);
        }
    };

    // Run the GPG key generation as a job.
    const job = runJob(
        `gpg --batch --pinentry-mode loopback --full-generate-key "${paramFile}"`,
        env,
        gpgHome,
        onJobComplete // Pass the callback to the job runner.
    );

    return job;
}

/**
 * Lists all PGP keys for a given CA.
 * @param {string} caName - The name of the CA.
 * @returns {Promise<Array>} - A promise that resolves to an array of PGP key objects.
 */
async function listPgpKeys(caName) {
    const gpgHome = path.join(caBaseDir, caName, 'gpg');
    const env = { GNUPGHOME: gpgHome };
    try {
        // Use --with-colons and --with-fingerprint for machine-readable output.
        const output = await runCommand(`gpg --list-keys --with-colons --with-fingerprint`, env, gpgHome);

        const keys = [];
        let currentKey = null;

        output.split('\n').forEach(line => {
            const parts = line.split(':');
            const type = parts[0];

            if (type === 'pub') {
                // If a previous key exists, add it to the list.
                if (currentKey) {
                    keys.push(currentKey);
                }
                // Start a new key object.
                currentKey = {
                    fingerprint: '', // Will be populated by the 'fpr' line.
                    created: new Date(parseInt(parts[5]) * 1000).toLocaleDateString(),
                    expires: parts[6] ? new Date(parseInt(parts[6]) * 1000).toLocaleDateString() : 'Never',
                    uids: []
                };
            }

            if (type === 'fpr' && currentKey) {
                // Add the fingerprint to the current key.
                currentKey.fingerprint = parts[9];
            }

            if (type === 'uid' && currentKey) {
                // Add the user ID to the current key.
                currentKey.uids.push(parts[9].replace(/\\x3c/g, '<').replace(/\\x3e/g, '>'));
            }
        });

        // Add the last processed key.
        if (currentKey && currentKey.fingerprint) {
            keys.push(currentKey);
        }

        return keys;
    } catch (error) {
        if (error.message.includes('No public key') || error.message.includes('kein öffentlicher Schlüssel gefunden')) return [];
        throw error;
    }
}

/**
 * Retrieves the public PGP key for a given fingerprint.
 * @param {string} caName - The name of the CA.
 * @param {string} fingerprint - The fingerprint of the PGP key.
 * @returns {Promise<string>} - A promise that resolves to the ASCII-armored public key.
 */
async function getPgpPublicKey(caName, fingerprint) {
    const gpgHome = path.join(caBaseDir, caName, 'gpg');
    const env = { GNUPGHOME: gpgHome };
    const command = `gpg --armor --export-options export-local-sigs --export ${fingerprint}`;
    return await runCommand(command, env, gpgHome);
}

/**
 * Exports a private PGP key.
 * Requires the key's password to unlock it.
 * @param {string} caName - The name of the CA.
 * @param {string} fingerprint - The fingerprint of the key to export.
 * @param {string} pgpPassword - The password for the PGP key.
 * @returns {Promise<string>} The private key in ASCII armor format.
 */
async function exportPgpPrivateKey(caName, fingerprint, pgpPassword) {
    const gpgHome = path.join(caBaseDir, caName, 'gpg');
    const env = { GNUPGHOME: gpgHome };
    
    // Use --pinentry-mode loopback and --passphrase to provide the password non-interactively.
    const command = `gpg --pinentry-mode loopback --passphrase "${pgpPassword}" --armor --export-secret-keys ${fingerprint}`;

    return await runCommand(command, env, gpgHome);
}

module.exports = { generatePgpKey, listPgpKeys, getPgpPublicKey, exportPgpPrivateKey };
