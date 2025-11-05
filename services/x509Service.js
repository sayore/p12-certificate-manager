const fs = require('fs');
const path = require('path');
const { runCommand } = require('./utils');
const { caBaseDir } = require('./caService');
const logger = require('../util/logger');

/**
 * Parses the OpenSSL index.txt database file for a given CA.
 * @param {string} caName - The name of the CA.
 * @returns {Array} - An array of certificate objects.
 */
function parseCaDatabase(caName) {
    const dbFile = path.join(caBaseDir, caName, 'index.txt');
    if (!fs.existsSync(dbFile)) return [];

    const dbContent = fs.readFileSync(dbFile, 'utf-8');
    return dbContent
        .split('\n')
        .filter(line => line.trim() !== '')
        .map(line => {
            const parts = line.split('\t');
            if (parts.length < 6) return null;

            const commonName = parts[5].split('/CN=')[1];
            // Simple heuristic to determine the certificate type.
            const type = commonName.includes('@') ? 'Client' : 'Server';

            return {
                status: parts[0],
                expirationDate: parts[1],
                revocationDate: parts[2] || 'N/A',
                serial: parts[3],
                commonName: commonName,
                type: type,
            };
        }).filter(Boolean);
}

/**
 * Issues a client certificate (.p12).
 * @param {string} caName - The name of the CA.
 * @param {string} caPassword - The password for the CA.
 * @param {string} commonName - The common name for the certificate.
 * @returns {Promise<object>} - A promise that resolves to an object containing the certificate details.
 */
async function issueClientCert(caName, caPassword, commonName) {
    if (!commonName || !/^[a-zA-Z0-9\-\._@]+$/.test(commonName)) {
        throw new Error('Invalid Common Name provided.');
    }
    const caDir = path.join(caBaseDir, caName);
    const env = { CA_PASS: caPassword };
    const userKey = path.join(caDir, `${commonName}.key`);
    const userCsr = path.join(caDir, `${commonName}.csr`);
    const userCrt = path.join(caDir, `${commonName}.crt`);
    const userP12 = path.join(caDir, `${commonName}.p12`);

    const issuedDir = path.join(caDir, 'issued', commonName);
    if (!fs.existsSync(issuedDir)) {
        fs.mkdirSync(issuedDir, { recursive: true });
    }

    try {
        // Step 1: Create the user's private key and CSR in the CA's root directory.
        await runCommand(`openssl genrsa -out "${userKey}" 2048`);
        await runCommand(`openssl req -config "openssl.cnf" -new -key "${userKey}" -out "${userCsr}" -subj "/CN=${commonName}"`, {}, caDir);

        // Step 2: Sign the certificate, which updates index.txt and creates the .crt file.
        await runCommand(`openssl ca -config "openssl.cnf" -extensions usr_cert -days 365 -notext -md sha256 -in "${userCsr}" -out "${userCrt}" -passin env:CA_PASS -batch`, env, caDir);

        // Step 3: Create the .p12 package.
        await runCommand(`openssl pkcs12 -export -out "${userP12}" -inkey "${userKey}" -in "${userCrt}" -certfile "ca.crt" -passout pass:`, {}, caDir);

        // Step 4: Move the final files to their permanent location.
        fs.renameSync(userP12, path.join(issuedDir, `${commonName}.p12`));
        fs.renameSync(userCrt, path.join(issuedDir, `${commonName}.crt`));
        fs.renameSync(userKey, path.join(issuedDir, `${commonName}.key`));

        // Step 5: Gather data for the response.
        const crtData = fs.readFileSync(path.join(issuedDir, `${commonName}.crt`), 'utf-8');
        const certDetails = await runCommand(`openssl x509 -in "${path.join(issuedDir, `${commonName}.crt`)}" -noout -serial -subject`);
        const serial = certDetails.match(/serial=(.*)/)[1];

        // Step 6: Clean up temporary files.
        if (fs.existsSync(userCsr)) {
            fs.unlinkSync(userCsr);
        }

        return { message: 'Client certificate issued.', serial, commonName, certificate: crtData };

    } catch (error) {
        // Clean up any generated files if an error occurs.
        [userKey, userCsr, userCrt, userP12].forEach(f => {
            if (fs.existsSync(f)) fs.unlinkSync(f);
        });
        throw error;
    }
}

/**
 * Issues a server certificate (.pem/.key) using the copy_extensions method.
 * @param {string} caName - The name of the CA.
 * @param {string} caPassword - The password for the CA.
 * @param {string} commonName - The common name for the certificate.
 * @param {string} altNames - A comma-separated list of alternative names.
 * @returns {Promise<object>} - A promise that resolves to an object containing the certificate details.
 */
async function issueServerCert(caName, caPassword, commonName, altNames) {
    if (!commonName || !/^[a-zA-Z0-9\-\.]+$/.test(commonName)) throw new Error('Invalid Common Name.');

    const caDir = path.join(caBaseDir, caName);
    const env = { CA_PASS: caPassword };

    // Temporary file paths
    const tempKeyPath = path.join(caDir, `${commonName}.key`);
    const tempCsrPath = path.join(caDir, `${commonName}.csr`);
    const tempCrtPath = path.join(caDir, `${commonName}.crt`);
    const tempCnfPath = path.join(caDir, 'temp_server_req.cnf');

    // Final file paths
    const issuedDir = path.join(caDir, 'issued', commonName);
    const finalKeyPath = path.join(issuedDir, `${commonName}.key`);
    const finalCrtPath = path.join(issuedDir, `${commonName}.crt`);

    try {
        if (!fs.existsSync(issuedDir)) {
            fs.mkdirSync(issuedDir, { recursive: true });
        }

        // Create a temporary config file with the subjectAltName extension.
        const mainCnfContent = fs.readFileSync(path.join(caDir, 'openssl.cnf'), 'utf-8');
        let sanSection = `\n[v3_req_san]\nsubjectAltName = @alt_names\n\n[alt_names]\nDNS.1 = ${commonName}\n`;
        if (altNames) {
            altNames.split(',').map(s => s.trim()).filter(Boolean).forEach((name, index) => { sanSection += `DNS.${index + 2} = ${name}\n`; });
        }
        fs.writeFileSync(tempCnfPath, mainCnfContent + sanSection);

        // Generate the private key and CSR.
        await runCommand(`openssl genrsa -out "${tempKeyPath}" 2048`);
        await runCommand(`openssl req -new -key "${tempKeyPath}" -out "${tempCsrPath}" -subj "/CN=${commonName}" -config "${tempCnfPath}" -reqexts v3_req_san`);

        // Sign the certificate.
        await runCommand(`openssl ca -config "openssl.cnf" -extensions server_cert -days 365 -notext -md sha256 -in "${tempCsrPath}" -out "${tempCrtPath}" -passin env:CA_PASS -batch`, env, caDir);

        // Move the final files to their permanent location.
        fs.renameSync(tempCrtPath, finalCrtPath);
        fs.renameSync(tempKeyPath, finalKeyPath);

        // Clean up temporary files.
        if (fs.existsSync(tempCsrPath)) fs.unlinkSync(tempCsrPath);
        if (fs.existsSync(tempCnfPath)) fs.unlinkSync(tempCnfPath);

        // Gather data for the response.
        const crtData = fs.readFileSync(finalCrtPath, 'utf-8');
        const keyData = fs.readFileSync(finalKeyPath, 'utf-8');
        const certDetails = await runCommand(`openssl x509 -in "${finalCrtPath}" -noout -serial -subject`);
        const serial = certDetails.match(/serial=(.*)/)[1];

        return { message: 'Server certificate issued.', serial, commonName, certificate: crtData, privateKey: keyData };

    } catch (error) {
        // Clean up any generated files if an error occurs.
        [tempKeyPath, tempCsrPath, tempCrtPath, tempCnfPath].forEach(f => {
            if (fs.existsSync(f)) fs.unlinkSync(f);
        });
        throw error;
    }
}

/**
 * Revokes a certificate.
 * @param {string} caName - The name of the CA.
 * @param {string} caPassword - The password for the CA.
 * @param {string} serial - The serial number of the certificate to revoke.
 * @returns {Promise<object>} - A promise that resolves to an object containing a success message.
 */
async function revokeCert(caName, caPassword, serial) {
    if (!serial || !/^[a-fA-F0-9]+$/.test(serial)) throw new Error('Invalid serial number.');
    const caDir = path.join(caBaseDir, caName);
    const relativeCertPath = path.join('newcerts', `${serial.toUpperCase()}.pem`);
    if (!fs.existsSync(path.join(caDir, relativeCertPath))) throw new Error(`Cert for serial ${serial} not found.`);

    const env = { CA_PASS: caPassword };
    await runCommand(`openssl ca -config "openssl.cnf" -revoke "${relativeCertPath}" -passin env:CA_PASS`, env, caDir);
    await runCommand(`openssl ca -config "openssl.cnf" -gencrl -out "crl.pem" -passin env:CA_PASS`, env, caDir);
    return { message: `Certificate ${serial} revoked and CRL updated.` };
}

module.exports = { parseCaDatabase, issueClientCert, issueServerCert, revokeCert };
