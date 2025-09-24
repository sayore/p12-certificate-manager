const fs = require('fs');
const path = require('path');
const { runCommand } = require('./utils');
const { caBaseDir } = require('./caService');
const logger = require('../util/logger');

/**
 * Parst die OpenSSL index.txt Datenbank.
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
            // Simple Heuristik zur Typ-Erkennung
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
 * Stellt ein Client-Zertifikat (.p12) aus.
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
        // Schritt 1: Schlüssel und CSR im Hauptverzeichnis der CA erstellen
        await runCommand(`openssl genrsa -out "${userKey}" 2048`);
        await runCommand(`openssl req -config "openssl.cnf" -new -key "${userKey}" -out "${userCsr}" -subj "/CN=${commonName}"`, {}, caDir);
        
        // Schritt 2: Zertifikat signieren. Dies aktualisiert index.txt und erstellt .crt
        await runCommand(`openssl ca -config "openssl.cnf" -extensions usr_cert -days 365 -notext -md sha256 -in "${userCsr}" -out "${userCrt}" -passin env:CA_PASS -batch`, env, caDir);

        // Schritt 3: .p12-Paket erstellen
        await runCommand(`openssl pkcs12 -export -out "${userP12}" -inkey "${userKey}" -in "${userCrt}" -certfile "ca.crt" -passout pass:`, {}, caDir);
        
        // Schritt 4: Finale Dateien an ihren permanenten Speicherort verschieben
        fs.renameSync(userP12, path.join(issuedDir, `${commonName}.p12`));
        fs.renameSync(userCrt, path.join(issuedDir, `${commonName}.crt`));
        fs.renameSync(userKey, path.join(issuedDir, `${commonName}.key`));

        // Schritt 5: Daten für die Antwort sammeln
        const crtData = fs.readFileSync(path.join(issuedDir, `${commonName}.crt`), 'utf-8');
        const certDetails = await runCommand(`openssl x509 -in "${path.join(issuedDir, `${commonName}.crt`)}" -noout -serial -subject`);
        const serial = certDetails.match(/serial=(.*)/)[1];
        
        // Schritt 6: Temporäre Dateien explizit am Ende des Erfolgsfalls aufräumen
        if (fs.existsSync(userCsr)) {
            fs.unlinkSync(userCsr);
        }
        
        return { message: 'Client certificate issued.', serial, commonName, certificate: crtData };

    } catch (error) {
        // Wenn irgendwo ein Fehler auftritt, versuche alles aufzuräumen
        [userKey, userCsr, userCrt, userP12].forEach(f => {
            if (fs.existsSync(f)) fs.unlinkSync(f);
        });
        // Und den Fehler weiterreichen, damit der Benutzer eine Nachricht sieht
        throw error;
    }
}

/**
 * Stellt ein Server-Zertifikat (.pem/.key) aus und verwendet die copy_extensions Methode.
 */
// ----- FILE: services/x509Service.js -----

async function issueServerCert(caName, caPassword, commonName, altNames) {
    if (!commonName || !/^[a-zA-Z0-9\-\.]+$/.test(commonName)) throw new Error('Invalid Common Name.');
    
    const caDir = path.join(caBaseDir, caName);
    const env = { CA_PASS: caPassword };

    // Temporäre Dateipfade
    const tempKeyPath = path.join(caDir, `${commonName}.key`);
    const tempCsrPath = path.join(caDir, `${commonName}.csr`);
    const tempCrtPath = path.join(caDir, `${commonName}.crt`);
    const tempCnfPath = path.join(caDir, 'temp_server_req.cnf');

    // Finale Speicherorte
    const issuedDir = path.join(caDir, 'issued', commonName);
    const finalKeyPath = path.join(issuedDir, `${commonName}.key`);
    const finalCrtPath = path.join(issuedDir, `${commonName}.crt`);

    try {
        if (!fs.existsSync(issuedDir)) {
            fs.mkdirSync(issuedDir, { recursive: true });
        }

        const mainCnfContent = fs.readFileSync(path.join(caDir, 'openssl.cnf'), 'utf-8');
        let sanSection = `\n[v3_req_san]\nsubjectAltName = @alt_names\n\n[alt_names]\nDNS.1 = ${commonName}\n`;
        if (altNames) {
            altNames.split(',').map(s => s.trim()).filter(Boolean).forEach((name, index) => { sanSection += `DNS.${index + 2} = ${name}\n`; });
        }
        fs.writeFileSync(tempCnfPath, mainCnfContent + sanSection);

        await runCommand(`openssl genrsa -out "${tempKeyPath}" 2048`);
        await runCommand(`openssl req -new -key "${tempKeyPath}" -out "${tempCsrPath}" -subj "/CN=${commonName}" -config "${tempCnfPath}" -reqexts v3_req_san`);
        
        // --- HIER IST DIE KORREKTUR ---
        await runCommand(`openssl ca -config "openssl.cnf" -extensions server_cert -days 365 -notext -md sha256 -in "${tempCsrPath}" -out "${tempCrtPath}" -passin env:CA_PASS -batch`, env, caDir);
        
        fs.renameSync(tempCrtPath, finalCrtPath);
        fs.renameSync(tempKeyPath, finalKeyPath);
        
        if (fs.existsSync(tempCsrPath)) fs.unlinkSync(tempCsrPath);
        if (fs.existsSync(tempCnfPath)) fs.unlinkSync(tempCnfPath);

        const crtData = fs.readFileSync(finalCrtPath, 'utf-8');
        const keyData = fs.readFileSync(finalKeyPath, 'utf-8');
        const certDetails = await runCommand(`openssl x509 -in "${finalCrtPath}" -noout -serial -subject`);
        const serial = certDetails.match(/serial=(.*)/)[1];

        return { message: 'Server certificate issued.', serial, commonName, certificate: crtData, privateKey: keyData };

    } catch (error) {
        [tempKeyPath, tempCsrPath, tempCrtPath, tempCnfPath].forEach(f => {
            if (fs.existsSync(f)) fs.unlinkSync(f);
        });
        throw error;
    }
}

/**
 * Widerruft ein Zertifikat.
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