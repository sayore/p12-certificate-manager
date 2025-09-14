const fs = require('fs');
const path = require('path');
const { runCommand } = require('./utils');
const { caBaseDir } = require('./caService');

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
    const userKey = `${commonName}.key`, userCsr = `${commonName}.csr`, userCrt = `${commonName}.crt`, userP12 = `${commonName}.p12`;

    const issuedDir = path.join(caDir, 'issued', commonName);
    if (!fs.existsSync(issuedDir)) {
        fs.mkdirSync(issuedDir, { recursive: true });
    }

    try {
        await runCommand(`openssl genrsa -out "${userKey}" 2048`, {}, caDir);
        await runCommand(`openssl req -config "openssl.cnf" -new -key "${userKey}" -out "${userCsr}" -subj "/CN=${commonName}"`, {}, caDir);
        await runCommand(`openssl ca -config "openssl.cnf" -extensions usr_cert -days 365 -notext -md sha256 -in "${userCsr}" -out "${userCrt}" -passin env:CA_PASS -batch`, env, caDir);
        // WICHTIG: Das Passwort für das .p12 wird jetzt auf einen bekannten Wert gesetzt (oder leer gelassen)
        // Hier verwenden wir 'export' als Beispiel-Passwort. Sie können auch `pass:` für kein Passwort verwenden.
        await runCommand(`openssl pkcs12 -export -out "${userP12}" -inkey "${userKey}" -in "${userCrt}" -certfile "ca.crt" -passout pass:export`, {}, caDir);
        
        // NEU: Verschiebe die wichtige .p12-Datei an ihren finalen Ort
        fs.renameSync(path.join(caDir, userP12), path.join(issuedDir, userP12));
        
        const crtData = fs.readFileSync(path.join(caDir, userCrt), 'utf-8');
        const certDetails = await runCommand(`openssl x509 -in "${path.join(caDir, userCrt)}" -noout -serial -subject`);
        const serial = certDetails.match(/serial=(.*)/)[1];
        // p12Data wird nicht mehr zurückgegeben, da es jetzt auf der Festplatte liegt
        return { message: 'Client certificate issued.', serial, commonName, certificate: crtData };
    } finally {
        // ÄNDERUNG: Wir löschen nur noch die temporären Dateien, nicht mehr die .p12-Datei
        [userKey, userCsr, userCrt].forEach(f => {
            const fullPath = path.join(caDir, f);
            if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
        });
    }
}

/**
 * Stellt ein Server-Zertifikat (.pem/.key) aus und verwendet die copy_extensions Methode.
 */
async function issueServerCert(caName, caPassword, commonName, altNames) {
    if (!commonName || !/^[a-zA-Z0-9\-\.]+$/.test(commonName)) throw new Error('Invalid Common Name.');
    
    const caDir = path.join(caBaseDir, caName);
    const env = { CA_PASS: caPassword };
    const serverKey = `${commonName}.key`, serverCsr = `${commonName}.csr`, serverCrt = `${commonName}.crt`;
    
    // NEU: Pfade für Konfigurationsdateien definieren
    const mainCnfPath = path.join(caDir, 'openssl.cnf');
    const tempCnfPath = path.join(caDir, 'temp_server_req.cnf');

    const issuedDir = path.join(caDir, 'issued', commonName);
    if (!fs.existsSync(issuedDir)) {
        fs.mkdirSync(issuedDir, { recursive: true });
    }

    // 1. Erstelle die dynamische SAN-Sektion
    let sanSection = `\n[v3_req_san]\nsubjectAltName = @alt_names\n\n[alt_names]\nDNS.1 = ${commonName}\n`;
    if (altNames) {
        altNames.split(',').map(s => s.trim()).filter(Boolean).forEach((name, index) => { sanSection += `DNS.${index + 2} = ${name}\n`; });
    }
    
    // 2. Lese die Haupt-Konfiguration und füge die SAN-Sektion hinzu, um eine vollständige temporäre Konfig zu erstellen
    const mainCnfContent = fs.readFileSync(mainCnfPath, 'utf-8');
    fs.writeFileSync(tempCnfPath, mainCnfContent + sanSection);

    try {
        await runCommand(`openssl genrsa -out "${serverKey}" 2048`, {}, caDir);
        
        // 3. KORRIGIERTER BEFEHL: Verwende nur die EINE, vollständige, temporäre Konfigurationsdatei
        await runCommand(`openssl req -new -key "${serverKey}" -out "${serverCsr}" -subj "/CN=${commonName}" -config "${tempCnfPath}" -reqexts v3_req_san`, {}, caDir);
        
        // Der 'ca' Befehl nutzt 'copy_extensions', was jetzt dank des korrekten CSRs funktioniert
        await runCommand(`openssl ca -config "openssl.cnf" -extensions server_cert -days 365 -notext -md sha256 -in "${serverCsr}" -out "${serverCrt}" -passin env:CA_PASS -batch`, env, caDir);
        
        fs.renameSync(path.join(caDir, serverCrt), path.join(issuedDir, serverCrt));
        fs.renameSync(path.join(caDir, serverKey), path.join(issuedDir, serverKey));
        
        const crtData = fs.readFileSync(path.join(issuedDir, serverCrt), 'utf-8');
        const keyData = fs.readFileSync(path.join(issuedDir, serverKey), 'utf-8');
        const certDetails = await runCommand(`openssl x509 -in "${path.join(issuedDir, serverCrt)}" -noout -serial -subject`);
        const serial = certDetails.match(/serial=(.*)/)[1];
        return { message: 'Server certificate issued.', serial, commonName, certificate: crtData, privateKey: keyData };

    } finally {
        // 4. Räume ALLE temporären Dateien auf
        [serverCsr, tempCnfPath].forEach(f => {
            const fullPath = path.join(caDir, f);
            if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
        });
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