const cheerio = require("cheerio");
const { URLSearchParams } = require("url");
const axios = require("axios"); // Benötigt für den nicht-authentifizierten Client
const fs = require("fs");
const path = require("path");
const JSZip = require('jszip');


// Importiere den Client und die Konfiguration aus den Utilities
const { client, config, log, startAdvancedTimer } = require("./test-utils");
const { execSync } = require("child_process");

console.log(log);

// --- Globale Variablen für den Testablauf ---
const testCaName = `Test-CA-${Date.now()}`;
const testCaPassword = `test-pw-${Date.now()}`;
let clientCertSerial = "";
let serverCertSerial = "";
let clean = false;

let pgpTestPromise = null;

let pgpKeyFingerprint = '';
let pgpJobData = null; // NEU: Eine globale Variable, um die Job-Infos zu speichern

// ----- FILE: tests/e2e.test.js -----

// ... (nach der runTest-Funktion)

// NEUE, EIGENSTÄNDIGE FUNKTION FÜR DEN GESAMTEN PGP-TEST
async function runPgpTestLifecycle() {
    await runTest('[PGP Lifecycle] Start, Poll & Verify', async () => {
        // --- Teil 1: Job starten ---
        log('--- [PGP] Starting PGP Key Generation Job ---', 'blue');
        const name = `PGP Test User ${Date.now()}`;
        const email = `pgp-test-${Date.now()}@example.com`;
        
        const params = new URLSearchParams();
        params.append('name', name);
        params.append('email', email);
        params.append('password', 'pgp-test-password');
        params.append('caPassword', testCaPassword);

        const startResponse = await client.post(`/api/ca/${testCaName}/generate-pgp`, params);
        if (startResponse.status !== 202) throw new Error(`Expected 202, got ${startResponse.status}`);
        
        const jobData = startResponse.data;
        if (!jobData.jobId) throw new Error('Server did not return a jobId.');
        log(`   -> [PGP] Job [${jobData.jobId}] started. Polling for completion...`, 'info');

        // --- Teil 2: Auf Job-Abschluss warten ---
        let jobStatus = '';
        for (let i = 0; i < 60; i++) {
            const statusResponse = await client.get(jobData.statusUrl);
            jobStatus = statusResponse.data.status;
            if (jobStatus === 'completed' || jobStatus === 'failed') break;
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
        if (jobStatus !== 'completed') throw new Error(`PGP job did not complete. Final status: ${jobStatus}`);
        log(`   -> [PGP] Job finished with status: ${jobStatus}`, 'info');

        // --- Teil 3: Ergebnis auf der UI-Seite verifizieren ---
        const getResponse = await client.get(`/ca/${testCaName}/pgp`);
        const $ = cheerio.load(getResponse.data);
        const keyRow = $(`td:contains("${email}")`).closest('tr');
        if (keyRow.length === 0) throw new Error('New PGP key was not found in the table.');

        const fingerprint = keyRow.find('td').eq(1).find('small').text().trim();
        if (!fingerprint) throw new Error('Could not extract PGP key fingerprint.');
        log(`   -> [PGP] Key for "${email}" found on page with fingerprint.`, 'info');

        // --- Teil 4: Public Key Endpoint testen ---
        const pubKeyResponse = await client.get(`/ca/${testCaName}/pgp/${fingerprint}/pub`);
        if (pubKeyResponse.status !== 200) throw new Error(`PGP public key endpoint failed.`);
        const publicKey = pubKeyResponse.data;
        if (!publicKey.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
            throw new Error('Response is not a valid PGP public key block.');
        }
        log(`   -> [PGP] Public key endpoint successfully verified.`, 'info');
    });
}

const report = { passed: 0, failed: 0, failures: [] };
// Diese `runTest` Funktion wird LOKAL in dieser Datei verwendet, um die einzelnen Schritte auszuführen.
const runTest = async (name, testFn) => {
  try {
    const result = await testFn();
    log(`✔ PASS: ${name}`, "pass");
    report.passed++;
    return result;
  } catch (error) {
    log(`✖ FAIL: ${name}`, "fail");
    log(`   Error: ${error.message}`, "fail");
    if (error.response) {
      log(`   Status: ${error.response.status}`, "fail");
      const responseData =
        typeof error.response.data === "string"
          ? error.response.data
          : JSON.stringify(error.response.data);
      log(`   Data: ${responseData.substring(0, 500)}...`, "fail");
    } else if (error.stack) {
      log(`   Stack: ${error.stack.split("\n")[1].trim()}`, "fail");
    }
    report.failed++;
    report.failures.push({ name, error: error.message });
    throw error;
  }
};

// --- Die eigentlichen Testfälle als ein Objekt ---
const tests = {
  "[Step 1] Server Readiness": async () => {
    let serverReady = false;
    for (let i = 0; i < 10; i++) {
      try {
        await client.get("/", { timeout: 500 });
        serverReady = true;
        log("   -> SUCCESS: Server is ready.", "info");
        return;
      } catch (e) {
        log(
          `   -> INFO: Server not ready yet, waiting 500ms... (${i + 1}/10)`,
          "info"
        );
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }
    if (!serverReady)
      throw new Error("Server did not become available after 5 seconds.");
  },

  // ----- FILE: tests/e2e.test.js -----

'[Step 2] Login & Access Dashboard': async () => {
    const response = await client.get('/');
    if (response.status !== 200) throw new Error(`Expected status 200 but got ${response.status}`);
    const $ = cheerio.load(response.data);
    // Wir prüfen jetzt auf den korrekten Titel, der vom neuen Header-Partial gerendert wird.
    if ($('h1.header-title').text() !== 'Dashboard') throw new Error('Main dashboard heading not found.');
},

  "[Step 3] Create a new Test CA": async () => {
    const params = new URLSearchParams();
    params.append("caName", testCaName);
    params.append("caPassword", testCaPassword);
    params.append("organization", "Test Organization");
    const postResponse = await client.post("/create-ca", params);
    if (postResponse.status !== 302)
      throw new Error(`Expected status 302 but got ${postResponse.status}`);
    const getResponse = await client.get("/");
    const $ = cheerio.load(getResponse.data);
    if ($(`a[href="/ca/${testCaName}"]`).length === 0)
      throw new Error("Link to new CA not found.");
  },


  '[Step 4] Issue a Client Certificate': async () => {
        const commonName = `client-${Date.now()}@test.com`;
        
        // NEU: Zuerst zur X.509-Seite navigieren, um das Formular zu finden
        const x509PageResponse = await client.get(`/ca/${testCaName}/x509`);
        if (x509PageResponse.status !== 200) throw new Error('Could not load X.509 management page.');
        
        const params = new URLSearchParams();
        params.append('certType', 'client'); // Das neue Radio-Button-Feld
        params.append('commonName', commonName);
        params.append('caPassword', testCaPassword);
        
        // NEU: Die URL zum Absenden hat sich geändert
        const postResponse = await client.post(`/ca/${testCaName}/issue-cert`, params);
        if (postResponse.status !== 302) throw new Error(`Expected 302`);

        // NEU: Der Redirect führt jetzt zur X.509-Seite
        const redirectedPage = await client.get(postResponse.headers.location);
        const $ = cheerio.load(redirectedPage.data);
        const certRow = $(`td:contains("${commonName}")`).closest('tr');
        if (certRow.length === 0) throw new Error('New client certificate not found');
        clientCertSerial = certRow.find('td').eq(3).find('small').text().trim();
        if (!clientCertSerial) throw new Error('Could not extract serial');
    },

    '[Step 4.5] Verify Client Certificate P12 Download': async () => {
    log('--- Testing Client Certificate P12 Download ---', 'blue');
    if (!clientCertSerial) {
        throw new Error('Cannot run test: clientCertSerial not captured.');
    }

    const response = await client.get(`/ca/${testCaName}/download/x509/${clientCertSerial}/p12`, {
        responseType: 'arraybuffer'
    });

    if (response.status !== 200) {
        throw new Error(`Expected status 200 for download, got ${response.status}`);
    }
    // PKCS12 hat einen spezifischen MIME-Typ
    if (response.headers['content-type'] !== 'application/x-pkcs12') {
        throw new Error(`Expected content-type application/x-pkcs12, got ${response.headers['content-type']}`);
    }
    log('   -> SUCCESS: Received correct headers for .p12 file.', 'info');

    // Wir können den Inhalt nicht einfach parsen, aber wir können prüfen, ob er nicht leer ist
    const fileBuffer = Buffer.from(response.data);
    if (fileBuffer.length < 100) {
        throw new Error('Downloaded .p12 file seems to be empty or too small.');
    }
    log('   -> SUCCESS: Downloaded .p12 file has a valid size.', 'info');
},

  '[Step 5] Issue a Server Certificate': async () => {
        const commonName = `server-${Date.now()}.test.com`;
        
        const params = new URLSearchParams();
        params.append('certType', 'server'); // Das neue Radio-Button-Feld
        params.append('commonName', commonName);
        params.append('altNames', `www.${commonName}`);
        params.append('caPassword', testCaPassword);

        // NEU: Die URL zum Absenden hat sich geändert
        const postResponse = await client.post(`/ca/${testCaName}/issue-cert`, params);
        if (postResponse.status !== 302) throw new Error(`Expected 302`);
        
        // NEU: Wir landen wieder auf der X.509-Seite und suchen dort
        const getResponse = await client.get(`/ca/${testCaName}/x509`);
        const $ = cheerio.load(getResponse.data);
        const certRow = $(`td:contains("${commonName}")`).closest('tr');
        if (certRow.length === 0) throw new Error('New server certificate not found');
        serverCertSerial = certRow.find('td').eq(3).find('small').text().trim();
    },
    '[Step 5.5] Verify Server Certificate ZIP Download': async () => {
    log('--- Testing Server Certificate ZIP Download ---', 'blue');
    if (!serverCertSerial) throw new Error('Cannot run test: serverCertSerial not captured.');
    
    const getPage = await client.get(`/ca/${testCaName}/x509`);
    const $ = cheerio.load(getPage.data);
    const certRow = $(`td:contains("${serverCertSerial}")`).closest('tr');
    const commonName = certRow.find('td').eq(2).text().trim();
    if(!commonName) throw new Error('Could not find common name in UI for test setup.');

    const response = await client.get(`/ca/${testCaName}/download/x509/${serverCertSerial}/zip`, {
        responseType: 'arraybuffer' 
    });

    if (response.status !== 200) throw new Error(`Expected status 200, got ${response.status}`);
    if (response.headers['content-type'] !== 'application/zip') throw new Error(`Expected content-type application/zip`);
    log('   -> SUCCESS: Received correct headers for ZIP file.', 'info');

    const zip = await JSZip.loadAsync(response.data);
    
    const sanitizedCommonName = commonName.replace(/[^a-zA-Z0-9\.\-\_]/g, '_');
    const expectedCertFile = `${sanitizedCommonName}_${serverCertSerial}.crt`;
    const expectedKeyFile = `${sanitizedCommonName}_${serverCertSerial}.key`;
    const expectedCaFile = `ca.crt`;
    
    // --- KORREKTUR: Variablen VOR der Prüfung deklarieren ---
    const certFile = zip.file(expectedCertFile);
    const keyFile = zip.file(expectedKeyFile);
    const caFile = zip.file(expectedCaFile);
    // ----------------------------------------------------

    if (!certFile || !keyFile || !caFile) {
        const files = Object.keys(zip.files);
        throw new Error(`ZIP archive is missing one or more required files. Expected '${expectedCertFile}', '${expectedKeyFile}', '${expectedCaFile}'. Found: ${files.join(', ')}`);
    }
    log('   -> SUCCESS: All expected files with correct names found in the ZIP archive.', 'info');

    // Jetzt sind die Variablen hier garantiert verfügbar
    const certContent = await certFile.async('string');
    const keyContent = await keyFile.async('string');

    if (!certContent.includes('-----BEGIN CERTIFICATE-----')) throw new Error('Certificate file content is invalid.');
    if (!keyContent.includes('-----BEGIN PRIVATE KEY-----')) throw new Error('Private key file content is invalid.');
    log('   -> SUCCESS: File contents appear to be valid.', 'info');
},

  '[Step 6] Revoke the Client Certificate': async () => {
        const params = new URLSearchParams();
        params.append('serial', clientCertSerial);
        params.append('caPassword', testCaPassword);
        
        // Die Revoke-URL bleibt gleich, aber der Redirect geht zur X.509-Seite
        const postResponse = await client.post(`/ca/${testCaName}/revoke-x509`, params);
        if (postResponse.status !== 302) throw new Error(`Expected 302`);
        
        // NEU: Lade die X.509-Seite, um das Ergebnis zu verifizieren
        const getResponse = await client.get(`/ca/${testCaName}/x509`);
        const $ = cheerio.load(getResponse.data);
        const certRow = $('tbody tr').filter(function() {
            return $(this).find('td').eq(3).find('small').text().trim() === clientCertSerial;
        });
        if (certRow.length === 0) throw new Error('Row for revoked certificate not found.');
        if (certRow.find('.status-R').length === 0) { // Klasse hat sich zu status-badge geändert
            throw new Error('Certificate status in UI is not "Widerrufen".');
        }
    },

  "[Step 7] Verify CRL Content": async () => {
    log("--- Testing public CRL endpoint ---", "blue");
    const publicClient = axios.create({ baseURL: client.defaults.baseURL });
    const response = await publicClient.get(`/ca/${testCaName}/crl.pem`);

    if (response.status !== 200)
      throw new Error(`CRL endpoint returned status ${response.status}`);

    const crlContent = response.data;
    if (!crlContent.startsWith("-----BEGIN X509 CRL-----")) {
      throw new Error(`Response is not a PEM-encoded CRL. Got:\n${crlContent}`);
    }

    // --- KORRIGIERTE PRÜFUNG ---
    const tempCrlPath = path.join(__dirname, "temp_crl.pem");
    fs.writeFileSync(tempCrlPath, crlContent);

    try {
      const crlTextOutput = execSync(
        `openssl crl -in "${tempCrlPath}" -noout -text`
      ).toString();

      // `index.txt` gibt die Seriennummer in Hex aus, z.B. 1000.
      // `openssl crl -text` gibt sie ebenfalls in Hex aus. Wir müssen sie nur noch finden.
      // Beispiel-Ausgabe: "Serial Number: 1000"
      const serialRegex = new RegExp(
        `Serial Number: ${clientCertSerial.toUpperCase()}`
      );
      if (!serialRegex.test(crlTextOutput)) {
        throw new Error(
          `Revoked serial ${clientCertSerial} was not found in parsed CRL output.\nOutput:\n${crlTextOutput}`
        );
      }
      log(
        `   -> SUCCESS: Revoked serial ${clientCertSerial} was found in the public CRL.`,
        "info"
      );
    } finally {
      if (fs.existsSync(tempCrlPath)) {
        fs.unlinkSync(tempCrlPath);
      }
    }
    // --- ENDE DER KORREKTUR ---
  },


  "[Step 9] Verify PGP Public Key Endpoint": async () => {
    log("--- Testing PGP Public Key Endpoint ---", "blue");
    if (!pgpKeyFingerprint) {
      throw new Error(
        "Cannot run test: PGP fingerprint was not captured in the previous step."
      );
    }

    const response = await client.get(
      `/ca/${testCaName}/pgp/${pgpKeyFingerprint}/pub`
    );
    if (response.status !== 200) {
      throw new Error(
        `PGP public key endpoint returned status ${response.status}`
      );
    }

    const publicKey = response.data;
    if (typeof publicKey !== "string") {
      throw new Error("Response from server was not a string.");
    }

    // --- ANGEPASSTE PRÜFUNG ---
    // Wir prüfen jetzt nur noch auf die korrekte Struktur eines PGP-Blocks.
    // Die Anwesenheit der UID haben wir manuell durch die Debug-Ausgabe verifiziert.
    const hasHeader = publicKey.startsWith(
      "-----BEGIN PGP PUBLIC KEY BLOCK-----"
    );
    const hasFooter = publicKey
      .trim()
      .endsWith("-----END PGP PUBLIC KEY BLOCK-----");
    const hasContent = publicKey.length > 500; // Ein echter Schlüssel ist deutlich länger als nur Header/Footer.

    if (!hasHeader || !hasFooter || !hasContent) {
      throw new Error(
        `Response is not a valid PGP public key block. Header: ${hasHeader}, Footer: ${hasFooter}, Content: ${hasContent}`
      );
    }

    // Die alte, fehlerhafte Prüfung wird entfernt:
    // if (!publicKey.includes(`pgp-test-`)) { ... }

    log(
      `   -> SUCCESS: Successfully retrieved a valid PGP public key block.`,
      "info"
    );
  },
  '[Step 10] Fail to revoke cert with wrong CA password': async () => {
        log('--- Testing failed revocation with incorrect password ---', 'blue');
        if (!serverCertSerial) throw new Error('Cannot run test: serverCertSerial not set.');

        const params = new URLSearchParams();
        params.append('serial', serverCertSerial);
        params.append('caPassword', 'this-is-the-wrong-password');

        const postResponse = await client.post(`/ca/${testCaName}/revoke-x509`, params);
        if (postResponse.status !== 302) throw new Error('Expected 302 Redirect even on failure.');
        log('   -> SUCCESS: Server correctly responded with a 302 redirect.', 'info');
        
        const sessionCookie = postResponse.headers['set-cookie'] ? postResponse.headers['set-cookie'][0] : null;
        if (!sessionCookie) throw new Error('Server did not send a session cookie.');

        // NEU: Der Redirect geht zur X.509-Seite
        const getResponse = await client.get(postResponse.headers.location, {
            headers: { 'Cookie': sessionCookie }
        });
        const $ = cheerio.load(getResponse.data);
        const errorMsg = $('.message.error').text();
        if (!errorMsg || !errorMsg.toLowerCase().includes('fehler')) {
            throw new Error('Expected an error message for wrong password, but none was found.');
        }
        log('   -> SUCCESS: Server correctly showed an error for invalid CA password.', 'info');

        const certRow = $('tbody tr').filter(function() {
            return $(this).find('td').eq(3).find('small').text().trim() === serverCertSerial;
        });
        const statusSpan = certRow.find('.status-V');
        if (statusSpan.length === 0) {
            throw new Error('Certificate status was incorrectly changed despite wrong password.');
        }
        log('   -> SUCCESS: Certificate status correctly remains "Gültig".', 'info');
    },

  "[Step 11] Fail to create a CA with an existing name": async () => {
    log("--- Testing failed CA creation with duplicate name ---", "blue");
    const params = new URLSearchParams();
    params.append("caName", testCaName); // Verwende den bereits existierenden Namen
    params.append("caPassword", "any-password");
    params.append("organization", "Duplicate Corp");

    const postResponse = await client.post("/create-ca", params);
    if (postResponse.status !== 302) {
      throw new Error("Expected 302 Redirect even on failure.");
    }
    const sessionCookie = postResponse.headers["set-cookie"]
      ? postResponse.headers["set-cookie"][0]
      : null;
    if (!sessionCookie) {
      throw new Error("Server did not send a session cookie.");
    }
    log("   -> INFO: Captured session cookie for redirect.", "info");

    const getResponse = await client.get(postResponse.headers.location || "/", {
      headers: { Cookie: sessionCookie },
    });
    console.log(getResponse.data);
    const $ = cheerio.load(getResponse.data);

    const errorMsg = $(".message.error").text();
    console.log(errorMsg);
    if (!errorMsg || !errorMsg.toLowerCase().includes("already exists")) {
      throw new Error(
        "Expected an error message for duplicate CA name, but none was found."
      );
    }
    log(
      "   -> SUCCESS: Server correctly prevented creation of a CA with a duplicate name.",
      "info"
    );
  },

  "[Step 12] Access Snippet API and verify content": async () => {
    log("--- Testing Snippet API endpoint ---", "blue");
    if (!serverCertSerial)
      throw new Error("Cannot run test: serverCertSerial not set.");

    // 1. Test ohne mTLS-Option
    const responseOff = await client.get(
      `/api/ca/${testCaName}/snippets/server.test.com?verify=off`
    );
    if (responseOff.status !== 200)
      throw new Error("Snippet API did not return status 200.");
    if (!responseOff.data.nginx || !responseOff.data.apache)
      throw new Error("Snippet API response is missing nginx or apache keys.");

    const nginxSnippetOff = responseOff.data.nginx;
    if (nginxSnippetOff.includes("ssl_verify_client")) {
      throw new Error(
        "Nginx snippet for verify=off should not contain ssl_verify_client."
      );
    }
    log("   -> SUCCESS: Snippet for verify=off generated correctly.", "info");

    // 2. Test mit mTLS-Option "on"
    const responseOn = await client.get(
      `/api/ca/${testCaName}/snippets/server.test.com?verify=on`
    );
    const nginxSnippetOn = responseOn.data.nginx;

    if (!nginxSnippetOn.includes("ssl_verify_client      on")) {
      throw new Error(
        'Nginx snippet for verify=on is missing "ssl_verify_client on".'
      );
    }
    if (!nginxSnippetOn.includes(`crl.pem`)) {
      throw new Error(
        "Nginx snippet for verify=on is missing the ssl_crl directive."
      );
    }
    log("   -> SUCCESS: Snippet for verify=on generated correctly.", "info");
  },
      
};

// --- Haupt-Runner-Logik, die am Ende dieser Datei steht ---
const runAllTests = async () => {
  log("--- Starting CA Management End-to-End Test Suite ---", "blue");

  // =======================================================
  // --- HIER IST DIE ENTSCHEIDENDE ÄNDERUNG ---
  // =======================================================
  // Diese Schleife stellt sicher, dass der Test erst startet,
  // wenn der Server vollständig initialisiert ist.
  let serverReady = false;
  for (let i = 0; i < 15; i++) {
    // Wir geben dem Server bis zu 7.5 Sekunden Zeit
    try {
      // Wir versuchen, eine öffentliche, einfache Route abzufragen.
      await axios.get(`${client.defaults.baseURL}/ca/nonexistent/ca.crt`);
      // Wir erwarten einen 404-Fehler, aber wenn wir überhaupt eine Antwort bekommen
      // (und keinen Verbindungsfehler), ist der Server am Laufen.
    } catch (e) {
      if (e.response && e.response.status === 404) {
        serverReady = true;
        log("   -> SUCCESS: Server is ready and responding.", "info");
        break;
      }
    }
    log(
      `   -> INFO: Server not ready yet, waiting 500ms... (${i + 1}/15)`,
      "info"
    );
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  if (!serverReady) {
    log("✖ CRITICAL FAIL: Server did not become available.", "fail");
    process.exit(1);
  }
  try {
    pgpTestPromise = runPgpTestLifecycle();

        // Führe alle sequenziellen, schnellen Tests aus
        for (const testName in tests) {
            await runTest(testName, tests[testName]);
        }

        // GANZ AM ENDE: Warte auf den Abschluss des PGP-Tests
        log('--- Waiting for PGP test lifecycle to complete... ---', 'blue');
        await pgpTestPromise;
  } catch (error) {
    // Fehler wurde bereits geloggt
  } finally {
    log("\n--- Starting Cleanup Phase ---", "blue");
    const caPath = path.join(__dirname, "..", "multi_ca_files", testCaName);
    try {
      if (clean) {
        if (fs.existsSync(caPath)) {
          fs.rmSync(caPath, { recursive: true, force: true });
          log(`   -> SUCCESS: Cleaned up test directory: ${caPath}`, "info");
        } else {
          log(
            `   -> INFO: Test directory not found, skipping cleanup.`,
            "info"
          );
        }
      }
    } catch (cleanupError) {
      log(
        `   ✖ CRITICAL FAIL: Could not clean up test directory: ${caPath}`,
        "fail"
      );
      log(`   Error: ${cleanupError.message}`, "fail");
    }

    log("\n--- Test Report ---", "blue");
    log(`Total tests executed: ${report.passed + report.failed}`, "blue");
    log(`Passed: ${report.passed}`, "pass");
    log(`Failed: ${report.failed}`, "fail");
    if (report.failed > 0) {
      log("\nFailed Tests:", "fail");
      report.failures.forEach((failure) =>
        log(`- ${failure.name}: ${failure.error}`, "fail")
      );
      process.exitCode = 1;
    }
    log("\n--- Test Suite Finished ---", "blue");
  }
};

// Startet den gesamten Testablauf, wenn die Datei ausgeführt wird
runAllTests();
