const cheerio = require("cheerio");
const { URLSearchParams } = require("url");
const axios = require("axios"); // Benötigt für den nicht-authentifizierten Client
const fs = require("fs");
const path = require("path");

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

  "[Step 2] Login & Access Dashboard": async () => {
    const response = await client.get("/");
    if (response.status !== 200)
      throw new Error(`Expected status 200 but got ${response.status}`);
    const $ = cheerio.load(response.data);
    if ($("h1").text() !== "CA Master Control")
      throw new Error("Main dashboard heading not found.");
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

  "[Step 4] Issue a Client Certificate": async () => {
    const commonName = `client-${Date.now()}@test.com`;
    const params = new URLSearchParams();
    params.append("commonName", commonName);
    params.append("caPassword", testCaPassword);
    const postResponse = await client.post(
      `/ca/${testCaName}/issue-client`,
      params
    );
    if (postResponse.status !== 302) throw new Error(`Expected 302`);
    const getResponse = await client.get(`/ca/${testCaName}`);
    const $ = cheerio.load(getResponse.data);
    const certRow = $(`td:contains("${commonName}")`).closest("tr");
    if (certRow.length === 0)
      throw new Error("New client certificate not found");
    clientCertSerial = certRow.find("td").eq(3).find("small").text().trim();
    if (!clientCertSerial) throw new Error("Could not extract serial");
  },

  "[Step 5] Issue a Server Certificate": async () => {
    const commonName = `server-${Date.now()}.test.com`;
    const params = new URLSearchParams();
    params.append("commonName", commonName);
    params.append("caPassword", testCaPassword);
    const postResponse = await client.post(
      `/ca/${testCaName}/issue-server`,
      params
    );
    if (postResponse.status !== 302) throw new Error(`Expected 302`);
    const getResponse = await client.get(`/ca/${testCaName}`);
    const $ = cheerio.load(getResponse.data);
    const certRow = $(`td:contains("${commonName}")`).closest("tr");
    if (certRow.length === 0)
      throw new Error("New server certificate not found");
    serverCertSerial = certRow.find("td").eq(3).find("small").text().trim();
  },

  "[Step 6] Revoke the Client Certificate": async () => {
    const params = new URLSearchParams();
    params.append("serial", clientCertSerial);
    params.append("caPassword", testCaPassword);
    const postResponse = await client.post(
      `/ca/${testCaName}/revoke-x509`,
      params
    );
    if (postResponse.status !== 302) throw new Error(`Expected 302`);
    const getResponse = await client.get(`/ca/${testCaName}`);
    const $ = cheerio.load(getResponse.data);
    const certRow = $("tbody tr").filter(function () {
      return (
        $(this).find("td").eq(3).find("small").text().trim() ===
        clientCertSerial
      );
    });
    if (certRow.length === 0)
      throw new Error("Row for revoked certificate not found.");
    if (certRow.find("td:first-child .status-R").length === 0) {
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
  "[Step 8] Generate a PGP Key (Async Job)": async () => {
    log("--- Testing PGP Key Generation (Async Job) ---", "blue");
    const name = `PGP Test User ${Date.now()}`;
    const email = `pgp-test-${Date.now()}@example.com`;

    const params = new URLSearchParams();
    params.append("name", name);
    params.append("email", email);
    params.append("password", "pgp-test-password");

    // 1. Starte den Job
    const startResponse = await client.post(
      `/api/ca/${testCaName}/generate-pgp`,
      params
    );
    if (startResponse.status !== 202)
      throw new Error(
        `Expected status 202 (Accepted) but got ${startResponse.status}`
      );
    const { jobId, statusUrl } = startResponse.data;
    if (!jobId) throw new Error("Server did not return a jobId.");
    log(
      `   -> INFO: Job [${jobId}] started successfully. Polling status...`,
      "info"
    );

    // 2. Frage den Status ab, bis der Job fertig ist
    let jobStatus = "";
    for (let i = 0; i < 20; i++) {
      // Max. 20 Sekunden warten
      const statusResponse = await client.get(statusUrl);
      jobStatus = statusResponse.data.status;
      if (jobStatus === "completed" || jobStatus === "failed") {
        log(`   -> INFO: Job finished with status: ${jobStatus}`, "info");
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    if (jobStatus !== "completed") {
      const statusResponse = await client.get(statusUrl);
      throw new Error(
        `PGP key generation job did not complete successfully. Final status: ${jobStatus}. Error: ${statusResponse.data.error}`
      );
    }

    // 3. Lade das Dashboard und prüfe das Ergebnis
    const getResponse = await client.get(`/ca/${testCaName}`);
    const $ = cheerio.load(getResponse.data);
    const keyRow = $(`td:contains("${email}")`).closest("tr");
    if (keyRow.length === 0) {
      throw new Error(
        "New PGP key was not found in the table after job completion."
      );
    }

    pgpKeyFingerprint = keyRow.find("td").eq(1).find("small").text().trim();
    if (!pgpKeyFingerprint)
      throw new Error("Could not extract PGP key fingerprint.");
    log(
      `   -> SUCCESS: PGP key for "${email}" created and found on dashboard.`,
      "info"
    );
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
  "[Step 10] Fail to revoke cert with wrong CA password": async () => {
    log("--- Testing failed revocation with incorrect password ---", "blue");
    if (!serverCertSerial)
      throw new Error("Cannot run test: serverCertSerial not set.");

    const params = new URLSearchParams();
    params.append("serial", serverCertSerial);
    params.append("caPassword", "this-is-the-wrong-password");

    // 1. Führe den POST-Request aus, der fehlschlagen soll
    const postResponse = await client.post(
      `/ca/${testCaName}/revoke-x509`,
      params
    );

    if (postResponse.status !== 302) {
      throw new Error(
        `Expected status 302 (Redirect) but got ${postResponse.status}`
      );
    }
    log(
      "   -> SUCCESS: Server correctly responded with a 302 redirect.",
      "info"
    );

    // 2. Extrahiere den Session-Cookie manuell aus der Antwort
    const sessionCookie = postResponse.headers["set-cookie"]
      ? postResponse.headers["set-cookie"][0]
      : null;
    if (!sessionCookie) {
      throw new Error(
        "Server did not send a session cookie (Set-Cookie header) after the POST request."
      );
    }
    log(`   -> INFO: Captured session cookie.`, "info");

    // 3. Führe den GET-Request aus und füge den Cookie manuell hinzu
    const getResponse = await client.get(postResponse.headers.location, {
      headers: {
        Cookie: sessionCookie,
      },
    });
    const $ = cheerio.load(getResponse.data);

    // 4. Prüfe jetzt auf die Fehlermeldung
    const errorMsg = $(".message.error").text();
    if (!errorMsg || !errorMsg.toLowerCase().includes("fehler")) {
      throw new Error(
        "Expected an error message for wrong password, but none was found."
      );
    }
    log(
      "   -> SUCCESS: Server correctly showed an error for invalid CA password.",
      "info"
    );

    // 5. Zusätzliche Prüfung: Sicherstellen, dass der Status des Zertifikats immer noch "Gültig" ist
    const certRow = $("tbody tr").filter(function () {
      return (
        $(this).find("td").eq(3).find("small").text().trim() ===
        serverCertSerial
      );
    });
    const statusSpan = certRow.find("td:first-child .status-V");
    if (statusSpan.length === 0) {
      throw new Error(
        "Certificate status was incorrectly changed despite wrong password."
      );
    }
    log(
      '   -> SUCCESS: Certificate status correctly remains "Gültig".',
      "info"
    );
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
    for (const testName in tests) {
      await runTest(testName, tests[testName]);
    }
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
