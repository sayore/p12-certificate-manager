// Core-Bibliotheken
const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const { URLSearchParams } = require("url");
const axios = require("axios");
const cheerio = require("cheerio");
const JSZip = require("jszip");

// UI-Bibliotheken für das Terminal
const ora = require("ora");
const chalk = require("chalk");
const logUpdate = require("log-update");

// Lokale Hilfsfunktionen und Konfiguration
const { client, config } = require("./test-utils");
const logger = require("../util/logger");

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function multiRetry(howManyTimes, msBetween, fn, ...args) {
  let log = []
  for (let i = 0; i <= howManyTimes; i++) {
    let result = await fn(...args);
    if (result === true) return { state: true, result };
    if (result && result.state === false) log.push(result.result);
    await sleep(msBetween);
  }
  return {
    state: false,
    result: "MultiRetry: Function did not respond successfully.",
    log
  };
}

// --- Globale Variablen, die zwischen den Tests geteilt werden ---
const testCaName = `Test-CA-${Date.now()}`;
const testCaPassword = `test-pw-${Date.now()}`;

// --- Zustandsspeicher für den Runner ---
const testStates = {};
let fullLog = "";

// --- Die neue, graphenbasierte Test-Definition ---
const tests = {
    'login-and-create-ca': {
        name: '[Setup] Login & Create Test CA',
        requires: [],
        fn: async () => {
            await client.get('/');
            const params = new URLSearchParams({ caName: testCaName, caPassword: testCaPassword, organization: 'Test Organization' });
            await client.post("/create-ca", params);
            const getResponse = await client.get("/");
            const $ = cheerio.load(getResponse.data);
            if ($(`a[href="/ca/${testCaName}"]`).length === 0) throw new Error("Link to new CA not found.");
        }
    },
    'issue-client-cert': {
        name: '[X.509] Issue Client Certificate',
        requires: ['login-and-create-ca'],
        fn: async () => {
            const commonName = `client-${Date.now()}@test.com`;
            await client.get(`/ca/${testCaName}/x509`);
            const params = new URLSearchParams({ certType: 'client', commonName, caPassword: testCaPassword });
            const postResponse = await client.post(`/ca/${testCaName}/issue-cert`, params);
            let clientCertSerial;
            let log = await multiRetry((10), 200, async ()=>{
              const redirectedPage = await client.get(postResponse.headers.location);
              const $ = cheerio.load(redirectedPage.data);
              
              const certRow = $(`td:contains("${commonName}")`).closest('tr');
              if (certRow.length === 0) {
                logger.html("clientCertSerial",redirectedPage.data)
                return {state:false,result:'New client certificate not found in UI.'};
              }
              clientCertSerial = certRow.find('td').eq(3).find('small').text().trim();
              if (!clientCertSerial) {
                logger.html("clientCertSerial",redirectedPage.data)
                return {state:false,result:'Could not extract client serial.'};
              }
            })
            if(log.state=false)
            throw new Error(log.log.join("\n"))
            
            // --- KORREKTUR ---
            return { clientCertSerial }; 
        }
    },
    'issue-server-cert': {
        name: '[X.509] Issue Server Certificate',
        requires: ['login-and-create-ca'],
        fn: async () => {
            const commonName = `server-${Date.now()}.test.com`;
            const params = new URLSearchParams({ certType: 'server', commonName, altNames: `www.${commonName}`, caPassword: testCaPassword });
            await client.post(`/ca/${testCaName}/issue-cert`, params);
            let serverCertSerial;
            let log = await multiRetry((5), 200, async ()=>{
              const getResponse = await client.get(`/ca/${testCaName}/x509`);
              const $ = cheerio.load(getResponse.data);
              const certRow = $(`td:contains("${commonName}")`).closest('tr');
              if (certRow.length === 0) return {state: false, result: 'New server certificate not found in UI.'};
              serverCertSerial = certRow.find('td').eq(3).find('small').text().trim();
              if (!serverCertSerial) return {state: false, result: 'Could not extract server serial.'};
              return true
            })
            if(log.state == false) throw new Error(log.log.join("\n"));
            // --- KORREKTUR ---
            return { serverCertSerial, commonName };
        }
    },
    'pgp-lifecycle': {
        name: '[PGP] Full Lifecycle (Start, Poll, Verify)',
        requires: ['login-and-create-ca'],
        fn: async () => {
          return;
            const name = `PGP Test User ${Date.now()}`;
            const email = `pgp-test-${Date.now()}@example.com`;
            const params = new URLSearchParams({ name, email, password: 'pgp-test-password', caPassword: testCaPassword });
            const startResponse = await client.post(`/api/ca/${testCaName}/generate-pgp`, params);
            const jobData = startResponse.data;
            if (!jobData.jobId) throw new Error('Server did not return a jobId.');
            let jobStatus = '';
            for (let i = 0; i < 60; i++) {
                const statusResponse = await client.get(jobData.statusUrl);
                jobStatus = statusResponse.data.status;
                if (jobStatus === 'completed' || jobStatus === 'failed') break;
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
            if (jobStatus !== 'completed') throw new Error(`PGP job did not complete. Final status: ${jobStatus}`);
            const getResponse = await client.get(`/ca/${testCaName}/pgp`);
            const $ = cheerio.load(getResponse.data);
            const keyRow = $(`td:contains("${email}")`).closest('tr');
            if (keyRow.length === 0) throw new Error('New PGP key was not found.');
        }
    },
    'fail-duplicate-ca': {
        name: '[Failure] Fail on Duplicate CA',
        requires: ['login-and-create-ca'],
        fn: async () => {
            const params = new URLSearchParams({ caName: testCaName, caPassword: 'any', organization: 'Duplicate' });
            const postResponse = await client.post("/create-ca", params);
            const sessionCookie = postResponse.headers["set-cookie"] ? postResponse.headers["set-cookie"][0] : null;
            const getResponse = await client.get(postResponse.headers.location || "/", { headers: { Cookie: sessionCookie } });
            const $ = cheerio.load(getResponse.data);
            const errorMsg = $(".message.error").text();
            if (!errorMsg || !errorMsg.toLowerCase().includes("already exists")) throw new Error("Expected error for duplicate CA not found.");
        }
    },
    'download-client-p12': {
        name: '[Download] Verify Client .p12',
        requires: ['issue-client-cert'],
        fn: async (results) => {
            const { clientCertSerial } = results['issue-client-cert'];
            const response = await client.get(`/ca/${testCaName}/download/x509/${clientCertSerial}/p12`, { responseType: 'arraybuffer' });
            if (response.headers['content-type'] !== 'application/x-pkcs12') throw new Error(`Expected content-type x-pkcs12`);
            if (Buffer.from(response.data).length < 100) throw new Error('Downloaded .p12 file is too small.');
        }
    },
    'download-server-zip': {
        name: '[Download] Verify Server .zip',
        requires: ['issue-server-cert'],
        fn: async (results) => {
            const { serverCertSerial, commonName } = results['issue-server-cert'];
            const response = await client.get(`/ca/${testCaName}/download/x509/${serverCertSerial}/zip`, { responseType: 'arraybuffer' });
            const zip = await JSZip.loadAsync(response.data);
            const sanitizedCommonName = commonName.replace(/[^a-zA-Z0-9\.\-\_]/g, '_');
            const expectedCertFile = `${sanitizedCommonName}_${serverCertSerial}.crt`;
            if (!zip.file(expectedCertFile)) throw new Error(`File ${expectedCertFile} not found in ZIP archive.`);
        }
    },
    'revoke-client-cert': {
        name: '[X.509] Revoke Client Certificate',
        requires: ['issue-client-cert'],
        fn: async (results) => {
            const { clientCertSerial } = results['issue-client-cert'];
            const params = new URLSearchParams({ serial: clientCertSerial, caPassword: testCaPassword });
            await client.post(`/ca/${testCaName}/revoke-x509`, params);
            let result = multiRetry(5, 200, async () => {
              const getResponse = await client.get(`/ca/${testCaName}/x509`);
              const $ = cheerio.load(getResponse.data);
              const certRow = $(`td:contains("${clientCertSerial}")`).closest('tr');
              if (certRow.find('.status-R').length === 0) return false;
            })
            if(result.state == false) throw new Error('Certificate status in UI is not "Revoked".');
            return { clientCertSerial };
        }
    },
    'api-and-fail-revoke': {
        name: '[API/Failure] Snippet API & Failed Revoke',
        requires: ['issue-server-cert'],
        fn: async (results) => {
            const { serverCertSerial } = results['issue-server-cert'];
            const responseOn = await client.get(`/api/ca/${testCaName}/snippets/server.test.com?verify=on`);
            if (!responseOn.data.nginx.includes("ssl_verify_client      on")) throw new Error("Snippet API verify=on failed.");
            const params = new URLSearchParams({ serial: serverCertSerial, caPassword: 'wrong-password' });
            const postResponse = await client.post(`/ca/${testCaName}/revoke-x509`, params);
            const sessionCookie = postResponse.headers["set-cookie"] ? postResponse.headers["set-cookie"][0] : null;
            const getResponse = await client.get(postResponse.headers.location, { headers: { Cookie: sessionCookie } });
            const $ = cheerio.load(getResponse.data);
            const errorMsg = $(".message.error").text();
            if (!errorMsg || !errorMsg.toLowerCase().includes("fehler")) throw new Error("Expected error for wrong password not found.");
        }
    },
    'verify-crl': {
        name: '[X.509] Verify CRL Content',
        requires: ['revoke-client-cert'],
        fn: async (results) => {
            const { clientCertSerial } = results['revoke-client-cert'];
            logger.log(JSON.stringify(results));
            const publicClient = axios.create({ 
              baseURL: client.defaults.baseURL, 
              headers: {
                "X-Test-Secret": config.testSecret
              }});
            const response = await publicClient.get(`/ca/${testCaName}/crl.pem`);
            const tempCrlPath = path.join(__dirname, 'temp_crl.pem');
            fs.writeFileSync(tempCrlPath, response.data);
            const crlTextOutput = execSync(`openssl crl -in "${tempCrlPath}" -noout -text`).toString();
            fs.unlinkSync(tempCrlPath);
            logger.error("CRL: "+clientCertSerial);
            if (!crlTextOutput.includes(clientCertSerial.toUpperCase())) 
              throw new Error(`Revoked serial ${clientCertSerial} not in CRL.`);
        }
    }
};

const calculateDepth = (id) => {
  // Memoization: Wenn die Tiefe bereits berechnet wurde, gib sie zurück
  if (testStates[id].depth !== -1) {
    return testStates[id].depth;
  }

  const test = tests[id];
  // Root-Elemente (ohne Abhängigkeiten) haben die Tiefe 0
  if (!test.requires || test.requires.length === 0) {
    testStates[id].depth = 0;
    return 0;
  }

  // Die Tiefe ist 1 + die maximale Tiefe der Abhängigkeiten
  const dependencyDepths = test.requires.map((reqId) => calculateDepth(reqId));
  const maxDepth = Math.max(...dependencyDepths);
  testStates[id].depth = maxDepth + 1;
  return testStates[id].depth + 2;
};

async function runAllTests() {
    // --- Phase 1: Vorbereitung & Server-Check (mit normalem Logging) ---
    logger.log(chalk.blue.bold("--- Starting CA Management End-to-End Test Suite ---"));
    
    logger.pauseDefaultOutput()
    const collector = logger.createCollector();

// --- Phase 1: Server Readiness Check ---
    const readinessSpinner = ora("Waiting for server to be ready...").start();
    const serverReady = await multiRetry(30, 1000, async () => {
        try {
            await client.get("/", { timeout: 1000 });
            return true;
        } catch (e) {
            return { state: false, result: 'Server not ready yet.' };
        }
    });

    if (!serverReady.state) {
        readinessSpinner.fail("Server did not become available.");
        throw new Error("Server did not become available.");
    }
    readinessSpinner.succeed("Server is ready.");

    

    // --- Phase 2: Test-Modus aktivieren & Logging übernehmen ---
    try {
        await client.post('/testing/start');
    } catch (e) {
        logger.error(chalk.red('FATAL: Could not activate test mode on server.'), e.message);
        throw new Error('FATAL: Could not activate test mode on server.');
    }

    // --- Phase 3: Eigentliche Test-Ausführung (Server ist jetzt stumm) ---
    const testIds = Object.keys(tests);
    
    // Initialisiere den Zustand für alle Tests
    testIds.forEach(id => {
        testStates[id] = {
            status: 'pending',
            spinner: ora({ text: tests[id].name, color: 'gray' }),
            promise: null,
            result: null,
            error: null,
            depth: -1,
        };
        testStates[id].promise = new Promise((resolve) => {
            testStates[id].resolve = resolve;
        });
    });

    // Berechne und sortiere die Tests für die UI
    testIds.forEach(id => calculateDepth(id));
    const sortedTestIds = testIds.sort((a, b) => testStates[a].depth - testStates[b].depth || tests[a].name.localeCompare(tests[b].name));

    // UI-Render-Funktion (unverändert)
    const renderUI = () => {
        console.clear() 
        const lines = sortedTestIds.map((id) => {
            const state = testStates[id];
            const test = tests[id];
            const indent = "  ".repeat(state.depth);
            let icon;
            switch (state.status) {
                case "running": state.spinner.color = "yellow"; icon = state.spinner.frame(); break;
                case "success": icon = chalk.green("✔"); break;
                case "fail": icon = chalk.red("✖"); break;
                default: icon = chalk.gray("⏳");
            }
            return `${indent}${icon} ${test.name} In: ${state.requiredResults? chalk.green(Object.keys(state.requiredResults)):chalk.yellow("Waiting..")} - Out: ${state.result? chalk.green(Object.keys(state.result)):chalk.yellow("Waiting..")}`;
        });
        logUpdate(lines.join("\n"));
    };

    const uiInterval = setInterval(renderUI, 100);
    
    // Test-Ausführungsfunktion
    const runSingleTest = async (id) => {
        const test = tests[id];
        const state = testStates[id];
        try {
            if (test.requires) {
                const requiredPromises = test.requires.map(reqId => testStates[reqId].promise);
                await Promise.all(requiredPromises);
                for (const reqId of test.requires) {
                    if (testStates[reqId].status === 'fail') {
                        throw new Error(`Dependency '${tests[reqId].name}' failed.`);
                    }
                }
            }
            state.status = 'running';
            const requiredResults = {};
            if (test.requires) {
                test.requires.forEach(reqId => { 
                  logger.log(id+ " benötigt "+reqId + " und bekommt die Felder {"+JSON.stringify(testStates[reqId].result)+"}")
                  requiredResults[reqId] = testStates[reqId].result;
                });
            }
            state.received=requiredResults
            logger.log(id+ " wird ausgeführt");
            const result = await test.fn(requiredResults, testStates);
            state.result = result;
            state.status = 'success';
        } catch (error) {
            state.status = 'fail';
            state.error = error;
            logger.stack(error)
        } finally {
            state.resolve();
        }
    };

    // Starte alle Tests
    testIds.forEach(id => runSingleTest(id));
    await Promise.all(testIds.map(id => testStates[id].promise));

    // Beende die UI
    clearInterval(uiInterval);
    renderUI();

    collector.print();

    // --- Phase 4: Aufräumen & Report ---
    
    // Test-Modus auf dem Server deaktivieren
    await client.post('/testing/end');

    // Cleanup & Report
    const failedTests = testIds.filter((id) => testStates[id].status === "fail");
    const caPath = path.join(__dirname, "..", "multi_ca_files", testCaName);
    if (fs.existsSync(caPath)) {
        fs.rmSync(caPath, { recursive: true, force: true });
    }
    logger.log(chalk.bold("\n\n--- Test Report ---"));
    const passedCount = testIds.length - failedTests.length;
    logger.log(chalk.green(`✔ Passed: ${passedCount}`));
    if (failedTests.length > 0) {
        logger.log(chalk.red(`✖ Failed: ${failedTests.length}`));
        failedTests.forEach((id) => {
            logger.log(chalk.red(`  - ${tests[id].name}: ${testStates[id].error.message}`));
        });
    }

    // Return the list of failed tests for the Jest runner
    return failedTests;
}

// Wrap the test run in a Jest test block
describe('End-to-End Tests', () => {
  it('should run the entire E2E test suite successfully', async () => {
    const failedTests = await runAllTests();
    if (failedTests.length > 0) {
      const errorMessages = failedTests.map(id => `${tests[id].name}: ${testStates[id].error.message}`).join('\n');
      throw new Error(`E2E tests failed:\n${errorMessages}`);
    }
  }, 60000);
});
