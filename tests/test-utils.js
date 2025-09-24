const axios = require("axios");
const path = require("path");
const readline = require("readline");

const { wrapper } = require("axios-cookiejar-support");
const { CookieJar } = require("tough-cookie");
const logger = require("../util/logger");

// Lädt die .env-Datei aus dem übergeordneten Verzeichnis
require("dotenv").config({ path: path.resolve(__dirname, "..", ".env") });

// --- Konfiguration ---
const config = {
  server: "http://localhost:3000",
  adminUser: process.env.ADMIN_USER,
  adminPassword: process.env.ADMIN_PASSWORD,
  testSecret: process.env.TEST_SECRET_TOKEN,
};

// 1. Erstelle eine neue "Cookie Jar", um Cookies zu speichern
const jar = new CookieJar();

// 2. Erstelle die Basis-Axios-Instanz
const baseClient = axios.create({
  baseURL: config.server,
  auth: {
    username: config.adminUser,
    password: config.adminPassword,
  },
  headers: {
    "X-Test-Secret": config.testSecret,
  },
  maxRedirects: 0, // Wichtig für manuelle Redirect-Prüfung
  validateStatus: (status) => status >= 200 && status < 400,
});

const client = wrapper(baseClient, jar);

// --- Logik und Runner, die von deinem util/tests.js erwartet werden ---
const log = (message, status) => {
  const color =
    status === "pass"
      ? "\x1b[32m"
      : status === "fail"
      ? "\x1b[31m"
      : status === "info"
      ? "\x1b[36m"
      : "\x1b[34m";
  logger.log(`${color}${message}\x1b[0m`);
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Time to wait. (This is not a precise function!)
 * @param {number} lengthInMs
 */
async function startAdvancedTimer(lengthInMs, silent = true) {
  logger.log("Timer startet...");

  for (let i = 0; i <= lengthInMs / 10; i++) {
    if (!silent) {
      // Zählt 5 Sekunden lang in 0.1s Schritten
      // Cursor an den Anfang der Zeile bewegen
      readline.cursorTo(process.stdout, 0);

      // Die aktuelle Zeile ab der Cursor-Position löschen
      readline.clearLine(process.stdout, 1);

      // Den neuen Text schreiben
      process.stdout.write(`Timer läuft: ${(i / 10).toFixed(1)}s`);
    }
    // 100ms warten
    await sleep(100);
  }

  // Neue Zeile für sauberen Abschluss
  logger.log("\nTimer fertig!");
}

/**
 * Time to wait. (This is not a precise function!)
 * @param {number} lengthInMs
 */
async function multiRetry(howManyTimes, msBetween, fn, ...args) {
  let log = []
  for (let i = 0; i <= howManyTimes; i++) {
    // Zählt 5 Sekunden lang in 0.1s Schritten
    let result = await fn(...args);
    if (result===true) return { state: true, result };
    if (!!result?.state) log.push(log);
    await sleep(msBetween);
  }
  return {
    state: true,
    result: "MultiRetry: Function did not respond successfully.",
    log
  };
}

// Exportiere alles, was die Testfälle benötigen
module.exports = {
  client,
  config,
  log,
  startAdvancedTimer,
  multiRetry,
};
