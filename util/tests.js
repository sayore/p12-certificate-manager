// runTest.js
import { spawn } from "child_process";
import { resolve, join } from "path";
import { existsSync } from "fs";
import clipboard from "clipboardy";

let logBuffer = "";


/**
 * Copy everything logged so far into the clipboard.
 */
export async function flushLogsToClipboard(marker = "LOGS") {
  const wrapped = `===== START ${marker} =====\n${logBuffer}\n===== END ${marker} =====`;
  await clipboard.write(wrapped);
  return wrapped;
}

function stripColors(log) {
  // Regex to match ANSI escape sequences
  const ansiRegex = /\x1B\[[0-9;]*m/g;
  return log.replace(ansiRegex, '');
}

/**
 * Runs a test from ./tests by name (convention: name.test.js).
 * Streams stdout/stderr live to console and also copies the
 * full output into the clipboard at the end.
 *
 * @param {string} name - Test name (without ".test.js")
 * @param {string} [args=""] - Optional arguments as a single string
 * @returns {Promise<number>} Exit code of the spawned process
 */
export async function runTest(name, args = "") {
  return new Promise((resolvePromise, reject) => {
    const testPath = resolve(join("./tests", `${name}.test.js`));
    if (!existsSync(testPath)) {
      return reject(new Error(`Test file not found: ${testPath}`));
    }
    const child = spawn("node", [testPath, ...args], {
      stdio: "inherit",
      // Setzt die Variable, damit der Server weiß, dass er leise sein soll
      env: { ...process.env, NODE_ENV: 'test' }
    });
    child.on("close", (code) => resolvePromise(code ?? 0)); // 0, damit der Server nicht abbricht
    child.on("close", (code) => resolvePromise(code ?? 0)); // 0, damit der Server nicht abbricht
    child.on("error", (err) => reject(err));
  });
}