// runTest.js
import { spawn } from "child_process";
import { resolve, join } from "path";
import { existsSync } from "fs";
import clipboard from "clipboardy";

let logBuffer = "";

/**
 * Patch console methods so logs are written both to stdout/stderr
 * and into a buffer for later use.
 */
export function patchConsole() {
  const origLog = console.log;
  const origError = console.error;
  const origWarn = console.warn;

  console.log = (...args) => {
    const text = args.join(" ") + "\n";
    process.stdout.write(text);
    logBuffer += text;
  };

  console.error = (...args) => {
    const text = args.join(" ") + "\n";
    process.stderr.write(text);
    logBuffer += text;
  };

  console.warn = (...args) => {
    const text = args.join(" ") + "\n";
    process.stderr.write(text);
    logBuffer += text;
  };

  return () => {
    // restore
    console.log = origLog;
    console.error = origError;
    console.warn = origWarn;
  };
}

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
      reject(new Error(`Test file not found: ${testPath}`));
      return;
    }

    const argList = args.trim() ? args.split(/\s+/) : [];
    const child = spawn("node", [testPath, ...argList], {
      stdio: ["ignore", "pipe", "pipe"],
    });

    let fullLog = `===== START ${name} =====\n`;

    child.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      process.stdout.write(text); // live log
      fullLog += text;
    });

    child.stderr.on("data", (chunk) => {
      const text = chunk.toString();
      process.stderr.write(text); // live error log
      fullLog += text;
    });

    child.on("close", async (code) => {
      fullLog += `\n===== END ${name} (exit ${code}) =====\n`;
      try {
        await clipboard.write(stripColors("```log\n"+fullLog+"```"));
        console.log(`[${name}] Output copied to clipboard ✅`);
      } catch (err) {
        console.error(`[${name}] Failed to copy to clipboard:`, err.message);
      }
      resolvePromise(code ?? 1);
    });

    child.on("error", (err) => reject(err));
  });
}