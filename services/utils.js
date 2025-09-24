const util = require("util");
const { exec } = require("child_process");
const crypto = require("crypto");
const logger = require('../util/logger');
const chalk = require("chalk");

const execPromise = util.promisify(exec);

/**
 * 
 * @param {*} command 
 * @param {*} env 
 * @param {*} cwd 
 * @param {*} logname 
 * @param {*} success String to find in stderr, if the command is still successful and no output is needed.
 * @returns 
 */
async function runCommand(command, env = {}, cwd = null, logname) {
    const options = {
        env: { ...process.env, ...env },
        cwd: cwd || process.cwd() 
    };

    try {
        const { stdout, stderr } = await execPromise(command, options);
        
        // --- NEU: Logge stderr nur, wenn nicht im Testmodus ---
        // GPG und OpenSSL schreiben oft harmlose Infos nach stderr.
        if (stderr && process.env.NODE_ENV !== 'test') {
            logger.warn(chalk.yellow(`${logname ?? "live"} [${chalk.blue.bold(command)}]\n${chalk.white(stderr)}`));
        }
        return stdout;
    } catch (error) {
        // Wir loggen den Fehler immer, da er kritisch ist.
        // Der Test-Runner fängt diese Ausgabe in seinem eigenen Puffer auf.
        if (error.stdout) logger.log(`${logname ?? "output"} [${chalk.bold(command)}]\n${chalk.red(error.stdout)}`);
        if (error.stderr) logger.error(`${logname ?? "error"} [${chalk.red.bold(command)}]\n${chalk.red(error.stderr)}`);
        
        throw new Error(error.stderr || 'Command execution failed.');
    }
}

// --- NEUE FUNKTIONEN ---
const algorithm = "aes-256-gcm";
const ivLength = 16;
const saltLength = 64;
const tagLength = 16;
const iterations = 100000;

function encrypt(text, masterPassword) {
  const salt = crypto.randomBytes(saltLength);
  const key = crypto.pbkdf2Sync(masterPassword, salt, iterations, 32, "sha512");
  const iv = crypto.randomBytes(ivLength);
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(text, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([salt, iv, tag, encrypted]).toString("hex");
}

function decrypt(encryptedHex, masterPassword) {
  const encryptedBuffer = Buffer.from(encryptedHex, "hex");
  const salt = encryptedBuffer.subarray(0, saltLength);
  const iv = encryptedBuffer.subarray(saltLength, saltLength + ivLength);
  const tag = encryptedBuffer.subarray(
    saltLength + ivLength,
    saltLength + ivLength + tagLength
  );
  const encrypted = encryptedBuffer.subarray(saltLength + ivLength + tagLength);

  const key = crypto.pbkdf2Sync(masterPassword, salt, iterations, 32, "sha512");
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  decipher.setAuthTag(tag);
  return decipher.update(encrypted, "hex", "utf8") + decipher.final("utf8");
}

module.exports = { runCommand, encrypt, decrypt };
