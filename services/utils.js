const util = require("util");
const { exec } = require("child_process");
const crypto = require("crypto");
const logger = require('../util/logger');
const chalk = require("chalk");

const execPromise = util.promisify(exec);

/**
 * Executes a shell command and returns its output.
 * @param {string} command - The command to execute.
 * @param {object} env - Environment variables to set for the command.
 * @param {string} cwd - The working directory to run the command in.
 * @param {string} logname - A name to use for logging.
 * @returns {Promise<string>} - A promise that resolves to the command's stdout.
 */
async function runCommand(command, env = {}, cwd = null, logname) {
    const options = {
        env: { ...process.env, ...env },
        cwd: cwd || process.cwd()
    };

    try {
        const { stdout, stderr } = await execPromise(command, options);

        // Log stderr only if not in test mode, as some tools write harmless info to stderr.
        if (stderr && process.env.NODE_ENV !== 'test') {
            logger.warn(chalk.yellow(`${logname ?? "live"} [${chalk.blue.bold(command)}]\n${chalk.white(stderr)}`));
        }
        return stdout;
    } catch (error) {
        // Log the error, as it is critical.
        if (error.stdout) logger.log(`${logname ?? "output"} [${chalk.bold(command)}]\n${chalk.red(error.stdout)}`);
        if (error.stderr) logger.error(`${logname ?? "error"} [${chalk.red.bold(command)}]\n${chalk.red(error.stderr)}`);

        throw new Error(error.stderr || 'Command execution failed.');
    }
}

const algorithm = "aes-256-gcm";
const ivLength = 16;
const saltLength = 64;
const tagLength = 16;
const iterations = 100000;

/**
 * Encrypts a string using AES-256-GCM.
 * @param {string} text - The text to encrypt.
 * @param {string} masterPassword - The password to use for encryption.
 * @returns {string} - The encrypted text, encoded in hex.
 */
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

/**
 * Decrypts a string that was encrypted with the encrypt function.
 * @param {string} encryptedHex - The encrypted text, encoded in hex.
 * @param {string} masterPassword - The password to use for decryption.
 * @returns {string} - The decrypted text.
 */
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
