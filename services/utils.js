const util = require('util');
const { exec } = require('child_process');
const crypto = require('crypto');

const execPromise = util.promisify(exec);

async function runCommand(command, env = {}, cwd = null) {
    const options = {
        env: { ...process.env, ...env },
        // Setze das Arbeitsverzeichnis, wenn eines angegeben ist
        cwd: cwd || process.cwd() 
    };

    try {
        console.log(`Executing in [${options.cwd}]: ${command}`);
        const { stdout, stderr } = await execPromise(command, options);
        if (stderr) {
            console.warn(`STDERR from command: ${stderr}`);
        }
        return stdout;
    } catch (error) {
        console.error(`\n===== COMMAND FAILED in [${options.cwd}] =====`);
        console.error(`COMMAND: ${command}`);
        if (error.stderr) {
            console.error(`STDERR: ${error.stderr}`);
        }
        if (error.stdout) {
            console.error(`STDOUT: ${error.stdout}`);
        }
        console.error(`EXIT CODE: ${error.code}`);
        console.error(`==========================\n`);
        
        throw new Error(error.stderr || 'Command execution failed.');
    }
}

// --- NEUE FUNKTIONEN ---
const algorithm = 'aes-256-gcm';
const ivLength = 16;
const saltLength = 64;
const tagLength = 16;
const iterations = 100000;

function encrypt(text, masterPassword) {
    const salt = crypto.randomBytes(saltLength);
    const key = crypto.pbkdf2Sync(masterPassword, salt, iterations, 32, 'sha512');
    const iv = crypto.randomBytes(ivLength);
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([salt, iv, tag, encrypted]).toString('hex');
}


function decrypt(encryptedHex, masterPassword) {
    const encryptedBuffer = Buffer.from(encryptedHex, 'hex');
    const salt = encryptedBuffer.subarray(0, saltLength);
    const iv = encryptedBuffer.subarray(saltLength, saltLength + ivLength);
    const tag = encryptedBuffer.subarray(saltLength + ivLength, saltLength + ivLength + tagLength);
    const encrypted = encryptedBuffer.subarray(saltLength + ivLength + tagLength);
    
    const key = crypto.pbkdf2Sync(masterPassword, salt, iterations, 32, 'sha512');
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    decipher.setAuthTag(tag);
    return decipher.update(encrypted, 'hex', 'utf8') + decipher.final('utf8');
}

module.exports = { runCommand, encrypt, decrypt };