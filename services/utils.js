const util = require('util');
const { exec } = require('child_process');

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

module.exports = { runCommand };