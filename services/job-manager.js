const { spawn } = require('child_process');
const logger = require('../util/logger');

const jobs = {}; // Simple in-memory job store.

/**
 * Runs a new job in a separate process.
 * @param {string} command - The command to execute.
 * @param {object} env - The environment variables for the job.
 * @param {string} cwd - The working directory for the job.
 * @param {function} onComplete - A callback function to execute when the job completes.
 * @returns {object} - The job object.
 */
function runJob(command, env = {}, cwd = null, onComplete = null) {
    const jobId = `job-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    
    logger.log(`Starting Job [${jobId}] in [${cwd}]: ${command}`);

    const job = {
        id: jobId,
        status: 'running',
        startTime: Date.now(),
        command: command,
        output: '',
        error: null,
    };
    jobs[jobId] = job;

    const [cmd, ...args] = command.split(' ');
    const options = { env: { ...process.env, ...env }, cwd, shell: true };
    const child = spawn(cmd, args, options);

    child.stdout.on('data', (data) => job.output += data.toString());
    child.stderr.on('data', (data) => job.output += data.toString());

    child.on('close', (code) => {
        logger.log(`Job [${jobId}] finished with code ${code}.`);
        if (code === 0) {
            if (onComplete) {
                try {
                    onComplete(job);
                } catch (e) {
                    logger.error(`Error in onComplete callback for job ${jobId}:`, e.message);
                    job.status = 'failed_in_callback';
                    job.error = e.message;
                }
            }

            job.status = 'completed';
        } else {
            job.status = 'failed';
            job.error = job.output;
        }
    });

    child.on('error', (err) => {
        logger.error(`Job [${jobId}] spawn error:`, err);
        job.status = 'failed';
        job.error = err.message;

        if (onComplete) {
            try {
                onComplete(job);
            } catch (e) {
                logger.error(`Error in onComplete callback for job ${jobId}:`, e.message);
                job.status = 'failed_in_callback';
                job.error = e.message;
            }
        }
    });

    return job;
}

/**
 * Retrieves a job by its ID.
 * @param {string} jobId - The ID of the job to retrieve.
 * @returns {object} - The job object, or undefined if not found.
 */
function getJob(jobId) {
    return jobs[jobId];
}

module.exports = { runJob, getJob };