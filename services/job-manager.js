const { spawn } = require('child_process');
const logger = require('../util/logger');

const jobs = {}; // Simpler In-Memory Job-Speicher

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
                    // Optional: Den Job-Status auf einen speziellen Fehler setzen
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

        // NEU: Führe den onComplete-Callback aus, wenn er existiert
        if (onComplete) {
            try {
                onComplete(job);
            } catch (e) {
                logger.error(`Error in onComplete callback for job ${jobId}:`, e.message);
                // Optional: Den Job-Status auf einen speziellen Fehler setzen
                job.status = 'failed_in_callback';
                job.error = e.message;
            }
        }
    });

    return job;
}

function getJob(jobId) {
    return jobs[jobId];
}

module.exports = { runJob, getJob };