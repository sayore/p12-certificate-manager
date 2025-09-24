// ----- FILE: util/logger.js -----
const EventEmitter = require('events');
const util = require('util');
const chalk = require('chalk');
const os = require('os');
const fs = require('fs');
const path = require('path');

class Logger extends EventEmitter {
    constructor() {
        super();
        this._originalConsole = {
            log: console.log,
            warn: console.warn,
            error: console.error,
        };

        this._useChalk = true; // default: farbig
        this._maxFileSize = 1024 * 1024; // default 10KB
        this._tmpBase = path.join(os.tmpdir(), `logger-${process.pid}`);
        this._rotationCounters = new Map(); // in-memory counters für N*name
        if (!fs.existsSync(this._tmpBase)) fs.mkdirSync(this._tmpBase, { recursive: true });

        this._useChalk = true; // default: farbig

        // Default-Handler mit optionalem Chalk
        this._defaultHandlers = {};
        ['log', 'warn', 'error'].forEach(level => {
            this._defaultHandlers[level] = (...args) => {
                let formatted = args.map(arg =>
                    typeof arg === 'object'
                        ? util.inspect(arg, { depth: null, colors: this._useChalk })
                        : arg
                );

                // Optional Chalk-Färbung
                if (this._useChalk) {
                    if (level === 'log')   formatted = formatted.map(x => chalk.white(x));
                    if (level === 'warn')  formatted = formatted.map(x => chalk.yellow(x));
                    if (level === 'error') formatted = formatted.map(x => chalk.red(x));
                }

                if (this._originalConsole[level]) {
                    this._originalConsole[level](...formatted);
                } else {
                    this._originalConsole.log(`[${level.toUpperCase()}]`, ...formatted);
                }
            };
            this.on(level, this._defaultHandlers[level]);
        });
    }

    // Chalk Steuerung
    enableChalk() { this._useChalk = true; }
    disableChalk() { this._useChalk = false; }

    // File size Steuerung
    setMaxFileSize(bytes) {
        if (!Number.isInteger(bytes) || bytes <= 0) throw new Error("maxFileSize must be a positive integer");
        this._maxFileSize = bytes;
    }
    getMaxFileSize() { return this._maxFileSize; }

    // Standard Levels
    log(...args)   { this._emitLevel('log', args); }
    warn(...args)  { this._emitLevel('warn', args); }
    error(...args) { this._emitLevel('error', args); }

    // Neuer Level: stack (spezial für Errors)
    stack(error, ...extra) {
        if (error instanceof Error) {
            let stack = error.stack;
            if (this._useChalk) {
                stack = chalk.redBright(stack);
            }
            this._emitLevel('error', [stack]);
        } else {
            if (error._useChalk) {
                stack = chalk.redBright(error);
            }
            this._emitLevel('error', [error]);
        }
    }

    // Freiform
    custom(level, ...args) {
        if (typeof level !== 'string') throw new Error("Level must be a string");
        this._emitLevel(level, args);
    }

    // Neue Methoden dynamisch hinzufügen
    addLevel(level) {
        if (this[level]) throw new Error(`Level "${level}" already exists`);
        this[level] = (...args) => this._emitLevel(level, args);
    }

    // Ausgabe-Flow
    _emitLevel(level, args) {
        this.emit(level, ...args);      // echte Parameter
        this.emit('all', level, ...args);  // spread statt array
    }

    // Default-Ausgabe steuern
    pauseDefaultOutput() {
        for (const [level, handler] of Object.entries(this._defaultHandlers)) {
            this.removeListener(level, handler);
        }
    }

    resumeDefaultOutput() {
        for (const [level, handler] of Object.entries(this._defaultHandlers)) {
            if (!this.listeners(level).includes(handler)) {
                this.on(level, handler);
            }
        }
    }

    // Collector-System
    createCollector(levels = ['log','error','warn','html','file','stack']) {
        const buffer = [];
        const handler = (level, ...args) => {
            buffer.push([level, ...args]);
        };

        // abonnieren
        levels.forEach(l => this.on(l, handler));

        return {
            stop: () => {
                levels.forEach(l => this.removeListener(l, handler));
            },
            print: () => {
                buffer.forEach(([level, ...args]) => {
                    this._originalConsole.log(`[${level}]`, ...args);
                });
                levels.forEach(l => this.removeListener(l, handler));
            },
            get: () => buffer.slice(),
        };
    }

    /**
     * Helper to build rotated filename, e.g. base.ext + .1 -> base.1.ext
     */
    _rotateName(baseName, idx) {
        const parsed = path.parse(baseName);
        // if no ext, append .<idx>
        if (!parsed.ext) return `${parsed.name}.${idx}`;
        return `${parsed.name}.${idx}${parsed.ext}`;
    }

    /**
     * Create a file in temp folder and return absolute path.
     * Supports rotation prefix like "5*index.html" -> creates index.1.html ... index.5.html cyclic.
     * Emits 'file' or 'html' event with (filePath, uri).
     * Throws if content size > maxFileSize.
     *
     * @param {string} filename
     * @param {string} content
     * @param {'file'|'html'} kind
     * @returns {string} absolute file path
     */
    _writeTempFile(filename, content, kind = 'file') {
        if (typeof filename !== 'string' || typeof content !== 'string') {
            throw new Error('invalid arguments; expected (filename:string, content:string)');
        }

        const byteLen = Buffer.byteLength(content, 'utf8');
        if (byteLen > this._maxFileSize) {
            throw new Error(`Content size ${byteLen} bytes exceeds maxFileSize ${this._maxFileSize} bytes`);
        }

        // Rotation prefix: /^(\d+)\*(.+)$/
        let rotation = 0;
        let baseName = filename;
        const m = filename.match(/^(\d+)\*(.+)$/);
        if (m) {
            rotation = parseInt(m[1], 10);
            baseName = m[2];
            if (!rotation || rotation <= 0) rotation = 1;
        }

        // sanitize baseName to avoid path traversal
        baseName = path.basename(baseName);

        let targetName;
        if (rotation > 0) {
            const key = `${rotation}*${baseName}`;
            let counter = this._rotationCounters.get(key) || 1;
            // ensure counter in [1..rotation]
            if (counter > rotation) counter = 1;
            targetName = this._rotateName(baseName, counter);
            // update counter for next call
            counter = counter + 1;
            if (counter > rotation) counter = 1;
            this._rotationCounters.set(key, counter);
        } else {
            targetName = baseName;
        }

        const filePath = path.join(this._tmpBase, "jslogger", targetName);
        const dir = path.dirname(filePath);
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        fs.writeFileSync(filePath, content, { encoding: 'utf8' });        
        


        // create URI for terminal (file://...)
        const absolute = path.resolve(filePath);
        let uri;
        if (process.platform === 'win32') {
            // convert to forward slashes and ensure drive is prefixed with a leading '/'
            // e.g. C:\foo\bar -> file:///C:/foo/bar
            const forward = absolute.replace(/\\/g, '/');
            uri = `file:///${forward}`;
        } else {
            // typical unix: file:///home/user/...
            uri = `file://${absolute}`;
        }

        // Emit event for consumers
        this.emit(kind, filePath, uri);
        //this.emit('all', kind, filePath, uri);

        // Log clickable link (styled)
        

        return filePath;
    }

    // Konsole hijacken
    hijackConsole() {
        console.log = this.log.bind(this);
        console.warn = this.warn.bind(this);
        console.error = this.error.bind(this);
    }
    /**
     * Public methods
     */
    html(filename, stringContent) {
        return this._writeTempFile(filename+".html", stringContent, 'html');
    }
    file(filename, stringContent) {
        return this._writeTempFile(filename, stringContent, 'file');
    }
}

module.exports = new Logger();
