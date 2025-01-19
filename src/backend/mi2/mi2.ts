import { IBackend, Stack, Variable, VariableObject, MIError,
    OurInstructionBreakpoint, OurDataBreakpoint, OurSourceBreakpoint } from '../backend';
import * as ChildProcess from 'child_process';
import { EventEmitter } from 'events';
import { parseMI, MINode } from '../mi_parse';
import { posix } from 'path';
import * as os from 'os';
import { ServerConsoleLog } from '../server';
import { hexFormat } from '../../frontend/utils';
import { ADAPTER_DEBUG_MODE, promiseWithResolvers, ResettableTimeout } from '../../common';
import { Sema } from 'async-sema';
const path = posix;

export interface ReadMemResults {
    startAddress: string;
    endAddress: string;
    data: string;
}

export function parseReadMemResults(node: MINode): ReadMemResults {
    const startAddress = node.resultRecords.results[0][1][0][0][1];
    const endAddress = node.resultRecords.results[0][1][0][2][1];
    const data = node.resultRecords.results[0][1][0][3][1];
    const ret: ReadMemResults = {
        startAddress: startAddress,
        endAddress: endAddress,
        data: data
    };
    return ret;
}

export function escape(str: string) {
    return str.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

const nonOutput = /^(?:\d*|undefined)[*+=]|[~@&^]/;
const gdbMatch = /(?:\d*|undefined)\(gdb\)/;
const numRegex = /\d+/;

function couldBeOutput(line: string) {
    if (nonOutput.exec(line)) {
        return false;
    }
    return true;
}

const trace = false;

interface CommandOptions {
    suppressFailure?: boolean;
    captureOutput?: boolean;
    forceNoDebug?: boolean;
    timeout?: number;
    expectResultClass?: string;
    action?: string;
}

const DEFAULT_TIMEOUT = 5000;

class Command {
    private output?: string;
    private resolve: (res: MINode) => void;
    private reject: (res: MIError) => void;
    private timeout: ResettableTimeout;

    constructor(readonly owner: MI2, readonly token: number, readonly command: string, readonly options: CommandOptions = {}) {
    }

    async execute(): Promise<MINode> {
        const { promise, resolve, reject } = promiseWithResolvers<MINode>();
        this.resolve = resolve;
        this.reject = reject;
        await this.owner.sendRaw(`${this.token}-${this.command}`);

        this.timeout = new ResettableTimeout(() => {
            reject(new MIError('command execution timed out', this.command));
        }, this.options.timeout ?? DEFAULT_TIMEOUT);

        let response: MINode;
        try {
            response = await promise;
        } finally {
            this.timeout.kill();
        }

        if (response.resultRecords.resultClass === 'error'
            || (this.options.expectResultClass
                && response.resultRecords.resultClass !== this.options.expectResultClass)) {
            if (this.options.suppressFailure) {
                // log error, but still succeed
                this.owner.log('stderr', `WARNING: Error executing command '${this.command}'`);
                return response;
            }

            try {
                const msg = response.result('msg');
                throw new MIError(msg || 'Internal error', this.options.action ?? this.command);
            } catch (e) {
                console.error('Huh?', e);
                throw new MIError(e.toString(), this.options.action ?? this.command);
            }
        }

        return response;
    }

    outOfBand(node: MINode) {
        this.timeout.reset();
    }

    response(parsed: MINode) {
        parsed.output = this.output;
        this.resolve(parsed);
    }

    serverLost() {
        this.reject(new MIError('GDB server lost', this.options.action ?? this.command));
    }

    get captureOutput() {
        return this.options.captureOutput;
    }

    appendOutput(content: string) {
        this.output = (this.output ?? '') + content;
    }
}

export class MI2 extends EventEmitter implements IBackend {
    public debugOutput: ADAPTER_DEBUG_MODE;
    public procEnv: any;
    protected nextToken: number = 1;
    protected readonly commands = new Map<number, Command>();
    protected buffer: string = '';
    protected errbuf: string = '';
    protected process: ChildProcess.ChildProcess;
    protected firstStop: boolean = true;
    protected exited: boolean = false;
    public gdbMajorVersion: number | undefined;
    public gdbMinorVersion: number | undefined;
    public status: 'running' | 'stopped' | 'none' = 'none';
    public pid: number = -1;
    protected lastContinueSeqId = -1;
    protected actuallyStarted = false;
    protected isExiting = false;
    // public gdbVarsPromise: Promise<MINode> = null;

    constructor(public application: string, public args: string[], public forLiveGdb = false) {
        super();
    }

    public async start(cwd: string, init: string[]): Promise<void> {
        const isLive = this.forLiveGdb ? 'Live ' : '';
        this.process = ChildProcess.spawn(this.application, this.args, { cwd: cwd, env: this.procEnv });
        this.pid = this.process.pid;
        this.process.stdout.on('data', this.stdout.bind(this));
        this.process.stderr.on('data', this.stderr.bind(this));
        this.process.on('exit', this.onExit.bind(this));
        this.process.on('error', this.onError.bind(this));
        this.process.on('spawn', () => {
            ServerConsoleLog(isLive + `GDB started ppid=${process.pid} pid=${this.process.pid}`, this.process.pid);
        });

        if (!this.forLiveGdb) {
            const v = await this.sendCommand('gdb-version', {
                captureOutput: true,
                timeout: 5000,
            });
            this.parseVersionInfo(v.output);
        }
        this.actuallyStarted = true;

        if ((this.gdbMajorVersion !== undefined) && (this.gdbMajorVersion < 9)) {
            this.isExiting = true;
            const ver = this.gdbMajorVersion ? this.gdbMajorVersion.toString() : 'Unknown';
            const msg = `ERROR: GDB major version should be >= 9, yours is ${ver}`;
            this.log('stderr', msg);
            this.sendRaw('-gdb-exit');
            // throw new Error(msg);
            return;
        }

        const asyncCmd = 'gdb-set mi-async on';
        const promises = [asyncCmd, ...init].map((c) => this.sendCommand(c));
        await Promise.all(promises);
    }

    private onError(err) {
        this.emit('launcherror', err);
    }

    private parseVersionInfo(str: string) {
        const regex = RegExp(/^GNU gdb.*\s(\d+)\.(\d+)[^\r\n]*/gm);
        const match = regex.exec(str);
        if (match !== null) {
            str = str.substr(0, match.index);
            this.gdbMajorVersion = parseInt(match[1]);
            this.gdbMinorVersion = parseInt(match[2]);
        }
        if (str) {
            this.log('console', str);
        }
        if (match === null) {
            this.log('log', 'ERROR: Could not determine gdb-version number (regex failed). We need version >= 9. Please report this problem.');
            this.log('log', '    This can result in silent failures');
        }
    }

    public async connect(commands: string[]): Promise<any> {
        const promises = commands.map((c) => this.sendCommand(c));
        await Promise.all(promises);
        this.emit('debug-ready');
    }

    private onExit(code: number, signal: string) {
        this.gdbStartError();
        ServerConsoleLog('GDB: exited', this.pid);
        if (this.process) {
            this.process = null;
            this.exited = true;
            // Unless we are the ones initiating the quitting,
            const codestr = code === null || code === undefined ? 'none' : code.toString();
            const sigstr = signal ? `, signal: ${signal}` : '';
            const how = this.exiting ? '' : ((code || signal) ? ' unexpectedly' : '');
            const msg = `GDB session ended${how}. exit-code: ${codestr}${sigstr}\n`;
            this.emit('quit', how ? 'stderr' : 'stdout', msg);
        }
        // abort all running commands
        for (const cmd of this.commands.values()) {
            cmd.serverLost();
        }
    }

    private gdbStartError() {
        if (!this.actuallyStarted) {
            this.log('log',
                'Error: Unable to start GDB even after 5 seconds or it couldn\'t even start '
                + 'Make sure you can start gdb from the command-line and run any command like "echo hello".\n');
            this.log('log', '    If you cannot, it is most likely because "libncurses" or "python" is not installed. Some GDBs require these\n');
        }
    }

    private stdout(data) {
        if (trace) {
            this.log('stderr', 'stdout: ' + data);
        }
        if (typeof data === 'string') {
            this.buffer += data;
        } else {
            this.buffer += data.toString('utf8');
        }
        const end = this.buffer.lastIndexOf('\n');
        if (end !== -1) {
            this.onOutput(this.buffer.substr(0, end));
            this.buffer = this.buffer.substr(end + 1);
        }
        if (this.buffer.length) {
            if (this.onOutputPartial(this.buffer)) {
                this.buffer = '';
            }
        }
    }

    private stderr(data) {
        if (typeof data === 'string') {
            this.errbuf += data;
        } else {
            this.errbuf += data.toString('utf8');
        }
        const end = this.errbuf.lastIndexOf('\n');
        if (end !== -1) {
            this.onOutputStderr(this.errbuf.substr(0, end));
            this.errbuf = this.errbuf.substr(end + 1);
        }
        if (this.errbuf.length) {
            this.logNoNewLine('stderr', this.errbuf);
            this.errbuf = '';
        }
    }

    private onOutputStderr(lines) {
        lines = lines.split('\n') as string[];
        lines.forEach((line) => {
            this.log('stderr', line);
        });
    }

    private onOutputPartial(line) {
        if (couldBeOutput(line)) {
            this.logNoNewLine('stdout', line);
            return true;
        }
        return false;
    }

    private onOutput(lines) {
        lines = lines.split('\n') as string[];
        lines.forEach((line) => {
            if (couldBeOutput(line)) {
                if (!gdbMatch.exec(line)) {
                    this.log('stdout', line);
                }
            } else {
                const parsed = parseMI(line);
                const command = this.commands.get(parsed.token);
                if (!command?.options.forceNoDebug && this.debugOutput && (this.debugOutput !== ADAPTER_DEBUG_MODE.NONE)) {
                    if ((this.debugOutput === ADAPTER_DEBUG_MODE.RAW) || (this.debugOutput === ADAPTER_DEBUG_MODE.BOTH)) {
                        this.log('log', '-> ' + line);
                    }
                    if (this.debugOutput !== ADAPTER_DEBUG_MODE.RAW) {
                        this.log('log', 'GDB -> App: ' + JSON.stringify(parsed));
                    }
                }

                let handled = false;
                if (parsed.token !== undefined && parsed.resultRecords) {
                    if (command) {
                        command.response(parsed);
                        handled = true;
                    } else if (parsed.token === this.lastContinueSeqId) {
                        // This is the situation where the last continue actually fails but is initially reported
                        // having worked. See if we can gracefully handle it. See #561
                        this.status = 'stopped';
                        this.log('stderr', `GDB Error? continue command is reported as error after initially succeeding. token '${parsed.token}'`);
                        this.emit('continue-failed', parsed);
                    } else {
                        this.log('stderr', `Internal Error? Multiple results or no handler for query token '${parsed.token}'`);
                    }
                }
                if (!handled && parsed.resultRecords && parsed.resultRecords.resultClass === 'error') {
                    this.log('stderr', parsed.result('msg') || line);
                }
                if (parsed.outOfBandRecord) {
                    command?.outOfBand(parsed);
                    parsed.outOfBandRecord.forEach((record) => {
                        if (record.isStream) {
                            if (record.type === 'console') {
                                const activeCommand = [...this.commands.values()].at(-1);
                                if (activeCommand && activeCommand.captureOutput) {
                                    activeCommand.appendOutput(record.content);
                                    return;
                                }
                            }

                            this.log(record.type, record.content);
                        } else {
                            if (record.type === 'exec') {
                                this.emit('exec-async-output', parsed);
                                if (record.asyncClass === 'running') {
                                    this.status = 'running';
                                    if (this.debugOutput) {
                                        this.log('log', `mi2.status = ${this.status}`);
                                    }
                                    this.emit('running', parsed);
                                } else if (record.asyncClass === 'stopped') {
                                    this.status = 'stopped';
                                    if (this.debugOutput) {
                                        this.log('log', `mi2.status = ${this.status}`);
                                    }
                                    const reason = parsed.record('reason');
                                    if (trace) {
                                        this.log('stderr', 'stop: ' + reason);
                                    }
                                    if (reason === 'breakpoint-hit') {
                                        this.emit('breakpoint', parsed);
                                    } else if (reason && (reason as string).includes('watchpoint-trigger')) {
                                        this.emit('watchpoint', parsed);
                                    } else if (reason && (reason as string).includes('watchpoint-scope')) {
                                        // When a local variable goes out of scope
                                        this.emit('watchpoint-scope', parsed);
                                    } else if (reason === 'end-stepping-range') {
                                        this.emit('step-end', parsed);
                                    } else if (reason === 'function-finished') {
                                        this.emit('step-out-end', parsed);
                                    } else if (reason === 'signal-received') {
                                        this.emit('signal-stop', parsed);
                                    } else if (reason === 'exited-normally') {
                                        this.emit('exited-normally', parsed);
                                    } else if (reason === 'exited') { // exit with error code != 0
                                        this.log('stderr', 'Program exited with code ' + parsed.record('exit-code'));
                                        this.emit('exited-normally', parsed);
                                    } else {
                                        if ((reason === undefined) && this.firstStop) {
                                            this.log('console', 'Program stopped, probably due to a reset and/or halt issued by debugger');
                                            this.emit('stopped', parsed, 'entry');
                                        } else {
                                            this.log('console', 'Not implemented stop reason (assuming exception): ' + reason || 'Unknown reason');
                                            this.emit('stopped', parsed);
                                        }
                                    }
                                    this.firstStop = false;
                                    this.emit('generic-stopped', parsed);
                                } else {
                                    this.log('log', JSON.stringify(parsed));
                                }
                            } else if (record.type === 'notify') {
                                let tid: undefined | string;
                                let gid: undefined | string;
                                let fid: undefined | string;
                                for (const item of record.output) {
                                    if (item[0] === 'id') {
                                        tid = item[1];
                                    } else if (item[0] === 'group-id') {
                                        gid = item[1];
                                    } else if (item[0] === 'frame') {
                                        fid = item[1];  // for future use, available for thread-selected
                                    }
                                }
                                if (record.asyncClass === 'thread-created') {
                                    this.emit('thread-created', { threadId: parseInt(tid), threadGroupId: gid });
                                } else if (record.asyncClass === 'thread-exited') {
                                    this.emit('thread-exited', { threadId: parseInt(tid), threadGroupId: gid });
                                } else if (record.asyncClass === 'thread-selected') {
                                    this.emit('thread-selected', { threadId: parseInt(tid), frameId: fid });
                                } else if (record.asyncClass === 'thread-group-exited') {
                                    this.emit('thread-group-exited', { threadGroupId: tid });
                                }
                            }
                        }
                    });
                    handled = true;
                }
                if (parsed.token === undefined && parsed.resultRecords === undefined && parsed.outOfBandRecord.length === 0) {
                    handled = true;
                }
                if (!handled) {
                    this.log('log', 'Unhandled: ' + JSON.stringify(parsed));
                }
            }
        });
    }

    private tryKill() {
        if (!this.exited && this.process) {
            const proc = this.process;
            try {
                ServerConsoleLog('GDB kill()', this.pid);
                process.kill(-proc.pid);
            } catch (e) {
                this.log('log', `kill failed for ${-proc.pid}` + e);
                this.onExit(-1, '');      // Process already died or quit. Cleanup
            }
        }
    }

    // stop() can get called twice ... once by the disconnect sequence and once by the server existing because
    // we called disconnect. And the sleeps don't help that cause
    private exiting = false;
    public async stop() {
        if (trace) {
            this.log('stderr', 'stop');
        }
        if (!this.exited && !this.exiting) {
            this.exiting = true;            // We won't unset this
            // With JLink all of these catches, timeouts occur one time or the other. Two back to back runs don't produce
            // the same program flow. Sometimes, we get all the way to a proper gdb-exit without any timers expiring and
            // everything working. Very next run totally erratic. Openocd has its own issues
            let timer;
            const startKillTimeout = (ms: number) => {
                if (timer) { clearTimeout(timer); }
                timer = setTimeout(() => {
                    if (timer && !this.exited) {
                        ServerConsoleLog('GDB Kill timer expired for a disconnect+exit, so forcing a kill', this.pid);
                        this.tryKill();
                    }
                    timer = undefined;
                }, ms);
            };
            const destroyTimer = () => {
                if (timer) {
                    clearTimeout(timer);
                    timer = undefined;
                }
            };
            this.process.on('exit', (code) => {
                destroyTimer();
            });
            // Disconnect first. Not doing so and exiting will cause an unwanted detach if the
            // program is in paused state
            try {
                startKillTimeout(500);
                await new Promise((res) => setTimeout(res, 100));       // For some people delay was needed. Doesn't hurt I guess
                await this.sendCommand('target-disconnect');            // Yes, this can fail
            } catch (e) {
                if (this.exited) {
                    ServerConsoleLog('GDB already exited during a target-disconnect', this.pid);
                    destroyTimer();
                    return;
                }
                ServerConsoleLog(`target-disconnect failed with exception: ${e}. Proceeding to gdb-exit` + e, this.pid);
            }

            startKillTimeout(350);                                  // Reset timer for a smaller timeout
            await new Promise((res) => setTimeout(res, 250));       // For some people delay was needed. Doesn't hurt I guess
            if (this.exited) {
                // This occurs sometimes after a successful disconnect.
                ServerConsoleLog('gdb already exited before an exit was requested', this.pid);
                return;
            }
            this.sendRaw('-gdb-exit');
        }
    }

    public detach() {
        if (trace) {
            this.log('stderr', 'detach');
        }
        let to = setTimeout(() => {
            if (to) {
                ServerConsoleLog('target-detach hung: target probably running, thats okay, continue to stop()', this.pid);
                to = null;
                this.stop();
            }
        }, 100);

        // Following can hang if no response, or fail because the target is still running. Yes,
        // we sometimes detach when target is still running. This also causes unhandled rejection
        // warning/error from Node, so handle rejections.
        this.sendCommand('target-detach').then(() => {
            if (to) {
                clearTimeout(to);
                to = null;
            }
            this.stop();
        }, (e) => {
            if (to) {
                clearTimeout(to);
                to = null;
            }
            ServerConsoleLog('target-detach failed: target probably running, thats okay, continue to stop()', this.pid);
            this.stop();
        });
    }

    public async interrupt(arg: string = ''): Promise<boolean> {
        if (trace) {
            this.log('stderr', 'interrupt ' + arg);
        }
        const info = await this.sendCommand(`exec-interrupt ${arg}`);
        return info.resultRecords.resultClass === 'done';
    }

    public async continue(threadId: number): Promise<boolean> {
        if (trace) {
            this.log('stderr', 'continue');
        }
        const info = await this.sendCommand(`exec-continue --thread ${threadId}`);
        return info.resultRecords.resultClass === 'running';
    }

    public async next(threadId: number, instruction?: boolean): Promise<boolean> {
        if (trace) {
            this.log('stderr', 'next');
        }
        const baseCmd = instruction ? 'exec-next-instruction' : 'exec-next';
        const info = await this.sendCommand(`${baseCmd} --thread ${threadId}`);
        return info.resultRecords.resultClass === 'running';
    }

    public async step(threadId: number, instruction?: boolean): Promise<boolean> {
        if (trace) {
            this.log('stderr', 'step');
        }
        const baseCmd = instruction ? 'exec-step-instruction' : 'exec-step';
        const info = await this.sendCommand(`${baseCmd} --thread ${threadId}`);
        return info.resultRecords.resultClass === 'running';
    }

    public async stepOut(threadId: number): Promise<boolean> {
        if (trace) {
            this.log('stderr', 'stepOut');
        }
        const info = await this.sendCommand(`exec-finish --thread ${threadId}`);
        return info.resultRecords.resultClass === 'running';
    }

    public async goto(filename: string, line: number): Promise<boolean> {
        if (trace) {
            this.log('stderr', 'goto');
        }
        const target: string = '"' + (filename ? escape(filename) + ':' : '') + line.toString() + '"';
        await this.sendCommand('break-insert -t ' + target);
        const info = await this.sendCommand('exec-jump ' + target);
        return info.resultRecords.resultClass === 'running';
    }

    public restart(commands: string[]): Thenable<boolean> {
        if (trace) {
            this.log('stderr', 'restart');
        }
        return this._sendCommandSequence(commands);
    }

    public postStart(commands: string[]): Thenable<boolean> {
        if (trace) {
            this.log('stderr', 'post-start');
        }
        return this._sendCommandSequence(commands);
    }

    private async _sendCommandSequence(commands: string[]): Promise<boolean> {
        for (const command of commands) {
            await this.sendCommand(command);
        }
        return true;
    }

    public changeVariable(name: string, rawValue: string): Thenable<any> {
        if (trace) {
            this.log('stderr', 'changeVariable');
        }
        return this.sendCommand('gdb-set var ' + name + '=' + rawValue);
    }

    private setBreakPointCondition(bkptNum, condition): Thenable<any> {
        if (trace) {
            this.log('stderr', 'setBreakPointCondition');
        }
        return this.sendCommand('break-condition ' + bkptNum + ' ' + condition, {
            expectResultClass: 'done',
            action: 'Setting breakpoint condition',
        });
    }

    public async addBreakPoint(breakpoint: OurSourceBreakpoint): Promise<OurSourceBreakpoint> {
        if (trace) {
            this.log('stderr', 'addBreakPoint');
        }

        let bkptArgs = '';
        if (breakpoint.hitCondition) {
            if (breakpoint.hitCondition[0] === '>') {
                bkptArgs += '-i ' + numRegex.exec(breakpoint.hitCondition.substr(1))[0] + ' ';
            } else {
                const match = numRegex.exec(breakpoint.hitCondition)[0];
                if (match.length !== breakpoint.hitCondition.length) {
                    this.log('stderr',
                        'Unsupported break count expression: \'' + breakpoint.hitCondition + '\'. '
                        + 'Only supports \'X\' for breaking once after X times or \'>X\' for ignoring the first X breaks'
                    );
                    bkptArgs += '-t ';
                } else if (parseInt(match) !== 0) {
                    bkptArgs += '-t -i ' + parseInt(match) + ' ';
                }
            }
        }

        if (breakpoint.condition) {
            bkptArgs += `-c "${breakpoint.condition}" `;
        }

        if (breakpoint.raw) {
            bkptArgs += '*' + escape(breakpoint.raw);
        } else {
            bkptArgs += '"' + escape(breakpoint.file) + ':' + breakpoint.line + '"';
        }

        const cmd = breakpoint.logMessage ? 'dprintf-insert' : 'break-insert';
        if (breakpoint.logMessage) {
            bkptArgs += ' ' + breakpoint.logMessage;
        }

        const result = await this.sendCommand(`${cmd} ${bkptArgs}`, {
            expectResultClass: 'done',
            action: `Setting breakpoint at ${bkptArgs}`,
        });

        const bkptNum = parseInt(result.result('bkpt.number'));
        const line = result.result('bkpt.line');
        const addr = result.result('bkpt.addr');
        breakpoint.line = line ? parseInt(line) : breakpoint.line;
        breakpoint.number = bkptNum;
        if (addr) {
            breakpoint.address = addr;
        }

        if (breakpoint.file === undefined) {
            const file = result.result('bkpt.fullname') || result.record('bkpt.file');
            breakpoint.file = file ? file : undefined;
        }
        return breakpoint;
    }

    public async addInstrBreakPoint(breakpoint: OurInstructionBreakpoint): Promise<OurInstructionBreakpoint> {
        if (trace) {
            this.log('stderr', 'addBreakPoint');
        }

        let bkptArgs = '';
        if (breakpoint.condition) {
            bkptArgs += `-c "${breakpoint.condition}" `;
        }

        bkptArgs += '*' + hexFormat(breakpoint.address);

        const result = await this.sendCommand(`break-insert ${bkptArgs}`, {
            expectResultClass: 'done',
            action: `Setting breakpoint at ${bkptArgs}`
        });

        const bkptNum = parseInt(result.result('bkpt.number'));
        breakpoint.number = bkptNum;
        return breakpoint;
    }

    public async removeBreakpoints(breakpoints: number[]): Promise<boolean> {
        if (trace) {
            this.log('stderr', 'removeBreakPoint');
        }

        if (breakpoints.length === 0) {
            return true;
        }

        const cmd = 'break-delete ' + breakpoints.join(' ');
        const result = await this.sendCommand(cmd);
        return result.resultRecords.resultClass === 'done';
    }

    public async addDataBreakPoint(breakpoint: OurDataBreakpoint): Promise<OurDataBreakpoint> {
        if (trace) {
            this.log('stderr', 'addBreakPoint');
        }

        let bkptArgs = '';
        if (breakpoint.hitCondition) {
            if (breakpoint.hitCondition[0] === '>') {
                bkptArgs += '-i ' + numRegex.exec(breakpoint.hitCondition.substr(1))[0] + ' ';
            } else {
                const match = numRegex.exec(breakpoint.hitCondition)[0];
                if (match.length !== breakpoint.hitCondition.length) {
                    this.log('stderr',
                        'Unsupported break count expression: \'' + breakpoint.hitCondition + '\'. '
                        + 'Only supports \'X\' for breaking once after X times or \'>X\' for ignoring the first X breaks'
                    );
                    bkptArgs += '-t ';
                } else if (parseInt(match) !== 0) {
                    bkptArgs += '-t -i ' + parseInt(match) + ' ';
                }
            }
        }

        bkptArgs += breakpoint.dataId;
        const aType = breakpoint.accessType === 'read' ? '-r' : (breakpoint.accessType === 'readWrite' ? '-a' : '');
        const result = await this.sendCommand(`break-watch ${aType} ${bkptArgs}`, {
            expectResultClass: 'done',
            action: `Setting breakpoint at ${bkptArgs}`,
        });

        const bkptNum = parseInt(result.result('hw-awpt.number') || result.result('hw-rwpt.number') || result.result('wpt.number'));
        breakpoint.number = bkptNum;

        if (breakpoint.condition) {
            try {
                await this.setBreakPointCondition(bkptNum, breakpoint.condition);
            } catch (err) {
                // Just delete the breakpoint we just created as the condition creation failed
                try {
                    await this.sendCommand(`break-delete ${bkptNum}`);
                } catch (err) {
                    console.error('MI2: failed to delete breakpoint after failing to set condition', err);
                }
                throw err;  // Use this reason as reason for failing to create the breakpoint
            }
        }

        return breakpoint;
    }

    public async getFrame(thread: number, frameNumber: number): Promise<Stack> {
        const command = `stack-info-frame --thread ${thread} --frame ${frameNumber}`;

        const result = await this.sendCommand(command);
        const frame = result.result('frame');
        const level = MINode.valueOf(frame, 'level');
        const addr = MINode.valueOf(frame, 'addr');
        const func = MINode.valueOf(frame, 'func');
        const file = MINode.valueOf(frame, 'file');
        const fullname = MINode.valueOf(frame, 'fullname');
        let line = 0;
        const linestr = MINode.valueOf(frame, 'line');
        if (linestr) { line = parseInt(linestr); }

        return {
            address: addr,
            fileName: file,
            file: fullname,
            function: func,
            level: level,
            line: line
        };
    }

    public async getStackDepth(threadId: number, maxDepth: number = 1000): Promise<number> {
        if (trace) {
            this.log('stderr', 'getStackDepth');
        }
        const result = await this.sendCommand(`stack-info-depth --thread ${threadId} ${maxDepth}`);
        const depth = result.result('depth');
        const ret = parseInt(depth);
        return ret;
    }

    public async getStack(threadId: number, startLevel: number, maxLevels: number): Promise<Stack[]> {
        if (trace) {
            this.log('stderr', 'getStack');
        }

        const result = await this.sendCommand(`stack-list-frames --thread ${threadId} ${startLevel} ${maxLevels}`);
        const stack = result.result('stack');
        const ret: Stack[] = [];
        stack.forEach((element) => {
            const level = MINode.valueOf(element, '@frame.level');
            const addr = MINode.valueOf(element, '@frame.addr');
            const func = MINode.valueOf(element, '@frame.func');
            const filename = MINode.valueOf(element, '@frame.file');
            const file = MINode.valueOf(element, '@frame.fullname');
            let line = 0;
            const lnstr = MINode.valueOf(element, '@frame.line');
            if (lnstr) { line = parseInt(lnstr); }
            const from = parseInt(MINode.valueOf(element, '@frame.from'));
            ret.push({
                address: addr,
                fileName: filename,
                file: file,
                function: func || from,
                level: level,
                line: line
            });
        });
        return ret;
    }

    public async getStackVariables(thread: number, frame: number): Promise<Variable[]> {
        if (trace) {
            this.log('stderr', 'getStackVariables');
        }

        const result = await this.sendCommand(`stack-list-variables --thread ${thread} --frame ${frame} --simple-values`);
        const variables = result.result('variables');
        const ret: Variable[] = [];
        for (const element of variables) {
            const key = MINode.valueOf(element, 'name');
            const value = MINode.valueOf(element, 'value');
            const type = MINode.valueOf(element, 'type');
            ret.push({
                name: key,
                valueStr: value,
                type: type,
                raw: element
            });
        }
        return ret;
    }

    public async examineMemory(from: number, length: number): Promise<any> {
        if (trace) {
            this.log('stderr', 'examineMemory');
        }

        const result = await this.sendCommand('data-read-memory-bytes 0x' + from.toString(16) + ' ' + length);
        return result.result('memory[0].contents');
    }

    // Pass negative threadId/frameId to specify no context or current context
    public evalExpression(name: string, threadId: number, frameId: number): Promise<MINode> {
        if (trace) {
            this.log('stderr', 'evalExpression');
        }

        const thFr = MI2.getThreadFrameStr(threadId, frameId);
        return this.sendCommand(`data-evaluate-expression ${thFr} ` + name);
    }

    public static FORMAT_SPEC_MAP = {
        b: 'binary',
        d: 'decimal',
        h: 'hexadecimal',
        o: 'octal',
        n: 'natural',
        x: 'hexadecimal'
    };

    private getExprAndFmt(expression: string): [string, string] {
        let fmt = '';
        expression = expression.trim();
        if (/,[bdhonx]$/i.test(expression)) {
            fmt = expression.substring(expression.length - 1).toLocaleLowerCase();
            expression = expression.substring(0, expression.length - 2);
        }
        expression = expression.replace(/"/g, '\\"');
        return [expression, fmt];
    }

    public async varCreate(
        parent: number, expression: string, name: string = '-', scope: string = '@',
        threadId?: number, frameId?: number): Promise<VariableObject> {
        if (trace) {
            this.log('stderr', 'varCreate');
        }

        const [expr, fmt] = this.getExprAndFmt(expression);
        const thFr = ((threadId !== undefined) && (frameId !== undefined)) ? `--thread ${threadId} --frame ${frameId}` : '';
        const createResp = await this.sendCommand(`var-create ${thFr} ${name} ${scope} "${expr}"`);
        let overrideVal: string = null;
        if (fmt && name !== '-') {
            const formatResp = await this.sendCommand(`var-set-format ${name} ${MI2.FORMAT_SPEC_MAP[fmt]}`);
            overrideVal = formatResp.result('value');
        }

        let result = createResp.result('');
        if (overrideVal) {
            result = result.map((r: string[]) => r[0] === 'value' ? ['value', overrideVal] : r);
        }
        return new VariableObject(parent, result);
    }

    public async varEvalExpression(name: string): Promise<MINode> {
        if (trace) {
            this.log('stderr', 'varEvalExpression');
        }
        return this.sendCommand(`var-evaluate-expression ${name}`);
    }

    public async varListChildren(parent: number, name: string): Promise<VariableObject[]> {
        if (trace) {
            this.log('stderr', 'varListChildren');
        }
        // TODO: add `from` and `to` arguments
        const res = await this.sendCommand(`var-list-children --all-values "${name}"`);
        const keywords = ['private', 'protected', 'public'];
        const children = res.result('children') || [];
        const omg: VariableObject[] = [];
        for (const item of children) {
            const child = new VariableObject(parent, item[1]);
            if (child.exp.startsWith('<anonymous ')) {
                omg.push(...await this.varListChildren(parent, child.name));
            } else if (keywords.find((x) => x === child.exp)) {
                omg.push(...await this.varListChildren(parent, child.name));
            } else {
                omg.push(child);
            }
        }
        return omg;
    }

    public static getThreadFrameStr(threadId: number, frameId: number): string {
        const th = ((threadId !== undefined) && (threadId > 0)) ? `--thread ${threadId} ` : '';
        const fr = ((frameId !== undefined) && (frameId >= 0)) ? `--frame ${frameId}` : '';
        return th + fr;
    }

    // Pass negative threadId/frameId to specify no context or current context
    public async varUpdate(name: string = '*', threadId: number, frameId: number): Promise<MINode> {
        if (trace) {
            this.log('stderr', 'varUpdate');
        }
        return this.sendCommand(`var-update ${MI2.getThreadFrameStr(threadId, frameId)} --all-values ${name}`);
    }

    // Pass negative threadId/frameId to specify no context or current context
    public async varAssign(name: string, rawValue: string, threadId: number, frameId: number): Promise<MINode> {
        if (trace) {
            this.log('stderr', 'varAssign');
        }
        return this.sendCommand(`var-assign ${MI2.getThreadFrameStr(threadId, frameId)} ${name} ${rawValue}`);
    }

    public async exprAssign(expr: string, rawValue: string, threadId: number, frameId: number): Promise<MINode> {
        if (trace) {
            this.log('stderr', 'exprAssign');
        }
        const [lhs, fmt] = this.getExprAndFmt(expr);
        return this.sendCommand(`var-assign ${MI2.getThreadFrameStr(threadId, frameId)} ${lhs} ${rawValue}`);
    }

    public logNoNewLine(type: string, msg: string) {
        this.emit('msg', type, msg);
    }

    public log(type: string, msg: string) {
        this.emit('msg', type, msg[msg.length - 1] === '\n' ? msg : (msg + '\n'));
    }

    public sendUserInput(command: string): Thenable<any> {
        if (command.startsWith('-')) {
            return this.sendCommand(command.substr(1));
        } else {
            return this.sendCommand(`interpreter-exec console "${command}"`);
        }
    }

    public sendRaw(raw: string, suppressOutput?: boolean): Promise<void> {
        if (!this.process?.stdin) {
            throw new Error('Cannot send command, GDB is already terminated');
        }
        if ((!suppressOutput && this.debugOutput) || trace) {
            this.log('log', raw);
        }
        const { promise, resolve, reject } = promiseWithResolvers();
        this.process.stdin.write(raw + '\n', (error) => {
            if (error) {
                reject(error);
            } else {
                resolve();
            }
        });   // Sometimes, process is already null
        return promise;
    }

    public isRunning(): boolean {
        if (this.isExiting) {
            return false;
        }
        return !!this.process;
    }

    public async doSendCommand(command: string, opts?: CommandOptions): Promise<MINode> {
        const token = this.nextToken++;

        if (command.startsWith('exec-continue')) {
            this.lastContinueSeqId = token;
        }

        const cmd = new Command(this, token, command, opts);
        this.commands.set(token, cmd);
        try {
            return await cmd.execute();
        } finally {
            this.commands.delete(token);
        }
    }

    // promise used for chaining the commands together, resolved whenever the current command completes
    private commandSemaphore = new Sema(1);
    public async sendCommand(command: string, opts?: CommandOptions): Promise<MINode> {
        // We queue these requests as there can be a flood of them. Especially if you have two variables or same name back to back
        // the second can fail because we are still in the process of creating that variable (update, fail, then create). Sources
        // for requests are from RTOS viewers, watch windows and hover. Even a watch window can have duplicates.
        await this.commandSemaphore.acquire();
        try {
            return await this.doSendCommand(command, opts);
        } finally {
            this.commandSemaphore.release();
        }
    }
}
