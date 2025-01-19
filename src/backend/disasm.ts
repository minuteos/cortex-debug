import { Source } from '@vscode/debugadapter';
import { DebugProtocol } from '@vscode/debugprotocol';
import { hexFormat } from '../frontend/utils';
import { MI2 } from './mi2/mi2';
import { GDBDebugSession } from '../gdb';
import { DisassemblyInstruction, ConfigurationArguments, ADAPTER_DEBUG_MODE, HrTimer, parseHexOrDecInt } from '../common';
import { SymbolInformation } from '../symbols';
import { MemoryRegion } from './symbols';
import { Sema } from 'async-sema';

enum TargetArchitecture {
    X64, X86, ARM64, ARM, XTENSA, UNKNOWN
}

/*
** We currently have two disassembler interfaces. One that follows the DAP protocol and VSCode is the client
** for it. The other is the original that works on a function at a time and the client is our own extension.
** The former is new and unproven but has more features and not mature even for VSCode. The latter is more
** mature and limited in functionality
*/
interface ProtocolInstruction {
    pvtAddress: number;
    pvtInstructionBytes?: string;
    pvtIsData?: boolean;
}

class Instruction {
    constructor(
        readonly addr: number,
        readonly endAddr: number,
        readonly bytes: Buffer,
        readonly isData: boolean,
        readonly isValid: boolean,
        readonly instruction: string,
        readonly functionName?: string,
        readonly offset?: number,
        readonly source?: Source,
        readonly line?: number) {
    }

    static fromRaw(ri: any, source?: Source, line?: number): Instruction | Instruction[] {
        const result = Object.fromEntries(ri);
        const { address, 'func-name': functionName, offset, inst, opcodes } = result;
        const addr = parseInt(address);
        const bytes = Buffer.from(opcodes.replace(/\s+/g, ''), 'hex');

        return new Instruction(addr, addr + bytes.length, bytes, false, true, inst, functionName, offset, source, line);
    }

    static fromMemory(addr: number, buf: Buffer): Instruction[] {
        const res: Instruction[] = [];
        const b = { len: 1, mnemonic: '.byte' };
        const w = { len: 2, mnemonic: '.word' };
        const d = { len: 4, mnemonic: '.dword' };

        function push(spec: { len: number; mnemonic: string }) {
            const { len, mnemonic } = spec;
            const data = buf.subarray(0, len);
            const num = data.readUIntLE(0, len);
            res.push(new Instruction(addr, addr + len, data, true, true, `${mnemonic}\t${hexFormat(num, spec.len * 2)}`));
            buf = buf.subarray(len);
            addr += len;
        }

        if ((addr & 1) && buf.length) { // unaligned byte
            push(b);
        }

        if ((addr & 3) && buf.length >= 2) { // unaligned word
            push(w);
        }

        while (buf.length >= 4) {
            push(d);
        }

        if (buf.length > 2) {    // unaligned word
            push(w);
        }

        if (buf.length) {   // unaligned byte
            push(b);
        }

        return res;
    }

    contains(addr: number) {
        return addr >= this.addr && addr < this.endAddr;
    }

    toString() {
        return `${this.addr.toString(16)}  ${this.instructionBytes.padEnd(11, ' ')}  ${this.instruction}`;
    }

    toProtocolInstruction(): ProtocolInstruction {
        return {
            pvtAddress: this.addr,
            pvtInstructionBytes: this.instructionBytes,
            pvtIsData: this.isData
        };
    }

    toDisassemblyInstruction(): DisassemblyInstruction {
        return {
            address: hexFormat(this.addr),
            instruction: this.instruction,
            opcodes: this.instructionBytes,
            functionName: this.functionName,
            offset: this.offset,
        };
    }

    toDebugInstruction(): DebugProtocol.DisassembledInstruction {
        return {
            address: hexFormat(this.addr),
            instructionBytes: this.symbol,
            instruction: this.instructionBytes + '\t' + this.instruction,
            symbol: this.functionName,
            presentationHint: this.isValid ? 'normal' : 'invalid',
            location: this.source,
            line: this.line,
        };
    }

    get symbol() {
        let nm = this.functionName;
        if (!nm) {
            return undefined;
        }
        if (nm.length > 22) {
            nm = '..' + nm.slice(-20);
        }
        return `<${nm}+${this.offset}>`;
    }

    get instructionBytes() {
        return this.bytes.toString('hex');
    }
}

export class GdbDisassembler {
    public static debug: boolean = true;    // TODO: Remove this once stable. Merge with showDevDebugOutput
    public doTiming = true;

    public Architecture = TargetArchitecture.ARM;
    private readonly cache: Instruction[] = [];
    public memoryRegions: MemoryRegion[];

    constructor(public gdbSession: GDBDebugSession, public launchArgs: ConfigurationArguments) {
        GdbDisassembler.debug = this.gdbSession.isDebugLoggingAvailable();
        if (launchArgs.showDevDebugOutput && (launchArgs.showDevDebugOutput !== ADAPTER_DEBUG_MODE.NONE)) {
            GdbDisassembler.debug = true;       // Can't turn it off, once enabled. Intentional
        }
    }

    public get miDebugger(): MI2 {
        return this.gdbSession.miDebugger;
    }

    private handleMsg(type: string, str: string) {
        this.gdbSession.handleMsg(type, str);
    }

    private async getMemoryRegions() {
        if (this.memoryRegions) {
            return;
        }
        try {
            this.memoryRegions = [];
            const miNode = await this.miDebugger.sendCommand('interpreter-exec console "info mem"', { captureOutput: true });
            const str = miNode.output;
            let match: RegExpExecArray;
            const regex = RegExp(/^[0-9]+\s+([^\s])\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+([^\r\n]*)/mgi);
            // Num Enb  Low Addr   High Addr  Attrs
            // 1   y    0x10000000 0x10100000 flash blocksize 0x200 nocache
            let lastEnd = Number.NEGATIVE_INFINITY;
            while ((match = regex.exec(str))) {
                const [flag, lowAddr, highAddr, attrsStr] = match.slice(1, 5);
                if (flag === 'y') {
                    const nHighAddr = parseInt(highAddr);
                    const nlowAddr = parseInt(lowAddr);
                    const attrs = attrsStr.split(/\s+/g);
                    const name = `GdbInfo${this.memoryRegions.length}`;
                    this.memoryRegions.push(new MemoryRegion({
                        name: match[1],
                        size: nHighAddr - nlowAddr,      // size
                        vmaStart: nlowAddr,  // vma
                        lmaStart: nlowAddr,  // lma
                        vmaStartOrig: nlowAddr,
                        attrs: attrs
                    }));
                    if (lastEnd < nlowAddr) {
                        this.cache.push(new Instruction(lastEnd, nlowAddr, Buffer.alloc(0), false, false, '<mem-out-of-bounds>'));
                    }
                    lastEnd = nHighAddr;
                }
            }
            this.cache.push(new Instruction(lastEnd, Number.POSITIVE_INFINITY, Buffer.alloc(0), false, false, '<mem-out-of-bounds>'));
        } catch (e) {
            this.handleMsg('log', `Error: ${e.toString()}`);
        }
        const fromGdb = this.memoryRegions.length;
        // There is a caveat here. Adding regions from executables is not reliable when you have PIC
        // (Position Independent Code) -- so far have not seen such a thing but it is possible
        this.memoryRegions = this.memoryRegions.concat(this.gdbSession.symbolTable.memoryRegions);

        if (this.memoryRegions.length > 0) {
            this.handleMsg('log', 'Note: We detected the following memory regions as valid using gdb "info mem" and "objdump -h"\n');
            this.handleMsg('log', '    This information is used to adjust bounds only when normal disassembly fails.\n');
            const hdrs = ['Size', 'VMA Beg', 'VMA End', 'LMA Beg', 'LMA End'].map((x: string) => x.padStart(10));
            const line = ''.padEnd(80, '=') + '\n';
            this.handleMsg('stdout', line);
            this.handleMsg('stdout', '  Using following memory regions for disassembly\n');
            this.handleMsg('stdout', line);
            this.handleMsg('stdout', hdrs.join('') + '  Attributes\n');
            this.handleMsg('stdout', line);
            let count = 0;
            for (const r of this.memoryRegions) {
                if (count++ === fromGdb) {
                    if (fromGdb === 0) {
                        this.handleMsg('stdout', '  Unfortunately, No memory information from gdb (or gdb-server). Will try to manage without\n');
                    }
                    this.handleMsg('stdout', '  '.padEnd(80, '-') + '\n');
                }
                const vals = [r.size, r.vmaStart, r.vmaEnd - 1, r.lmaStart, r.lmaEnd - 1].map((v) => hexFormat(v, 8, false).padStart(10));
                if (r.vmaStart === r.lmaStart) {
                    vals[3] = vals[4] = '  '.padEnd(10, '-');
                }
                const attrs = ((count > fromGdb) ? `(${r.name}) ` : '') + r.attrs.join(' ');
                this.handleMsg('stdout', vals.join('') + '  ' + attrs + '\n');
            }
            this.handleMsg('stdout', line);
        }
    }

    private findCacheIndex(addr: number): number {
        const cache = this.cache;
        let s = 0, e = cache.length;
        while (s < e) {
            const m = (s + e) >> 1;
            if (addr >= cache[m].endAddr) {
                s = m + 1;
            } else {
                e = m;
            }
        }
        return s;
    }

    //
    // This is not normal disassembly. We have to conform to what VSCode expects even beyond
    // what the DAP spec says. This is how VSCode is working
    //
    // * They hinge off of the addresses reported during the stack trace that we gave them. Which btw, is a
    //   hex-string (memoryReference)
    // * Initially, they ask for 400 instructions with 200 instructions before and 200 after the frame PC address
    // * While it did (seem to) work if we return more than 400 instructions, that is violating the spec. and may not work
    //   so we have to return precisely the number of instruction demanded (not a request)
    // * Since this is all based on strings (I don't think they interpret the address string). Yet another
    //   reason why we have to be careful
    // * When you scroll just beyond the limits of what is being displayed, they make another request. They use
    //   the address string for the last (or first depending on direction) instruction previously returned by us
    //   as a base address for this request. Then they ask for +/- 50 instructions from that base address NOT
    //   including the base address.  But we use the instruction at the baseAddress to validate what we are returning
    //   since we know that was valid.
    // * All requests are in terms of instruction counts and not addresses (understandably from their POV)
    //
    // Other notes: We know that most ARM instructions are either 2 or 4 bytes. So we translate insruction counts
    // multiple of 4 bytes as worst case. We can easily go beyond the boundaries of the memory and at this point,
    // not sure what to do. Code can be anywhere in non-contiguous regions and we have no idea to tell what is even
    // valid.
    //
    public async disassembleProtocolRequest(
        response: DebugProtocol.DisassembleResponse,
        args: DebugProtocol.DisassembleArguments,
        request?: DebugProtocol.Request): Promise<void> {
        if (args.memoryReference === undefined) {
            // This is our own request.
            return this.customDisassembleRequest(response, args);
        }
        const seq = request?.seq;
        if (GdbDisassembler.debug) {
            const msg = `Debug-${seq}: Received ${JSON.stringify(request)}\n`;
            this.handleMsg('log', msg);
            this.debugDump(msg);
        }

        await this.disasmSema.acquire();
        try {
            await this.disassembleProtocolRequest2(response, args, request);
        } finally {
            this.disasmSema.release();
        }
    }

    // VSCode as a client, frequently makes duplicate requests, back to back before results for the first one are ready
    // As a result, older results are not in cache yet, we end up doing work that was not needed. It also happens
    // windows get re-arranged, during reset because we have back to back stops and in other situations. So, we
    // put things in a queue before starting work on the next item. Save quite a bit of work
    private disasmSema = new Sema(1);

    private async getInstructions(addr: number, offset: number, count: number): Promise<Instruction[]> {
        const cache = this.cache;
        let index = await this.requireCache(addr);

        while (offset < 0) {
            // walk backwards, filling the cache as we go
            if (cache[index - 1]?.endAddr !== cache[index].addr) {
                index = await this.fillCache(cache[index].addr - 1, true);
            } else {
                index--;
            }
            offset++;
        }

        while (offset > 0) {
            // walk forward, filling the cache as we go
            if (cache[index + 1]?.addr !== cache[index].endAddr) {
                index = await this.fillCache(cache[index].endAddr);
            } else {
                index++;
            }
            offset--;
        }

        let endIndex = index;
        while (count > 1) {
            // make sure we have enough instructions to return
            if (cache[endIndex + 1]?.addr !== cache[endIndex].endAddr) {
                endIndex = await this.fillCache(cache[endIndex].endAddr);
            } else {
                endIndex++;
            }
            count--;
        }

        return cache.slice(index, endIndex + 1);
    }

    private async requireCache(addr: number): Promise<number> {
        const cache = this.cache;
        let index = this.findCacheIndex(addr);
        if (!cache[index].contains(addr)) {
            index = await this.fillCache(addr);
        }
        return index;
    }

    private async fillCache(addr: number, reverse = false, noRecover = false): Promise<number> {
        if (addr === -Infinity) {
            return 0;
        }

        const result = await this.miDebugger.sendCommand(`data-disassemble -a ${hexFormat(addr)} -- 5`, {
            suppressFailure: true
        });

        if (result.resultRecords.resultClass === 'error') {
            if (noRecover) {
                return;
            }

            // there is no function at the requested address
            const nextAddr = this.gdbSession.symbolTable.getNearestFunctionAddress(addr, reverse);
            if (nextAddr !== undefined) {
                // try reading the next function in the chosen direction
                await this.fillCache(nextAddr, false, true);
            }

            // there is still a chance the above fill covered the missing space 🤷‍♂️
            let index = this.findCacheIndex(addr);
            if (!this.cache[index].contains(addr)) {
                // fill the hole with memory contents
                const from = this.cache[index - 1].endAddr;
                const to = this.cache[index].addr;
                if (from - to > 65536) {
                    // a bit too much to fill, this has to be some strange region, mark it with the error message
                    this.cache.splice(index, 0, new Instruction(
                        this.cache[index - 1].endAddr, this.cache[index].addr,
                        Buffer.alloc(0), false, false, result.result('msg')));
                } else {
                    const mem = await this.miDebugger.sendCommand(`data-read-memory-bytes ${from} ${to - from}`, {
                        suppressFailure: true
                    });

                    if (mem.resultRecords.resultClass === 'error') {
                        this.cache.splice(index, 0, new Instruction(
                            from, to, Buffer.alloc(0), false, false, mem.result('msg')));
                    } else {
                        const contents = mem.result('memory[0].contents');
                        const buf = Buffer.from(contents, 'hex');
                        this.cache.splice(index, 0, ...Instruction.fromMemory(from, buf));
                    }
                    index = this.findCacheIndex(addr);
                }
            }
            return index;
        }

        const rawInstructions: any[] = result.result('asm_insns');
        if (rawInstructions.length) {
            const instructions = rawInstructions.flatMap((ins) => {
                if (ins[0] == 'src_and_asm_line') {
                    // instructions with source information
                    const data = Object.fromEntries(ins[1]);
                    const { line, fullname } = data;
                    const nested: any[] = data.line_asm_insn;
                    const src = this.gdbSession.getSource(fullname);
                    return nested.flatMap((ins) => Instruction.fromRaw(ins, src, line));
                } else {
                    return Instruction.fromRaw(ins);
                }
            });

            const start = this.findCacheIndex(instructions[0].addr);
            const end = this.findCacheIndex(instructions.at(-1).addr - 1);

            this.cache.splice(start, end - start, ...instructions);
        }

        return this.findCacheIndex(addr);
    }

    private async disassembleProtocolRequest2(
        response: DebugProtocol.DisassembleResponse,
        args: DebugProtocol.DisassembleArguments,
        request?: DebugProtocol.Request): Promise<void> {
        try {
            await this.getMemoryRegions();
            const seq = request?.seq;
            if (GdbDisassembler.debug) {
                const msg = `Debug-${seq}: Starting... `;
                this.handleMsg('log', msg + '\n');
                this.debugDump(msg + JSON.stringify(args));
            }

            const baseAddress = parseInt(args.memoryReference);
            const offset = args.offset || 0;
            const instrOffset = args.instructionOffset || 0;
            const timer = this.doTiming ? new HrTimer() : undefined;

            if (offset !== 0) {
                throw (new Error('VSCode using non-zero disassembly offset? Don\'t know how to handle this yet. Please report this problem'));
            }

            const instructions = await this.getInstructions(baseAddress, instrOffset, args.instructionCount || 0);
            const vsInstructions = instructions.map((ins) => ins.toDebugInstruction());

            response.body = { instructions: vsInstructions };

            if (this.doTiming) {
                const ms = timer.createPaddedMs(3);
                this.handleMsg('log', `Debug-${seq}: Elapsed time for Disassembly Request: ${ms} ms\n`);
            }

            if (this.gdbSession.isDebugLoggingAvailable()) {
                const respObj = { ...response, body: {} };   // Make a shallow copy, replace instructions
                this.gdbSession.writeToDebugLog('Dumping disassembly response to VSCode\n', true);
                this.debugDump(JSON.stringify(respObj), vsInstructions);
            }

            this.gdbSession.sendResponse(response);
        } catch (e) {
            const msg = `Unable to disassemble: ${e.toString()}: ${JSON.stringify(request)}`;
            if (GdbDisassembler.debug) {
                this.debugDump(msg);
            }
            this.gdbSession.sendErrorResponsePub(response, 1, msg);
        }
    }

    private debugDump(header: string, instrs?: any[]) {
        if (header) {
            if (!header.endsWith('\n')) {
                header = header + '\n';
            }
            this.gdbSession.writeToDebugLog(header, true);
        }
        if (instrs && (instrs.length > 0)) {
            let count = 0;
            for (const instr of instrs) {
                this.gdbSession.writeToDebugLog(count.toString().padStart(4) + ': ' + JSON.stringify(instr) + '\n', false);
                count++;
            }
        }
    }

    public async customDisassembleRequest(response: DebugProtocol.Response, args: any): Promise<void> {
        if (args.function) {
            try {
                const funcInfo: SymbolInformation = await this.getDisassemblyForFunction(args.function, args.file);
                response.body = {
                    instructions: funcInfo.instructions,
                    name: funcInfo.name,
                    file: funcInfo.file,
                    address: funcInfo.address,
                    length: funcInfo.length
                };
                this.gdbSession.sendResponse(response);
            } catch (e) {
                this.gdbSession.sendErrorResponsePub(response, 1, `Unable to disassemble: ${e.toString()}`);
            }
            return;
        } else if (args.startAddress) {
            try {
                let funcInfo = this.gdbSession.symbolTable.getFunctionAtAddress(args.startAddress);
                if (funcInfo) {
                    funcInfo = await this.getDisassemblyForFunction(funcInfo.name, funcInfo.file as string);
                    response.body = {
                        instructions: funcInfo.instructions,
                        name: funcInfo.name,
                        file: funcInfo.file,
                        address: funcInfo.address,
                        length: funcInfo.length
                    };
                    this.gdbSession.sendResponse(response);
                } else {
                    const instructions: DisassemblyInstruction[] = await this.getDisassemblyForAddresses(args.startAddress, args.length || 256);
                    response.body = { instructions: instructions };
                    this.gdbSession.sendResponse(response);
                }
            } catch (e) {
                this.gdbSession.sendErrorResponsePub(response, 1, `Unable to disassemble: ${e.toString()}`);
            }
            return;
        } else {
            this.gdbSession.sendErrorResponsePub(response, 1, 'Unable to disassemble; invalid parameters.');
        }
    }

    public async getDisassemblyForFunction(functionName: string, file?: string): Promise<SymbolInformation> {
        const symbol: SymbolInformation = this.gdbSession.symbolTable.getFunctionByName(functionName, file);

        if (!symbol) { throw new Error(`Unable to find function with name ${functionName}.`); }

        symbol.instructions ??= await this.getDisassemblyForAddresses(symbol.address, symbol.length);

        return symbol;
    }

    private async getDisassemblyForAddresses(startAddress: number, length: number): Promise<DisassemblyInstruction[]> {
        const endAddress = startAddress + length;

        const index = await this.requireCache(startAddress);

        let endIndex = index + 1;
        while (this.cache[endIndex]?.addr < endAddress) {
            endIndex++;
        }

        return this.cache.slice(index, endIndex).map((ins) => ins.toDisassemblyInstruction());
    }
}
