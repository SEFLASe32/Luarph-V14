#!/usr/bin/env node
/**
 * encoder.mjs
 * -----------------------------------------------------------------------------
 * จำลองอัลกอริทึมการเข้ารหัสแบบย้อนกลับ (Reverse Encoding Simulator)
 * ตามโครงสร้างที่วิเคราะห์ได้จาก Luraph v14.3 (loader.lua_5e4ba8d7.txt):
 *
 *   1. Mini-Compiler: แปลงโค้ด Lua ตัวอย่าง -> Register-based VM Bytecode
 *      (ใช้ชุด Opcode และโครงสร้าง Prototype เดียวกับที่แกะได้:
 *       OP 34 LOADK, OP 12 GETGLOBAL, OP 2 ADD, OP 102 MUL, OP 42 CONCAT,
 *       OP 25/46 FORPREP/FORLOOP, OP 20 CALL, OP 69 RETURN, OP 90 CLOSURE, ฯลฯ)
 *   2. Binary Serializer: เข้ารหัส Chunk ด้วยรูปแบบเดียวกับไฟล์ต้นฉบับ:
 *      - Constant count biased ด้วย +0x12074 (73844) แบบ Unsigned LEB128
 *      - Deferred flag byte (รองรับ XOR string encryption mode เหมือน Stage 2)
 *      - Constant tags: <=8 (int64 <i8), 9..13 (float64 <d), 0xE3 (bool), 0xE6 (str)
 *      - Prototype count biased ด้วย +0xE81A (59418)
 *      - Line info เข้ารหัสแบบ RLE (uint32 LE)
 *      - Instruction count biased ด้วย +39325
 *      - แต่ละคำสั่ง: 3 Signed 53-bit LEB128 operands (`val * 8 + mode`) + opcode
 *   3. Ascii85 (Base85) Encoder:
 *      - แปลง 4-byte Big-Endian chunks -> 5 ตัวอักษรฐาน 85 (offset 33)
 *      - บีบอัด 0x00000000 เป็นตัวอักษร 'z'
 *      - ใส่ Header "LPH-"
 *   4. Lua Output Generator:
 *      - สร้างไฟล์ Lua แบบ Self-contained ที่มี Ascii85 Decoder, Binary Reader,
 *        Chunk Deserializer และ Register VM Runtime พร้อมรันได้จริง
 * -----------------------------------------------------------------------------
 * วิธีใช้:
 *   node encoder.mjs [input.lua] [output_encoded.lua] [--xor-key=0x5A]
 */

import fs from 'node:fs';
import path from 'node:path';

// =============================================================================
// 1. Constants (ตรงกับค่าที่แกะได้จาก Static Analysis ของ loader.lua)
// =============================================================================
export const FORMAT_CONSTANTS = {
  HEADER_MAGIC: 'LPH-',
  CONST_COUNT_BIAS: 0x12074,       // 73844
  PROTO_COUNT_BIAS: 0xe81a,        // 59418
  INST_COUNT_BIAS: 39325,
  TAG_INT64: 8,                    // <= 8
  TAG_FLOAT64: 13,                 // 9..13
  TAG_BOOL: 0xe3,                  // 227
  TAG_STRING: 0xe6,                // 230
  SIGNED_THRESHOLD: 4503599627370496, // 2^52
  SIGNED_MODULUS: 9007199254740992,   // 2^53
};

// Opcode subset ที่ตรงกับเลข Opcode ใน loader.lua_5e4ba8d7.txt
export const OP = {
  NOP: 0,
  ADD: 2,         // R[C] = R[B] + R[A]
  JMP: 5,         // pc = B
  GETGLOBAL: 12,  // R[B] = env[A_const]
  SUB: 17,        // R[C] = R[B] - R[A]
  CALL: 20,       // R[B].. = R[B](R[B+1]..R[B+C-1]), A = nRets+1
  FORPREP: 25,    // init numeric for loop at R[A], jump C
  LOADK: 34,      // R[A] = C_const
  CONCAT: 42,     // R[C] = R[B] .. R[A]
  FORLOOP: 46,    // step numeric for loop, store R[B+3], jump C
  MOVE: 47,       // R[A] = R[C]
  RETURN0: 57,    // return
  SETGLOBAL: 64,  // env[C_const] = R[A]
  ADDK: 68,       // R[A] = R[B] + C_const
  RETURN1: 69,    // return R[B]
  LOADARGS: 86,   // for i=1..B do R[i] = args[i]
  EQ: 88,         // R[C] = (R[B] == R[A])
  CLOSURE: 90,    // R[A] = closure(B_const)
  LOOP_POP: 99,   // pop loop frame
  MUL: 102,       // R[B] = R[A] * R[C]
};

// Operand modes (3 บิตล่างของแต่ละ operand)
export const MODE = {
  NONE: 0,
  REG: 1,
  CONST: 2,
  PROTO: 4,
};

// =============================================================================
// 2. Binary Stream Writer (LEB128, Signed 53-bit, Little-Endian primitives)
// =============================================================================
export class BinaryWriter {
  constructor() {
    this.chunks = [];
  }

  writeByte(v) {
    this.chunks.push(Buffer.from([v & 0xff]));
  }

  writeUInt32(v) {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(v >>> 0, 0);
    this.chunks.push(b);
  }

  writeInt64(v) {
    const b = Buffer.alloc(8);
    b.writeBigInt64LE(BigInt(Math.trunc(v)), 0);
    this.chunks.push(b);
  }

  writeFloat64(v) {
    const b = Buffer.alloc(8);
    b.writeDoubleLE(v, 0);
    this.chunks.push(b);
  }

  writeVarint(value) {
    let v = value;
    if (v < 0) throw new RangeError(`Unsigned varint cannot be negative: ${v}`);
    const out = [];
    do {
      let byte = v % 128;
      v = Math.floor(v / 128);
      if (v > 0) byte |= 0x80;
      out.push(byte);
    } while (v > 0);
    this.chunks.push(Buffer.from(out));
  }

  writeSignedVarint(value) {
    const encoded = value < 0 ? value + FORMAT_CONSTANTS.SIGNED_MODULUS : value;
    this.writeVarint(encoded);
  }

  writeString(str) {
    const buf = Buffer.from(str, 'utf8');
    this.writeVarint(buf.length);
    this.chunks.push(buf);
  }

  toBuffer() {
    return Buffer.concat(this.chunks);
  }
}

// =============================================================================
// 3. Ascii85 (Base85) Encoder & Decoder ("LPH-" format)
// =============================================================================
export function encodeAscii85(buffer) {
  // Pad ให้ครบพหุคูณของ 4 ไบต์ (เนื่องจาก decoder อ่านทีละ 5 chars -> 4 bytes)
  const padLen = (4 - (buffer.length % 4)) % 4;
  const padded = padLen > 0 ? Buffer.concat([buffer, Buffer.alloc(padLen)]) : buffer;

  let out = FORMAT_CONSTANTS.HEADER_MAGIC;
  for (let i = 0; i < padded.length; i += 4) {
    const v = padded.readUInt32BE(i);
    if (v === 0) {
      out += 'z';
      continue;
    }
    let n = v;
    const digits = new Array(5);
    for (let j = 4; j >= 0; j--) {
      digits[j] = String.fromCharCode((n % 85) + 33);
      n = Math.floor(n / 85);
    }
    out += digits.join('');
  }
  return out;
}

export function decodeAscii85(payload) {
  if (!payload.startsWith(FORMAT_CONSTANTS.HEADER_MAGIC)) {
    throw new Error('Invalid header: expected "LPH-"');
  }
  const expanded = payload.slice(4).replace(/z/g, '!!!!!');
  const bytes = [];
  for (let i = 0; i + 5 <= expanded.length; i += 5) {
    const c0 = expanded.charCodeAt(i) - 33;
    const c1 = expanded.charCodeAt(i + 1) - 33;
    const c2 = expanded.charCodeAt(i + 2) - 33;
    const c3 = expanded.charCodeAt(i + 3) - 33;
    const c4 = expanded.charCodeAt(i + 4) - 33;
    const v = c4 + c3 * 85 + c2 * 7225 + c1 * 614125 + c0 * 52200625;
    bytes.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
  }
  return Buffer.from(bytes);
}

// =============================================================================
// 4. Chunk Serializer & Deserializer (Round-Trip Compatible กับ loader.lua)
// =============================================================================
export function xorString(str, key) {
  if (!key) return str;
  const buf = Buffer.from(str, 'utf8');
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    out[i] = buf[i] ^ ((key + i * 17) & 0xff);
  }
  return out.toString('latin1');
}

export function unxorString(latin1Str, key) {
  if (!key) return latin1Str;
  const buf = Buffer.from(latin1Str, 'latin1');
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    out[i] = buf[i] ^ ((key + i * 17) & 0xff);
  }
  return out.toString('utf8');
}

export function serializeChunk(chunk, { xorKey = 0 } = {}) {
  const w = new BinaryWriter();
  const deferred = xorKey !== 0;

  // 1) Constant Pool
  w.writeVarint(chunk.consts.length + FORMAT_CONSTANTS.CONST_COUNT_BIAS);
  w.writeByte(deferred ? 1 : 0);

  for (const val of chunk.consts) {
    if (typeof val === 'boolean') {
      w.writeByte(FORMAT_CONSTANTS.TAG_BOOL);
      w.writeByte(val ? 1 : 0);
    } else if (typeof val === 'number') {
      if (Number.isInteger(val) && val >= -2147483648 && val <= 2147483647) {
        w.writeByte(FORMAT_CONSTANTS.TAG_INT64);
        w.writeInt64(val);
      } else {
        w.writeByte(FORMAT_CONSTANTS.TAG_FLOAT64);
        w.writeFloat64(val);
      }
    } else {
      w.writeByte(FORMAT_CONSTANTS.TAG_STRING);
      const raw = deferred ? xorString(String(val), xorKey) : String(val);
      const b = Buffer.from(raw, deferred ? 'latin1' : 'utf8');
      w.writeVarint(b.length);
      w.chunks.push(b);
    }
  }

  // 2) Prototypes
  w.writeVarint(chunk.protos.length + FORMAT_CONSTANTS.PROTO_COUNT_BIAS);
  for (const p of chunk.protos) {
    // RLE Line info (1 entry per instruction for simplicity)
    w.writeUInt32(p.insts.length);
    for (let i = 0; i < p.insts.length; i++) {
      const line = p.insts[i].line || 1;
      w.writeUInt32(line * 2); // even -> single PC line entry
    }

    w.writeVarint(p.maxStack);
    w.writeVarint(p.numParams);

    // Upvalues
    const upvals = p.upvals || [];
    w.writeVarint(upvals.length);
    for (const uv of upvals) {
      w.writeVarint(uv.idx * 4 + uv.kind);
    }

    // Instructions
    w.writeVarint(p.insts.length + FORMAT_CONSTANTS.INST_COUNT_BIAS);
    for (const inst of p.insts) {
      const rawA = (inst.A || 0) * 8 + (inst.modeA || MODE.NONE);
      const rawB = (inst.B || 0) * 8 + (inst.modeB || MODE.NONE);
      const rawC = (inst.C || 0) * 8 + (inst.modeC || MODE.NONE);
      w.writeSignedVarint(rawA);
      w.writeSignedVarint(rawB);
      w.writeSignedVarint(rawC);
      w.writeSignedVarint(inst.op);
    }
  }

  // 3) Entry Prototype Index (1-based)
  w.writeVarint(chunk.entryIdx);
  return w.toBuffer();
}

export function deserializeChunk(buf, { xorKey = 0 } = {}) {
  let pos = 0;
  const readByte = () => buf[pos++];
  const readU32 = () => { const v = buf.readUInt32LE(pos); pos += 4; return v; };
  const readI64 = () => { const v = buf.readBigInt64LE(pos); pos += 8; return Number(v); };
  const readF64 = () => { const v = buf.readDoubleLE(pos); pos += 8; return v; };
  const readVarint = () => {
    let res = 0, mul = 1;
    while (true) {
      const b = readByte();
      res += (b > 127 ? b - 128 : b) * mul;
      mul *= 128;
      if (b < 128) break;
    }
    return res;
  };
  const readSigned = () => {
    const k = readVarint();
    return k >= FORMAT_CONSTANTS.SIGNED_THRESHOLD ? k - FORMAT_CONSTANTS.SIGNED_MODULUS : k;
  };

  const numConsts = readVarint() - FORMAT_CONSTANTS.CONST_COUNT_BIAS;
  const deferred = readByte() !== 0;
  const consts = [null];
  for (let i = 1; i <= numConsts; i++) {
    const tag = readByte();
    let val;
    if (tag <= 13) {
      val = tag <= FORMAT_CONSTANTS.TAG_INT64 ? readI64() : readF64();
    } else if (tag === FORMAT_CONSTANTS.TAG_BOOL) {
      val = readByte() === 1;
    } else {
      const len = readVarint();
      const slice = buf.subarray(pos, pos + len);
      pos += len;
      val = deferred ? unxorString(slice.toString('latin1'), xorKey) : slice.toString('utf8');
    }
    consts.push(val);
  }

  const numProtos = readVarint() - FORMAT_CONSTANTS.PROTO_COUNT_BIAS;
  const protos = [null];
  const patchList = [];

  for (let pIdx = 1; pIdx <= numProtos; pIdx++) {
    const lineCount = readU32();
    const lines = {};
    let linePc = 1;
    for (let i = 1; i <= lineCount; i++) {
      const raw = readU32();
      const half = Math.floor(raw / 2);
      if (raw % 2 !== 0) {
        const end = readU32();
        const ln = readU32();
        for (let k = half; k <= end; k++) lines[k] = ln;
        linePc = end;
      } else {
        lines[linePc] = half;
      }
      linePc++;
    }
    const maxStack = readVarint();
    const numParams = readVarint();
    const numUpvals = readVarint();
    const upvals = [];
    for (let i = 0; i < numUpvals; i++) {
      const u = readVarint();
      upvals.push({ kind: u % 4, idx: Math.floor(u / 4) });
    }
    const numInsts = readVarint() - FORMAT_CONSTANTS.INST_COUNT_BIAS;
    const insts = [];
    for (let i = 0; i < numInsts; i++) {
      const rawA = readSigned();
      const rawB = readSigned();
      const rawC = readSigned();
      const op = readSigned();
      const modeA = ((rawA % 8) + 8) % 8;
      const modeB = ((rawB % 8) + 8) % 8;
      const modeC = ((rawC % 8) + 8) % 8;
      const A = (rawA - modeA) / 8;
      const B = (rawB - modeB) / 8;
      const C = (rawC - modeC) / 8;
      const inst = {
        op,
        A, modeA, Ak: modeA === MODE.CONST ? consts[A] : undefined,
        B, modeB, Bk: modeB === MODE.CONST ? consts[B] : undefined,
        C, modeC, Ck: modeC === MODE.CONST ? consts[C] : undefined,
        line: lines[i + 1] || 1,
      };
      if (modeA === MODE.PROTO) patchList.push([inst, 'Ak', A]);
      if (modeB === MODE.PROTO) patchList.push([inst, 'Bk', B]);
      if (modeC === MODE.PROTO) patchList.push([inst, 'Ck', C]);
      insts.push(inst);
    }
    protos.push({ id: pIdx, maxStack, numParams, upvals, insts, lines });
  }

  for (const [inst, field, pIdx] of patchList) {
    inst[field] = protos[pIdx];
  }
  const entryIdx = readVarint();
  return { numConsts, deferred, consts: consts.slice(1), protos: protos.slice(1), entryIdx };
}

// =============================================================================
// 5. Mini Lua-to-Luraph-VM Compiler (คอมไพล์ Subset ของ Lua เป็น Bytecode)
// =============================================================================
export function compileLuaToChunk(luaSource) {
  const consts = [];
  const constMap = new Map();
  const addConst = (val) => {
    const key = `${typeof val}:${String(val)}`;
    if (constMap.has(key)) return constMap.get(key);
    consts.push(val);
    const idx = consts.length; // 1-based
    constMap.set(key, idx);
    return idx;
  };

  // Tokenizer สำหรับ Lua subset (local, function, for, return, print, strings, numbers, ops)
  const tokenize = (src) => {
    const tokens = [];
    let i = 0, line = 1;
    while (i < src.length) {
      const ch = src[i];
      if (ch === '\n') { line++; i++; continue; }
      if (/\s/.test(ch)) { i++; continue; }
      if (ch === '-' && src[i + 1] === '-') {
        while (i < src.length && src[i] !== '\n') i++;
        continue;
      }
      if (ch === '"' || ch === "'") {
        const quote = ch; i++;
        let s = '';
        while (i < src.length && src[i] !== quote) {
          if (src[i] === '\\') { i++; s += src[i] === 'n' ? '\n' : src[i]; }
          else s += src[i];
          i++;
        }
        i++;
        tokens.push({ type: 'STR', val: s, line });
        continue;
      }
      if (/[0-9]/.test(ch)) {
        let num = '';
        while (i < src.length && /[0-9.]/.test(src[i])) num += src[i++];
        tokens.push({ type: 'NUM', val: Number(num), line });
        continue;
      }
      if (/[A-Za-z_]/.test(ch)) {
        let id = '';
        while (i < src.length && /[A-Za-z0-9_]/.test(src[i])) id += src[i++];
        const kw = ['local', 'function', 'for', 'do', 'end', 'return', 'true', 'false'];
        tokens.push({ type: kw.includes(id) ? 'KW' : 'ID', val: id, line });
        continue;
      }
      const two = src.slice(i, i + 2);
      if (['..', '==', '~=', '<=', '>='].includes(two)) {
        tokens.push({ type: 'OP', val: two, line });
        i += 2; continue;
      }
      tokens.push({ type: 'SYM', val: ch, line });
      i++;
    }
    tokens.push({ type: 'EOF', val: '', line });
    return tokens;
  };

  const tokens = tokenize(luaSource);
  let tPos = 0;
  const peek = (offset = 0) => tokens[tPos + offset] || tokens[tokens.length - 1];
  const next = () => tokens[tPos++];
  const expect = (val) => {
    const t = next();
    if (t.val !== val) throw new SyntaxError(`Line ${t.line}: expected '${val}', got '${t.val}'`);
    return t;
  };

  const protos = [];

  function compileBlock(params = [], stopAtEnd = false) {
    const insts = [];
    const locals = new Map();
    let nextReg = 1;
    let maxStack = 1;

    const allocReg = () => {
      const r = nextReg++;
      if (nextReg > maxStack) maxStack = nextReg;
      return r;
    };

    if (params.length > 0) {
      insts.push({ op: OP.LOADARGS, A: 0, modeA: 0, B: params.length, modeB: MODE.REG, C: 0, modeC: 0, line: 1 });
      for (const p of params) locals.set(p, allocReg());
    }

    const emit = (inst) => { insts.push(inst); return insts.length; };

    function compileExpr(targetReg) {
      return compileCompare(targetReg);
    }

    function compileCompare(targetReg) {
      const left = compileConcat(targetReg);
      while (peek().type === 'OP' && peek().val === '==') {
        const opTok = next();
        const right = compileConcat(allocReg());
        const dest = targetReg ?? allocReg();
        emit({ op: OP.EQ, A: right, modeA: MODE.REG, B: left, modeB: MODE.REG, C: dest, modeC: MODE.REG, line: opTok.line });
        return dest;
      }
      return left;
    }

    function compileConcat(targetReg) {
      let left = compileAddSub(targetReg);
      while (peek().type === 'OP' && peek().val === '..') {
        const opTok = next();
        const right = compileAddSub(allocReg());
        const dest = targetReg ?? allocReg();
        emit({ op: OP.CONCAT, A: right, modeA: MODE.REG, B: left, modeB: MODE.REG, C: dest, modeC: MODE.REG, line: opTok.line });
        left = dest;
      }
      return left;
    }

    function compileAddSub(targetReg) {
      let left = compileMul(targetReg);
      while (peek().type === 'SYM' && (peek().val === '+' || peek().val === '-')) {
        const opTok = next();
        const right = compileMul(allocReg());
        const dest = targetReg ?? allocReg();
        emit({
          op: opTok.val === '+' ? OP.ADD : OP.SUB,
          A: right, modeA: MODE.REG,
          B: left, modeB: MODE.REG,
          C: dest, modeC: MODE.REG,
          line: opTok.line,
        });
        left = dest;
      }
      return left;
    }

    function compileMul(targetReg) {
      let left = compilePrimary(targetReg);
      while (peek().type === 'SYM' && peek().val === '*') {
        const opTok = next();
        const right = compilePrimary(allocReg());
        const dest = targetReg ?? allocReg();
        emit({ op: OP.MUL, A: left, modeA: MODE.REG, B: dest, modeB: MODE.REG, C: right, modeC: MODE.REG, line: opTok.line });
        left = dest;
      }
      return left;
    }

    function compilePrimary(targetReg) {
      const t = peek();
      if (t.type === 'SYM' && t.val === '(') {
        next();
        const r = compileExpr(targetReg);
        expect(')');
        return r;
      }
      if (t.type === 'NUM' || t.type === 'STR' || (t.type === 'KW' && (t.val === 'true' || t.val === 'false'))) {
        next();
        const dest = targetReg ?? allocReg();
        const val = t.type === 'KW' ? t.val === 'true' : t.val;
        const kIdx = addConst(val);
        emit({ op: OP.LOADK, A: dest, modeA: MODE.REG, B: 0, modeB: 0, C: kIdx, modeC: MODE.CONST, line: t.line });
        return dest;
      }
      if (t.type === 'ID') {
        next();
        let reg;
        if (locals.has(t.val)) {
          const src = locals.get(t.val);
          if (targetReg !== undefined && targetReg !== src) {
            emit({ op: OP.MOVE, A: targetReg, modeA: MODE.REG, B: 0, modeB: 0, C: src, modeC: MODE.REG, line: t.line });
            reg = targetReg;
          } else {
            reg = src;
          }
        } else {
          const dest = targetReg ?? allocReg();
          const kIdx = addConst(t.val);
          emit({ op: OP.GETGLOBAL, A: kIdx, modeA: MODE.CONST, B: dest, modeB: MODE.REG, C: 0, modeC: 0, line: t.line });
          reg = dest;
        }
        // Function call
        if (peek().type === 'SYM' && peek().val === '(') {
          const callBase = allocReg();
          emit({ op: OP.MOVE, A: callBase, modeA: MODE.REG, B: 0, modeB: 0, C: reg, modeC: MODE.REG, line: t.line });
          next(); // '('
          let argCount = 0;
          if (!(peek().type === 'SYM' && peek().val === ')')) {
            while (true) {
              const argReg = allocReg();
              compileExpr(argReg);
              argCount++;
              if (peek().type === 'SYM' && peek().val === ',') next();
              else break;
            }
          }
          expect(')');
          emit({
            op: OP.CALL,
            A: 2, modeA: MODE.REG, // expect 1 return value
            B: callBase, modeB: MODE.REG,
            C: argCount + 1, modeC: MODE.REG,
            line: t.line,
          });
          if (targetReg !== undefined && targetReg !== callBase) {
            emit({ op: OP.MOVE, A: targetReg, modeA: MODE.REG, B: 0, modeB: 0, C: callBase, modeC: MODE.REG, line: t.line });
            return targetReg;
          }
          return callBase;
        }
        return reg;
      }
      throw new SyntaxError(`Line ${t.line}: unexpected token '${t.val}'`);
    }

    while (peek().type !== 'EOF') {
      if (stopAtEnd && peek().type === 'KW' && peek().val === 'end') {
        next();
        break;
      }
      const t = peek();
      if (t.type === 'KW' && t.val === 'local') {
        next();
        if (peek().type === 'KW' && peek().val === 'function') {
          next();
          const nameTok = next();
          expect('(');
          const fnParams = [];
          if (!(peek().type === 'SYM' && peek().val === ')')) {
            while (true) {
              fnParams.push(next().val);
              if (peek().type === 'SYM' && peek().val === ',') next();
              else break;
            }
          }
          expect(')');
          const subProtoIdx = compileBlock(fnParams, true);
          const fnReg = allocReg();
          locals.set(nameTok.val, fnReg);
          emit({ op: OP.CLOSURE, A: fnReg, modeA: MODE.REG, B: subProtoIdx, modeB: MODE.PROTO, C: 0, modeC: 0, line: nameTok.line });
        } else {
          const nameTok = next();
          expect('=');
          const varReg = allocReg();
          compileExpr(varReg);
          locals.set(nameTok.val, varReg);
        }
      } else if (t.type === 'KW' && t.val === 'for') {
        next();
        const varTok = next();
        expect('=');
        const base = allocReg(); // start
        const limitReg = allocReg();
        const stepReg = allocReg();
        const loopVarReg = allocReg(); // base + 3
        compileExpr(base);
        expect(',');
        compileExpr(limitReg);
        if (peek().type === 'SYM' && peek().val === ',') {
          next();
          compileExpr(stepReg);
        } else {
          const kOne = addConst(1);
          emit({ op: OP.LOADK, A: stepReg, modeA: MODE.REG, B: 0, modeB: 0, C: kOne, modeC: MODE.CONST, line: varTok.line });
        }
        expect('do');
        const prepPc = emit({ op: OP.FORPREP, A: base, modeA: MODE.REG, B: 0, modeB: 0, C: 0, modeC: MODE.REG, line: varTok.line });
        const bodyStartPc = insts.length; // 1-based PC before first body inst (since VM increments pc++)
        const prevLocal = locals.get(varTok.val);
        locals.set(varTok.val, loopVarReg);
        while (!(peek().type === 'KW' && peek().val === 'end')) {
          compileSingleStmt();
        }
        expect('end');
        if (prevLocal === undefined) locals.delete(varTok.val);
        else locals.set(varTok.val, prevLocal);
        const loopPc = emit({ op: OP.FORLOOP, A: 0, modeA: 0, B: base, modeB: MODE.REG, C: bodyStartPc, modeC: MODE.REG, line: varTok.line });
        insts[prepPc - 1].C = loopPc - 1; // FORPREP jumps right before FORLOOP
        emit({ op: OP.LOOP_POP, A: 0, modeA: 0, B: 0, modeB: 0, C: 0, modeC: 0, line: varTok.line });
      } else if (t.type === 'KW' && t.val === 'return') {
        next();
        if (peek().type === 'EOF' || (peek().type === 'KW' && peek().val === 'end')) {
          emit({ op: OP.RETURN0, A: 0, modeA: 0, B: 0, modeB: 0, C: 0, modeC: 0, line: t.line });
        } else {
          const r = compileExpr();
          emit({ op: OP.RETURN1, A: 0, modeA: 0, B: r, modeB: MODE.REG, C: 0, modeC: 0, line: t.line });
        }
      } else {
        compileSingleStmt();
      }
    }

    function compileSingleStmt() {
      const t = peek();
      if (t.type === 'ID' && peek(1).type === 'SYM' && peek(1).val === '=') {
        next();
        expect('=');
        if (locals.has(t.val)) {
          compileExpr(locals.get(t.val));
        } else {
          const r = compileExpr();
          const kIdx = addConst(t.val);
          emit({ op: OP.SETGLOBAL, A: r, modeA: MODE.REG, B: 0, modeB: 0, C: kIdx, modeC: MODE.CONST, line: t.line });
        }
      } else {
        compileExpr();
      }
    }

    if (insts.length === 0 || (insts[insts.length - 1].op !== OP.RETURN0 && insts[insts.length - 1].op !== OP.RETURN1)) {
      emit({ op: OP.RETURN0, A: 0, modeA: 0, B: 0, modeB: 0, C: 0, modeC: 0, line: 1 });
    }

    protos.push({ maxStack: maxStack + 4, numParams: params.length, upvals: [], insts });
    return protos.length; // 1-based prototype index
  }

  const entryIdx = compileBlock([], false);
  return { consts, protos, entryIdx };
}

// =============================================================================
// 6. Reconstructed VM Runtime in JS (รัน Bytecode เพื่อทดสอบเทียบผลลัพธ์)
// =============================================================================
export function executeChunk(chunk, envOverrides = {}) {
  const logs = [];
  const env = {
    print: (...args) => {
      const line = args.map((v) => String(v)).join('\t');
      logs.push(line);
    },
    ...envOverrides,
  };

  function wrapProto(proto) {
    return function (...args) {
      const reg = {};
      let pc = 1;
      let loopIter = 0, loopLimit = 0, loopStep = 0;
      const loopStack = [];

      while (pc <= proto.insts.length) {
        const inst = proto.insts[pc - 1];
        switch (inst.op) {
          case OP.NOP:
            break;
          case OP.ADD:
            reg[inst.C] = reg[inst.B] + reg[inst.A];
            break;
          case OP.JMP:
            pc = inst.B;
            break;
          case OP.GETGLOBAL:
            reg[inst.B] = env[inst.Ak];
            break;
          case OP.SUB:
            reg[inst.C] = reg[inst.B] - reg[inst.A];
            break;
          case OP.CALL: {
            const base = inst.B;
            const nArgs = inst.C - 1;
            const callArgs = [];
            for (let i = 1; i <= nArgs; i++) callArgs.push(reg[base + i]);
            const ret = reg[base](...callArgs);
            if (inst.A >= 2) reg[base] = ret;
            break;
          }
          case OP.FORPREP: {
            loopStack.push({ loopIter, loopLimit, loopStep });
            loopStep = Number(reg[inst.A + 2]);
            loopLimit = Number(reg[inst.A + 1]);
            loopIter = Number(reg[inst.A]) - loopStep;
            pc = inst.C;
            break;
          }
          case OP.LOADK:
            reg[inst.A] = inst.Ck;
            break;
          case OP.CONCAT:
            reg[inst.C] = String(reg[inst.B]) + String(reg[inst.A]);
            break;
          case OP.FORLOOP: {
            loopIter += loopStep;
            const ok = loopStep <= 0 ? loopIter >= loopLimit : loopIter <= loopLimit;
            if (ok) {
              reg[inst.B + 3] = loopIter;
              pc = inst.C;
            }
            break;
          }
          case OP.MOVE:
            reg[inst.A] = reg[inst.C];
            break;
          case OP.RETURN0:
            return undefined;
          case OP.SETGLOBAL:
            env[inst.Ck] = reg[inst.A];
            break;
          case OP.ADDK:
            reg[inst.A] = reg[inst.B] + inst.Ck;
            break;
          case OP.RETURN1:
            return reg[inst.B];
          case OP.LOADARGS:
            for (let i = 1; i <= inst.B; i++) reg[i] = args[i - 1];
            break;
          case OP.EQ:
            reg[inst.C] = reg[inst.B] === reg[inst.A];
            break;
          case OP.CLOSURE:
            reg[inst.A] = wrapProto(inst.Bk);
            break;
          case OP.LOOP_POP: {
            const prev = loopStack.pop();
            if (prev) ({ loopIter, loopLimit, loopStep } = prev);
            break;
          }
          case OP.MUL:
            reg[inst.B] = reg[inst.A] * reg[inst.C];
            break;
          default:
            throw new Error(`Unsupported opcode: ${inst.op}`);
        }
        pc++;
      }
    };
  }

  const entryProto = chunk.protos[chunk.entryIdx - 1];
  const returnValue = wrapProto(entryProto)();
  return { logs, returnValue };
}

// =============================================================================
// 7. Luraph v14.3-Style Obfuscated Lua Emitter (จำลองชั้น Obfuscation ให้เหมือนต้นฉบับ)
//    - Wrapper Argument Injection (ส่ง stdlib, bit32 table C, key table L)
//    - Control-Flow Flattening (CFF) ด้วยลูป while true + state p + memoized R + bit32
//    - Number & String Literal Obfuscation (0X..., 0B..., underscores, \ddd, \xHH, \u{}, \z)
//    - Ascii85 ("LPH-...") + Biased LEB128 + Deferred Constant Patching (I[2], I[3])
//    - 7-Level Balanced Binary-Search if/else VM Opcode Dispatch Tree (0..103)
// =============================================================================

function createRng(seed = 0x143a7) {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function makeObfNum(rng, dialect = 'luau') {
  return (n) => {
    if (!Number.isInteger(n) || n < 0) return String(n);
    const pick = rng();
    if (dialect === 'luau') {
      if (pick < 0.38 && n <= 0xffff) {
        const bin = n.toString(2);
        const prefix = rng() < 0.5 ? '0B' : '0b';
        if (bin.length > 3 && rng() < 0.7) {
          const cut = Math.max(1, bin.length - 2 - Math.floor(rng() * 3));
          return `${prefix}${bin.slice(0, cut)}_${bin.slice(cut)}`;
        }
        return `${prefix}${bin}`;
      }
      if (pick < 0.78) {
        const hex = n.toString(16);
        const mixed = hex
          .split('')
          .map((ch) => (rng() < 0.5 ? ch.toUpperCase() : ch.toLowerCase()))
          .join('');
        const prefix = rng() < 0.5 ? '0X' : '0x';
        const pad = rng() < 0.35 ? '0' : '';
        const full = pad + mixed;
        if (full.length > 2 && rng() < 0.65) {
          const cut = 1 + Math.floor(rng() * (full.length - 1));
          return `${prefix}${full.slice(0, cut)}_${full.slice(cut)}`;
        }
        return `${prefix}${full}`;
      }
      return String(n);
    }
    // Standard Lua 5.3 / 5.4 dialect (no 0b binary or underscores)
    if (pick < 0.65) {
      const prefix = rng() < 0.5 ? '0X' : '0x';
      return `${prefix}${n.toString(16).toUpperCase()}`;
    }
    return String(n);
  };
}

function makeObfStr(rng) {
  return (str) => {
    let out = '';
    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i);
      const r = rng();
      if (r < 0.28) {
        out += `\\${String(code).padStart(3, '0')}`;
      } else if (r < 0.56) {
        out += `\\x${code.toString(16).padStart(2, '0').toUpperCase()}`;
      } else if (r < 0.80) {
        const pad = rng() < 0.5 ? '00' : '';
        out += `\\u{${pad}${code.toString(16)}}`;
      } else {
        const ch = str[i];
        out += ch === '\\' || ch === '"' || ch === "'" ? `\\${String(code).padStart(3, '0')}` : ch;
      }
      if (i > 0 && i < str.length - 1 && rng() < 0.35) {
        out += '\\z  ';
      }
    }
    return `"${out}"`;
  };
}

function buildCFFBlock(steps, L, rng, obfNum, usedMemoKeys, cffChecks) {
  // สร้าง state IDs ที่ไม่ซ้ำกัน
  const states = [];
  const used = new Set();
  for (let i = 0; i < steps.length; i++) {
    let st;
    do {
      st = 11 + Math.floor(rng() * 110);
    } while (used.has(st));
    used.add(st);
    states.push(st);
  }

  const pickMemoKey = () => {
    let k;
    do {
      k = 1000 + Math.floor(rng() * 31000);
    } while (usedMemoKeys.has(k));
    usedMemoKeys.add(k);
    return k;
  };

  // สุ่มลำดับ branch ใน while true (control-flow flattening)
  const order = steps.map((_, idx) => idx);
  for (let i = order.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }

  const branches = order.map((stepIdx) => {
    const curState = states[stepIdx];
    const isLast = stepIdx === steps.length - 1;
    let transition;
    if (isLast) {
      transition = 'break;';
    } else {
      const nextState = states[stepIdx + 1];
      const memoKey = pickMemoKey();
      const i1 = Math.floor(rng() * L.length);
      let i2 = Math.floor(rng() * L.length);
      if (i2 === i1) i2 = (i1 + 1) % L.length;
      const masks = [0xff, 0x3ff, 0x7ff, 0xfff, 0x1fff];
      const mask = masks[Math.floor(rng() * masks.length)];
      const exprVal = (((L[i1] ^ L[i2]) >>> 0) & mask) >>> 0;
      const delta = nextState - exprVal;
      const deltaStr = delta < 0 ? `-${obfNum(-delta)}` : obfNum(delta);
      const mk = obfNum(memoKey);
      cffChecks.push({ curState, nextState, memoKey, i1: i1 + 1, i2: i2 + 1, mask, delta, exprVal });
      transition = `if not R[${mk}]then p=(${deltaStr}+C.x(C.s(L[${obfNum(i1 + 1)}],L[${obfNum(i2 + 1)}]),${obfNum(mask)}));(R)[${mk}]=p;else p=R[${mk}];end;`;
    }
    return { curState, code: `${steps[stepIdx]};${transition}` };
  });

  // ประกอบเป็น if / elseif tree ภายใน while true
  let body = '';
  for (let i = 0; i < branches.length; i++) {
    const b = branches[i];
    const cond = `p==${obfNum(b.curState)}`;
    if (i === 0) body += `if ${cond} then ${b.code}`;
    else if (i === branches.length - 1) body += `else ${b.code}`;
    else body += `elseif ${cond} then ${b.code}`;
  }
  body += 'end;';
  return `p=${obfNum(states[0])};while true do ${body}end;`;
}

function buildOpcodeHandlers(obfNum) {
  const N0 = obfNum(0);
  const N1 = obfNum(1);
  const N2 = obfNum(2);
  const N3 = obfNum(3);

  // ครบทั้ง 20 active opcodes + self-modifying aliases (6->17, 36->87, 45->4, 89->35)
  // + VM introspection + standard Lua opcodes บนช่วง 0..103
  return {
    0: '',
    2: `(GO)[h[EO]]=(GO[l[EO]]+GO[PO[EO]]);`,
    4: `(GO)[PO[EO]]=(N);`,
    5: `EO=(l[EO]);`,
    6: `(N)[EO]=${obfNum(17)};(GO)[h[EO]]=(GO[l[EO]]-GO[PO[EO]]);`,
    10: `(GO)[PO[EO]]=(h);`,
    11: `(GO)[l[EO]]=({});`,
    12: `(GO)[l[EO]]=(g[AO[EO]]);`,
    13: `if GO[l[EO]]then EO=(PO[EO]);end;`,
    14: `(GO)[l[EO]]=(#GO[h[EO]]);`,
    17: `(GO)[h[EO]]=(GO[l[EO]]-GO[PO[EO]]);`,
    18: `(GO)[h[EO]]=C.s(GO[l[EO]],GO[PO[EO]]);`,
    20: `local bO,nA=l[EO],h[EO]-${N1};local ca={};for k=${N1},nA do ca[k]=GO[bO+k];end;local rv=GO[bO](cO(ca,${N1},nA));if PO[EO]>=${N2} then GO[bO]=rv;end;`,
    21: `if GO[l[EO]]==GO[h[EO]]then EO=(PO[EO]);end;`,
    23: `(GO)[PO[EO]]=(GO[l[EO]][GO[h[EO]]]);`,
    25: `local bO=PO[EO];f[#f+${N1}]={vO,RO,E};E=GO[bO+${N2}];RO=GO[bO+${N1}];vO=GO[bO]-E;EO=h[EO];`,
    26: `(GO[PO[EO]])[oO[EO]]=(t[EO]);`,
    32: `(GO)[PO[EO]]=(GO[h[EO]][oO[EO]]);`,
    34: `(GO)[PO[EO]]=(t[EO]);`,
    35: `if GO[PO[EO]]~=oO[EO]then EO=(h[EO]);end;`,
    36: `(N)[EO]=${obfNum(87)};(GO)[PO[EO]]=(GO[l[EO]]<=GO[h[EO]]);`,
    38: `(GO)[PO[EO]]=(GO[h[EO]]/oO[EO]);`,
    40: `(GO[PO[EO]])[GO[l[EO]]]=(t[EO]);`,
    41: `local uv=sO[l[EO]];GO[h[EO]]=uv[${N1}][uv[${N3}]];`,
    42: `(GO)[h[EO]]=(S(GO[l[EO]])..S(GO[PO[EO]]));`,
    43: `if GO[PO[EO]]==oO[EO]then EO=(h[EO]);end;`,
    44: `(GO)[PO[EO]]=(GO[l[EO]]%GO[h[EO]]);`,
    45: `(N)[EO]=${obfNum(4)};(GO)[PO[EO]]=(N);`,
    46: `vO=vO+E;if(E<=${N0} and vO>=RO)or(E>${N0} and vO<=RO)then GO[l[EO]+${N3}]=vO;EO=h[EO];end;`,
    47: `(GO)[PO[EO]]=(GO[h[EO]]);`,
    48: `(GO)[l[EO]]=(GO);`,
    49: `if GO[PO[EO]]~=GO[l[EO]]then EO=(h[EO]);end;`,
    50: `(GO)[PO[EO]]=(GO[h[EO]]*oO[EO]);`,
    51: `if not GO[l[EO]]then EO=(h[EO]);end;`,
    52: `(GO)[l[EO]]=(sO[PO[EO]]);`,
    57: `return;`,
    59: `(GO)[PO[EO]]=(GO[h[EO]]^GO[l[EO]]);`,
    60: `(GO)[PO[EO]]=(GO[l[EO]]-t[EO]);`,
    61: `(GO)[PO[EO]]=(not GO[l[EO]]);`,
    64: `(g)[t[EO]]=(GO[PO[EO]]);`,
    65: `(GO)[l[EO]]=(nO);`,
    67: `(GO)[l[EO]]=(I[h[EO]]);`,
    68: `(GO)[PO[EO]]=(GO[l[EO]]+t[EO]);`,
    69: `return GO[l[EO]];`,
    73: `(I)[l[EO]]=(GO[PO[EO]]);`,
    75: `(GO)[l[EO]]=(-GO[PO[EO]]);`,
    76: `for k=PO[EO],h[EO]do GO[k]=Q;end;`,
    77: `(GO)[PO[EO]]=(S(oO[EO])..S(GO[h[EO]]));`,
    79: `(GO)[h[EO]]=(GO[l[EO]]%AO[EO]);`,
    80: `(GO)[PO[EO]]=(t[EO]^GO[l[EO]]);`,
    81: `(GO)[PO[EO]]=(GO[h[EO]]/GO[l[EO]]);`,
    82: `(GO)[PO[EO]]=Q;`,
    83: `(GO)[PO[EO]]=(S(GO[l[EO]])..S(t[EO]));`,
    85: `(GO[PO[EO]])[oO[EO]]=(GO[h[EO]]);`,
    86: `for k=${N1},l[EO]do GO[k]=u[k];end;`,
    87: `(GO)[PO[EO]]=(GO[l[EO]]<=GO[h[EO]]);`,
    88: `(GO)[h[EO]]=(GO[l[EO]]==GO[PO[EO]]);`,
    89: `(N)[EO]=${obfNum(35)};if GO[PO[EO]]~=oO[EO]then EO=(h[EO]);end;`,
    90: `(GO)[PO[EO]]=y(oO[EO],{});`,
    93: `(GO)[l[EO]]=(l);`,
    94: `(GO[h[EO]])[GO[PO[EO]]]=(GO[l[EO]]);`,
    95: `local uv=sO[h[EO]];uv[${N1}][uv[${N3}]]=GO[PO[EO]];`,
    98: `(GO)[PO[EO]]=WO(h[EO]);`,
    99: `local sT=f[#f];f[#f]=Q;if sT then vO,RO,E=sT[${N1}],sT[${N2}],sT[${N3}];end;`,
    100: `local tb=GO[PO[EO]];GO[h[EO]+${N1}]=tb;GO[h[EO]]=tb[oO[EO]];`,
    101: `(GO)[PO[EO]]=(PO);`,
    102: `(GO)[l[EO]]=(GO[PO[EO]]*GO[h[EO]]);`,
  };
}

function buildBinarySearchDispatch(sortedOps, handlers, rng, obfNum) {
  if (sortedOps.length === 0) return '';
  if (sortedOps.length === 1) {
    return handlers[sortedOps[0]] || '';
  }
  if (sortedOps.length === 2) {
    const [opA, opB] = sortedOps;
    const hA = handlers[opA] || '';
    const hB = handlers[opB] || '';
    if (rng() < 0.5) {
      return `if a==${obfNum(opA)} then ${hA}else ${hB}end;`;
    }
    return `if a~=${obfNum(opB)} then ${hA}else ${hB}end;`;
  }
  const midIdx = Math.floor(sortedOps.length / 2);
  const pivot = sortedOps[midIdx];
  const leftOps = sortedOps.slice(0, midIdx);
  const rightOps = sortedOps.slice(midIdx);
  const leftCode = buildBinarySearchDispatch(leftOps, handlers, rng, obfNum);
  const rightCode = buildBinarySearchDispatch(rightOps, handlers, rng, obfNum);

  const style = rng();
  if (style < 0.34) {
    return `if a<${obfNum(pivot)} then ${leftCode}else ${rightCode}end;`;
  }
  if (style < 0.67) {
    return `if not(a>=${obfNum(pivot)})then ${leftCode}else ${rightCode}end;`;
  }
  return `if a<=${obfNum(pivot - 1)} then ${leftCode}else ${rightCode}end;`;
}

export function generateEncodedLua(
  ascii85Payload,
  { xorKey = 0, style = 'luraph', dialect = 'luau', seed = 0x143a7, returnMeta = false } = {}
) {
  const escaped = ascii85Payload.replace(/\\/g, '\\\\').replace(/"/g, '\\"');

  if (style === 'readable') {
    const code = `-- Encoded with Luraph-Style Reverse Encoder Simulator (Readable Mode)
-- Format: Ascii85 ("LPH-") + LEB128 Biased Chunk + Register-based VM
return (function(PAYLOAD, XOR_KEY, CONST_BIAS, PROTO_BIAS, INST_BIAS)
  local sbyte, schar, ssub, sgsub = string.byte, string.char, string.sub, string.gsub
  local spack, sunpack = string.pack, string.unpack
  local bxor = (bit32 and bit32.bxor) or function(a, b)
    local r, bit = 0, 1
    while a > 0 or b > 0 do
      if (a % 2) ~= (b % 2) then r = r + bit end
      a, b, bit = math.floor(a / 2), math.floor(b / 2), bit * 2
    end
    return r
  end

  local function decode85(str)
    str = sgsub(ssub(str, 5), "z", "!!!!!")
    return sgsub(str, ".....", function(c)
      local a, b, d, e, f = sbyte(c, 1, 5)
      local v = (f-33) + (e-33)*85 + (d-33)*7225 + (b-33)*614125 + (a-33)*52200625
      return spack(">I4", v)
    end)
  end

  local G, pos = decode85(PAYLOAD), 1
  local function rByte() local b = sbyte(G, pos, pos); pos = pos + 1; return b end
  local function rU32() local v, n = sunpack("<I4", G, pos); pos = n; return v end
  local function rI64() local v, n = sunpack("<i8", G, pos); pos = n; return v end
  local function rF64() local v, n = sunpack("<d", G, pos); pos = n; return v end
  local function rVar()
    local r, m = 0, 1
    repeat local b = rByte(); r = r + (b > 127 and b - 128 or b) * m; m = m * 128 until b < 128
    return r
  end
  local function rSVar() local k = rVar(); return k >= 4503599627370496 and (k - 9007199254740992) or k end
  local function rStr(dec)
    local len = rVar(); local raw = ssub(G, pos, pos + len - 1); pos = pos + len
    if not dec or XOR_KEY == 0 then return raw end
    local out = {}
    for i = 1, #raw do out[i] = schar(bxor(sbyte(raw, i), (XOR_KEY + (i - 1) * 17) % 256)) end
    return table.concat(out)
  end

  local numK = rVar() - CONST_BIAS
  local deferred = rByte() ~= 0
  local K = {}
  for i = 1, numK do
    local tag = rByte()
    if tag <= 13 then K[i] = (tag <= 8) and rI64() or rF64()
    elseif tag == 0xE3 then K[i] = (rByte() == 1)
    else K[i] = rStr(deferred) end
  end

  local numP = rVar() - PROTO_BIAS
  local P, patches = {}, {}
  for pid = 1, numP do
    for _ = 1, rU32() do local n = rU32(); if n % 2 ~= 0 then rU32(); rU32() end end
    local maxStack, numParams, numUp = rVar(), rVar(), rVar()
    for _ = 1, numUp do rVar() end
    local nInst = rVar() - INST_BIAS
    local A, B, C, Ak, Bk, Ck, O = {}, {}, {}, {}, {}, {}, {}
    for i = 1, nInst do
      local rA, rB, rC, op = rSVar(), rSVar(), rSVar(), rSVar()
      local mA, mB, mC = rA % 8, rB % 8, rC % 8
      A[i], B[i], C[i], O[i] = (rA - mA)/8, (rB - mB)/8, (rC - mC)/8, op
      if mA == 2 then Ak[i] = K[A[i]] elseif mA == 4 then patches[#patches+1] = {Ak, i, A[i]} end
      if mB == 2 then Bk[i] = K[B[i]] elseif mB == 4 then patches[#patches+1] = {Bk, i, B[i]} end
      if mC == 2 then Ck[i] = K[C[i]] elseif mC == 4 then patches[#patches+1] = {Ck, i, C[i]} end
    end
    P[pid] = { A=A, B=B, C=C, Ak=Ak, Bk=Bk, Ck=Ck, O=O, maxStack=maxStack }
  end
  for i = 1, #patches do patches[i][1][patches[i][2]] = P[patches[i][3]] end
  local entry = P[rVar()]

  local env = _ENV or getfenv()
  local function wrap(pr)
    return function(...)
      local R, args, pc, st = {}, {...}, 1, {}
      local lIt, lLim, lStep = 0, 0, 0
      while pc <= #pr.O do
        local op = pr.O[pc]
        if op == 2 then R[pr.C[pc]] = R[pr.B[pc]] + R[pr.A[pc]]
        elseif op == 5 then pc = pr.B[pc]
        elseif op == 12 then R[pr.B[pc]] = env[pr.Ak[pc]]
        elseif op == 17 then R[pr.C[pc]] = R[pr.B[pc]] - R[pr.A[pc]]
        elseif op == 20 then
          local base, nA = pr.B[pc], pr.C[pc] - 1
          local ca = {}; for i = 1, nA do ca[i] = R[base + i] end
          local res = R[base]((table.unpack or unpack)(ca, 1, nA))
          if pr.A[pc] >= 2 then R[base] = res end
        elseif op == 25 then
          st[#st+1] = {lIt, lLim, lStep}
          lStep, lLim = R[pr.A[pc]+2], R[pr.A[pc]+1]
          lIt = R[pr.A[pc]] - lStep; pc = pr.C[pc]
        elseif op == 34 then R[pr.A[pc]] = pr.Ck[pc]
        elseif op == 42 then R[pr.C[pc]] = tostring(R[pr.B[pc]]) .. tostring(R[pr.A[pc]])
        elseif op == 46 then
          lIt = lIt + lStep
          if (lStep <= 0 and lIt >= lLim) or (lStep > 0 and lIt <= lLim) then
            R[pr.B[pc]+3] = lIt; pc = pr.C[pc]
          end
        elseif op == 47 then R[pr.A[pc]] = R[pr.C[pc]]
        elseif op == 57 then return
        elseif op == 64 then env[pr.Ck[pc]] = R[pr.A[pc]]
        elseif op == 68 then R[pr.A[pc]] = R[pr.B[pc]] + pr.Ck[pc]
        elseif op == 69 then return R[pr.B[pc]]
        elseif op == 86 then for i = 1, pr.B[pc] do R[i] = args[i] end
        elseif op == 88 then R[pr.C[pc]] = (R[pr.B[pc]] == R[pr.A[pc]])
        elseif op == 90 then R[pr.A[pc]] = wrap(pr.Bk[pc])
        elseif op == 99 then local s = table.remove(st); lIt, lLim, lStep = s[1], s[2], s[3]
        elseif op == 102 then R[pr.B[pc]] = R[pr.A[pc]] * R[pr.C[pc]]
        end
        pc = pc + 1
      end
    end
  end
  return wrap(entry)(...)
end)("${escaped}", ${xorKey}, ${FORMAT_CONSTANTS.CONST_COUNT_BIAS}, ${FORMAT_CONSTANTS.PROTO_COUNT_BIAS}, ${FORMAT_CONSTANTS.INST_COUNT_BIAS})
`;
    return returnMeta ? { code, cffChecks: [], opcodeCount: 20, keyTableL: [] } : code;
  }

  // ---- Luraph v14.3-Style Obfuscated Emitter ----
  const rng = createRng(seed);
  const obfNum = makeObfNum(rng, dialect);
  const obfStr = makeObfStr(rng);
  const usedMemoKeys = new Set();
  const cffChecks = [];

  // Key table L (9 32-bit constants คล้าย L ใน loader.lua_5e4ba8d7.txt)
  const L = Array.from({ length: 9 }, () => Math.floor(rng() * 0x7fffffff) + 1024);

  const handlers = buildOpcodeHandlers(obfNum);
  const sortedOps = Object.keys(handlers)
    .map(Number)
    .sort((a, b) => a - b);
  const dispatchTree = buildBinarySearchDispatch(sortedOps, handlers, rng, obfNum);

  // CFF Block 1: Bootstrapper & Ascii85 Decoder + Binary Stream Readers
  const cffBootstrap = buildCFFBlock(
    [
      `z=C.m;E=C.A;WO=C.t;I={};R={}`,
      `local d85=function(k)k=s(q(k,${obfNum(5)}),${obfStr('z')},${obfStr('!!!!!')});return s(k,${obfStr('.....')},function(c)local a1,a2,a3,a4,a5=z(c,${obfNum(1)},${obfNum(5)});return C.i(${obfStr('>I4')},(a5-${obfNum(33)})+(a4-${obfNum(33)})*${obfNum(85)}+(a3-${obfNum(33)})*${obfNum(7225)}+(a2-${obfNum(33)})*${obfNum(614125)}+(a1-${obfNum(33)})*${obfNum(52200625)});end);end;HO=function(st)G=st;_=${obfNum(1)};end;HO(d85(mO))`,
      `VO=function()local b=z(G,_,_);_=_+DO;return b;end;W=function()local v,n=E(${obfStr('<I4')},G,_);_=n;return v;end`,
      `ZO=function()local v,n=E(H,G,_);_=n;return v;end;x=function()local v,n=E(${obfStr('<d')},G,_);_=n;return v;end`,
      `e=function()local m,k=${obfNum(0)},${obfNum(1)};repeat local b=VO();m=m+(b>${obfNum(127)} and b-${obfNum(128)} or b)*k;k=k*${obfNum(128)};until b<${obfNum(128)};return m;end`,
      `gO=function()local k=e();if k>=${obfNum(FORMAT_CONSTANTS.SIGNED_THRESHOLD)} then return k-P;end;return k;end;iO=function()local k=e();_=_+k;return q(G,_-k,_-DO);end`,
    ],
    L,
    rng,
    obfNum,
    usedMemoKeys,
    cffChecks
  );

  // Prototype Deserializer s() (ตรงกับ slot mapping qO[1..11] ของ loader.lua)
  const protoDeserializer =
    `sO_fn=function()` +
    `local qO={Q,Q,Q,Q,Q,Q,Q,Q,Q,Q,Q};local LO={};qO[${obfNum(10)}]=LO;local lP=${obfNum(1)};` +
    `for _i=${obfNum(1)},W()do local n=W();local hf=n/${obfNum(2)};` +
    `if n%${obfNum(2)}~=${obfNum(0)} then local en=W();local ln=W();for k=hf-hf%DO,en do LO[k]=ln;end;lP=en;else LO[lP]=hf-hf%DO;end;lP=lP+DO;end;` +
    `qO[${obfNum(4)}]=e();qO[${obfNum(7)}]=e();local nU=e();local uT=WO(nU);` +
    `for _i=${obfNum(1)},nU do local u=e();local k=u/b;uT[_i]={[${obfNum(3)}]=k-k%DO,[${obfNum(1)}]=u%b};end;qO[${obfNum(5)}]=uT;` +
    `local S=e()-${obfNum(FORMAT_CONSTANTS.INST_COUNT_BIAS)};` +
    `local Gc,Pr,Bt,Mt,cT,Ba,Op=WO(S),WO(S),WO(S),WO(S),WO(S),WO(S),WO(S);` +
    `qO[${obfNum(1)}]=Pr;qO[${obfNum(2)}]=Mt;qO[${obfNum(3)}]=Bt;qO[${obfNum(6)}]=Ba;qO[${obfNum(8)}]=cT;qO[${obfNum(9)}]=Op;qO[fO]=Gc;` +
    `for idx=${obfNum(1)},S do local g1,g2,g3,op=gO(),gO(),gO(),gO();` +
    `local m1,m2,m3=g1%${obfNum(8)},g2%${obfNum(8)},g3%${obfNum(8)};` +
    `local v1,v2,v3=(g1-m1)/${obfNum(8)},(g2-m2)/${obfNum(8)},(g3-m3)/${obfNum(8)};` +
    `cT[idx]=v1;Mt[idx]=v2;Gc[idx]=v3;Op[idx]=op;` +
    `if m1==c then if rO then local h=_O[v1];local n=#h;h[n+DO]=qO;h[n+${obfNum(2)}]=idx;h[n+${obfNum(3)}]=${obfNum(6)};else Ba[idx]=_O[v1];end;` +
    `elseif m1==b then local n=#v;v[n+DO]=Ba;v[n+${obfNum(2)}]=idx;v[n+${obfNum(3)}]=v1;end;` +
    `if m2==c then if rO then local h=_O[v2];local n=#h;h[n+DO]=qO;h[n+${obfNum(2)}]=idx;h[n+${obfNum(3)}]=${obfNum(3)};else Bt[idx]=_O[v2];end;` +
    `elseif m2==b then local n=#v;v[n+DO]=Bt;v[n+${obfNum(2)}]=idx;v[n+${obfNum(3)}]=v2;end;` +
    `if m3==c then if rO then local h=_O[v3];local n=#h;h[n+DO]=qO;h[n+${obfNum(2)}]=idx;h[n+${obfNum(3)}]=DO;else Pr[idx]=_O[v3];end;` +
    `elseif m3==b then local n=#v;v[n+DO]=Pr;v[n+${obfNum(2)}]=idx;v[n+${obfNum(3)}]=v3;end;` +
    `end;return qO;end;`;

  // CFF Block 2: Chunk Deserializer FO()
  const cffDeserialize = buildCFFBlock(
    [
      `nK=e()-${obfNum(FORMAT_CONSTANTS.CONST_COUNT_BIAS)};_O=WO(nK);rO=(VO()~=kO)`,
      `for idx=DO,nK do local tg=VO();local vl;if tg<=${obfNum(13)} then if tg<=${obfNum(8)} then vl=ZO();else vl=x();end;elseif tg==A then vl=(VO()==DO);else vl=iO();end;if rO then _O[idx]={[kO]=vl};else _O[idx]=vl;end;end`,
      `nP=e()-${obfNum(FORMAT_CONSTANTS.PROTO_COUNT_BIAS)};aP=WO(nP);v={};for idx=DO,nP do aP[idx]=sO_fn();end`,
      `for idx=DO,#v,${obfNum(3)} do v[idx][v[idx+DO]]=aP[v[idx+c]];end;if rO then I[c]=_O;I[${obfNum(3)}]=aP;end;enP=aP[e()];_O=Q;v=Q`,
    ],
    L,
    rng,
    obfNum,
    usedMemoKeys,
    cffChecks
  );

  // VM Interpreter y(nO, sO) พร้อม 7-level balanced binary search dispatch tree
  const vmClosure =
    `y=function(nO,sO)` +
    `local qS=nO[${obfNum(4)}];` +
    `local LO,oO,h,N,PO,AO,t,l=nO[${obfNum(10)}],nO[${obfNum(3)}],nO[fO],nO[${obfNum(9)}],nO[${obfNum(8)}],nO[${obfNum(6)}],nO[DO],nO[c];` +
    `return(function(...)` +
    `local GO,u,EO,g,f=WO(qS),{...},DO,Y(),{};local vO,RO,E=kO,kO,kO;` +
    `while EO<=#N do local a=(N[EO]);${dispatchTree}EO=EO+DO;end;` +
    `end);end;`;

  // CFF Block 3: Stage-1-Style Deferred Constant Decryption & Final Launch
  const cffLaunch = buildCFFBlock(
    [
      `k=FO()`,
      `if I[c]then local dT=I[c];for idx=DO,#dT do local ent=dT[idx];local vl=ent[kO];` +
        `if type(vl)==${obfStr('string')} and xK~=kO then local bf={};for jx=DO,#vl do bf[jx]=C.J(C.s(z(vl,jx),(xK+(jx-DO)*${obfNum(17)})%${obfNum(256)}));end;vl=B.concat(bf);end;` +
        `for jx=DO,#ent,${obfNum(3)} do ent[jx][ent[jx+c]][ent[jx+DO]]=vl;end;end;I[c]=Q;end`,
      `resFn=y(k,U)`,
    ],
    L,
    rng,
    obfNum,
    usedMemoKeys,
    cffChecks
  );

  // Bit32 / table.create fallback expression inside injected C table (ทำงานได้ทั้ง Luau และ Lua 5.3/5.4)
  const cTableExpr =
    dialect === 'luau'
      ? `{g=bit32.rrotate,A=string.unpack,l=bit32.bnot,j=bit32.countrz,x=bit32.band,D=setmetatable,f=bit32.lrotate,i=string.pack,u=bit32.lshift,a=bit32.bor,m=string.byte,r=bit32.countlz,q=bit32.rshift,J=string.char,s=bit32.bxor,t=table.create}`
      : `(function()local b3=bit32 or{bxor=function(a,b)local r,m=0,1;while a>0 or b>0 do if(a%2)~=(b%2)then r=r+m end;a,b,m=math.floor(a/2),math.floor(b/2),m*2 end;return r end,band=function(a,b)local r,m=0,1;while a>0 and b>0 do if(a%2)==1 and(b%2)==1 then r=r+m end;a,b,m=math.floor(a/2),math.floor(b/2),m*2 end;return r end};return{A=string.unpack,x=b3.band,i=string.pack,m=string.byte,J=string.char,s=b3.bxor,t=table.create or function()return{}end}end)()`;

  const envExpr = dialect === 'luau' ? `getfenv` : `(getfenv or function()return _ENV end)`;
  const unpackExpr = dialect === 'luau' ? `unpack` : `(table.unpack or unpack)`;
  const keyTableExpr = `{${L.map((v) => obfNum(v)).join(',')}}`;

  const body =
    `local z,E,WO,I,R,G,_,HO,VO,W,ZO,x,e,gO,iO,sO_fn,FO,y,rO,_O,v,k,resFn,p;` +
    cffBootstrap +
    protoDeserializer +
    `FO=function()local nK,nP,aP,enP,p;${cffDeserialize}return enP;end;` +
    vmClosure +
    cffLaunch +
    `return resFn;`;

  const code =
    `-- This file was encoded using Luraph-Style Reverse Encoder Simulator (v14.3 Format)\n` +
    `return(function(A,P,DO,H,Q,Y,s,kO,c,b,S,cO,fO,C,q,B,U,L,mO,xK)${body}end)(` +
    `${obfNum(FORMAT_CONSTANTS.TAG_BOOL)},${FORMAT_CONSTANTS.SIGNED_MODULUS},${obfNum(1)},${obfStr('<i8')},nil,${envExpr},string.gsub,${obfNum(0)},${obfNum(2)},${obfNum(4)},tostring,${unpackExpr},${obfNum(11)},${cTableExpr},string.sub,table,{},${keyTableExpr},"${escaped}",${obfNum(xorKey)})(...);\n`;

  return returnMeta ? { code, cffChecks, opcodeCount: sortedOps.length, keyTableL: L } : code;
}

// =============================================================================
// 8. CLI Entry Point
// =============================================================================
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  const args = process.argv.slice(2).filter((a) => !a.startsWith('--'));
  const xorArg = process.argv.find((a) => a.startsWith('--xor-key='));
  const styleArg = process.argv.find((a) => a.startsWith('--style='));
  const dialectArg = process.argv.find((a) => a.startsWith('--dialect='));
  const seedArg = process.argv.find((a) => a.startsWith('--seed='));
  const readableFlag = process.argv.includes('--readable');

  const xorKey = xorArg ? Number(xorArg.split('=')[1]) : 0x5a;
  const style = readableFlag ? 'readable' : styleArg ? styleArg.split('=')[1] : 'luraph';
  const dialect = dialectArg ? dialectArg.split('=')[1] : 'luau';
  const seed = seedArg ? Number(seedArg.split('=')[1]) : 0x143a7;

  const inputPath = args[0] || 'input.lua';
  const outputPath = args[1] || 'output_encoded.lua';

  const source = fs.readFileSync(inputPath, 'utf8');
  const chunk = compileLuaToChunk(source);
  const binary = serializeChunk(chunk, { xorKey });
  const ascii85 = encodeAscii85(binary);
  const { code: encodedLua, cffChecks, opcodeCount } = generateEncodedLua(ascii85, {
    xorKey,
    style,
    dialect,
    seed,
    returnMeta: true,
  });

  fs.writeFileSync(outputPath, encodedLua, 'utf8');
  console.log(`[encoder.mjs] Encoded "${inputPath}" -> "${outputPath}"`);
  console.log(`  Style     : ${style} (dialect=${dialect}, seed=0x${seed.toString(16).toUpperCase()})`);
  console.log(`  Constants : ${chunk.consts.length}`);
  console.log(`  Prototypes: ${chunk.protos.length} (entry=#${chunk.entryIdx})`);
  console.log(`  Binary    : ${binary.length} bytes -> Ascii85 ${ascii85.length} chars`);
  console.log(`  VM Tree   : ${opcodeCount} opcodes (balanced binary-search dispatch)`);
  console.log(`  CFF States: ${cffChecks.length} memoized bit32 transitions`);
  console.log(`  XOR Key   : 0x${xorKey.toString(16).toUpperCase()} (deferred=${xorKey !== 0})`);
}

