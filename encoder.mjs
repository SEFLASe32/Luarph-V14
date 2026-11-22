#!/usr/bin/env node
/**
 * encoder.mjs
 * -----------------------------------------------------------------------------
 * จำลองอัลกอริทึมการเข้ารหัสแบบย้อนกลับ (Reverse Encoding Simulator)
 * ตามโครงสร้างที่วิเคราะห์ได้จาก Luraph v14.3 (loader.lua_5e4ba8d7.txt):
 *
 *   1. Lua-to-VM Compiler: รองรับ local, function, if/elseif/else, for, while,
 *      repeat..until, tables ({}, t.k, t[i]), arithmetic (+ - * / % ^),
 *      unary (-, not, #), concat (..), comparisons (== ~= < <= > >=), and/or, return
 *   2. Binary Serializer: เข้ารหัส Chunk ด้วยรูปแบบเดียวกับไฟล์ต้นฉบับ:
 *      - Constant count biased ด้วย +0x12074 (73844) แบบ Unsigned LEB128
 *      - Deferred flag byte (รองรับ XOR string encryption mode + I[2]/I[3] patching)
 *      - Constant tags: <=8 (int64 <i8), 9..13 (float64 <d), 0xE3 (bool), 0xE6 (str)
 *      - Prototype count biased ด้วย +0xE81A (59418), RLE Line info (uint32 LE)
 *      - Instruction count biased ด้วย +39325
 *      - แต่ละคำสั่ง: 3 Signed 53-bit LEB128 operands (`val * 8 + mode`) + opcode
 *   3. Ascii85 (Base85) Encoder ("LPH-" header + 'z' compression + >I4 chunks)
 *   4. Luraph v14.3-Style Obfuscated Lua Emitter:
 *      - Wrapper Argument Injection (ส่ง stdlib, bit32 table C, key table L)
 *      - Control-Flow Flattening (CFF) ด้วยลูป while true + state p + memoized R + bit32
 *      - Number & String Literal Obfuscation (0X..., 0B..., underscores, \ddd, \xHH, \u{}, \z)
 *      - Full 104-Opcode (0..103) 7-Level Balanced Binary-Search if/else VM Dispatch Tree
 * -----------------------------------------------------------------------------
 * วิธีใช้:
 *   node encoder.mjs [input.lua] [output_encoded.lua]
 *                    [--xor-key=0x5A] [--dialect=luau|lua53] [--seed=0x143A7] [--readable]
 */

import fs from 'node:fs';
import path from 'node:path';

// =============================================================================
// 1. Constants (ตรงกับค่าที่แกะได้จาก Static Analysis ของ loader.lua)
// =============================================================================
export const FORMAT_CONSTANTS = {
  HEADER_MAGIC: 'LPH-',
  CONST_COUNT_BIAS: 0x12074, // 73844
  PROTO_COUNT_BIAS: 0xe81a, // 59418
  INST_COUNT_BIAS: 39325,
  TAG_INT64: 8, // <= 8
  TAG_FLOAT64: 13, // 9..13
  TAG_BOOL: 0xe3, // 227
  TAG_STRING: 0xe6, // 230
  SIGNED_THRESHOLD: 4503599627370496, // 2^52
  SIGNED_MODULUS: 9007199254740992, // 2^53
};

// Opcode map ที่ตรงกับเลข Opcode ใน loader.lua_5e4ba8d7.txt
export const OP = {
  NOP: 0,
  ADD: 2, // R[C] = R[B] + R[A]
  JMP: 5, // pc = B
  NEWTABLE: 11, // R[B] = {}
  GETGLOBAL: 12, // R[B] = env[A_const]
  LEN: 14, // R[B] = #R[C]
  SUB: 17, // R[C] = R[B] - R[A]
  CALL: 20, // R[B].. = R[B](R[B+1]..R[B+C-1]), A = nRets+1
  GETTABLE: 23, // R[A] = R[B][R[C]]
  FORPREP: 25, // init numeric for loop at R[A], jump C
  GETTABLE_K: 32, // R[A] = R[C][B_const]
  LOADK: 34, // R[A] = C_const
  CONCAT: 42, // R[C] = R[B] .. R[A]
  MOD: 44, // R[A] = R[B] % R[C]
  FORLOOP: 46, // step numeric for loop, store R[B+3], jump C
  MOVE: 47, // R[A] = R[C]
  TEST_FALSE: 51, // if not R[B] then pc = C end
  RETURN0: 57, // return
  LT: 58, // R[A] = (R[B] < R[C])
  POW: 59, // R[A] = R[C] ^ R[B]
  NOT: 61, // R[A] = not R[B]
  SETGLOBAL: 64, // env[C_const] = R[A]
  ADDK: 68, // R[A] = R[B] + C_const
  RETURN1: 69, // return R[B]
  UNM: 75, // R[B] = -R[A]
  DIV: 81, // R[A] = R[C] / R[B]
  LOADNIL: 82, // R[A] = nil
  SETTABLE_KR: 85, // R[A][B_const] = R[C]
  LOADARGS: 86, // for i=1..B do R[i] = args[i]
  LE: 87, // R[A] = (R[B] <= R[C])
  EQ: 88, // R[C] = (R[B] == R[A])
  CLOSURE: 90, // R[A] = closure(B_const)
  SETTABLE: 94, // R[C][R[A]] = R[B]
  LOOP_POP: 99, // pop loop frame
  MUL: 102, // R[B] = R[A] * R[C]
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

  w.writeVarint(chunk.protos.length + FORMAT_CONSTANTS.PROTO_COUNT_BIAS);
  for (const p of chunk.protos) {
    w.writeUInt32(p.insts.length);
    for (let i = 0; i < p.insts.length; i++) {
      const line = p.insts[i].line || 1;
      w.writeUInt32(line * 2);
    }

    w.writeVarint(p.maxStack);
    w.writeVarint(p.numParams);

    const upvals = p.upvals || [];
    w.writeVarint(upvals.length);
    for (const uv of upvals) {
      w.writeVarint(uv.idx * 4 + uv.kind);
    }

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

  w.writeVarint(chunk.entryIdx);
  return w.toBuffer();
}

export function deserializeChunk(buf, { xorKey = 0 } = {}) {
  let pos = 0;
  const readByte = () => {
    if (pos >= buf.length) throw new Error('Unexpected EOF while deserializing chunk');
    return buf[pos++];
  };
  const readU32 = () => {
    const v = buf.readUInt32LE(pos);
    pos += 4;
    return v;
  };
  const readI64 = () => {
    const v = buf.readBigInt64LE(pos);
    pos += 8;
    return Number(v);
  };
  const readF64 = () => {
    const v = buf.readDoubleLE(pos);
    pos += 8;
    return v;
  };
  const readVarint = () => {
    let res = 0;
    let mul = 1;
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
        A,
        modeA,
        Ak: modeA === MODE.CONST ? consts[A] : undefined,
        B,
        modeB,
        Bk: modeB === MODE.CONST ? consts[B] : undefined,
        C,
        modeC,
        Ck: modeC === MODE.CONST ? consts[C] : undefined,
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
// 5. Expanded Lua-to-Luraph-VM Compiler
//    รองรับ: local, function, if/elseif/else, for, while, repeat..until, tables,
//    arithmetic (+ - * / % ^), unary (- not #), concat (..), comparisons, and/or
// =============================================================================
export function compileLuaToChunk(luaSource) {
  const consts = [];
  const constMap = new Map();
  const addConst = (val) => {
    const key = `${typeof val}:${String(val)}`;
    if (constMap.has(key)) return constMap.get(key);
    consts.push(val);
    const idx = consts.length;
    constMap.set(key, idx);
    return idx;
  };

  const KEYWORDS = new Set([
    'local',
    'function',
    'for',
    'while',
    'repeat',
    'until',
    'if',
    'then',
    'elseif',
    'else',
    'do',
    'end',
    'return',
    'true',
    'false',
    'nil',
    'not',
    'and',
    'or',
  ]);

  const tokenize = (src) => {
    const tokens = [];
    let i = 0;
    let line = 1;
    while (i < src.length) {
      const ch = src[i];
      if (ch === '\n') {
        line++;
        i++;
        continue;
      }
      if (/\s/.test(ch)) {
        i++;
        continue;
      }
      if (ch === '-' && src[i + 1] === '-') {
        while (i < src.length && src[i] !== '\n') i++;
        continue;
      }
      if (ch === '"' || ch === "'") {
        const quote = ch;
        i++;
        let s = '';
        while (i < src.length && src[i] !== quote) {
          if (src[i] === '\\') {
            i++;
            if (src[i] === 'n') s += '\n';
            else if (src[i] === 't') s += '\t';
            else if (src[i] === 'r') s += '\r';
            else s += src[i];
          } else {
            s += src[i];
          }
          i++;
        }
        i++;
        tokens.push({ type: 'STR', val: s, line });
        continue;
      }
      if (/[0-9]/.test(ch)) {
        let num = '';
        if (ch === '0' && (src[i + 1] === 'x' || src[i + 1] === 'X')) {
          num = src.slice(i, i + 2);
          i += 2;
          while (i < src.length && /[0-9a-fA-F]/.test(src[i])) num += src[i++];
          tokens.push({ type: 'NUM', val: Number.parseInt(num.slice(2), 16), line });
          continue;
        }
        while (i < src.length && /[0-9.]/.test(src[i])) num += src[i++];
        tokens.push({ type: 'NUM', val: Number(num), line });
        continue;
      }
      if (/[A-Za-z_]/.test(ch)) {
        let id = '';
        while (i < src.length && /[A-Za-z0-9_]/.test(src[i])) id += src[i++];
        tokens.push({ type: KEYWORDS.has(id) ? 'KW' : 'ID', val: id, line });
        continue;
      }
      const two = src.slice(i, i + 2);
      if (['..', '==', '~=', '<=', '>='].includes(two)) {
        tokens.push({ type: 'OP', val: two, line });
        i += 2;
        continue;
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
      insts.push({
        op: OP.LOADARGS,
        A: 0,
        modeA: 0,
        B: params.length,
        modeB: MODE.REG,
        C: 0,
        modeC: 0,
        line: 1,
      });
      for (const p of params) locals.set(p, allocReg());
    }

    const emit = (inst) => {
      insts.push(inst);
      return insts.length;
    };

    function compileExpr(targetReg) {
      return compileOr(targetReg);
    }

    function compileOr(targetReg) {
      let left = compileAnd(targetReg);
      while (peek().type === 'KW' && peek().val === 'or') {
        const opTok = next();
        const dest = targetReg ?? allocReg();
        if (left !== dest) {
          emit({ op: OP.MOVE, A: dest, modeA: MODE.REG, B: 0, modeB: 0, C: left, modeC: MODE.REG, line: opTok.line });
        }
        // if dest is truthy, skip RHS
        const notReg = allocReg();
        emit({ op: OP.NOT, A: notReg, modeA: MODE.REG, B: dest, modeB: MODE.REG, C: 0, modeC: 0, line: opTok.line });
        const skipRhs = emit({ op: OP.TEST_FALSE, A: 0, modeA: 0, B: notReg, modeB: MODE.REG, C: 0, modeC: MODE.REG, line: opTok.line });
        compileAnd(dest);
        insts[skipRhs - 1].C = insts.length;
        left = dest;
      }
      return left;
    }

    function compileAnd(targetReg) {
      let left = compileCompare(targetReg);
      while (peek().type === 'KW' && peek().val === 'and') {
        const opTok = next();
        const dest = targetReg ?? allocReg();
        if (left !== dest) {
          emit({ op: OP.MOVE, A: dest, modeA: MODE.REG, B: 0, modeB: 0, C: left, modeC: MODE.REG, line: opTok.line });
        }
        const skipRhs = emit({ op: OP.TEST_FALSE, A: 0, modeA: 0, B: dest, modeB: MODE.REG, C: 0, modeC: MODE.REG, line: opTok.line });
        compileCompare(dest);
        insts[skipRhs - 1].C = insts.length;
        left = dest;
      }
      return left;
    }

    function compileCompare(targetReg) {
      let left = compileConcat(targetReg);
      while (
        (peek().type === 'OP' && ['==', '~=', '<=', '>='].includes(peek().val)) ||
        (peek().type === 'SYM' && (peek().val === '<' || peek().val === '>'))
      ) {
        const opTok = next();
        const right = compileConcat(allocReg());
        const dest = targetReg ?? allocReg();
        if (opTok.val === '==') {
          emit({ op: OP.EQ, A: right, modeA: MODE.REG, B: left, modeB: MODE.REG, C: dest, modeC: MODE.REG, line: opTok.line });
        } else if (opTok.val === '~=') {
          emit({ op: OP.EQ, A: right, modeA: MODE.REG, B: left, modeB: MODE.REG, C: dest, modeC: MODE.REG, line: opTok.line });
          emit({ op: OP.NOT, A: dest, modeA: MODE.REG, B: dest, modeB: MODE.REG, C: 0, modeC: 0, line: opTok.line });
        } else if (opTok.val === '<') {
          emit({ op: OP.LT, A: dest, modeA: MODE.REG, B: left, modeB: MODE.REG, C: right, modeC: MODE.REG, line: opTok.line });
        } else if (opTok.val === '>') {
          emit({ op: OP.LT, A: dest, modeA: MODE.REG, B: right, modeB: MODE.REG, C: left, modeC: MODE.REG, line: opTok.line });
        } else if (opTok.val === '<=') {
          emit({ op: OP.LE, A: dest, modeA: MODE.REG, B: left, modeB: MODE.REG, C: right, modeC: MODE.REG, line: opTok.line });
        } else if (opTok.val === '>=') {
          emit({ op: OP.LE, A: dest, modeA: MODE.REG, B: right, modeB: MODE.REG, C: left, modeC: MODE.REG, line: opTok.line });
        }
        left = dest;
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
      let left = compileMulDivMod(targetReg);
      while (peek().type === 'SYM' && (peek().val === '+' || peek().val === '-')) {
        const opTok = next();
        const right = compileMulDivMod(allocReg());
        const dest = targetReg ?? allocReg();
        emit({
          op: opTok.val === '+' ? OP.ADD : OP.SUB,
          A: right,
          modeA: MODE.REG,
          B: left,
          modeB: MODE.REG,
          C: dest,
          modeC: MODE.REG,
          line: opTok.line,
        });
        left = dest;
      }
      return left;
    }

    function compileMulDivMod(targetReg) {
      let left = compileUnary(targetReg);
      while (peek().type === 'SYM' && (peek().val === '*' || peek().val === '/' || peek().val === '%')) {
        const opTok = next();
        const right = compileUnary(allocReg());
        const dest = targetReg ?? allocReg();
        if (opTok.val === '*') {
          emit({ op: OP.MUL, A: left, modeA: MODE.REG, B: dest, modeB: MODE.REG, C: right, modeC: MODE.REG, line: opTok.line });
        } else if (opTok.val === '/') {
          // DIV: R[A] = R[C] / R[B]
          emit({ op: OP.DIV, A: dest, modeA: MODE.REG, B: right, modeB: MODE.REG, C: left, modeC: MODE.REG, line: opTok.line });
        } else {
          // MOD: R[A] = R[B] % R[C]
          emit({ op: OP.MOD, A: dest, modeA: MODE.REG, B: left, modeB: MODE.REG, C: right, modeC: MODE.REG, line: opTok.line });
        }
        left = dest;
      }
      return left;
    }

    function compileUnary(targetReg) {
      const t = peek();
      if (t.type === 'SYM' && t.val === '-') {
        next();
        const operand = compileUnary(allocReg());
        const dest = targetReg ?? allocReg();
        emit({ op: OP.UNM, A: operand, modeA: MODE.REG, B: dest, modeB: MODE.REG, C: 0, modeC: 0, line: t.line });
        return dest;
      }
      if (t.type === 'KW' && t.val === 'not') {
        next();
        const operand = compileUnary(allocReg());
        const dest = targetReg ?? allocReg();
        emit({ op: OP.NOT, A: dest, modeA: MODE.REG, B: operand, modeB: MODE.REG, C: 0, modeC: 0, line: t.line });
        return dest;
      }
      if (t.type === 'SYM' && t.val === '#') {
        next();
        const operand = compileUnary(allocReg());
        const dest = targetReg ?? allocReg();
        emit({ op: OP.LEN, A: 0, modeA: 0, B: dest, modeB: MODE.REG, C: operand, modeC: MODE.REG, line: t.line });
        return dest;
      }
      return compilePow(targetReg);
    }

    function compilePow(targetReg) {
      const left = compilePrimary(targetReg);
      if (peek().type === 'SYM' && peek().val === '^') {
        const opTok = next();
        const right = compileUnary(allocReg());
        const dest = targetReg ?? allocReg();
        // POW: R[A] = R[C] ^ R[B]
        emit({ op: OP.POW, A: dest, modeA: MODE.REG, B: right, modeB: MODE.REG, C: left, modeC: MODE.REG, line: opTok.line });
        return dest;
      }
      return left;
    }

    function compilePostfix(reg, targetReg, startLine) {
      let cur = reg;
      while (true) {
        if (peek().type === 'SYM' && peek().val === '.') {
          next();
          const fieldTok = next();
          const kIdx = addConst(fieldTok.val);
          const nextRegOut = allocReg();
          // GETTABLE_K: R[A] = R[C][B_const]
          emit({ op: OP.GETTABLE_K, A: nextRegOut, modeA: MODE.REG, B: kIdx, modeB: MODE.CONST, C: cur, modeC: MODE.REG, line: fieldTok.line });
          cur = nextRegOut;
        } else if (peek().type === 'SYM' && peek().val === '[') {
          const lb = next();
          const keyReg = compileExpr(allocReg());
          expect(']');
          const nextRegOut = allocReg();
          // GETTABLE: R[A] = R[B][R[C]]
          emit({ op: OP.GETTABLE, A: nextRegOut, modeA: MODE.REG, B: cur, modeB: MODE.REG, C: keyReg, modeC: MODE.REG, line: lb.line });
          cur = nextRegOut;
        } else if (peek().type === 'SYM' && peek().val === '(') {
          next();
          const argRegs = [];
          if (!(peek().type === 'SYM' && peek().val === ')')) {
            while (true) {
              argRegs.push(compileExpr(allocReg()));
              if (peek().type === 'SYM' && peek().val === ',') next();
              else break;
            }
          }
          expect(')');
          const callBase = allocReg();
          emit({ op: OP.MOVE, A: callBase, modeA: MODE.REG, B: 0, modeB: 0, C: cur, modeC: MODE.REG, line: startLine });
          for (let ai = 0; ai < argRegs.length; ai++) {
            const slot = allocReg();
            emit({ op: OP.MOVE, A: slot, modeA: MODE.REG, B: 0, modeB: 0, C: argRegs[ai], modeC: MODE.REG, line: startLine });
          }
          emit({ op: OP.CALL, A: 2, modeA: MODE.REG, B: callBase, modeB: MODE.REG, C: argRegs.length + 1, modeC: MODE.REG, line: startLine });
          cur = callBase;
        } else {
          break;
        }
      }
      if (targetReg !== undefined && targetReg !== cur) {
        emit({ op: OP.MOVE, A: targetReg, modeA: MODE.REG, B: 0, modeB: 0, C: cur, modeC: MODE.REG, line: startLine });
        return targetReg;
      }
      return cur;
    }

    function compilePrimary(targetReg) {
      const t = peek();
      if (t.type === 'SYM' && t.val === '(') {
        next();
        const r = compileExpr(allocReg());
        expect(')');
        return compilePostfix(r, targetReg, t.line);
      }
      if (t.type === 'SYM' && t.val === '{') {
        next();
        const tblReg = targetReg ?? allocReg();
        emit({ op: OP.NEWTABLE, A: 0, modeA: 0, B: tblReg, modeB: MODE.REG, C: 0, modeC: 0, line: t.line });
        let arrIdx = 1;
        while (!(peek().type === 'SYM' && peek().val === '}')) {
          if (peek().type === 'ID' && peek(1).type === 'SYM' && peek(1).val === '=') {
            const kTok = next();
            expect('=');
            const valReg = compileExpr(allocReg());
            const kIdx = addConst(kTok.val);
            // SETTABLE_KR: R[A][B_const] = R[C]
            emit({ op: OP.SETTABLE_KR, A: tblReg, modeA: MODE.REG, B: kIdx, modeB: MODE.CONST, C: valReg, modeC: MODE.REG, line: kTok.line });
          } else if (peek().type === 'SYM' && peek().val === '[') {
            next();
            const keyReg = compileExpr(allocReg());
            expect(']');
            expect('=');
            const valReg = compileExpr(allocReg());
            // SETTABLE: R[C][R[A]] = R[B]
            emit({ op: OP.SETTABLE, A: keyReg, modeA: MODE.REG, B: valReg, modeB: MODE.REG, C: tblReg, modeC: MODE.REG, line: t.line });
          } else {
            const valReg = compileExpr(allocReg());
            const idxReg = allocReg();
            const kIdx = addConst(arrIdx++);
            emit({ op: OP.LOADK, A: idxReg, modeA: MODE.REG, B: 0, modeB: 0, C: kIdx, modeC: MODE.CONST, line: t.line });
            emit({ op: OP.SETTABLE, A: idxReg, modeA: MODE.REG, B: valReg, modeB: MODE.REG, C: tblReg, modeC: MODE.REG, line: t.line });
          }
          if (peek().type === 'SYM' && (peek().val === ',' || peek().val === ';')) next();
          else break;
        }
        expect('}');
        return tblReg;
      }
      if (t.type === 'KW' && t.val === 'nil') {
        next();
        const dest = targetReg ?? allocReg();
        emit({ op: OP.LOADNIL, A: dest, modeA: MODE.REG, B: 0, modeB: 0, C: 0, modeC: 0, line: t.line });
        return dest;
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
          reg = locals.get(t.val);
        } else {
          const dest = allocReg();
          const kIdx = addConst(t.val);
          emit({ op: OP.GETGLOBAL, A: kIdx, modeA: MODE.CONST, B: dest, modeB: MODE.REG, C: 0, modeC: 0, line: t.line });
          reg = dest;
        }
        return compilePostfix(reg, targetReg, t.line);
      }
      throw new SyntaxError(`Line ${t.line}: unexpected token '${t.val}'`);
    }

    function compileStatementsUntil(stopSet) {
      while (peek().type !== 'EOF') {
        if (peek().type === 'KW' && stopSet.has(peek().val)) break;
        compileStatement();
      }
    }

    function compileStatement() {
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
          const varReg = allocReg();
          if (peek().type === 'SYM' && peek().val === '=') {
            next();
            compileExpr(varReg);
          } else {
            emit({ op: OP.LOADNIL, A: varReg, modeA: MODE.REG, B: 0, modeB: 0, C: 0, modeC: 0, line: nameTok.line });
          }
          locals.set(nameTok.val, varReg);
        }
      } else if (t.type === 'KW' && t.val === 'if') {
        next();
        const exitJumps = [];
        const condReg = compileExpr(allocReg());
        expect('then');
        let jFalse = emit({ op: OP.TEST_FALSE, A: 0, modeA: 0, B: condReg, modeB: MODE.REG, C: 0, modeC: MODE.REG, line: t.line });
        compileStatementsUntil(new Set(['elseif', 'else', 'end']));

        while (peek().type === 'KW' && peek().val === 'elseif') {
          const eiTok = next();
          exitJumps.push(emit({ op: OP.JMP, A: 0, modeA: 0, B: 0, modeB: MODE.REG, C: 0, modeC: 0, line: eiTok.line }));
          insts[jFalse - 1].C = insts.length;
          const eiCond = compileExpr(allocReg());
          expect('then');
          jFalse = emit({ op: OP.TEST_FALSE, A: 0, modeA: 0, B: eiCond, modeB: MODE.REG, C: 0, modeC: MODE.REG, line: eiTok.line });
          compileStatementsUntil(new Set(['elseif', 'else', 'end']));
        }

        if (peek().type === 'KW' && peek().val === 'else') {
          const elTok = next();
          exitJumps.push(emit({ op: OP.JMP, A: 0, modeA: 0, B: 0, modeB: MODE.REG, C: 0, modeC: 0, line: elTok.line }));
          insts[jFalse - 1].C = insts.length;
          compileStatementsUntil(new Set(['end']));
        } else {
          insts[jFalse - 1].C = insts.length;
        }
        expect('end');
        for (const jp of exitJumps) {
          insts[jp - 1].B = insts.length;
        }
      } else if (t.type === 'KW' && t.val === 'while') {
        next();
        const loopStart = insts.length;
        const condReg = compileExpr(allocReg());
        expect('do');
        const jExit = emit({ op: OP.TEST_FALSE, A: 0, modeA: 0, B: condReg, modeB: MODE.REG, C: 0, modeC: MODE.REG, line: t.line });
        compileStatementsUntil(new Set(['end']));
        expect('end');
        emit({ op: OP.JMP, A: 0, modeA: 0, B: loopStart, modeB: MODE.REG, C: 0, modeC: 0, line: t.line });
        insts[jExit - 1].C = insts.length;
      } else if (t.type === 'KW' && t.val === 'repeat') {
        next();
        const loopStart = insts.length;
        compileStatementsUntil(new Set(['until']));
        const uTok = expect('until');
        const condReg = compileExpr(allocReg());
        emit({ op: OP.TEST_FALSE, A: 0, modeA: 0, B: condReg, modeB: MODE.REG, C: loopStart, modeC: MODE.REG, line: uTok.line });
      } else if (t.type === 'KW' && t.val === 'for') {
        next();
        const varTok = next();
        expect('=');
        const base = allocReg();
        const limitReg = allocReg();
        const stepReg = allocReg();
        const loopVarReg = allocReg();
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
        const bodyStartPc = insts.length;
        const prevLocal = locals.get(varTok.val);
        locals.set(varTok.val, loopVarReg);
        compileStatementsUntil(new Set(['end']));
        expect('end');
        if (prevLocal === undefined) locals.delete(varTok.val);
        else locals.set(varTok.val, prevLocal);
        const loopPc = emit({ op: OP.FORLOOP, A: 0, modeA: 0, B: base, modeB: MODE.REG, C: bodyStartPc, modeC: MODE.REG, line: varTok.line });
        insts[prepPc - 1].C = loopPc - 1;
        emit({ op: OP.LOOP_POP, A: 0, modeA: 0, B: 0, modeB: 0, C: 0, modeC: 0, line: varTok.line });
      } else if (t.type === 'KW' && t.val === 'return') {
        next();
        if (
          peek().type === 'EOF' ||
          (peek().type === 'KW' && ['end', 'else', 'elseif', 'until'].includes(peek().val))
        ) {
          emit({ op: OP.RETURN0, A: 0, modeA: 0, B: 0, modeB: 0, C: 0, modeC: 0, line: t.line });
        } else {
          const r = compileExpr();
          emit({ op: OP.RETURN1, A: 0, modeA: 0, B: r, modeB: MODE.REG, C: 0, modeC: 0, line: t.line });
        }
      } else if (t.type === 'ID' && peek(1).type === 'SYM' && peek(1).val === '=') {
        next();
        expect('=');
        if (locals.has(t.val)) {
          compileExpr(locals.get(t.val));
        } else {
          const r = compileExpr();
          const kIdx = addConst(t.val);
          emit({ op: OP.SETGLOBAL, A: r, modeA: MODE.REG, B: 0, modeB: 0, C: kIdx, modeC: MODE.CONST, line: t.line });
        }
      } else if (t.type === 'ID' && peek(1).type === 'SYM' && (peek(1).val === '.' || peek(1).val === '[')) {
        // Table field/index assignment or call
        const savedPos = tPos;
        const baseTok = next();
        let curReg;
        if (locals.has(baseTok.val)) {
          curReg = locals.get(baseTok.val);
        } else {
          curReg = allocReg();
          const kIdx = addConst(baseTok.val);
          emit({ op: OP.GETGLOBAL, A: kIdx, modeA: MODE.CONST, B: curReg, modeB: MODE.REG, C: 0, modeC: 0, line: baseTok.line });
        }
        let lastAccess = null;
        while (peek().type === 'SYM' && (peek().val === '.' || peek().val === '[')) {
          if (lastAccess) {
            const nextR = allocReg();
            if (lastAccess.kind === 'dot') {
              emit({ op: OP.GETTABLE_K, A: nextR, modeA: MODE.REG, B: lastAccess.kIdx, modeB: MODE.CONST, C: curReg, modeC: MODE.REG, line: baseTok.line });
            } else {
              emit({ op: OP.GETTABLE, A: nextR, modeA: MODE.REG, B: curReg, modeB: MODE.REG, C: lastAccess.keyReg, modeC: MODE.REG, line: baseTok.line });
            }
            curReg = nextR;
          }
          if (peek().val === '.') {
            next();
            const fTok = next();
            lastAccess = { kind: 'dot', kIdx: addConst(fTok.val), line: fTok.line };
          } else {
            const lb = next();
            const keyReg = compileExpr(allocReg());
            expect(']');
            lastAccess = { kind: 'bracket', keyReg, line: lb.line };
          }
        }
        if (peek().type === 'SYM' && peek().val === '=') {
          next();
          const valReg = compileExpr(allocReg());
          if (lastAccess.kind === 'dot') {
            emit({ op: OP.SETTABLE_KR, A: curReg, modeA: MODE.REG, B: lastAccess.kIdx, modeB: MODE.CONST, C: valReg, modeC: MODE.REG, line: lastAccess.line });
          } else {
            emit({ op: OP.SETTABLE, A: lastAccess.keyReg, modeA: MODE.REG, B: valReg, modeB: MODE.REG, C: curReg, modeC: MODE.REG, line: lastAccess.line });
          }
        } else {
          // Not an assignment — rewind and compile as expression
          tPos = savedPos;
          compileExpr();
        }
      } else {
        compileExpr();
      }
    }

    compileStatementsUntil(stopAtEnd ? new Set(['end']) : new Set());
    if (stopAtEnd) expect('end');

    if (
      insts.length === 0 ||
      (insts[insts.length - 1].op !== OP.RETURN0 && insts[insts.length - 1].op !== OP.RETURN1)
    ) {
      emit({ op: OP.RETURN0, A: 0, modeA: 0, B: 0, modeB: 0, C: 0, modeC: 0, line: 1 });
    }

    protos.push({ maxStack: maxStack + 4, numParams: params.length, upvals: [], insts });
    return protos.length;
  }

  const entryIdx = compileBlock([], false);
  return { consts, protos, entryIdx };
}

// =============================================================================
// 6. Reconstructed VM Runtime in JS (รัน Bytecode เพื่อทดสอบเทียบผลลัพธ์)
// =============================================================================
function luaTruthy(v) {
  return v !== false && v !== undefined && v !== null;
}

function luaLength(v) {
  if (typeof v === 'string') return v.length;
  if (v && typeof v === 'object') {
    let n = 0;
    while (Object.prototype.hasOwnProperty.call(v, n + 1) && v[n + 1] !== undefined) {
      n++;
    }
    return n;
  }
  return 0;
}

function luaMod(a, b) {
  return a - Math.floor(a / b) * b;
}

export function executeChunk(chunk, envOverrides = {}) {
  const logs = [];
  const env = {
    print: (...args) => {
      const line = args.map((v) => (v === undefined ? 'nil' : String(v))).join('\t');
      logs.push(line);
    },
    ...envOverrides,
  };

  function wrapProto(proto) {
    return function (...args) {
      const reg = {};
      let pc = 1;
      let loopIter = 0;
      let loopLimit = 0;
      let loopStep = 0;
      const loopStack = [];
      let steps = 0;

      while (pc <= proto.insts.length) {
        if (++steps > 100000) throw new Error('VM step limit exceeded');
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
          case OP.NEWTABLE:
            reg[inst.B] = {};
            break;
          case OP.GETGLOBAL:
            reg[inst.B] = env[inst.Ak];
            break;
          case OP.LEN:
            reg[inst.B] = luaLength(reg[inst.C]);
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
          case OP.GETTABLE:
            reg[inst.A] = reg[inst.B][reg[inst.C]];
            break;
          case OP.FORPREP: {
            loopStack.push({ loopIter, loopLimit, loopStep });
            loopStep = Number(reg[inst.A + 2]);
            loopLimit = Number(reg[inst.A + 1]);
            loopIter = Number(reg[inst.A]) - loopStep;
            pc = inst.C;
            break;
          }
          case OP.GETTABLE_K:
            reg[inst.A] = reg[inst.C][inst.Bk];
            break;
          case OP.LOADK:
            reg[inst.A] = inst.Ck;
            break;
          case OP.CONCAT:
            reg[inst.C] = String(reg[inst.B]) + String(reg[inst.A]);
            break;
          case OP.MOD:
            reg[inst.A] = luaMod(Number(reg[inst.B]), Number(reg[inst.C]));
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
          case OP.TEST_FALSE:
            if (!luaTruthy(reg[inst.B])) pc = inst.C;
            break;
          case OP.RETURN0:
            return undefined;
          case OP.LT:
            reg[inst.A] = reg[inst.B] < reg[inst.C];
            break;
          case OP.POW:
            reg[inst.A] = Math.pow(Number(reg[inst.C]), Number(reg[inst.B]));
            break;
          case OP.NOT:
            reg[inst.A] = !luaTruthy(reg[inst.B]);
            break;
          case OP.SETGLOBAL:
            env[inst.Ck] = reg[inst.A];
            break;
          case OP.ADDK:
            reg[inst.A] = reg[inst.B] + inst.Ck;
            break;
          case OP.RETURN1:
            return reg[inst.B];
          case OP.UNM:
            reg[inst.B] = -Number(reg[inst.A]);
            break;
          case OP.DIV:
            reg[inst.A] = Number(reg[inst.C]) / Number(reg[inst.B]);
            break;
          case OP.LOADNIL:
            reg[inst.A] = undefined;
            break;
          case OP.SETTABLE_KR:
            reg[inst.A][inst.Bk] = reg[inst.C];
            break;
          case OP.LOADARGS:
            for (let i = 1; i <= inst.B; i++) reg[i] = args[i - 1];
            break;
          case OP.LE:
            reg[inst.A] = reg[inst.B] <= reg[inst.C];
            break;
          case OP.EQ:
            reg[inst.C] = reg[inst.B] === reg[inst.A];
            break;
          case OP.CLOSURE:
            reg[inst.A] = wrapProto(inst.Bk);
            break;
          case OP.SETTABLE:
            reg[inst.C][reg[inst.A]] = reg[inst.B];
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
// 7. Luraph v14.3-Style Obfuscated Lua Emitter (104-Opcode Tree + CFF + Bit32)
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
      } else if (r < 0.8) {
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

function buildFull104OpcodeHandlers(obfNum) {
  const N0 = obfNum(0);
  const N1 = obfNum(1);
  const N2 = obfNum(2);
  const N3 = obfNum(3);

  const core = {
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
    58: `(GO)[PO[EO]]=(GO[l[EO]]<GO[h[EO]]);`,
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

  // เติมทุกช่องที่เหลือใน 0..103 ให้ครบ 104 opcodes (7-level tree เหมือน Luraph v14.3)
  const full = {};
  for (let op = 0; op < 104; op++) {
    full[op] = core[op] !== undefined ? core[op] : '';
  }
  return full;
}

function buildBinarySearchDispatch(sortedOps, handlers, rng, obfNum) {
  if (sortedOps.length === 0) return '';
  if (sortedOps.length === 1) return handlers[sortedOps[0]] || '';
  if (sortedOps.length === 2) {
    const [opA, opB] = sortedOps;
    const hA = handlers[opA] || '';
    const hB = handlers[opB] || '';
    if (rng() < 0.5) return `if a==${obfNum(opA)} then ${hA}else ${hB}end;`;
    return `if a~=${obfNum(opB)} then ${hA}else ${hB}end;`;
  }
  const midIdx = Math.floor(sortedOps.length / 2);
  const pivot = sortedOps[midIdx];
  const leftCode = buildBinarySearchDispatch(sortedOps.slice(0, midIdx), handlers, rng, obfNum);
  const rightCode = buildBinarySearchDispatch(sortedOps.slice(midIdx), handlers, rng, obfNum);

  const style = rng();
  if (style < 0.34) return `if a<${obfNum(pivot)} then ${leftCode}else ${rightCode}end;`;
  if (style < 0.67) return `if not(a>=${obfNum(pivot)})then ${leftCode}else ${rightCode}end;`;
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
        elseif op == 11 then R[pr.B[pc]] = {}
        elseif op == 12 then R[pr.B[pc]] = env[pr.Ak[pc]]
        elseif op == 14 then R[pr.B[pc]] = #R[pr.C[pc]]
        elseif op == 17 then R[pr.C[pc]] = R[pr.B[pc]] - R[pr.A[pc]]
        elseif op == 20 then
          local base, nA = pr.B[pc], pr.C[pc] - 1
          local ca = {}; for i = 1, nA do ca[i] = R[base + i] end
          local res = R[base]((table.unpack or unpack)(ca, 1, nA))
          if pr.A[pc] >= 2 then R[base] = res end
        elseif op == 23 then R[pr.A[pc]] = R[pr.B[pc]][R[pr.C[pc]]]
        elseif op == 25 then
          st[#st+1] = {lIt, lLim, lStep}
          lStep, lLim = R[pr.A[pc]+2], R[pr.A[pc]+1]
          lIt = R[pr.A[pc]] - lStep; pc = pr.C[pc]
        elseif op == 32 then R[pr.A[pc]] = R[pr.C[pc]][pr.Bk[pc]]
        elseif op == 34 then R[pr.A[pc]] = pr.Ck[pc]
        elseif op == 42 then R[pr.C[pc]] = tostring(R[pr.B[pc]]) .. tostring(R[pr.A[pc]])
        elseif op == 44 then R[pr.A[pc]] = R[pr.B[pc]] % R[pr.C[pc]]
        elseif op == 46 then
          lIt = lIt + lStep
          if (lStep <= 0 and lIt >= lLim) or (lStep > 0 and lIt <= lLim) then
            R[pr.B[pc]+3] = lIt; pc = pr.C[pc]
          end
        elseif op == 47 then R[pr.A[pc]] = R[pr.C[pc]]
        elseif op == 51 then if not R[pr.B[pc]] then pc = pr.C[pc] end
        elseif op == 57 then return
        elseif op == 58 then R[pr.A[pc]] = (R[pr.B[pc]] < R[pr.C[pc]])
        elseif op == 59 then R[pr.A[pc]] = R[pr.C[pc]] ^ R[pr.B[pc]]
        elseif op == 61 then R[pr.A[pc]] = not R[pr.B[pc]]
        elseif op == 64 then env[pr.Ck[pc]] = R[pr.A[pc]]
        elseif op == 68 then R[pr.A[pc]] = R[pr.B[pc]] + pr.Ck[pc]
        elseif op == 69 then return R[pr.B[pc]]
        elseif op == 75 then R[pr.B[pc]] = -R[pr.A[pc]]
        elseif op == 81 then R[pr.A[pc]] = R[pr.C[pc]] / R[pr.B[pc]]
        elseif op == 82 then R[pr.A[pc]] = nil
        elseif op == 85 then R[pr.A[pc]][pr.Bk[pc]] = R[pr.C[pc]]
        elseif op == 86 then for i = 1, pr.B[pc] do R[i] = args[i] end
        elseif op == 87 then R[pr.A[pc]] = (R[pr.B[pc]] <= R[pr.C[pc]])
        elseif op == 88 then R[pr.C[pc]] = (R[pr.B[pc]] == R[pr.A[pc]])
        elseif op == 90 then R[pr.A[pc]] = wrap(pr.Bk[pc])
        elseif op == 94 then R[pr.C[pc]][R[pr.A[pc]]] = R[pr.B[pc]]
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
    return returnMeta ? { code, cffChecks: [], opcodeCount: Object.keys(OP).length, keyTableL: [] } : code;
  }

  // ---- Luraph v14.3-Style Obfuscated Emitter (104-Opcode 7-Level Tree) ----
  const rng = createRng(seed);
  const obfNum = makeObfNum(rng, dialect);
  const obfStr = makeObfStr(rng);
  const usedMemoKeys = new Set();
  const cffChecks = [];

  const L = Array.from({ length: 9 }, () => Math.floor(rng() * 0x7fffffff) + 1024);

  const handlers = buildFull104OpcodeHandlers(obfNum);
  const sortedOps = Array.from({ length: 104 }, (_, i) => i);
  const dispatchTree = buildBinarySearchDispatch(sortedOps, handlers, rng, obfNum);

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

  const vmClosure =
    `y=function(nO,sO)` +
    `local qS=nO[${obfNum(4)}];` +
    `local LO,oO,h,N,PO,AO,t,l=nO[${obfNum(10)}],nO[${obfNum(3)}],nO[fO],nO[${obfNum(9)}],nO[${obfNum(8)}],nO[${obfNum(6)}],nO[DO],nO[c];` +
    `return(function(...)` +
    `local GO,u,EO,g,f=WO(qS),{...},DO,Y(),{};local vO,RO,E=kO,kO,kO;` +
    `while EO<=#N do local a=(N[EO]);${dispatchTree}EO=EO+DO;end;` +
    `end);end;`;

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
  console.log(`  VM Tree   : ${opcodeCount} opcodes (7-level balanced binary-search dispatch)`);
  console.log(`  CFF States: ${cffChecks.length} memoized bit32 transitions`);
  console.log(`  XOR Key   : 0x${xorKey.toString(16).toUpperCase()} (deferred=${xorKey !== 0})`);
}
