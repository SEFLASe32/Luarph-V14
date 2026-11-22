#!/usr/bin/env node
/**
 * test-compare.mjs
 * -----------------------------------------------------------------------------
 * ชุดทดสอบเปรียบเทียบผลลัพธ์แบบครบชุด (Multi-Case Round-Trip & Obfuscation Suite):
 *   Case 1: input.lua                        (Luraph-Style · Luau · XOR 0x5A) -> output_encoded.lua
 *   Case 2: examples/conditionals_loops.lua  (Luraph-Style · Lua 5.3 · XOR 0x3C)
 *   Case 3: examples/tables_fibonacci.lua    (Luraph-Style · Luau · Plaintext XOR 0x00)
 *   Case 4: input.lua                        (Readable VM Mode · XOR 0x5A)
 *
 * วิธีรัน:
 *   node test-compare.mjs
 */

import fs from 'node:fs';
import {
  compileLuaToChunk,
  serializeChunk,
  deserializeChunk,
  encodeAscii85,
  decodeAscii85,
  executeChunk,
  generateEncodedLua,
} from './encoder.mjs';

// Reference evaluators สำหรับแต่ละไฟล์ตัวอย่าง
const TEST_CASES = [
  {
    name: 'Case 1: Basic Function + Numeric For (Luraph-Style · Luau · XOR 0x5A)',
    file: 'input.lua',
    outputFile: 'output_encoded.lua',
    xorKey: 0x5a,
    style: 'luraph',
    dialect: 'luau',
    seed: 0x143a7,
    expected: {
      logs: ['Static Analysis Verified | Score=172', 'Check:\ttrue'],
      returnValue: 'Static Analysis Verified | Score=172',
    },
  },
  {
    name: 'Case 2: Conditionals, While, Repeat, Math & Unary (Luraph-Style · Lua 5.3 · XOR 0x3C)',
    file: 'examples/conditionals_loops.lua',
    outputFile: null,
    xorKey: 0x3c,
    style: 'luraph',
    dialect: 'lua53',
    seed: 0x99881,
    expected: {
      logs: ['FizzBuzz(15):\tFizzBuzz', 'OddSqSum:\t165\tNeg:\t-165\tFlag:\ttrue', 'Trace:\t3-2-1-'],
      returnValue: 'FizzBuzz:165:3-2-1-',
    },
  },
  {
    name: 'Case 3: Tables, Array/Field Access & Fibonacci (Luraph-Style · Luau · Plaintext)',
    file: 'examples/tables_fibonacci.lua',
    outputFile: null,
    xorKey: 0x0,
    style: 'luraph',
    dialect: 'luau',
    seed: 0x42024,
    expected: {
      logs: ['FibVM[8]=21', 'F(6):\t8\tF(8):\t21'],
      returnValue: 'FibVM[8]=21',
    },
  },
  {
    name: 'Case 4: Readable VM Round-Trip Mode (input.lua · XOR 0x5A)',
    file: 'input.lua',
    outputFile: null,
    xorKey: 0x5a,
    style: 'readable',
    dialect: 'luau',
    seed: 0x143a7,
    expected: {
      logs: ['Static Analysis Verified | Score=172', 'Check:\ttrue'],
      returnValue: 'Static Analysis Verified | Score=172',
    },
  },
];

function verifyCase(tc) {
  const source = fs.readFileSync(tc.file, 'utf8');
  const compiledChunk = compileLuaToChunk(source);
  const binaryBuffer = serializeChunk(compiledChunk, { xorKey: tc.xorKey });
  const ascii85 = encodeAscii85(binaryBuffer);
  const {
    code: encodedLua,
    cffChecks,
    opcodeCount,
    keyTableL,
  } = generateEncodedLua(ascii85, {
    xorKey: tc.xorKey,
    style: tc.style,
    dialect: tc.dialect,
    seed: tc.seed,
    returnMeta: true,
  });

  if (tc.outputFile) {
    fs.writeFileSync(tc.outputFile, encodedLua, 'utf8');
  }

  // 1) ตรวจสอบสมการ CFF bit32 ทุก transition
  for (const ch of cffChecks) {
    const computed =
      ch.delta + ((((keyTableL[ch.i1 - 1] ^ keyTableL[ch.i2 - 1]) >>> 0) & ch.mask) >>> 0);
    if (computed !== ch.nextState) {
      throw new Error(`${tc.name}: CFF mismatch expected ${ch.nextState}, got ${computed}`);
    }
  }

  // 2) ตรวจสอบโครงสร้าง Obfuscation (กรณี style = 'luraph')
  if (tc.style === 'luraph') {
    if (!/return\(function\(A,P,DO,H,Q,Y,s/.test(encodedLua)) {
      throw new Error(`${tc.name}: Missing wrapper argument injection`);
    }
    if (!/while true do if p==/.test(encodedLua) || !/C\.x\(C\.s\(L\[/.test(encodedLua)) {
      throw new Error(`${tc.name}: Missing CFF bit32 state machine`);
    }
    if (opcodeCount !== 104) {
      throw new Error(`${tc.name}: Expected 104-opcode tree, got ${opcodeCount}`);
    }
    if (tc.dialect === 'lua53' && /\b0[bB][01_]+/.test(encodedLua)) {
      throw new Error(`${tc.name}: Lua 5.3 dialect should not contain 0b binary literals`);
    }
  }

  // 3) แกะ Payload "LPH-..." กลับจากโค้ด Lua ที่สร้างขึ้นจริง แล้วรันเทียบผลลัพธ์
  const match = encodedLua.match(/"(LPH-(?:\\.|[^"\\])+)"/);
  if (!match) {
    throw new Error(`${tc.name}: Failed to extract LPH- payload`);
  }
  const extracted = match[1].replace(/\\(.)/g, '$1');
  const decodedBytes = decodeAscii85(extracted);
  const roundTrippedChunk = deserializeChunk(decodedBytes, { xorKey: tc.xorKey });
  const encodedResult = executeChunk(roundTrippedChunk);

  const logsMatch = JSON.stringify(encodedResult.logs) === JSON.stringify(tc.expected.logs);
  const retMatch = encodedResult.returnValue === tc.expected.returnValue;

  if (!logsMatch || !retMatch) {
    console.error(`  [FAIL] ${tc.name}`);
    console.error(`    Expected stdout: ${JSON.stringify(tc.expected.logs)}`);
    console.error(`    Actual   stdout: ${JSON.stringify(encodedResult.logs)}`);
    console.error(`    Expected return: ${JSON.stringify(tc.expected.returnValue)}`);
    console.error(`    Actual   return: ${JSON.stringify(encodedResult.returnValue)}`);
    process.exit(1);
  }

  console.log(`[PASS] ${tc.name}`);
  console.log(
    `       Binary=${binaryBuffer.length}B | Ascii85=${ascii85.length}ch | Out=${encodedLua.length}B | Ops=${opcodeCount} | CFF=${cffChecks.length}/${cffChecks.length}`
  );
  console.log(`       stdout=${JSON.stringify(encodedResult.logs)} | return=${JSON.stringify(encodedResult.returnValue)}`);
}

function main() {
  console.log('========================================================================');
  console.log(' Luraph v14.3-Style Reverse-Encoding & Multi-Case Verification Suite');
  console.log('========================================================================\n');

  for (const tc of TEST_CASES) {
    verifyCase(tc);
  }

  console.log('\n------------------------------------------------------------------------');
  console.log(` ALL ${TEST_CASES.length}/${TEST_CASES.length} TESTS PASSED (100% Output & Obfuscation Integrity Verified)`);
  console.log('------------------------------------------------------------------------');
}

main();
