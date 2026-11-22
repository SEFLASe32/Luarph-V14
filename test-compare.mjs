#!/usr/bin/env node
/**
 * test-compare.mjs
 * -----------------------------------------------------------------------------
 * สคริปต์ทดสอบเปรียบเทียบผลลัพธ์ระหว่าง:
 *   (A) การประมวลผลโค้ดต้นฉบับ `input.lua` (Reference Evaluator)
 *   (B) การเข้ารหัส `input.lua` -> Binary Chunk -> Ascii85 ("LPH-") -> `output_encoded.lua`
 *       ในรูปแบบ Luraph v14.3-Style (Wrapper Injection, CFF + Memoized R/bit32,
 *       Literal Obfuscation, Deferred I[2] Patching, Binary-Search Opcode Tree)
 *       แล้วถอดรหัสกลับจากไฟล์ `output_encoded.lua` และรันบน Reconstructed VM
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

const XOR_KEY = 0x5a;
const SEED = 0x143a7;
const INPUT_FILE = 'input.lua';
const OUTPUT_FILE = 'output_encoded.lua';

// Reference execution ของ input.lua (เทียบผลลัพธ์จาก logic ต้นฉบับโดยตรง)
function evaluateOriginalInputLua() {
  const logs = [];
  const print = (...args) => logs.push(args.map(String).join('\t'));

  function computeScore(base, multiplier, bonus) {
    let total = 0;
    for (let i = 1; i <= 5; i++) {
      total = total + base * multiplier + i;
    }
    total = total + bonus;
    return total;
  }

  const greeting = 'Static Analysis Verified';
  const score = computeScore(10, 3, 7);
  const summary = greeting + ' | Score=' + score;

  print(summary);
  print('Check:', score === 172);
  return { logs, returnValue: summary };
}

function main() {
  console.log('====================================================================');
  console.log(' Luraph v14.3-Style Reverse-Encoding & Round-Trip Verification Test');
  console.log('====================================================================\n');

  // Step 1: อ่าน input.lua และเข้ารหัสเป็น output_encoded.lua แบบ Luraph-style
  const luaSource = fs.readFileSync(INPUT_FILE, 'utf8');
  const compiledChunk = compileLuaToChunk(luaSource);
  const binaryBuffer = serializeChunk(compiledChunk, { xorKey: XOR_KEY });
  const ascii85 = encodeAscii85(binaryBuffer);
  const {
    code: encodedLua,
    cffChecks,
    opcodeCount,
    keyTableL,
  } = generateEncodedLua(ascii85, {
    xorKey: XOR_KEY,
    style: 'luraph',
    dialect: 'luau',
    seed: SEED,
    returnMeta: true,
  });
  fs.writeFileSync(OUTPUT_FILE, encodedLua, 'utf8');

  console.log(`[1] Compiled & Obfuscated "${INPUT_FILE}" -> "${OUTPUT_FILE}"`);
  console.log(`    - Source size  : ${luaSource.length} bytes`);
  console.log(`    - Output size  : ${encodedLua.length} bytes (single-line Luraph-style)`);
  console.log(`    - Constants    : ${compiledChunk.consts.length}`);
  console.log(`    - Prototypes   : ${compiledChunk.protos.length} (Entry Proto #${compiledChunk.entryIdx})`);
  console.log(`    - Raw bytecode : ${binaryBuffer.length} bytes`);
  console.log(`    - Ascii85 str  : ${ascii85.length} chars ("${ascii85.slice(0, 28)}...")`);
  console.log(`    - VM Dispatch  : ${opcodeCount} opcodes (balanced binary-search if/else tree)`);
  console.log(`    - CFF States   : ${cffChecks.length} memoized bit32 transitions\n`);

  // Step 2: ตรวจสอบความถูกต้องของ CFF state transitions และโครงสร้าง Obfuscation
  let cffValidCount = 0;
  for (const ch of cffChecks) {
    const computed = ch.delta + ((((keyTableL[ch.i1 - 1] ^ keyTableL[ch.i2 - 1]) >>> 0) & ch.mask) >>> 0);
    if (computed !== ch.nextState) {
      throw new Error(`CFF transition mismatch: expected ${ch.nextState}, got ${computed}`);
    }
    cffValidCount++;
  }

  const writtenFile = fs.readFileSync(OUTPUT_FILE, 'utf8');
  const hasWrapper = /return\(function\(A,P,DO,H,Q,Y,s/.test(writtenFile);
  const hasCFF = /while true do if p==/.test(writtenFile) && /C\.x\(C\.s\(L\[/.test(writtenFile);
  const hasBinaryTree = /while EO<=#N do local a=\(N\[EO\]\);if /.test(writtenFile);
  const hasLiteralObf = /0[bB][01_]+/.test(writtenFile) && /\\u\{/.test(writtenFile);

  console.log('[2] Obfuscation Layer Verification:');
  console.log(`    - Wrapper Arg Injection : ${hasWrapper ? 'OK' : 'FAIL'}`);
  console.log(`    - CFF + bit32 Memoize   : ${hasCFF ? 'OK' : 'FAIL'} (${cffValidCount}/${cffChecks.length} equations verified)`);
  console.log(`    - Binary-Search VM Tree : ${hasBinaryTree ? 'OK' : 'FAIL'}`);
  console.log(`    - Literal Obfuscation   : ${hasLiteralObf ? 'OK' : 'FAIL'}\n`);

  // Step 3: แกะ Payload "LPH-..." กลับจากไฟล์ output_encoded.lua ที่เพิ่งสร้าง
  const match = writtenFile.match(/"(LPH-(?:\\.|[^"\\])*)"/);
  if (!match) {
    throw new Error('Failed to extract LPH- payload from output_encoded.lua');
  }
  const extractedPayload = match[1].replace(/\\(.)/g, '$1');
  const decodedBytes = decodeAscii85(extractedPayload);
  const roundTrippedChunk = deserializeChunk(decodedBytes, { xorKey: XOR_KEY });

  console.log(`[3] Decoded & Deserialized "${OUTPUT_FILE}"`);
  console.log(`    - Decoded bytes: ${decodedBytes.length} bytes (padded to 4-byte boundary)`);
  console.log(`    - Deferred mode: ${roundTrippedChunk.deferred} (XOR key = 0x${XOR_KEY.toString(16).toUpperCase()})`);
  console.log(`    - Constants    : ${JSON.stringify(roundTrippedChunk.consts)}\n`);

  // Step 4: รันเทียบผลลัพธ์ระหว่างโค้ดต้นฉบับ vs โค้ดที่เข้ารหัสใหม่
  const originalResult = evaluateOriginalInputLua();
  const encodedResult = executeChunk(roundTrippedChunk);

  console.log('[4] Execution Output Comparison:');
  console.log('    Original stdout :', JSON.stringify(originalResult.logs));
  console.log('    Encoded  stdout :', JSON.stringify(encodedResult.logs));
  console.log('    Original return :', JSON.stringify(originalResult.returnValue));
  console.log('    Encoded  return :', JSON.stringify(encodedResult.returnValue));

  const logsMatch = JSON.stringify(originalResult.logs) === JSON.stringify(encodedResult.logs);
  const retMatch = originalResult.returnValue === encodedResult.returnValue;
  const layersOk = hasWrapper && hasCFF && hasBinaryTree && hasLiteralObf && cffValidCount === cffChecks.length;

  console.log('\n--------------------------------------------------------------------');
  if (logsMatch && retMatch && layersOk) {
    console.log(' PASS: โครงสร้าง Luraph-Style ครบทุกชั้น และผลลัพธ์ตรงกับโค้ดต้นฉบับ 100%!');
  } else {
    console.error(' FAIL: ตรวจสอบพบข้อผิดพลาด!');
    process.exit(1);
  }
  console.log('--------------------------------------------------------------------');
}

main();
