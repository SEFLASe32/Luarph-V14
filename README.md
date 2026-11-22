# Lua VM Static Analyzer & Luraph-Style Reverse Encoder Simulator

เครื่องมือวิเคราะห์โครงสร้างสคริปต์ Lua แบบ **Static Analysis** (อ้างอิงสถาปัตยกรรม Luraph v14.3) พร้อมตัวจำลองการคอมไพล์และเข้ารหัสย้อนกลับ (**Reverse Encoding Simulator**) ด้วย Node.js และเว็บ Workbench สำหรับตรวจสอบ Bytecode, Opcode Table และทดสอบ Round-Trip

> **Educational & Defensive Research Notice**: โปรเจกต์นี้สร้างขึ้นเพื่อการศึกษาโครงสร้าง Register-based VM, Binary Serialization (LEB128/Ascii85) และเทคนิค Control-Flow Flattening แบบ clean-room เท่านั้น ไม่มีการ bypass หรือถอดกลไก anti-tamper ของซอฟต์แวร์บุคคลที่สาม

---

## โครงสร้างไฟล์ในโปรเจกต์ (Repository Structure)

```text
.
├── decoded.lua                      # โครงสร้าง VM, Ascii85 Decoder และ Chunk Deserializer ที่แกะแบบอ่านง่าย
├── encoder.mjs                      # Node.js CLI คอมไพล์ Lua -> Binary Chunk -> Ascii85 -> Luraph-Style Lua
├── test-compare.mjs                 # ชุดทดสอบเทียบผลลัพธ์ (Original vs Encoded VM) + ตรวจสมการ CFF
├── input.lua                        # สคริปต์ตัวอย่างหลัก (ฟังก์ชัน, numeric for, concat, comparison)
├── output_encoded.lua               # ผลลัพธ์ไฟล์ Lua ที่ผ่านการเข้ารหัส (สร้างจาก encoder.mjs)
├── examples/
│   ├── conditionals_loops.lua       # ตัวอย่าง if/elseif/else, while, repeat..until, %, ^, unary ops
│   └── tables_fibonacci.lua         # ตัวอย่าง table literals, array/field access, #length, Fibonacci
├── src/                             # React + TypeScript + Tailwind Static Analysis Workbench
├── .github/workflows/ci.yml         # GitHub Actions CI (รัน test-compare, lint และ build อัตโนมัติ)
├── package.json
└── LICENSE                          # MIT License
```

---

## ชั้น Obfuscation ที่วิเคราะห์และจำลองใน `encoder.mjs`

| ชั้น | เทคนิค | รายละเอียดโครงสร้าง |
| :--- | :--- | :--- |
| **01** | **Wrapper Argument Injection** | ส่ง stdlib, ค่าคงที่, ตาราง `C` (`bit32`/`string`) และคีย์ `L[1..9]` เข้า anonymous function ชั้นนอก |
| **02** | **Control-Flow Flattening (CFF)** | แตกขั้นตอนการทำงานเป็น `while true` state machine (`p`) พร้อมคำนวณ state ถัดไปด้วย `bit32` และ cache ลง `R[key]` |
| **03** | **Literal Obfuscation** | แปลงตัวเลขเป็น `0B...`/`0X...` พร้อม underscore (โหมด Luau) และ string escape `\ddd`, `\xHH`, `\u{}`, `\z` |
| **04** | **Ascii85 (`"LPH-"`) Payload** | ตัด header 4 ไบต์, ขยาย `'z'` เป็น `'!!!!!'`, แปลง 5 chars ฐาน 85 (offset 33) เป็น Big-Endian `>I4` |
| **05** | **Biased LEB128 Binary Chunk** | Bias constants (`+0x12074`), prototypes (`+0xE81A`), instructions (`+39325`), RLE line info, signed 53-bit varint (`val*8+mode`) |
| **06** | **Deferred Constant Patching** | เข้ารหัส string ด้วย XOR stream (`I[2]`/`I[3]`) แล้ว patch กลับเข้า prototype (`slot 6/3/1`) ก่อนรัน `y(k, U)` |
| **07** | **Binary-Search VM Dispatch** | ต้นไม้ `if/else` สมดุล 7 ชั้น ครอบคลุมช่วง `0..103` พร้อม self-modifying opcodes (`6→17, 36→87, 45→4, 89→35`) |

---

## วิธีใช้งาน (CLI Quick Start)

ต้องใช้ **Node.js v18+** (แนะนำ Node.js 22)

### 1. เข้ารหัสไฟล์ Lua เป็นรูปแบบ Luraph-Style
```bash
# ค่าเริ่มต้น: สไตล์ Luraph-Style, โหมด Luau (0B/0X/_), Deferred XOR Key 0x5A
node encoder.mjs input.lua output_encoded.lua

# โหมด Lua 5.3 / 5.4 มาตรฐาน (ไม่ใช้ 0b binary และ underscore)
node encoder.mjs input.lua output_lua53.lua --dialect=lua53

# กำหนด Seed และ XOR Key เอง (หรือใส่ --xor-key=0 เพื่อปิด XOR)
node encoder.mjs examples/tables_fibonacci.lua output_fib.lua --seed=0x9999 --xor-key=0x3C

# โหมดอ่านง่าย (Readable VM) สำหรับเปรียบเทียบโครงสร้าง
node encoder.mjs input.lua output_readable.lua --readable
```

### 2. รันชุดทดสอบ Round-Trip Verification
```bash
node test-compare.mjs
```
หรือผ่าน npm scripts:
```bash
npm run encode
npm run test:encoder
```

### 3. เปิดหน้า Web Workbench (ตัวเลือกเสริม)
```bash
npm install
npm run dev
```

---

## วิธีอัปโหลดขึ้น GitHub

```bash
git init
git add .
git commit -m "feat: Lua VM static analysis, Luraph-style reverse encoder, and test suite"
git branch -M main
git remote add origin https://github.com/<USERNAME>/<REPO_NAME>.git
git push -u origin main
```

---

## License

MIT — ดูรายละเอียดในไฟล์ [LICENSE](./LICENSE)
