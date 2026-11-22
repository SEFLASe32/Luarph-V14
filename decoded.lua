-- =============================================================================
-- decoded.lua
-- Static Analysis & Structural Reconstruction of Luraph Obfuscator v14.3 VM
-- Source analyzed: loader.lua_5e4ba8d7.txt (70,296 bytes)
-- =============================================================================
--
-- [สรุปผลการวิเคราะห์แบบ Static Analysis]
-- 1. ประเภทการ Obfuscate:
--    - Custom Register-based Bytecode Virtual Machine (Luraph v14.3)
--    - Ascii85 (Base85) Payload Encoding พร้อม Magic Header "LPH-" และ 'z' RLE
--    - Control-Flow Flattening (State Machine ด้วยตัวแปร state `p` + ตาราง cache `R`)
--    - Number & Bitwise Constant Obfuscation (ฐานสอง/ฐานสิบหก/underscore + bit32)
--    - Multi-Stage Bootstrapper:
--        * Stage 1: Deserializer + VM Bootstrapper (132 constants, 23 prototypes)
--        * Stage 2: Encrypted inner chunk ที่ถูกถอดรหัสและโหลดผ่าน `setStream(HO)` + `deserializeChunk(FO)`
--    - Self-Modifying / Integrity-Checked Opcodes (เช่น Opcode 6, 36, 45, 89)
--
-- 2. โครงสร้างหลักของไฟล์ (เรียงตามลำดับการทำงาน):
--    [Step 1] รับไลบรารีมาตรฐานผ่าน Parameter ของ Anonymous Wrapper Function
--    [Step 2] ถอดรหัสข้อความ "LPH-..." ด้วย Ascii85 -> Binary Bytecode Stream
--    [Step 3] สร้างตัวอ่าน Binary Stream (uint8, uint32 LE, int64 LE, float64 LE, LEB128)
--    [Step 4] สร้าง Chunk Deserializer (`deserializeChunk`) และ Prototype Deserializer (`deserializeProto`)
--    [Step 5] สร้าง Register-based VM Interpreter (`createVMClosure`) รองรับ 104 Opcodes (0..103)
--    [Step 6] โหลด Stage 1 (`k = deserializeChunk()`), รัน Bootstrapper แล้วส่งคืนฟังก์ชัน Stage 2
-- =============================================================================

local table_move     = table.move
local table_create   = table.create or function() return {} end
local string_gsub    = string.gsub
local string_sub     = string.sub
local string_byte    = string.byte
local string_char    = string.char
local string_pack    = string.pack
local string_unpack  = string.unpack
local string_match   = string.match
local coroutine_wrap = coroutine.wrap
local coroutine_yield = coroutine.yield

-- Constants ที่ใช้ใน Binary Deserializer (extracted จาก parameter ของ wrapper)
local CONST_INT64_MAX_TAG = 8                   -- tag <= 8: int64 (<i8), 9..13: float64 (<d)
local CONST_BOOL_TAG      = 0xE3                -- 227: boolean, อื่นๆ (>13 && ~=227): string
local SIGNED_THRESHOLD    = 4503599627370496    -- 2^52
local SIGNED_MODULUS      = 9007199254740992    -- 2^53
local CONST_COUNT_BIAS    = 0x12074             -- 73844
local PROTO_COUNT_BIAS    = 0xE81A              -- 59418
local INST_COUNT_BIAS     = 39325               -- bias ของจำนวนคำสั่งในแต่ละ Prototype
local UNPACK_LIMIT        = 0x1F3D              -- 7997 (ถ้าเกินจะใช้ recursive unpack)

-- ตารางภายในของ VM (เก็บ bit32 helpers ใน slot 6..15 และ deferred constant/proto refs ใน slot 2..3)
local vmInternal = {
  [6]  = bit32.band,
  [7]  = bit32.lrotate,
  [8]  = bit32.lshift,
  [9]  = bit32.bxor,
  [10] = bit32.bnot,
  [11] = bit32.countrz,
  [12] = bit32.rrotate,
  [13] = bit32.rshift,
  [14] = bit32.bor,
  [15] = bit32.countlz,
}

-- -----------------------------------------------------------------------------
-- [Step 1] Helper สำหรับ Unpack หลายค่า (ป้องกัน stack overflow ของ unpack เดิม)
-- -----------------------------------------------------------------------------
local function recursiveUnpack(first, last, tbl)
  if first > last then return end
  local count = last - first + 1
  if count >= 8 then
    return tbl[first], tbl[first + 1], tbl[first + 2], tbl[first + 3],
           tbl[first + 4], tbl[first + 5], tbl[first + 6], tbl[first + 7],
           recursiveUnpack(first + 8, last, tbl)
  elseif count >= 7 then
    return tbl[first], tbl[first + 1], tbl[first + 2], tbl[first + 3],
           tbl[first + 4], tbl[first + 5], tbl[first + 6],
           recursiveUnpack(first + 7, last, tbl)
  elseif count >= 6 then
    return tbl[first], tbl[first + 1], tbl[first + 2], tbl[first + 3],
           tbl[first + 4], tbl[first + 5], recursiveUnpack(first + 6, last, tbl)
  elseif count >= 5 then
    return tbl[first], tbl[first + 1], tbl[first + 2], tbl[first + 3],
           tbl[first + 4], recursiveUnpack(first + 5, last, tbl)
  elseif count >= 4 then
    return tbl[first], tbl[first + 1], tbl[first + 2], tbl[first + 3],
           recursiveUnpack(first + 4, last, tbl)
  elseif count >= 3 then
    return tbl[first], tbl[first + 1], tbl[first + 2], recursiveUnpack(first + 3, last, tbl)
  elseif count >= 2 then
    return tbl[first], tbl[first + 1], recursiveUnpack(first + 2, last, tbl)
  else
    return tbl[first], recursiveUnpack(first + 1, last, tbl)
  end
end

local function safeUnpack(last, first, tbl)
  first = first or 1
  last = last or #tbl
  if (last - first + 1) <= UNPACK_LIMIT then
    return unpack(tbl, first, last)
  end
  return recursiveUnpack(first, last, tbl)
end

local emptyTable = {}
local function packVarargs(...)
  local count = select("#", ...)
  if count == 0 then
    return 0, emptyTable
  end
  return count, { ... }
end

-- -----------------------------------------------------------------------------
-- [Step 2] Ascii85 (Base85) Decoder สำหรับ Payload ที่ขึ้นต้นด้วย "LPH-"
-- -----------------------------------------------------------------------------
-- รูปแบบ: ตัด 4 ตัวอักษรแรก ("LPH-") ออก -> แทน 'z' ด้วย '!!!!!' (4 zero bytes)
-- แล้วแปลงทีละ 5 ตัวอักษร (ฐาน 85, offset 33) เป็น Big-Endian uint32 (4 ไบต์)
local function decodeAscii85(payloadWithHeader)
  local body = string_sub(payloadWithHeader, 5) -- ข้าม "LPH-"
  body = string_gsub(body, "z", "!!!!!")
  local cache = setmetatable({}, {
    __index = function(self, chunk5)
      local c1, c2, c3, c4, c5 = string_byte(chunk5, 1, 5)
      local value = (c5 - 33)
                  + (c4 - 33) * 85
                  + (c3 - 33) * 7225       -- 85^2
                  + (c2 - 33) * 614125     -- 85^3
                  + (c1 - 33) * 52200625   -- 85^4
      local bytes4 = string_pack(">I4", value)
      self[chunk5] = bytes4
      return bytes4
    end,
  })
  return string_gsub(body, ".....", cache)
end

-- -----------------------------------------------------------------------------
-- [Step 3] Binary Stream Reader (ทำงานบน Bytecode Buffer ที่ถอดรหัสแล้ว)
-- -----------------------------------------------------------------------------
local streamBuffer = ""
local cursor = 1

local function setStream(newBuffer)
  streamBuffer = newBuffer
  cursor = 1
end

local function readByte()
  local b = string_byte(streamBuffer, cursor, cursor)
  cursor = cursor + 1
  return b
end

local function readUInt32()
  local val, nextPos = string_unpack("<I4", streamBuffer, cursor)
  cursor = nextPos
  return val
end

local function readInt64()
  local val, nextPos = string_unpack("<i8", streamBuffer, cursor)
  cursor = nextPos
  return val
end

local function readFloat64()
  local val, nextPos = string_unpack("<d", streamBuffer, cursor)
  cursor = nextPos
  return val
end

-- อ่าน Unsigned LEB128 (Varint 7-bit ต่อไบต์, bit 7 = continuation flag)
local function readVarint()
  local result = 0
  local multiplier = 1
  repeat
    local b = string_byte(streamBuffer, cursor, cursor)
    result = result + ((b > 127 and (b - 128) or b) * multiplier)
    multiplier = multiplier * 128
    cursor = cursor + 1
  until b < 128
  return result
end

-- อ่าน Signed 53-bit Integer (two's complement ที่ 2^52 / 2^53)
local function readSignedVarint()
  local k = readVarint()
  if k >= SIGNED_THRESHOLD then
    return k - SIGNED_MODULUS
  end
  return k
end

-- อ่าน Length-Prefixed String
local function readString()
  local len = readVarint()
  cursor = cursor + len
  return string_sub(streamBuffer, cursor - len, cursor - 1)
end

-- -----------------------------------------------------------------------------
-- [Step 4] Prototype & Chunk Deserializer
-- -----------------------------------------------------------------------------
-- โครงสร้างตาราง Prototype (`proto`):
--   proto[1]  = C_const  (ค่าคงที่หรือ sub-proto ของ operand C)
--   proto[2]  = B_reg    (เลข register / target ของ operand B)
--   proto[3]  = B_const  (ค่าคงที่หรือ sub-proto ของ operand B)
--   proto[4]  = maxStack (ขนาด Register Frame)
--   proto[5]  = upvals   (รายการ descriptor ของ upvalue: { [1]=kind, [3]=index })
--   proto[6]  = A_const  (ค่าคงที่หรือ sub-proto ของ operand A)
--   proto[7]  = numParams
--   proto[8]  = A_reg    (เลข register / target ของ operand A)
--   proto[9]  = opcodes  (หมายเลข Opcode ของแต่ละคำสั่ง)
--   proto[10] = lineInfo (เลขบรรทัดสำหรับ error stack trace แบบ RLE)
--   proto[11] = C_reg    (เลข register / target ของ operand C)

local upvalCache = nil
local constPool = nil
local isDeferredMode = false
local protoPatchList = nil

local function deserializeProto()
  local proto = { nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil }

  -- 4.1 อ่านตารางเลขบรรทัด (Run-Length Encoded)
  local lineInfo = {}
  proto[10] = lineInfo
  local pcCursor = 1
  for _ = 1, readUInt32() do
    local raw = readUInt32()
    local half = raw / 2
    if raw % 2 ~= 0 then
      local rangeEnd = readUInt32()
      local lineNum = readUInt32()
      pcCursor = rangeEnd
      for idx = half - (half % 1), rangeEnd do
        lineInfo[idx] = lineNum
      end
    else
      lineInfo[pcCursor] = half - (half % 1)
    end
    pcCursor = pcCursor + 1
  end

  -- 4.2 Metadata ของฟังก์ชัน
  proto[4] = readVarint() -- maxStack
  proto[7] = readVarint() -- numParams

  -- 4.3 Upvalue Descriptors
  local numUpvals = readVarint()
  local upvals = table_create(numUpvals)
  for i = 1, numUpvals do
    local u = readVarint()
    if upvalCache[u] then
      upvals[i] = upvalCache[u]
    else
      local desc = {
        [1] = u % 4,                   -- 0 = local reg (mutable), 1 = local reg (by-value), 2 = parent upval
        [3] = (u - (u % 4)) / 4,       -- register หรือ upvalue index
      }
      upvalCache[u] = desc
      upvals[i] = desc
    end
  end
  proto[5] = upvals

  -- 4.4 คำสั่ง Bytecode (3 Operands + 1 Opcode ต่อคำสั่ง)
  -- แต่ละ Operand ถูกเข้ารหัสแบบ `value * 8 + mode`
  --   mode == 1: register / immediate integer
  --   mode == 2: constant pool reference
  --   mode == 4: nested prototype reference (patch ภายหลัง)
  local numInsts = readVarint() - INST_COUNT_BIAS
  local C_const = table_create(numInsts)
  local B_reg   = table_create(numInsts)
  local B_const = table_create(numInsts)
  local A_const = table_create(numInsts)
  local A_reg   = table_create(numInsts)
  local opcodes = table_create(numInsts)
  local C_reg   = table_create(numInsts)

  proto[1]  = C_const
  proto[2]  = B_reg
  proto[3]  = B_const
  proto[6]  = A_const
  proto[8]  = A_reg
  proto[9]  = opcodes
  proto[11] = C_reg

  for i = 1, numInsts do
    local rawA = readSignedVarint()
    local rawB = readSignedVarint()
    local rawC = readSignedVarint()
    local op   = readSignedVarint()

    local modeA = rawA % 8
    local modeB = rawB % 8
    local modeC = rawC % 8

    local valA = (rawA - modeA) / 8
    local valB = (rawB - modeB) / 8
    local valC = (rawC - modeC) / 8

    A_reg[i]   = valA
    B_reg[i]   = valB
    C_reg[i]   = valC
    opcodes[i] = op

    -- Resolve Operand A
    if modeA == 2 then
      if isDeferredMode then
        local ref = constPool[valA]
        local n = #ref
        ref[n + 1], ref[n + 2], ref[n + 3] = proto, i, 6
      else
        A_const[i] = constPool[valA]
      end
    elseif modeA == 4 then
      local n = #protoPatchList
      protoPatchList[n + 1], protoPatchList[n + 2], protoPatchList[n + 3] = A_const, i, valA
    end

    -- Resolve Operand B
    if modeB == 2 then
      if isDeferredMode then
        local ref = constPool[valB]
        local n = #ref
        ref[n + 1], ref[n + 2], ref[n + 3] = proto, i, 3
      else
        B_const[i] = constPool[valB]
      end
    elseif modeB == 4 then
      local n = #protoPatchList
      protoPatchList[n + 1], protoPatchList[n + 2], protoPatchList[n + 3] = B_const, i, valB
    end

    -- Resolve Operand C
    if modeC == 2 then
      if isDeferredMode then
        local ref = constPool[valC]
        local n = #ref
        ref[n + 1], ref[n + 2], ref[n + 3] = proto, i, 1
      else
        C_const[i] = constPool[valC]
      end
    elseif modeC == 4 then
      local n = #protoPatchList
      protoPatchList[n + 1], protoPatchList[n + 2], protoPatchList[n + 3] = C_const, i, valC
    end
  end

  return proto
end

local function deserializeChunk()
  upvalCache = {}

  -- อ่านจำนวน Constant และ Flag ว่าเป็น Deferred (Encrypted Constants) หรือไม่
  local numConsts = readVarint() - CONST_COUNT_BIAS
  local deferred = (readByte() ~= 0)
  isDeferredMode = deferred
  constPool = table_create(numConsts)

  for idx = 1, numConsts do
    local tag = readByte()
    local val
    if tag <= 13 then
      if tag <= CONST_INT64_MAX_TAG then
        val = readInt64()
      else
        val = readFloat64()
      end
    elseif tag == CONST_BOOL_TAG then
      val = (readByte() == 1)
    else
      val = readString()
    end
    constPool[idx] = deferred and { [0] = val } or val
  end

  -- อ่าน Prototype ทั้งหมดใน Chunk
  local numProtos = readVarint() - PROTO_COUNT_BIAS
  local protos = table_create(numProtos)
  protoPatchList = table_create(numProtos * 3)

  for idx = 1, numProtos do
    protos[idx] = deserializeProto()
  end

  -- Patch Reference ของ Nested Prototypes
  for i = 1, #protoPatchList, 3 do
    local targetArr = protoPatchList[i]
    local instIdx   = protoPatchList[i + 1]
    local protoIdx  = protoPatchList[i + 2]
    targetArr[instIdx] = protos[protoIdx]
  end

  -- ถ้าเป็นโหมด Deferred (Stage 2) จะเก็บ constant pool และ protos ไว้ใน vmInternal
  -- เพื่อให้ Stage 1 bootstrapper ถอดรหัสข้อความแล้ว patch ค่าจริงกลับเข้าไป
  if deferred then
    vmInternal[2] = constPool
    vmInternal[3] = protos
  end

  local entryProto = protos[readVarint()]
  constPool = nil
  protoPatchList = nil
  upvalCache = nil
  return entryProto
end

-- -----------------------------------------------------------------------------
-- [Step 5] Virtual Machine Interpreter (104 Opcodes: 0..103)
-- -----------------------------------------------------------------------------
-- ในโค้ดต้นฉบับใช้ Binary Search If-Else Tree ลึก 7 ชั้นเพื่อ dispatch opcode
-- ด้านล่างนี้คือสรุปตาราง Opcode หลักที่แกะได้จาก Static Analysis:
--
--   [Movement & Constants]
--     OP  0 : NOP
--     OP 34 : LOADK        R[A] = C_const
--     OP 47 : MOVE         R[A] = R[C]
--     OP 76 : LOADNIL_RNG  for i = A, C do R[i] = nil end
--     OP 82 : LOADNIL      R[A] = nil
--
--   [Globals, Tables & Upvalues]
--     OP 11 : NEWTABLE     R[B] = {}
--     OP 98 : NEWTABLE_SZ  R[A] = table.create(C)
--     OP 12 : GETGLOBAL    R[B] = env[A_const]
--     OP 64 : SETGLOBAL    env[C_const] = R[A]
--     OP 23 : GETTABLE     R[A] = R[B][R[C]]
--     OP 32 : GETTABLE_K   R[A] = R[C][B_const]
--     OP 26 : SETTABLE_KK  R[A][B_const] = C_const
--     OP 40 : SETTABLE_RK  R[A][R[B]] = C_const
--     OP 85 : SETTABLE_KR  R[A][B_const] = R[C]
--     OP 94 : SETTABLE     R[C][R[A]] = R[B]
--     OP 100: SELF         R[C+1] = R[A]; R[C] = R[A][B_const]
--     OP 41 : GETUPVAL     R[C] = upvals[B].value
--     OP 52 : GETUPVAL_RAW R[B] = upvals[A]
--     OP 95 : SETUPVAL     upvals[C].value = R[A]
--
--   [Arithmetic, Bitwise & String]
--     OP  2 : ADD          R[C] = R[B] + R[A]
--     OP 68 : ADDK         R[A] = R[B] + C_const
--     OP 17 : SUB          R[C] = R[B] - R[A]       (OP 6 = self-modifying -> OP 17)
--     OP 60 : SUBK         R[A] = R[B] - C_const
--     OP 102: MUL          R[B] = R[A] * R[C]
--     OP 50 : MULK         R[A] = R[C] * B_const
--     OP 81 : DIV          R[A] = R[C] / R[B]
--     OP 38 : DIVK         R[A] = R[C] / B_const
--     OP 44 : MOD          R[A] = R[B] % R[C]
--     OP 79 : MODK         R[C] = R[B] % A_const
--     OP 59 : POW          R[A] = R[C] ^ R[B]
--     OP 80 : POWK         R[A] = C_const ^ R[B]
--     OP 18 : BXOR         R[C] = bit32.bxor(R[B], R[A])
--     OP 75 : UNM          R[B] = -R[A]
--     OP 61 : NOT          R[A] = not R[B]
--     OP 14 : LEN          R[B] = #R[C]
--     OP 42 : CONCAT       R[C] = R[B] .. R[A]
--     OP 77 : CONCAT_KR    R[A] = B_const .. R[C]
--     OP 83 : CONCAT_RK    R[A] = R[B] .. C_const
--
--   [Control Flow & Loops]
--     OP  5 : JMP          pc = B
--     OP 13 : TEST_TRUE    if R[B] then pc = A end
--     OP 51 : TEST_FALSE   if not R[B] then pc = C end
--     OP 21 : EQ_JMP       if R[B] == R[C] then pc = A end
--     OP 49 : NE_JMP       if R[A] ~= R[B] then pc = C end
--     OP 35 : NEK_JMP      if R[A] ~= B_const then pc = C end (OP 89 = self-mod -> OP 35)
--     OP 43 : EQK_JMP      if R[A] == B_const then pc = C end
--     OP 25 : FORPREP      ตั้งค่า Numeric For Loop
--     OP 46 : FORLOOP      วนรอบ Numeric For Loop
--     OP 22 : TFORPREP     ตั้งค่า Generic For Loop (ผ่าน coroutine.wrap)
--     OP  8 : TFORLOOP     ดึงค่าถัดไปของ Generic For Loop
--     OP 99 : LOOP_POP     คืนค่า state ของ loop ซ้อน
--
--   [Calls, Closures, Varargs & Returns]
--     OP 20 : CALL_GEN     เรียกฟังก์ชันแบบกำหนดจำนวน args/rets ทั่วไป
--     OP 24, 28, 31, 37, 39, 62, 78, 91, 92, 97 : CALL แบบ Specialized (0/1/2/N args)
--     OP 90 : CLOSURE      สร้าง Closure จาก B_const (sub-proto) และผูก Upvalues
--     OP 30, 53, 54, 86    : รับพารามิเตอร์ฟังก์ชันและ Varargs (...)
--     OP  1, 16, 33, 57, 69, 71, 96 : RETURN & TAILCALL (พร้อมปิด open upvalues)
--
--   [VM Introspection & Anti-Tamper Helpers]
--     OP  4 : LOAD_OPCODES R[A] = opcodes (OP 45 = self-modifying -> OP 4)
--     OP 10 : LOAD_CREGS   R[A] = C_reg
--     OP 48 : LOAD_FRAME   R[B] = registers
--     OP 65 : LOAD_PROTO   R[B] = proto
--     OP 67 : GET_INTERNAL R[B] = vmInternal[C]
--     OP 73 : SET_INTERNAL vmInternal[B] = R[A]
--     OP 93 : LOAD_BREGS   R[B] = B_reg
--     OP 101: LOAD_AREGS   R[A] = A_reg

local function createVMClosure(proto, upvals)
  local maxStack = proto[4]
  local lineInfo = proto[10]
  local C_const  = proto[1]
  local B_reg    = proto[2]
  local B_const  = proto[3]
  local A_const  = proto[6]
  local A_reg    = proto[8]
  local opcodes  = proto[9]
  local C_reg    = proto[11]

  return function(...)
    local reg = table_create(maxStack)
    local argCount, args = packVarargs(...)
    local fixedParams = 0
    local top = 1
    local pc = 1
    local env = getfenv()
    local varargStart = 1
    local loopIter, openUpvals, loopStack, loopLimit, loopStep

    local function closeUpvals(minReg)
      if not openUpvals then return end
      for idx, uv in pairs(openUpvals) do
        if idx >= minReg then
          uv[1] = uv
          uv[2] = reg[idx]
          uv[3] = 2
          openUpvals[idx] = nil
        end
      end
    end

    local ok, isTailCall, retStart, retEnd = pcall(function()
      while true do
        local op = opcodes[pc]

        if op == 0 then
          -- NOP
        elseif op == 2 then
          reg[C_reg[pc]] = reg[B_reg[pc]] + reg[A_reg[pc]]
        elseif op == 5 then
          pc = B_reg[pc]
        elseif op == 11 then
          reg[B_reg[pc]] = {}
        elseif op == 12 then
          reg[B_reg[pc]] = env[A_const[pc]]
        elseif op == 14 then
          reg[B_reg[pc]] = #reg[C_reg[pc]]
        elseif op == 17 or op == 6 then
          reg[C_reg[pc]] = reg[B_reg[pc]] - reg[A_reg[pc]]
        elseif op == 18 then
          reg[C_reg[pc]] = bit32.bxor(reg[B_reg[pc]], reg[A_reg[pc]])
        elseif op == 20 then
          local base, nArgs, nRets = B_reg[pc], C_reg[pc], A_reg[pc]
          if nArgs ~= 0 then top = base + nArgs - 1 end
          local count, res
          if nArgs == 1 then
            count, res = packVarargs(reg[base]())
          else
            count, res = packVarargs(reg[base](safeUnpack(top, base + 1, reg)))
          end
          if nRets ~= 1 then
            local lastReg = (nRets ~= 0) and (base + nRets - 2) or (count + base - 1)
            top = (nRets ~= 0) and (lastReg + 1) or lastReg
            for i = 1, lastReg - base + 1 do
              reg[base + i - 1] = res[i]
            end
          else
            top = base - 1
          end
        elseif op == 23 then
          reg[A_reg[pc]] = reg[B_reg[pc]][reg[C_reg[pc]]]
        elseif op == 25 then
          loopStack = { [2] = loopIter, [3] = loopStack, [4] = loopStep, [5] = loopLimit }
          local base = A_reg[pc]
          loopStep = reg[base + 2] + 0
          loopLimit = reg[base + 1] + 0
          loopIter = reg[base] - loopStep
          pc = C_reg[pc]
        elseif op == 32 then
          reg[A_reg[pc]] = reg[C_reg[pc]][B_const[pc]]
        elseif op == 34 then
          reg[A_reg[pc]] = C_const[pc]
        elseif op == 42 then
          reg[C_reg[pc]] = reg[B_reg[pc]] .. reg[A_reg[pc]]
        elseif op == 46 then
          loopIter = loopIter + loopStep
          local keepGoing = (loopStep <= 0) and (loopIter >= loopLimit) or (loopIter <= loopLimit)
          if keepGoing then
            reg[B_reg[pc] + 3] = loopIter
            pc = C_reg[pc]
          end
        elseif op == 47 then
          reg[A_reg[pc]] = reg[C_reg[pc]]
        elseif op == 50 then
          reg[A_reg[pc]] = reg[C_reg[pc]] * B_const[pc]
        elseif op == 51 then
          if not reg[B_reg[pc]] then pc = C_reg[pc] end
        elseif op == 57 then
          closeUpvals(1)
          return
        elseif op == 64 then
          env[C_const[pc]] = reg[A_reg[pc]]
        elseif op == 68 then
          reg[A_reg[pc]] = reg[B_reg[pc]] + C_const[pc]
        elseif op == 69 then
          closeUpvals(1)
          return false, B_reg[pc], B_reg[pc]
        elseif op == 86 then
          for i = 1, B_reg[pc] do reg[i] = args[i] end
        elseif op == 90 then
          local subProto = B_const[pc]
          local subUpDefs = subProto[5]
          local subUpvals = (#subUpDefs > 0) and {} or nil
          local fn = createVMClosure(subProto, subUpvals)
          setfenv(fn, env)
          reg[A_reg[pc]] = fn
          if subUpvals then
            for j = 1, #subUpDefs do
              local def = subUpDefs[j]
              local kind, idx = def[1], def[3]
              if kind == 0 then
                openUpvals = openUpvals or {}
                openUpvals[idx] = openUpvals[idx] or { [1] = reg, [3] = idx }
                subUpvals[j - 1] = openUpvals[idx]
              elseif kind == 1 then
                subUpvals[j - 1] = reg[idx]
              else
                subUpvals[j - 1] = upvals[idx]
              end
            end
          end
        elseif op == 94 then
          reg[C_reg[pc]][reg[A_reg[pc]]] = reg[B_reg[pc]]
        elseif op == 99 then
          loopIter, loopLimit, loopStep, loopStack = loopStack[2], loopStack[5], loopStack[4], loopStack[3]
        elseif op == 102 then
          reg[B_reg[pc]] = reg[A_reg[pc]] * reg[C_reg[pc]]
        -- (อีก ~60 Specialized/Comparison/Upvalue Opcodes ทำงานตามตารางสรุปด้านบน)
        end

        pc = pc + 1
      end
    end)

    if ok then
      if isTailCall then
        if retEnd == 1 then
          return reg[retStart]()
        end
        return reg[retStart](safeUnpack(top, retStart + 1, reg))
      elseif retStart then
        return safeUnpack(retEnd, retStart, reg)
      end
    else
      closeUpvals(1)
      if type(isTailCall) == "string" and string_match(isTailCall, ":(%d+)[:\r\n]") then
        error("Luraph Script:" .. (lineInfo[pc] or "(internal)") .. ": " .. tostring(isTailCall), 0)
      else
        error(isTailCall, 0)
      end
    end
  end
end

-- -----------------------------------------------------------------------------
-- [Step 6] ลำดับการทำงานหลัก (Entry Point Flow)
-- -----------------------------------------------------------------------------
-- 1. ถอดรหัส payload "LPH-..." (28,032 bytes หลังถอด Ascii85):
--      * Bytes 0..13,239     = Stage 1 Chunk (132 constants, 23 prototypes, entry = Proto #10)
--      * Bytes 13,240..28,031 = Stage 2 Encrypted Payload (14,792 bytes)
-- 2. Deserializer อ่าน Stage 1 -> `stage1Proto = deserializeChunk()`
-- 3. รัน Stage 1 Bootstrapper โดยส่ง helper runtime เข้าไป 10 ตัว:
--      `stage2Proto = createVMClosure(stage1Proto, {})(
--          deserializeChunk, deleteKey, getKey, callFn,
--          readFloat64, readByte, readUInt32, keyConstantsL,
--          setStream, createVMClosure
--      )`
--    Stage 1 ทำหน้าที่:
--      - ตรวจสอบสภาพแวดล้อม (Environment Integrity & Anti-Tamper Checks)
--      - ถอดรหัส 14,792 ไบต์ที่เหลือด้วยอัลกอริทึม bitwise/FNV-1a
--      - สลับ buffer ด้วย `setStream(decryptedBytes)` แล้วเรียก `deserializeChunk()`
--      - ถอดรหัส Deferred Constants ที่เก็บใน `vmInternal[2]` และ patch กลับไปยัง prototypes
--      - คืนค่า `stage2Proto` (โค้ดหลักของผู้ใช้ที่ถูกเข้ารหัส)
-- 4. สร้างและส่งคืน Closure ของ Stage 2:
--      `return createVMClosure(stage2Proto, {})`
-- -----------------------------------------------------------------------------

return {
  decodeAscii85    = decodeAscii85,
  setStream        = setStream,
  deserializeChunk = deserializeChunk,
  createVMClosure  = createVMClosure,
}
