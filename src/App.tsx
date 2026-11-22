import { useMemo, useState } from 'react';
import {
  Binary,
  Check,
  Code2,
  Copy,
  Cpu,
  Download,
  FileCode2,
  Play,
  RotateCcw,
  Search,
  Terminal,
} from 'lucide-react';
import decodedLuaRaw from '../decoded.lua?raw';
import defaultInputLua from '../input.lua?raw';
import {
  ANALYZED_OPCODES,
  FORMAT_CONSTANTS,
  MODE,
  OP_NAMES,
  compileLuaToChunk,
  decodeAscii85,
  deserializeChunk,
  encodeAscii85,
  executeChunk,
  generateEncodedLua,
  serializeChunk,
  type EmitterStyle,
  type LuaDialect,
  type OpcodeCategory,
  type VMChunk,
} from './lib/vmEngine';

type NavTab = 'overview' | 'opcodes' | 'decoded' | 'encoder';

const OPCODE_CATEGORIES: ('All' | OpcodeCategory)[] = [
  'All',
  'Movement',
  'Tables & Upvalues',
  'Arithmetic & String',
  'Control Flow',
  'Calls & Returns',
  'VM Introspection',
];

const OBFUSCATION_LAYERS = [
  {
    layer: '01',
    name: 'Wrapper Argument Injection',
    detail:
      'ส่ง standard libraries และค่าคงที่ 39 พารามิเตอร์ (table.move, bit32, string.pack/unpack, getfenv/setfenv, select, unpack, key table L) เข้า anonymous function เพื่อลดการเรียก global โดยตรง',
  },
  {
    layer: '02',
    name: 'Control-Flow Flattening (CFF)',
    detail:
      'ใช้ลูป while true / repeat..until คุมด้วยตัวแปร state p พร้อมตาราง memoization R ที่คำนวณ state ถัดไปด้วย bit32',
  },
  {
    layer: '03',
    name: 'Numeric & Literal Obfuscation',
    detail:
      'เข้ารหัสตัวเลขด้วยฐานสิบหก (0X...), ฐานสอง (0B...), ตัวคั่น underscore (0b100_00) และ escape sequence (\\z, \\u{...})',
  },
  {
    layer: '04',
    name: 'Ascii85 (Base85) Payload ("LPH-")',
    detail:
      'ตัด header "LPH-" 4 ตัวอักษร, ขยาย "z" เป็น "!!!!!" (4 zero bytes), แปลงทีละ 5 ตัวอักษรฐาน 85 (offset 33) เป็น >I4 ได้ binary ขนาด 28,032 ไบต์',
  },
  {
    layer: '05',
    name: 'LEB128 Biased Binary Serialization',
    detail:
      'บวกค่า bias กับจำนวน constants (+0x12074), prototypes (+0xE81A), instructions (+39325) พร้อม signed 53-bit varint และ bit-packed operand (val * 8 + mode)',
  },
  {
    layer: '06',
    name: 'Two-Stage VM & Self-Modifying Opcodes',
    detail:
      'Register-based VM 104 opcodes (0..103) ใช้ binary-search if/else ลึก 7 ชั้น พร้อม self-modifying opcodes (6→17, 36→87, 45→4, 89→35) และโหลด Stage 2 แบบ deferred constants',
  },
];

const BINARY_SPEC_ROWS = [
  { field: 'Payload Prefix', value: '"LPH-"', encoding: '4 ASCII bytes + Ascii85 ("z" = 0x00000000)' },
  { field: 'numConsts', value: 'varint - 0x12074', encoding: 'Unsigned LEB128 (bias 73,844)' },
  { field: 'deferredFlag', value: 'uint8 ~= 0', encoding: '1 byte (เปิดโหมด deferred constant patching)' },
  { field: 'Constant Tag <= 8', value: 'int64', encoding: 'Little-Endian <i8 (8 bytes)' },
  { field: 'Constant Tag 9..13', value: 'float64', encoding: 'IEEE-754 Little-Endian <d (8 bytes)' },
  { field: 'Constant Tag 0xE3 (227)', value: 'boolean', encoding: '1 byte (1 = true, 0 = false)' },
  { field: 'Constant Tag (other)', value: 'string', encoding: 'Unsigned LEB128 length + raw bytes' },
  { field: 'numProtos', value: 'varint - 0xE81A', encoding: 'Unsigned LEB128 (bias 59,418)' },
  { field: 'Line Info (RLE)', value: 'uint32 count', encoding: 'เลขคู่ = บรรทัดเดียว (n/2), เลขคี่ = ช่วง [n/2..end]' },
  { field: 'Upvalue Descriptor', value: 'idx * 4 + kind', encoding: 'kind: 0=local, 1=by-val, 2=parent upval' },
  { field: 'numInsts', value: 'varint - 39325', encoding: 'Unsigned LEB128 (bias 39,325)' },
  { field: 'Instruction Operands', value: 'val * 8 + mode', encoding: '4 Signed 53-bit varints (A, B, C, op); mode 1=reg, 2=const, 4=proto' },
];

function downloadTextFile(filename: string, content: string) {
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function formatOperand(val: number, mode: number, resolved: unknown): string {
  if (mode === MODE.NONE) return '—';
  if (mode === MODE.REG) return `R${val}`;
  if (mode === MODE.CONST) return `K[${val}] (${JSON.stringify(resolved)})`;
  if (mode === MODE.PROTO) return `P#${val}`;
  return `${val}:${mode}`;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [opcodeQuery, setOpcodeQuery] = useState('');
  const [opcodeCategory, setOpcodeCategory] = useState<'All' | OpcodeCategory>('All');
  const [decodedQuery, setDecodedQuery] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Reverse Encoder state
  const [luaInput, setLuaInput] = useState(defaultInputLua);
  const [xorKeyHex, setXorKeyHex] = useState('5A');
  const [emitterStyle, setEmitterStyle] = useState<EmitterStyle>('luraph');
  const [luaDialect, setLuaDialect] = useState<LuaDialect>('luau');
  const [seed, setSeed] = useState<number>(0x143a7);
  const [outputMode, setOutputMode] = useState<'lua' | 'ascii85' | 'disasm'>('lua');

  const copyText = (key: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    window.setTimeout(() => {
      setCopiedKey((prev) => (prev === key ? null : prev));
    }, 1800);
  };

  const filteredOpcodes = useMemo(() => {
    const q = opcodeQuery.trim().toLowerCase();
    return ANALYZED_OPCODES.filter((op) => {
      if (opcodeCategory !== 'All' && op.category !== opcodeCategory) return false;
      if (!q) return true;
      return (
        String(op.code).includes(q) ||
        op.mnemonic.toLowerCase().includes(q) ||
        op.semantics.toLowerCase().includes(q) ||
        (op.note && op.note.toLowerCase().includes(q))
      );
    });
  }, [opcodeQuery, opcodeCategory]);

  const decodedLines = useMemo(() => decodedLuaRaw.split('\n'), []);
  const matchingDecodedLines = useMemo(() => {
    const q = decodedQuery.trim().toLowerCase();
    if (!q) return null;
    const matches = new Set<number>();
    decodedLines.forEach((line, idx) => {
      if (line.toLowerCase().includes(q)) matches.add(idx);
    });
    return matches;
  }, [decodedLines, decodedQuery]);

  const parsedXorKey = useMemo(() => {
    const cleaned = xorKeyHex.replace(/^0x/i, '').trim();
    if (!cleaned) return 0;
    const n = Number.parseInt(cleaned, 16);
    if (Number.isNaN(n)) return 0;
    return Math.max(0, Math.min(255, n));
  }, [xorKeyHex]);

  const encoderRun = useMemo(() => {
    try {
      const compiled = compileLuaToChunk(luaInput);
      const binary = serializeChunk(compiled, parsedXorKey);
      const ascii85 = encodeAscii85(binary);
      const generated = generateEncodedLua(ascii85, parsedXorKey, {
        style: emitterStyle,
        dialect: luaDialect,
        seed,
      });
      const encodedLua = generated.code;

      // Verify all generated CFF bit32 state transitions mathematically
      const cffVerified = generated.cffChecks.every((ch) => {
        const computed =
          ch.delta +
          ((((generated.keyTableL[ch.i1 - 1] ^ generated.keyTableL[ch.i2 - 1]) >>> 0) &
            ch.mask) >>>
            0);
        return computed === ch.nextState;
      });

      // Extract LPH- back out of the generated Lua file just like test-compare.mjs
      const match = encodedLua.match(/"(LPH-(?:\\.|[^"\\])*)"/);
      if (!match) {
        throw new Error('Could not extract LPH- payload from generated Lua output');
      }
      const extracted = match[1].replace(/\\(.)/g, '$1');
      const decodedBytes = decodeAscii85(extracted);
      const roundTripped: VMChunk = deserializeChunk(decodedBytes, parsedXorKey);

      // Compare direct compiled execution (with plaintext round-trip) vs full encoded round-trip
      const directChunk = deserializeChunk(serializeChunk(compiled, 0), 0);
      const directResult = executeChunk(directChunk);
      const roundTripResult = executeChunk(roundTripped);

      const logsMatch =
        JSON.stringify(directResult.logs) === JSON.stringify(roundTripResult.logs);
      const returnMatch = directResult.returnValue === roundTripResult.returnValue;

      return {
        ok: true as const,
        compiled,
        binaryLength: binary.length,
        decodedLength: decodedBytes.length,
        ascii85,
        encodedLua,
        cffCount: generated.cffChecks.length,
        cffVerified,
        opcodeCount: generated.opcodeCount,
        roundTripped,
        directResult,
        roundTripResult,
        passed: logsMatch && returnMatch && cffVerified,
      };
    } catch (err) {
      return {
        ok: false as const,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }, [luaInput, parsedXorKey, emitterStyle, luaDialect, seed]);

  const navItems: { id: NavTab; label: string; icon: typeof Binary; meta: string }[] = [
    { id: 'overview', label: 'Static Analysis', icon: Binary, meta: 'Luraph v14.3' },
    { id: 'opcodes', label: 'Opcode Map', icon: Cpu, meta: '104 ops' },
    { id: 'decoded', label: 'decoded.lua', icon: FileCode2, meta: `${decodedLines.length} lines` },
    { id: 'encoder', label: 'Reverse Encoder', icon: Terminal, meta: 'Round-Trip' },
  ];

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col lg:flex-row">
      {/* Sidebar Navigation */}
      <aside className="w-full lg:w-64 shrink-0 bg-white border-b lg:border-b-0 lg:border-r border-slate-200 flex flex-col">
        <div className="px-5 py-4 border-b border-slate-200">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded bg-slate-900 text-white flex items-center justify-center">
              <Code2 className="w-4 h-4" />
            </div>
            <div>
              <h1 className="text-sm font-semibold tracking-tight text-slate-900">
                Lua VM Analyzer
              </h1>
              <p className="text-xs text-slate-500">Static Analysis Workbench</p>
            </div>
          </div>
        </div>

        <nav className="p-2.5 flex lg:flex-col gap-1 overflow-x-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center justify-between gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors whitespace-nowrap cursor-pointer ${
                  active
                    ? 'bg-slate-900 text-white'
                    : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                }`}
              >
                <span className="flex items-center gap-2.5">
                  <Icon className="w-4 h-4 shrink-0" />
                  <span>{item.label}</span>
                </span>
                <span
                  className={`text-xs font-mono tabular-nums ${
                    active ? 'text-slate-300' : 'text-slate-400'
                  }`}
                >
                  {item.meta}
                </span>
              </button>
            );
          })}
        </nav>

        <div className="hidden lg:block mt-auto p-4 border-t border-slate-200 text-xs text-slate-500 space-y-1.5">
          <div className="font-medium text-slate-700">Target Sample</div>
          <div className="font-mono text-slate-600 truncate">loader.lua_5e4ba8d7.txt</div>
          <div className="font-mono tabular-nums text-slate-500">
            70,296 B · Ascii85 28,032 B
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 min-w-0 flex flex-col">
        {/* Top Bar */}
        <header className="bg-white border-b border-slate-200 px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
          <div>
            <div className="text-xs font-mono text-slate-500">
              Luraph Obfuscator v14.3 · Static Structural Analysis · Clean-Room Simulation
            </div>
            <h2 className="text-base font-semibold text-slate-900 mt-0.5">
              {activeTab === 'overview' && 'Obfuscation Architecture & Binary Format Specification'}
              {activeTab === 'opcodes' && 'Reconstructed Register-VM Opcode Table (0..103)'}
              {activeTab === 'decoded' && 'decoded.lua — Reconstructed VM & Deserializer Logic'}
              {activeTab === 'encoder' && 'Reverse Encoder Simulator & Round-Trip Output Verifier'}
            </h2>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => downloadTextFile('decoded.lua', decodedLuaRaw)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-slate-200 bg-white text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              decoded.lua
            </button>
            <button
              type="button"
              onClick={() => {
                setActiveTab('encoder');
              }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-blue-600 text-xs font-medium text-white hover:bg-blue-700 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5" />
              Open Encoder
            </button>
          </div>
        </header>

        <main className="p-6 max-w-6xl w-full space-y-6">
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <>
              {/* Key Metrics Row */}
              <section className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-white border border-slate-200 rounded-lg p-4">
                  <div className="text-xs text-slate-500">Source File Size</div>
                  <div className="mt-1 text-xl font-semibold font-mono tabular-nums text-slate-900">
                    70,296 B
                  </div>
                  <div className="mt-1 text-xs text-slate-500">Luraph v14.3 wrapper</div>
                </div>
                <div className="bg-white border border-slate-200 rounded-lg p-4">
                  <div className="text-xs text-slate-500">Decoded Ascii85 Stream</div>
                  <div className="mt-1 text-xl font-semibold font-mono tabular-nums text-slate-900">
                    28,032 B
                  </div>
                  <div className="mt-1 text-xs text-slate-500">Stage 1 + Stage 2 payload</div>
                </div>
                <div className="bg-white border border-slate-200 rounded-lg p-4">
                  <div className="text-xs text-slate-500">Stage 1 Structure</div>
                  <div className="mt-1 text-xl font-semibold font-mono tabular-nums text-slate-900">
                    132 K · 23 P
                  </div>
                  <div className="mt-1 text-xs text-slate-500">Entry Proto #10</div>
                </div>
                <div className="bg-white border border-slate-200 rounded-lg p-4">
                  <div className="text-xs text-slate-500">VM Dispatch Space</div>
                  <div className="mt-1 text-xl font-semibold font-mono tabular-nums text-slate-900">
                    104 Opcodes
                  </div>
                  <div className="mt-1 text-xs text-slate-500">7-level binary-search tree</div>
                </div>
              </section>

              {/* Two-Stage Payload Map */}
              <section className="bg-white border border-slate-200 rounded-lg p-5 space-y-4">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <h3 className="text-sm font-semibold text-slate-900">
                    Two-Stage Binary Payload Layout (28,032 bytes)
                  </h3>
                  <span className="text-xs font-mono text-slate-500">
                    Header: "LPH-" · Big-Endian &gt;I4 chunks
                  </span>
                </div>

                <div className="w-full h-9 rounded-md overflow-hidden flex border border-slate-200 font-mono text-xs">
                  <div
                    className="bg-slate-900 text-white flex items-center justify-center px-3"
                    style={{ width: '47.2%' }}
                  >
                    Stage 1: 0..13,239 (13,240 B · 47.2%)
                  </div>
                  <div
                    className="bg-slate-100 text-slate-700 flex items-center justify-center px-3 border-l border-slate-300"
                    style={{ width: '52.8%' }}
                  >
                    Stage 2: 13,240..28,031 (14,792 B · 52.8%)
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs text-slate-600 leading-relaxed pt-1">
                  <div>
                    <div className="font-semibold text-slate-900 mb-1">
                      Stage 1 — Bootstrapper &amp; Environment Integrity (Bytes 0..13,239)
                    </div>
                    อ่านด้วย <code className="text-slate-900">deserializeChunk()</code> ทันทีหลังถอด
                    Ascii85 ประกอบด้วย 132 constants (ชื่อฟังก์ชันมาตรฐาน, metamethods, ค่าคงที่ FNV-1a{' '}
                    <code className="text-slate-900">2166136261 / 16777619</code>, ตาราง{' '}
                    <code className="text-slate-900">LPH_NO_UPVALUES</code>) และ 23 prototypes เริ่มต้นที่
                    Proto #10
                  </div>
                  <div>
                    <div className="font-semibold text-slate-900 mb-1">
                      Stage 2 — Deferred Encrypted Inner Chunk (Bytes 13,240..28,031)
                    </div>
                    ถูกโหลดใน runtime หลัง Stage 1 ผ่านการตรวจสอบและส่ง stream ใหม่เข้า{' '}
                    <code className="text-slate-900">setStream(HO)</code> +{' '}
                    <code className="text-slate-900">deserializeChunk(FO)</code> ในโหมด{' '}
                    <code className="text-slate-900">deferred = true</code> (เก็บ ref ไว้ใน{' '}
                    <code className="text-slate-900">vmInternal[2..3]</code> เพื่อ patch constant ทีหลัง)
                  </div>
                </div>
              </section>

              {/* Obfuscation Layers */}
              <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
                <div className="px-5 py-3.5 border-b border-slate-200 flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-slate-900">
                    Obfuscation Techniques Identified (6 Layers)
                  </h3>
                  <span className="text-xs text-slate-500">Static Analysis Summary</span>
                </div>
                <div className="divide-y divide-slate-200">
                  {OBFUSCATION_LAYERS.map((item) => (
                    <div
                      key={item.layer}
                      className="px-5 py-3.5 grid grid-cols-1 md:grid-cols-12 gap-2 md:gap-4 items-baseline"
                    >
                      <div className="md:col-span-4 flex items-baseline gap-2.5">
                        <span className="font-mono text-xs text-slate-400 tabular-nums">
                          {item.layer}
                        </span>
                        <span className="text-sm font-medium text-slate-900">{item.name}</span>
                      </div>
                      <p className="md:col-span-8 text-xs text-slate-600 leading-relaxed">
                        {item.detail}
                      </p>
                    </div>
                  ))}
                </div>
              </section>

              {/* Binary Format Table */}
              <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
                <div className="px-5 py-3.5 border-b border-slate-200">
                  <h3 className="text-sm font-semibold text-slate-900">
                    Binary Deserializer Specification (Extracted Constants &amp; Wire Layout)
                  </h3>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs">
                    <thead>
                      <tr className="border-b border-slate-200 bg-slate-50 text-slate-500">
                        <th className="py-2.5 px-5 font-medium">Field</th>
                        <th className="py-2.5 px-5 font-medium">Decoded Value / Formula</th>
                        <th className="py-2.5 px-5 font-medium">Wire Encoding</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200">
                      {BINARY_SPEC_ROWS.map((row) => (
                        <tr key={row.field} className="hover:bg-slate-50/70">
                          <td className="py-2.5 px-5 font-medium text-slate-900 whitespace-nowrap">
                            {row.field}
                          </td>
                          <td className="py-2.5 px-5 font-mono text-blue-700 whitespace-nowrap">
                            {row.value}
                          </td>
                          <td className="py-2.5 px-5 text-slate-600">{row.encoding}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          )}

          {/* TAB 2: OPCODE MAP */}
          {activeTab === 'opcodes' && (
            <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
              <div className="p-4 border-b border-slate-200 flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div className="relative flex-1 max-w-sm">
                  <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={opcodeQuery}
                    onChange={(e) => setOpcodeQuery(e.target.value)}
                    placeholder="ค้นหาเลข opcode, ชื่อคำสั่ง หรือ semantics..."
                    className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded-md focus:outline-none focus:border-blue-500 focus:bg-white"
                  />
                </div>
                <div className="flex flex-wrap items-center gap-1">
                  {OPCODE_CATEGORIES.map((cat) => (
                    <button
                      key={cat}
                      type="button"
                      onClick={() => setOpcodeCategory(cat)}
                      className={`px-2.5 py-1 text-xs rounded-md font-medium transition-colors cursor-pointer ${
                        opcodeCategory === cat
                          ? 'bg-slate-900 text-white'
                          : 'text-slate-600 hover:bg-slate-100'
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-200 bg-slate-50 text-slate-500">
                      <th className="py-2.5 px-4 font-medium w-20">Op</th>
                      <th className="py-2.5 px-4 font-medium w-40">Mnemonic</th>
                      <th className="py-2.5 px-4 font-medium w-44">Category</th>
                      <th className="py-2.5 px-4 font-medium">Reconstructed Semantics</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-200">
                    {filteredOpcodes.map((item) => (
                      <tr key={item.code} className="hover:bg-slate-50/70">
                        <td className="py-2.5 px-4 font-mono tabular-nums font-semibold text-slate-900">
                          {String(item.code).padStart(3, '0')}
                        </td>
                        <td className="py-2.5 px-4 font-mono font-medium text-blue-700">
                          {item.mnemonic}
                        </td>
                        <td className="py-2.5 px-4 text-slate-500">{item.category}</td>
                        <td className="py-2.5 px-4 font-mono text-slate-700">
                          {item.semantics}
                          {item.note && (
                            <span className="ml-2 text-amber-700 font-sans font-medium">
                              · {item.note}
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                    {filteredOpcodes.length === 0 && (
                      <tr>
                        <td colSpan={4} className="py-8 text-center text-slate-500">
                          ไม่พบ opcode ที่ตรงกับเงื่อนไขการค้นหา
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              <div className="px-4 py-2.5 bg-slate-50 border-t border-slate-200 text-xs text-slate-500 flex items-center justify-between">
                <span>
                  แสดง {filteredOpcodes.length} จาก {ANALYZED_OPCODES.length} core opcodes (รวม specialized CALL/RETURN/VARARG ทั้งหมด 104 opcodes: 0..103)
                </span>
                <span className="font-mono">Self-mod: 6→17 · 36→87 · 45→4 · 89→35</span>
              </div>
            </section>
          )}

          {/* TAB 3: DECODED.LUA VIEWER */}
          {activeTab === 'decoded' && (
            <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3 flex-1 min-w-[220px]">
                  <span className="font-mono text-xs font-medium text-slate-900">decoded.lua</span>
                  <span className="text-xs text-slate-400">·</span>
                  <span className="text-xs font-mono tabular-nums text-slate-500">
                    {decodedLines.length} lines · {decodedLuaRaw.length.toLocaleString()} chars
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      value={decodedQuery}
                      onChange={(e) => setDecodedQuery(e.target.value)}
                      placeholder="ค้นหาใน decoded.lua..."
                      className="pl-8 pr-3 py-1 text-xs bg-slate-50 border border-slate-200 rounded-md focus:outline-none focus:border-blue-500 focus:bg-white w-52"
                    />
                  </div>
                  <button
                    type="button"
                    onClick={() => copyText('decoded', decodedLuaRaw)}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-slate-200 text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer"
                  >
                    {copiedKey === 'decoded' ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                        Copied
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        Copy
                      </>
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={() => downloadTextFile('decoded.lua', decodedLuaRaw)}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-slate-200 text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    Download
                  </button>
                </div>
              </div>

              {matchingDecodedLines && (
                <div className="px-4 py-2 bg-blue-50 border-b border-blue-100 text-xs text-blue-800">
                  พบคำว่า &ldquo;{decodedQuery}&rdquo; ทั้งหมด{' '}
                  <span className="font-mono font-semibold">{matchingDecodedLines.size}</span> บรรทัด
                </div>
              )}

              <div className="max-h-[68vh] overflow-auto bg-slate-950 text-slate-100 font-mono text-xs leading-relaxed">
                <table className="w-full border-collapse">
                  <tbody>
                    {decodedLines.map((line, i) => {
                      const isMatch = matchingDecodedLines?.has(i);
                      if (matchingDecodedLines && !isMatch) return null;
                      return (
                        <tr
                          key={i}
                          className={isMatch ? 'bg-blue-950/70' : 'hover:bg-slate-900/80'}
                        >
                          <td className="select-none text-right pr-4 pl-4 py-0.5 text-slate-500 tabular-nums w-12 align-top border-r border-slate-800">
                            {i + 1}
                          </td>
                          <td className="pl-4 pr-4 py-0.5 whitespace-pre text-slate-100">
                            {line || ' '}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* TAB 4: REVERSE ENCODER & VERIFIER */}
          {activeTab === 'encoder' && (
            <div className="space-y-5">
              {/* CLI Reference Strip */}
              <section className="bg-white border border-slate-200 rounded-lg p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="text-xs font-semibold text-slate-900">
                    Node.js CLI Commands (Workspace Root)
                  </div>
                  <div className="text-xs text-slate-500">
                    สคริปต์จริงในโปรเจกต์:{' '}
                    <code className="text-slate-800">encoder.mjs</code> ·{' '}
                    <code className="text-slate-800">input.lua</code> ·{' '}
                    <code className="text-slate-800">test-compare.mjs</code>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <code className="px-3 py-1.5 bg-slate-900 text-slate-100 rounded text-xs font-mono">
                    node encoder.mjs input.lua output_encoded.lua
                  </code>
                  <code className="px-3 py-1.5 bg-slate-900 text-slate-100 rounded text-xs font-mono">
                    node test-compare.mjs
                  </code>
                </div>
              </section>

              {/* Two-column Workspace */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 items-start">
                {/* Left: Input Lua Editor */}
                <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
                  <div className="px-4 py-3 border-b border-slate-200 space-y-2.5">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <div className="text-xs font-semibold text-slate-900">
                          Source Script (input.lua)
                        </div>
                        <div className="text-xs text-slate-500">
                          แก้ไขโค้ดเพื่อทดสอบคอมไพล์และเข้ารหัสแบบ Luraph-Style real-time
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          setLuaInput(defaultInputLua);
                          setXorKeyHex('5A');
                          setEmitterStyle('luraph');
                          setLuaDialect('luau');
                          setSeed(0x143a7);
                        }}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md border border-slate-200 text-xs font-medium text-slate-600 hover:bg-slate-50 cursor-pointer"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                        Reset
                      </button>
                    </div>

                    <div className="flex flex-wrap items-center gap-3 pt-1 text-xs">
                      <div className="flex items-center gap-1">
                        {(
                          [
                            ['luraph', 'Luraph-Style'],
                            ['readable', 'Readable VM'],
                          ] as const
                        ).map(([id, label]) => (
                          <button
                            key={id}
                            type="button"
                            onClick={() => setEmitterStyle(id)}
                            className={`px-2 py-1 rounded text-xs font-medium cursor-pointer ${
                              emitterStyle === id
                                ? 'bg-slate-900 text-white'
                                : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                            }`}
                          >
                            {label}
                          </button>
                        ))}
                      </div>

                      {emitterStyle === 'luraph' && (
                        <>
                          <div className="flex items-center gap-1">
                            {(
                              [
                                ['luau', 'Luau (0B/0X/_)'],
                                ['lua53', 'Lua 5.3'],
                              ] as const
                            ).map(([id, label]) => (
                              <button
                                key={id}
                                type="button"
                                onClick={() => setLuaDialect(id)}
                                className={`px-2 py-1 rounded text-xs font-medium cursor-pointer ${
                                  luaDialect === id
                                    ? 'bg-blue-600 text-white'
                                    : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                                }`}
                              >
                                {label}
                              </button>
                            ))}
                          </div>
                          <button
                            type="button"
                            onClick={() => setSeed((s) => ((s * 1664525 + 1013904223) >>> 0) % 0xfffff)}
                            className="px-2 py-1 rounded border border-slate-200 font-mono text-slate-600 hover:bg-slate-50 cursor-pointer"
                            title="สุ่ม Seed ใหม่เพื่อเปลี่ยนเลข state CFF, ตาราง L และรูป literal"
                          >
                            Seed 0x{seed.toString(16).toUpperCase()}
                          </button>
                        </>
                      )}

                      <label className="flex items-center gap-1 text-slate-600 ml-auto">
                        <span>XOR: 0x</span>
                        <input
                          type="text"
                          value={xorKeyHex}
                          onChange={(e) => setXorKeyHex(e.target.value.slice(0, 2).toUpperCase())}
                          className="w-11 px-1.5 py-0.5 font-mono text-xs bg-slate-50 border border-slate-200 rounded text-slate-900 focus:outline-none focus:border-blue-500"
                          title="Hex byte 00..FF (00 = plaintext, 5A = deferred XOR)"
                        />
                      </label>
                    </div>
                  </div>
                  <textarea
                    value={luaInput}
                    onChange={(e) => setLuaInput(e.target.value)}
                    spellCheck={false}
                    rows={20}
                    className="w-full p-4 font-mono text-xs leading-relaxed bg-slate-950 text-slate-100 focus:outline-none resize-y"
                  />
                  <div className="px-4 py-2.5 bg-slate-50 border-t border-slate-200 text-xs text-slate-500 font-mono flex items-center justify-between">
                    <span>
                      Biases: K+{FORMAT_CONSTANTS.CONST_COUNT_BIAS} · P+
                      {FORMAT_CONSTANTS.PROTO_COUNT_BIAS} · I+{FORMAT_CONSTANTS.INST_COUNT_BIAS}
                    </span>
                    <span>
                      Mode: {parsedXorKey !== 0 ? `Deferred XOR (0x${parsedXorKey.toString(16).toUpperCase().padStart(2, '0')})` : 'Plaintext'}
                    </span>
                  </div>
                </section>

                {/* Right: Round-Trip Verification & Output Inspector */}
                <div className="space-y-4">
                  {!encoderRun.ok ? (
                    <section className="bg-white border border-red-200 rounded-lg p-5">
                      <div className="text-sm font-semibold text-red-700">
                        Compile / Execution Error
                      </div>
                      <pre className="mt-2 text-xs font-mono text-red-600 whitespace-pre-wrap">
                        {encoderRun.error}
                      </pre>
                    </section>
                  ) : (
                    <>
                      {/* Verification Comparison Card */}
                      <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
                        <div className="px-4 py-3 border-b border-slate-200 flex items-center justify-between">
                          <div className="text-xs font-semibold text-slate-900">
                            Round-Trip Execution Comparison
                          </div>
                          <span
                            className={`text-xs font-mono font-semibold ${
                              encoderRun.passed ? 'text-emerald-700' : 'text-red-700'
                            }`}
                          >
                            {encoderRun.passed ? 'PASS · 100% MATCH' : 'MISMATCH'}
                          </span>
                        </div>

                        <div className="grid grid-cols-2 sm:grid-cols-4 divide-x divide-slate-200 border-b border-slate-200 text-xs">
                          <div className="p-3">
                            <div className="text-slate-500">Raw Binary</div>
                            <div className="font-mono font-semibold tabular-nums text-slate-900 mt-0.5">
                              {encoderRun.binaryLength} B
                            </div>
                          </div>
                          <div className="p-3">
                            <div className="text-slate-500">Ascii85 ("LPH-")</div>
                            <div className="font-mono font-semibold tabular-nums text-slate-900 mt-0.5">
                              {encoderRun.ascii85.length} chars
                            </div>
                          </div>
                          <div className="p-3">
                            <div className="text-slate-500">VM Tree</div>
                            <div className="font-mono font-semibold tabular-nums text-slate-900 mt-0.5">
                              {encoderRun.opcodeCount} ops
                            </div>
                          </div>
                          <div className="p-3">
                            <div className="text-slate-500">CFF bit32 States</div>
                            <div className="font-mono font-semibold tabular-nums text-slate-900 mt-0.5">
                              {encoderRun.cffCount > 0
                                ? `${encoderRun.cffCount}/${encoderRun.cffCount} OK`
                                : 'Off'}
                            </div>
                          </div>
                        </div>

                        <div className="p-4 space-y-3 text-xs">
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            <div>
                              <div className="text-slate-500 font-medium mb-1">
                                Original Execution stdout
                              </div>
                              <pre className="p-2.5 rounded bg-slate-50 border border-slate-200 font-mono text-slate-800 overflow-x-auto">
                                {encoderRun.directResult.logs.length > 0
                                  ? encoderRun.directResult.logs.join('\n')
                                  : '(no stdout)'}
                              </pre>
                            </div>
                            <div>
                              <div className="text-slate-500 font-medium mb-1">
                                Encoded → Decoded VM stdout
                              </div>
                              <pre className="p-2.5 rounded bg-slate-50 border border-slate-200 font-mono text-slate-800 overflow-x-auto">
                                {encoderRun.roundTripResult.logs.length > 0
                                  ? encoderRun.roundTripResult.logs.join('\n')
                                  : '(no stdout)'}
                              </pre>
                            </div>
                          </div>

                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                            <div>
                              <span className="text-slate-500">Original return: </span>
                              <code className="font-mono text-slate-900">
                                {JSON.stringify(encoderRun.directResult.returnValue)}
                              </code>
                            </div>
                            <div>
                              <span className="text-slate-500">Encoded return: </span>
                              <code className="font-mono text-slate-900">
                                {JSON.stringify(encoderRun.roundTripResult.returnValue)}
                              </code>
                            </div>
                          </div>
                        </div>
                      </section>

                      {/* Output Artifacts Viewer */}
                      <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
                        <div className="px-4 py-2.5 border-b border-slate-200 flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-1">
                            {(
                              [
                                ['lua', 'output_encoded.lua'],
                                ['ascii85', 'LPH- Payload'],
                                ['disasm', 'Disassembly'],
                              ] as const
                            ).map(([id, label]) => (
                              <button
                                key={id}
                                type="button"
                                onClick={() => setOutputMode(id)}
                                className={`px-2.5 py-1 rounded text-xs font-medium cursor-pointer ${
                                  outputMode === id
                                    ? 'bg-slate-900 text-white'
                                    : 'text-slate-600 hover:bg-slate-100'
                                }`}
                              >
                                {label}
                              </button>
                            ))}
                          </div>
                          <div className="flex items-center gap-1.5">
                            <button
                              type="button"
                              onClick={() =>
                                copyText(
                                  'output',
                                  outputMode === 'ascii85'
                                    ? encoderRun.ascii85
                                    : encoderRun.encodedLua
                                )
                              }
                              className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-200 text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer"
                            >
                              {copiedKey === 'output' ? (
                                <>
                                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                                  Copied
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3.5 h-3.5" />
                                  Copy
                                </>
                              )}
                            </button>
                            <button
                              type="button"
                              onClick={() =>
                                downloadTextFile('output_encoded.lua', encoderRun.encodedLua)
                              }
                              className="inline-flex items-center gap-1 px-2.5 py-1 rounded border border-slate-200 text-xs font-medium text-slate-700 hover:bg-slate-50 cursor-pointer"
                            >
                              <Download className="w-3.5 h-3.5" />
                              .lua
                            </button>
                          </div>
                        </div>

                        {outputMode === 'ascii85' && (
                          <div className="p-4 space-y-3">
                            <div className="text-xs text-slate-500">
                              Ascii85 Encoded Stream (Header <code className="text-slate-800">LPH-</code>,
                              4-byte aligned {encoderRun.decodedLength} B)
                            </div>
                            <pre className="p-3 rounded bg-slate-950 text-slate-100 font-mono text-xs break-all whitespace-pre-wrap max-h-60 overflow-auto">
                              {encoderRun.ascii85}
                            </pre>
                            <div className="text-xs text-slate-500">
                              Decoded Constant Pool ({encoderRun.roundTripped.consts.length} items):
                            </div>
                            <div className="font-mono text-xs bg-slate-50 border border-slate-200 rounded p-2.5 text-slate-700 break-words">
                              {encoderRun.roundTripped.consts
                                .map((c, idx) => `[${idx + 1}]=${JSON.stringify(c)}`)
                                .join('  ·  ')}
                            </div>
                          </div>
                        )}

                        {outputMode === 'disasm' && (
                          <div className="max-h-96 overflow-auto divide-y divide-slate-200">
                            {encoderRun.roundTripped.protos.map((proto, pIdx) => (
                              <div key={pIdx} className="p-3.5 space-y-2">
                                <div className="text-xs font-mono font-semibold text-slate-900">
                                  Proto #{pIdx + 1}
                                  {pIdx + 1 === encoderRun.roundTripped.entryIdx ? ' (ENTRY)' : ''}{' '}
                                  · params={proto.numParams} · maxStack={proto.maxStack} ·{' '}
                                  {proto.insts.length} insts
                                </div>
                                <div className="overflow-x-auto">
                                  <table className="w-full text-left font-mono text-[11px] border-collapse">
                                    <thead>
                                      <tr className="text-slate-400 border-b border-slate-200">
                                        <th className="py-1 pr-2">PC</th>
                                        <th className="py-1 pr-2">OP</th>
                                        <th className="py-1 pr-2">A</th>
                                        <th className="py-1 pr-2">B</th>
                                        <th className="py-1">C</th>
                                      </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-100">
                                      {proto.insts.map((inst, iIdx) => (
                                        <tr key={iIdx}>
                                          <td className="py-1 pr-2 text-slate-400 tabular-nums">
                                            {String(iIdx + 1).padStart(2, '0')}
                                          </td>
                                          <td className="py-1 pr-2 text-blue-700 font-medium">
                                            {OP_NAMES[inst.op] || `OP_${inst.op}`} ({inst.op})
                                          </td>
                                          <td className="py-1 pr-2 text-slate-700">
                                            {formatOperand(inst.A, inst.modeA, inst.Ak)}
                                          </td>
                                          <td className="py-1 pr-2 text-slate-700">
                                            {formatOperand(inst.B, inst.modeB, inst.Bk)}
                                          </td>
                                          <td className="py-1 text-slate-700">
                                            {formatOperand(inst.C, inst.modeC, inst.Ck)}
                                          </td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                </div>
                              </div>
                            ))}
                          </div>
                        )}

                        {outputMode === 'lua' && (
                          <div className="bg-slate-950">
                            <div className="px-4 py-2 border-b border-slate-800 text-[11px] font-mono text-slate-400 flex items-center justify-between">
                              <span>
                                {emitterStyle === 'luraph'
                                  ? `Luraph-Style Single-Line (${luaDialect}) · ${encoderRun.encodedLua.length.toLocaleString()} bytes`
                                  : `Readable VM Format · ${encoderRun.encodedLua.length.toLocaleString()} bytes`}
                              </span>
                              <span>Seed 0x{seed.toString(16).toUpperCase()}</span>
                            </div>
                            <pre className="p-4 text-slate-100 font-mono text-[11px] leading-relaxed max-h-96 overflow-auto whitespace-pre-wrap break-all">
                              {encoderRun.encodedLua}
                            </pre>
                          </div>
                        )}
                      </section>
                    </>
                  )}
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
