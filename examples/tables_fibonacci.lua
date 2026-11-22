-- =============================================================================
-- examples/tables_fibonacci.lua
-- ทดสอบ Table literals, Array indexing, Field access (t.key), #length และ loop
-- =============================================================================

local function buildFib(count)
  local seq = { 1, 1 }
  local i = 3
  while i <= count do
    seq[i] = seq[i - 1] + seq[i - 2]
    i = i + 1
  end
  return seq
end

local fib = buildFib(8)
local meta = { name = "FibVM", count = #fib }
meta.last = fib[#fib]
meta.ratio = meta.last / fib[#fib - 1]

local out = meta.name .. "[" .. meta.count .. "]=" .. meta.last
print(out)
print("F(6):", fib[6], "F(8):", meta.last)
return out
