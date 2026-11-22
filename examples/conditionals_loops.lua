-- =============================================================================
-- examples/conditionals_loops.lua
-- ทดสอบ if / elseif / else, while, repeat..until, ตัวดำเนินการเปรียบเทียบและคณิตศาสตร์
-- =============================================================================

local function classify(n)
  if n % 15 == 0 then
    return "FizzBuzz"
  elseif n % 3 == 0 then
    return "Fizz"
  elseif n % 5 == 0 then
    return "Buzz"
  else
    return "Num"
  end
end

local sum = 0
local k = 1
while k <= 10 do
  if k % 2 ~= 0 then
    sum = sum + (k ^ 2)
  end
  k = k + 1
end

local countdown = 3
local trace = ""
repeat
  trace = trace .. countdown .. "-"
  countdown = countdown - 1
until countdown <= 0

local neg = -sum
local flag = not (neg > 0)

print("FizzBuzz(15):", classify(15))
print("OddSqSum:", sum, "Neg:", neg, "Flag:", flag)
print("Trace:", trace)
return classify(15) .. ":" .. sum .. ":" .. trace
