-- =============================================================================
-- input.lua
-- สคริปต์ตัวอย่างสำหรับทดสอบการเข้ารหัสย้อนกลับ (Reverse Encoding Simulation)
-- และเปรียบเทียบผลลัพธ์ระหว่างโค้ดต้นฉบับกับโค้ดที่ผ่าน VM Encoder
-- =============================================================================

local function computeScore(base, multiplier, bonus)
  local total = 0
  for i = 1, 5 do
    total = total + (base * multiplier) + i
  end
  total = total + bonus
  return total
end

local greeting = "Static Analysis Verified"
local score = computeScore(10, 3, 7)
local summary = greeting .. " | Score=" .. score

print(summary)
print("Check:", score == 172)
return summary
