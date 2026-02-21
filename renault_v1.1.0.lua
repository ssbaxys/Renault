-- ʙᴇᴩᴄия: 1.0.0
-- ʙʏ ꜱꜱʙᴀxʏꜱ
gg.alert("🌟 𝚆𝙴𝙻𝙲𝙾𝙼𝙴 𝚃𝙾 𝚁𝙴𝙽𝙰𝚄𝙻𝚃 𝚂𝙲𝚁𝙸𝙿𝚃 🌟\n\n📌 𝙾𝙵𝙵𝙸𝙲𝙸𝙰𝙻 𝚂𝙸𝚃𝙴: https://renault-site.onrender.com\n💎 𝚃𝙴𝙻𝙴𝙶𝚁𝙰𝙼: https://t.me/SsbaxyS\n💬 𝙾𝙵𝙵𝙸𝙲𝙸𝙰𝙻 𝚃𝙶: https://t.me/ssbaxys_official\n📺 𝚈𝙾𝚄𝚃𝚄𝙱𝙴: https://www.youtube.com/@SsbaxyS\n🛠️ 𝙶𝙸𝚃𝙷𝚄𝙱: https://github.com/Ssbaxys\n🛠️ 𝙶𝙸𝚃𝙷𝚄𝙱 𝟸: https://github.com/SsbaxysS\n\n© Copyrights: @ssbaxys, @ssbaxyss, @SSbaxySLab, @ssbaxys., @ssbi, @sparta")

local gg = gg
local info = gg.getTargetInfo()
local pointerType = (info.x64 == true and gg.TYPE_QWORD or gg.TYPE_DWORD)
local pointerOffset = (info.x64 == true and 0x18 or 0xC)
local metadata = gg.getRangesList("libil2cpp.so")
local VOID = (info.x64 == true and "h C0 03 5F D6" or "h 1E FF 2F E1")

local GetUnityMethod = function(method, flag)
    local results = {}
    gg.clearResults()
    gg.setRanges(gg.REGION_C_ALLOC | gg.REGION_ANONYMOUS | gg.REGION_OTHER | gg.REGION_C_HEAP)
    gg.searchNumber(':' .. method, gg.TYPE_BYTE, false, gg.SIGN_EQUAL, metadata[#metadata and 1 or 1]['start'], metadata[#metadata]['end'], 0)
    local count = gg.getResultsCount()
    if (count ~= 0) then
        gg.refineNumber(tonumber(gg.getResults(1)[1].value) .. '', gg.TYPE_BYTE)
        local t = gg.getResults(count)
        gg.setRanges(gg.REGION_C_ALLOC | gg.REGION_ANONYMOUS)
        gg.loadResults(t)
        gg.searchPointer(0)
        t = gg.getResults(count)
        for i, v in ipairs(t) do
            v.address = v.address - pointerOffset
            v.flags = pointerType
        end
        t = gg.getValues(t)
        for i, v in ipairs(t) do
            table.insert(results, {
                address = v.value,
                flags = flag
            })
        end
        gg.loadResults(results)
    else
        gg.toast(method .. ' Not Found')
    end
end

v = gg.getTargetInfo()
L = v.label
V = v.versionName
function isProcess64Bit()
    local regions = gg.getRangesList()
    local lastAddress = regions[#regions]["end"]
    return (lastAddress >> 32) ~= 0
end
local ISA = isProcess64Bit()
function ISAOffsets()
    if (ISA == false) then
        edi = "+0x"
        ed = "-0x"
    elseif (ISA == true) then
        edi = "0x"
        ed = "-0x"
    end
end
ISAOffsets()
function ISAOffsetss()
    if (ISA == false) then
        edit = "~A B " .. edits
    elseif (ISA == true) then
        edit = "~A8 B\t [PC,#" .. edits .. "]"
    end
end
liby = 1
libf = 0
libzz = "libil2cpp.so"
libx = gg.getRangesList("libil2cpp.so")
for i, v in ipairs(libx) do
    if (libx[i].state == "Xa") then
        libz = "libil2cpp.so[" .. liby .. "].start"
        xand = gg.getRangesList("libil2cpp.so")[liby].start
        libf = 1
        break
    end
    liby = liby + 1
end
if (libf == 0) then
    liby = 1
    libzz = "libUE4.so"
    libx = gg.getRangesList("libUE4.so")
    for i, v in ipairs(libx) do
        if (libx[i].state == "Xa") then
            libz = "libUE4.so[" .. liby .. "].start"
            xand = gg.getRangesList("libUE4.so")[liby].start
            libf = 1
            break
        end
        liby = liby + 1
    end
end
lib = xand
local sf = string.format
function tohex(Data)
    if (type(Data) == "number") then
        return sf("0x%08X", Data)
    end
    return Data:gsub(".", function(a)
        return string.format("%02X", (string.byte(a)))
    end):gsub(" ", "")
end
function __()
    xHEX = string.format("%X", aaaa)
    if (#xHEX > 8) then
        act = (#xHEX - 8) + 1
        xHEX = string.sub(xHEX, act)
    end
    edits = edi .. xHEX
    ISAOffsetss()
end
function _()
    aaa = b - a
    xHEX = string.format("%X", aaa)
    if (#xHEX > 8) then
        act = (#xHEX - 8) + 1
        xHEX = string.sub(xHEX, act)
    end
    edits = ed .. xHEX
    ISAOffsetss()
end
function hook_void(cc, bb)
    LibStart = lib
    local m = {}
    m[1] = {address=(LibStart + bb),flags=gg.TYPE_DWORD}
    gg.addListItems(m)
    a = m[1].address
    gg.clearList()
    local p = {}
    p[1] = {address=(LibStart + cc),flags=gg.TYPE_DWORD}
    gg.addListItems(p)
    gg.loadResults(p)
    endhook = gg.getResults(1)
    local n = {}
    n[1] = {address=(LibStart + cc),flags=gg.TYPE_DWORD}
    gg.addListItems(n)
    b = n[1].address
    gg.clearResults()
    gg.clearList()
    aaaa = a - b
    if (tonumber(aaaa) < 0) then
        _()
    end
    if (tonumber(aaaa) > 0) then
        __()
    end
    local n = {}
    n[1] = {address=(LibStart + cc),flags=gg.TYPE_DWORD,value=edit,freeze=true}
    gg.addListItems(n)
    gg.clearList()
end

gg.alert("ʙᴇᴩᴄия: 1.0.0")
gg.alert("ʀᴇɴᴀᴜʟᴛ ʙʏ ꜱꜱʙᴀxʏꜱ")
function HOME()
  SN = gg.choice({
   	"⛨ 𝙿𝚕𝚊𝚢𝚎𝚛",
       "⛨ 𝚂𝚎𝚛𝚟𝚎𝚛",
       "⛨ 𝙵𝚞𝚗𝚌𝚝𝚒𝚘𝚗𝚜",
       "⛨ 𝚆𝚎𝚊𝚙𝚘𝚗𝚜",
       "⛨ 𝚂𝚔𝚒𝚗𝚜",
       "ᴄᴋоᴩо...",
       "ᴄᴋоᴩо...",
       "ᴄᴋоᴩо...",
       "ᴄᴋоᴩо...",
       "ᴄᴋоᴩо...",
       "ᴄᴋоᴩо...",
       "ᴄᴋоᴩо...",
       "ᴄᴋоᴩо...",
       "ᴄᴋоᴩо...",
       "ᴄᴋоᴩо...",
       "⛨ 𝙴𝚡𝚒𝚝"
}, nil,"ʀᴇɴᴀᴜʟᴛ ϟ 1.0.0")
 if SN == nil then
    else
    if SN == 1 then
      FOLDER1()
      end
    if SN == 2 then
      FOLDER2()
     end
    if SN == 3 then
      FOLDER3()
     end
    if SN == 4 then
      FOLDER4()
     end
    if SN == 5 then
       FOLDER5()
     end
    if SN == 6 then
       FOLDER6()
      end
    if SN == 7 then
       FOLDER7()
      end
     if SN == 8 then
       FOLDER8()
      end
     if SN == 9 then
       FOLDER9()
      end
     if SN == 10 then
       FOLDER10()
      end
     if SN == 11 then
       FOLDER11()
      end
     if SN == 12 then
       FOLDER12()
     end
     if SN == 13 then
       FOLDER13()
     end
     if SN == 14 then
       FOLDER14()
     end
     if SN == 15 then
       FOLDER15()
     end
     if SN == 16 then
        EXIT()
       end
     end
SsbaxyS = -1
end
function FOLDER1()
  MN8 = gg.multiChoice({
          "⛨ 𝙽𝚘𝚌𝚕𝚒𝚙(Fix))",
          "⛨ Я Не помню что была здесь за функция лол",
          "⛨ Flash Speed",
          "⛨ Infinity Jump",
          "⛨ Noclip(ALT)",
          "⛨ Fly",
          "⛨ Immortal",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "⛨ God mod",
          "⛨ Slide floor x2",
          "⛨ Slide jump x2",
          "⛨ Slide car x2",
          "⛨ Freeze Animations",
          "⛨ Invisible",
          "⛨ Teleport",
          "⛨ Bunny Hop",
          "⛨ FOV",
          "⛨ Convulsions",
          "⛨ Free Camera",
          "⛨ Jump Fly",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "⛨ 𝙱𝚊𝚌𝚔"
}, nil,"⛨ 𝙿𝚕𝚊𝚢𝚎𝚛")
    if MN8 == nil then
    else
      if MN8[1] == true then
        HACK1()
      end
      if MN8[2] == true then
        HACK2()
      end
      if MN8[3] == true then
        HACK3()
      end
      if MN8[4] == true then
        HACK4()
      end
      if MN8[5] == true then
        HACK5()
      end
      if MN8[6] == true then
        HACK6()
      end
      if MN8[7] == true then
        HACK7()
      end
      if MN8[8] == true then
        HACK8()
     end
      if MN8[9] == true then
        HACK9()
     end
     if MN8[10] == true then
       HACK10()
     end
     if MN8[11] == true then
       HACK11()
     end
     if MN8[12] == true then
       HACK12()
     end
    if MN8[13] == true then
       HACK13()
    end
    if MN8[14] == true then
       HACK14()
    end
    if MN8[15] == true then
       HACK15()
    end
    if MN8[16] == true then
       HACK16()
    end
    if MN8[17] == true then
       HACK17()
    end
    if MN8[18] == true then
       HACK18()
     end
    if MN8[19] == true then
       HACK19()
     end
   if  MN8[20] == true then
       HACK20()
   end
   if MN8[21] == true then
      HACK21()
   end
   if MN8[22] == true then
     HACK22()
   end
   if MN8[23] == true then
     HACK23()
   end
   if MN8[24] == true then 
     HACK24()
   end
   if MN8[25] == true then
     HOME()
     end
   end
 SsbaxyS = -1
 end

function HACK1()
gg.processPause()
gg.clearResults()
gg.searchNumber("281 479 271 678 208", gg.TYPE_QWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
revert = gg.getResults(5000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("16 777 472", gg.TYPE_QWORD)

gg.clearResults()
gg.searchNumber("3 239 900 611", gg.TYPE_QWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
revert = gg.getResults(4000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("0", gg.TYPE_QWORD)

gg.clearResults()
gg.searchNumber("-10", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
revert = gg.getResults(20000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("999", gg.TYPE_FLOAT)
gg.processResume() 
gg.freeze = true
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK2()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("257698037761Q;60D:20", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
gg.getResults(10000)
gg.editAll("0", gg.TYPE_DWORD) gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
gg.setVisible(false)
end

function HACK3()
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("4515609228873826304Q;4392630932057270955Q", gg.TYPE_QWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
gg.refineNumber("4515609228873826304", gg.TYPE_QWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
revert = gg.getResults(1000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("4515609228892700672", gg.TYPE_QWORD)
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
gg.clearResults()
end

function HACK4()
end

function HACK5()
gg.processPause()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.clearResults()

gg.searchNumber("h7600000040451798760000000001000001000100", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("h7600000040451798760000000001000101000100", gg.TYPE_BYTE)


gg.clearResults()
gg.searchNumber("hC3F51CC1", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
gg.getResults(50000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("h00000000", gg.TYPE_BYTE)


gg.clearResults()
gg.searchNumber("h000020C100000000", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
revert = gg.getResults(50000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("h00426F4900000000", gg.TYPE_BYTE)
gg.processResume() 
addSoafSYSTEM(1)
gg.freeze = true
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
gg.clearResults()
end

function HACK6()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber('1.1', gg.TYPE_FLOAT)
gg.getResults(10000)
gg.editAll('1000', gg.TYPE_FLOAT)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK7()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("1117782016;600.0", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
gg.refineNumber("1117782016", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(10, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("-1", gg.TYPE_DWORD)
gg.clearResults()
gg.searchNumber("70.0;600.0", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
gg.refineNumber("70", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
revert = gg.getResults(10, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("-10", gg.TYPE_FLOAT)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK8()
gg.setVisible(false)
gg.setRanges(gg.REGION_CODE_APP)
gg.searchNumber("h 26 F9 F7 97 FF 43 04 D1 EF 3B 09 6D ED 33 0A 6D", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(6660, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("h 26 F9 F7 97 00 00 80 D2 C0 03 5F D6 ED 33 0A 6D", gg.TYPE_BYTE)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK9()
gg.setVisible(false)
gg.setRanges(gg.REGION_CODE_APP)
gg.searchNumber("h 20 00 1F D6 FF C3 00 D1 FE 0B 00 F9 F4 4F 02 A9", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(6660, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("h 20 00 1F D6 00 00 80 D2 C0 03 5F D6 F4 4F 02 A9", gg.TYPE_BYTE)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK10()
gg.setVisible(false)
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber('h803FCDCC4C3E0000A040', gg.TYPE_BYTE)
gg.refineNumber('h803FCDCC4C3E0000A040', gg.TYPE_BYTE)
gg.getResults(500000)
gg.editAll('h803F4054094B0000A040', gg.TYPE_BYTE)
gg.searchNumber('h8C3F0000803FCDCC4C3E', gg.TYPE_BYTE)
gg.refineNumber('h8C3F0000803FCDCC4C3E', gg.TYPE_BYTE)
gg.getResults(500000)
gg.editAll('h8C3F00BA5B49CDCC4C3E', gg.TYPE_BYTE)          
gg.processResume()
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK11()
gg.setVisible(false)
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber('h9D74CDCC4C3D0000003F', gg.TYPE_BYTE)
gg.refineNumber('h9D74CDCC4C3D0000003F', gg.TYPE_BYTE)
gg.getResults(500000)
gg.editAll('h9D74000000BF0000003F', gg.TYPE_BYTE)
gg.processResume()
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK12()
gg.setVisible(false)
local void1=0x374CC0
local void2=0x374640
hook_void(void1,void2)
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK13()
gg.setVisible(false)
gg.setRanges(gg.REGION_CODE_APP)
gg.searchNumber("h 53 9E BD 97 FE 57 BE A9 F4 4F 01 A9 15 66 00 F0", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(6660, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("h 53 9E BD 97 20 00 80 D2 C0 03 5F D6 15 66 00 F0", gg.TYPE_BYTE)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK14()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("-9.81", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(2000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("100", gg.TYPE_FLOAT)
gg.processResume()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ : Teleport Off in 2.5s")
gg.sleep(2500)
if revert ~= nil then gg.setValues(revert) end
end

function HACK15()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("-9.81", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(2000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("1", gg.TYPE_FLOAT)
gg.processResume()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ : Bunny Hop Off in 10s")
gg.sleep(10000)
if revert ~= nil then gg.setValues(revert) end
end

function HACK16()
  fov = gg.prompt({
    "Current FOV (Default 60)",
    "New FOV"
  }, {"60", nil}, {"number", "number"})
  if fov == nil then
    gg.alert("Invalid Input")
  else
  gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber(fov[1], gg.TYPE_FLOAT)
    gg.getResults(100000)
    gg.editAll(fov[2], gg.TYPE_FLOAT)
    gg.toast("⛨ FOV ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
    gg.clearResults()
  end
end

function HACK17()
gg.searchNumber("1.57079637051", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(5000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("15000", gg.TYPE_FLOAT)
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK18()
gg.processPause()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.clearResults()
gg.searchNumber("281 479 271 678 208", gg.TYPE_QWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(5000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("16 777 472", gg.TYPE_QWORD)
gg.clearResults()
gg.searchNumber("3 239 900 611", gg.TYPE_QWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
revert = gg.getResults(4000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("0", gg.TYPE_QWORD)
gg.clearResults()
gg.searchNumber("-10", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
revert = gg.getResults(20000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("999", gg.TYPE_FLOAT)
gg.processResume()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK19()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.clearResults()
gg.searchNumber("4 575 657 222 474 616 013", gg.TYPE_QWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(5000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("4 575 657 222 807 803 045", gg.TYPE_QWORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK20()
end

function HACK21()
end

function HACK22()
end

function HACK23()
end

function HACK24()
end

function FOLDER2()
  MN8 = gg.multiChoice({
          "⛨ Anti-Kick",
          "⛨ Anti-Kick(ALT1)",
          "⛨ Anti-Kick(ALT2)",
          "⛨ Anti-Damage",
          "⛨ Anti Crash",
          "⛨ Anti crash Chat",
          "⛨ Crash Chat",
          "⛨ Steal Adventure Map",
          "⛨ No Password (Override)",
          "⛨ Speed Hack (Menu)",
          "⛨ Anti Crash PP",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "⛨ 𝙱𝚊𝚌𝚔"
}, nil,"⛨ 𝚂𝚎𝚛𝚟𝚎𝚛")
    if MN8 == nil then
    else
      if MN8[1] == true then
        HACK26()
      end
      if MN8[2] == true then
        HACK27()
      end
      if MN8[3] == true then
        HACK28()
      end
      if MN8[4] == true then
        HACK29()
      end
      if MN8[5] == true then
        HACK30()
      end
      if MN8[6] == true then
        HACK31()
      end
      if MN8[7] == true then
        HACK32()
      end
      if MN8[8] == true then
        HACK33()
     end
      if MN8[9] == true then
        HACK34()
     end
     if MN8[10] == true then
       HACK35()
     end
     if MN8[11] == true then
       HACK36()
     end
     if MN8[12] == true then
       HACK37()
     end
    if MN8[13] == true then
       HACK38()
    end
    if MN8[14] == true then
       HACK39()
    end
    if MN8[15] == true then
       HACK40()
    end
    if MN8[16] == true then
       HACK41()
    end
    if MN8[17] == true then
       HACK42()
    end
    if MN8[18] == true then
       HACK43()
     end
    if MN8[19] == true then
       HACK44()
     end
   if  MN8[20] == true then
       HACK45()
   end
   if MN8[21] == true then
      HACK46()
   end
   if MN8[22] == true then
     HACK47()
   end
   if MN8[23] == true then
     HACK48()
   end
   if MN8[24] == true then 
     HACK49()
   end
   if MN8[25] == true then
     HOME()
     end
   end
 SsbaxyS = -1
 end

function HACK26()
gg.clearResults()
GetUnityMethod("LeaveRoom", 4)
gg.getResults(gg.getResultsCount())
gg.editAll(VOID, 4)
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
gg.clearResults()
end

function HACK27()
end

function HACK28()
end

function HACK29()
gg.setVisible(false)
gg.clearResults()
GetUnityMethod("TakeDamageLocal", 4)
gg.getResults(gg.getResultsCount())
gg.editAll(VOID, 4)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK30()
gg.setVisible(false)
gg.setRanges(gg.REGION_CODE_APP)
gg.searchNumber("h BB BA BD 97 FF 83 02 D1 FD 7B 04 A9 FC 6F 05 A9", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(6660, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("h BB BA BD 97 20 00 80 D2 C0 03 5F D6 FC 6F 05 A9", gg.TYPE_BYTE)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK31()
gg.setVisible(false)
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";<color=red>", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(6660, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";", gg.TYPE_WORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK32()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ : После активации зайди в чат и вставь то что скопировалось.")
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";<color=red>", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(6660, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";", gg.TYPE_WORD)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("257698037761Q;60D:20", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
revert = gg.getResults(6660, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("0", gg.TYPE_DWORD)
gg.clearResults()
gg.copyText("<color=#87CEFA><quad size=999999999 width=999999999 height=19></a>")
end

function HACK33()
gg.setVisible(false)
gg.alert("Врубите функцию перед заходом на сервер, затем зайдите и сохраните карту. Отключите функцию и выйдите в меню.")
gg.searchNumber(";GameMode", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";kingpidr", gg.TYPE_WORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK34()
gg.setVisible(false)
gg.searchNumber(";Password", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";sosihaho", gg.TYPE_WORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK35()
  local speedcum = gg.choice({
  "x2 speed",
  "x5 speed",
  "x10 speed",
  "x100 speed",
  "Back"},nil,
  "⛨ Speed Hack Selection")
  
  if speedcum == nil then return end
  if speedcum == 1 then 
    gg.searchNumber("4 515 609 228 873 826 304", gg.TYPE_QWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
    local revert = gg.getResults(5000, nil, nil, nil, nil, nil, nil, nil, nil)
    gg.editAll("4 515 609 228 886 409 216", gg.TYPE_QWORD)
    gg.clearResults()
  elseif speedcum == 2 then 
    gg.searchNumber("4 515 609 228 873 826 304", gg.TYPE_QWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
    local revert = gg.getResults(5000, nil, nil, nil, nil, nil, nil, nil, nil)
    gg.editAll("4 515 609 228 892 700 672", gg.TYPE_QWORD)
    gg.clearResults()
  elseif speedcum == 3 then 
    gg.setRanges(gg.REGION_ANONYMOUS)
    gg.searchNumber("4515609228873826304Q;4392630932057270955Q", gg.TYPE_QWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
    gg.refineNumber("4515609228873826304", gg.TYPE_QWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
    local revert = gg.getResults(1000, nil, nil, nil, nil, nil, nil, nil, nil)
    gg.editAll("4515609228892700672", gg.TYPE_QWORD)
    gg.clearResults()
  elseif speedcum == 4 then 
    gg.setRanges(gg.REGION_ANONYMOUS | gg.REGION_CODE_APP)
    gg.searchNumber("4515609228873826304Q;4392630932057270955Q", gg.TYPE_QWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
    gg.refineNumber("4515609228873826304", gg.TYPE_QWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
    local revert = gg.getResults(1000, nil, nil, nil, nil, nil, nil, nil, nil)
    gg.editAll("4 515 609 228 894 797 824", gg.TYPE_QWORD)
    gg.clearResults()
  end
  gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK36()
local ACKA01 = gg.getRangesList('libil2cpp.so')[3].start
local APEX = {}
APEX[1] = {address=ACKA01+0x11C4984+0, value='D2800000h', flags=4}
APEX[2] = {address=ACKA01+0x11C4984+4, value='D65F03C0h', flags=4}
gg.setValues(APEX)
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK37()
end

function HACK38()
end

function HACK39()
end

function HACK40()
end

function HACK41()
end

function HACK42()
end

function HACK43()
end

function HACK44()
end

function HACK45()
end

function HACK46()
end

function HACK47()
end

function HACK48()
end

function HACK49()
end

function FOLDER3()
  MN8 = gg.multiChoice({
          "⛨ Gravity",
          "⛨ Enable Spawn Objects",
          "⛨ Disable Passwords",
          "⛨ Assigment Props",
          "⛨ Infinity Props",
          "⛨ Infinity Vehicles",
          "⛨ Delete Map",
          "⛨ Multimine",
          "⛨ Explode All Vehicles",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "⛨ 𝙱𝚊𝚌𝚔"
}, nil," ⛨ 𝙵𝚞𝚗𝚌𝚝𝚒𝚘𝚗𝚜")
    if MN8 == nil then
    else
      if MN8[1] == true then
        HACK51()
      end
      if MN8[2] == true then
        HACK52()
      end
      if MN8[3] == true then
        HACK53()
      end
      if MN8[4] == true then
        HACK54()
      end
      if MN8[5] == true then
        HACK55()
      end
      if MN8[6] == true then
        HACK56()
      end
      if MN8[7] == true then
        HACK57()
      end
      if MN8[8] == true then
        HACK58()
     end
      if MN8[9] == true then
        HACK59()
     end
     if MN8[10] == true then
       HACK60()
     end
     if MN8[11] == true then
       HACK61()
     end
     if MN8[12] == true then
       HACK62()
     end
    if MN8[13] == true then
       HACK63()
    end
    if MN8[14] == true then
       HACK64()
    end
    if MN8[15] == true then
       HACK65()
    end
    if MN8[16] == true then
       HACK66()
    end
    if MN8[17] == true then
       HACK67()
    end
    if MN8[18] == true then
       HACK68()
     end
    if MN8[19] == true then
       HACK69()
     end
   if  MN8[20] == true then
       HACK70()
   end
   if MN8[21] == true then
      HACK71()
   end
   if MN8[22] == true then
     HACK72()
   end
   if MN8[23] == true then
     HACK73()
   end
   if MN8[24] == true then 
     HACK74()
   end
   if MN8[25] == true then
     HOME()
     end
   end
 SsbaxyS = -1
 end

function HACK51()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("-9.81", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(1000, nil, nil, nil, nil, nil, nil, nil, nil)
local t = gg.getResults(1000, nil, nil, nil, nil, nil, nil, nil, nil)
for i, v in ipairs(t) do
    if v.flags == gg.TYPE_FLOAT then
        v.value = "-5"
        v.freeze = true
    end
end
gg.addListItems(t)
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK52()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";DisableSpawnObject", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";", gg.TYPE_WORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK53()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";Password", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";", gg.TYPE_WORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK54()
gg.setVisible(false)
local void1=0x37D4E0
local void2=0x37DB1C
hook_void(void1,void2)
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK55()
gg.setVisible(false)
gg.setRanges(gg.REGION_CODE_APP)
gg.searchNumber("h A0 4A F8 97 FE 0F 1E F8 F4 4F 01 A9 53 DB 00 F0", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(6660, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("h A0 4A F8 97 E0 FF 9F 52 E0 FF AF 72 C0 03 5F D6", gg.TYPE_BYTE)
gg.clearResults() 
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK56()
gg.setVisible(false)
gg.setRanges(gg.REGION_CODE_APP)
gg.searchNumber("h 74 4B F8 97 FE 0F 1E F8 F4 4F 01 A9 53 DB 00 F0", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(6660, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("h 74 4B F8 97 E0 FF 9F 52 E0 FF AF 72 C0 03 5F D6", gg.TYPE_BYTE)
gg.clearResults() 
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK57()
gg.setVisible(false)
local void1=0x37D4E0
local void2=0x37DAB0
hook_void(void1,void2)
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function HACK58()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";10.0;3.4028234664E38;2", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";10000.0;3.4028234664E38;2", gg.TYPE_FLOAT)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ : Multimine")
end

function HACK59()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("2;2.8025969286E-45;3.4028234664E38;0;200.0;30.0", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("2;2.8025969286E-45;3.4028234664E38;0;-1.8;30.0", gg.TYPE_FLOAT)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ : Explode All")
end

function HACK60()
end

function HACK61()
end

function HACK62()
end

function HACK63()
end

function HACK64()
end

function HACK65()
end

function HACK66()
end

function HACK67()
end

function HACK68()
end

function HACK69()
end

function HACK70()
end

function HACK71()
end

function HACK72()
end

function HACK73()
end

function HACK74()
end

function FOLDER4()
  MN8 = gg.multiChoice({
          "⛨ Nands = RPG",
          "⛨ SMG Rockets",
          "⛨ SMG Arrows",
          "⛨ Nan Pistol",
          "⛨ Give SMG",
          "⛨ Give Pistol",
          "⛨ Give Bat",
          "⛨ Give AKM",
          "⛨ Give Shotgun",
          "⛨ Rapidfire",
          "⛨ Infinity ammo",
          "⛨ Smg NaN Damage",
          "⛨ Pistol NaN",
          "⛨ Fast Pistol",
          "⛨ Fast SMG",
          "⛨ Fast Shotgun",
          "⛨ All Gun Infinity Ammo",
          "⛨ All Gun Rapidfire",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "⛨ 𝙱𝚊𝚌𝚔"
}, nil," ⛨ 𝚆𝚎𝚊𝚙𝚘𝚗𝚜")
    if MN8 == nil then
    else
      if MN8[1] == true then
        ITEM1()
      end
      if MN8[2] == true then
        ITEM2()
      end
      if MN8[3] == true then
        ITEM3()
      end
      if MN8[4] == true then
        ITEM4()
      end
      if MN8[5] == true then
        ITEM5()
      end
      if MN8[6] == true then
        ITEM6()
      end
      if MN8[7] == true then
        ITEM7()
      end
      if MN8[8] == true then
        ITEM8()
     end
      if MN8[9] == true then
        ITEM9()
     end
     if MN8[10] == true then
       ITEM10()
     end
     if MN8[11] == true then
       ITEM11()
     end
     if MN8[12] == true then
       ITEM12()
     end
    if MN8[13] == true then
       ITEM13()
    end
    if MN8[14] == true then
       ITEM14()
    end
    if MN8[15] == true then
       ITEM15()
    end
    if MN8[16] == true then
       ITEM16()
    end
    if MN8[17] == true then
       ITEM17()
    end
    if MN8[18] == true then
       ITEM18()
     end
    if MN8[19] == true then
       ITEM19()
     end
   if  MN8[20] == true then
       ITEM20()
   end
   if MN8[21] == true then
      ITEM21()
   end
   if MN8[22] == true then
      ITEM22()
   end
   if MN8[23] == true then
     ITEM23()
   end
   if MN8[24] == true then 
     ITEM24()
   end
   if MN8[25] == true then
     HOME()
     end
   end
 SsbaxyS = -1
 end

function ITEM1()
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("1D;2.80259693e-45F;2F;15F", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
gg.refineNumber("2.80259693e-45", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
revert = gg.getResults(1000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("4.20389539e-45", gg.TYPE_FLOAT)
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
gg.clearResults()
end

function ITEM2()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("30;10;1.40129846e-45", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
gg.refineNumber("1.40129846e-45", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(2500, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("4.20389539e-45", gg.TYPE_FLOAT)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM3()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("30;10;1", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
gg.refineNumber("1", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(2000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("4", gg.TYPE_DWORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM4()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("10;1097859072;1137180672", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
gg.refineNumber("1097859072", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(500, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("-1", gg.TYPE_DWORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM5()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(":Hands", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(":Smg", gg.TYPE_BYTE)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM6()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(":Camera", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(":Pistol", gg.TYPE_BYTE)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM7()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(":Camera", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(":Bat", gg.TYPE_BYTE)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM8()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(":Hands", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(":Akm", gg.TYPE_BYTE)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM9()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(":Crossbow", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(":Shotgun", gg.TYPE_BYTE)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM10()
gg.setVisible(false)
gg.setRanges(gg.REGION_CODE_APP)
gg.searchNumber("h 00 00 1F D6 FE 4F BF A9 53 31 00 D0 60 8A 42 F9 A0 00 00 B5", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(6660, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("h 00 00 1F D6 00 00 88 52 40 8F A8 72 00 00 27 1E C0 03 5F D6", gg.TYPE_BYTE)
gg.clearResults() 
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM11()
gg.setVisible(false)
gg.setRanges(gg.REGION_CODE_APP)
gg.searchNumber("h C0 03 5F D6 FE 0F 1E F8 F4 4F 01 A9 34 D9 00 90", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(6660, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("h C0 03 5F D6 00 00 80 D2 C0 03 5F D6 34 D9 00 90", gg.TYPE_BYTE)
gg.clearResults() 
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM12()
gg.setVisible(false)
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("h 00 00 20 41 00 00 FA 43", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(6660, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("h 78 86 07 64 00 00 FA 43", gg.TYPE_BYTE)
gg.clearResults() 
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM13()
gg.setVisible(false)
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber('h000070410000C842', gg.TYPE_BYTE)
gg.refineNumber('h000070410000C842', gg.TYPE_BYTE)
gg.getResults(500000)
gg.editAll('h30FAFFFF0000C842', gg.TYPE_BYTE)
gg.processResume()
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM14()
gg.searchNumber("257;3;10", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
gg.processResume()
gg.toast("⛨ Shoot your pistol!")
gg.sleep(2000)
gg.refineNumber("257;3;9", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(70000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("3", gg.TYPE_DWORD)
gg.processResume()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM15()
gg.searchNumber("257;1;30", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
gg.processResume()
gg.toast("⛨ Shoot your smg!")
gg.sleep(2000)
gg.refineNumber("257;1;29", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(70000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("1", gg.TYPE_DWORD)
gg.processResume()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM16()
gg.searchNumber("6;30;10F", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
gg.processResume()
gg.refineNumber("6;10F", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(2000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("9999", gg.TYPE_FLOAT)
gg.processResume()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM17()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_CODE_APP)
gg.searchNumber("h 52 88 00 00 72 A8 8F 40 1E 27 00 00 D6 5F 03 C0", gg.TYPE_BYTE, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(6660, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("h A8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00", gg.TYPE_BYTE)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ : All Gun Infinity Ammo")
end

function ITEM18()
local ACKA01 = gg.getRangesList('libil2cpp.so')[3].start
local APEX = {}
APEX[1] = {address=ACKA01+0x18A7DB0+0, value='52880000h', flags=4}
APEX[2] = {address=ACKA01+0x18A7DB0+4, value='72A88F40h', flags=4}
APEX[3] = {address=ACKA01+0x18A7DB0+8, value='1E270000h', flags=4}
APEX[4] = {address=ACKA01+0x18A7DB0+12, value='D65F03C0h', flags=4}
gg.setValues(APEX)
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ : All Gun Rapidfire")
end

function ITEM19()
end

function ITEM20()
end

function ITEM21()
end

function ITEM22()
end

function ITEM23()
end

function ITEM24()
end

function FOLDER5()
  MN8 = gg.multiChoice({
          "⛨ 𝙸𝚗𝚏𝚒𝚗𝚒𝚝𝚢 𝙽𝚒𝚌𝚔",
          "⛨ Color Nick",
          "⛨ Wizard Hat(Free)",
          "⛨ Rock Avatar",
          "⛨ Coke Avatar",
          "⛨ Cone Avatar",
          "⛨ Crate Avatar",
          "⛨ Bottle Avatar",
          "⛨ Ball Avatar",
          "⛨ Lucky Block Avatar",
          "⛨ Bush Avatar",
          "⛨ Barrier Avatar",
          "⛨ Tire Avatar",
          "⛨ Infinity Nickname",
          "⛨ Anti < error",
          "⛨ Santa hat",
          "⛨ MikkyMouse/Dread hat",
          "⛨ Corpse skin",
          "⛨ Swat skin",
          "⛨ Butcher skin",
          "⛨ Backflip Anim",
          "⛨ Flair Anim",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "⛨ 𝙱𝚊𝚌𝚔"
}, nil,"⛨ 𝚂𝚔𝚒𝚗𝚜")
    if MN8 == nil then
    else
      if MN8[1] == true then
        ITEM26()
      end
      if MN8[2] == true then
        ITEM26()
      end
      if MN8[3] == true then
        ITEM27()
      end
      if MN8[4] == true then
        ITEM28()
      end
      if MN8[5] == true then
        ITEM29()
      end
      if MN8[6] == true then
        ITEM30()
      end
      if MN8[7] == true then
        ITEM31()
      end
      if MN8[8] == true then
        ITEM32()
     end
      if MN8[9] == true then
        ITEM33()
     end
     if MN8[10] == true then
       ITEM34()
     end
     if MN8[11] == true then
       ITEM35()
     end
     if MN8[12] == true then
       ITEM36()
     end
    if MN8[13] == true then
       ITEM37()
    end
    if MN8[14] == true then
       ITEM38()
    end
    if MN8[15] == true then
       ITEM39()
    end
    if MN8[16] == true then
       ITEM40()
    end
    if MN8[17] == true then
       ITEM41()
    end
    if MN8[18] == true then
       ITEM42()
     end
    if MN8[19] == true then
       ITEM43()
     end
   if  MN8[20] == true then
       ITEM44()
   end
   if MN8[21] == true then
      ITEM45()
   end
   if MN8[22] == true then
      ITEM46()
   end
   if MN8[23] == true then
     ITEM47()
   end
   if MN8[24] == true then 
     ITEM48()
   end
   if MN8[25] == true then
     HOME()
     end
   end
 SsbaxyS = -1
 end

function ITEM26()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("0;16;0;1044957385", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
revert = gg.getResults(55555, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("0", gg.TYPE_DWORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM27()
addSoafSYSTEM(1)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("257698037761Q;60D:20", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
revert = gg.getResults(10000, nil, nil, nil, "60", "60", nil, nil, nil)
gg.editAll("0", gg.TYPE_DWORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM28()
gg.searchNumber(";Helmet", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
revert = gg.getResults(55555, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";Wizard", gg.TYPE_WORD)
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
gg.clearResults()
end

function ITEM29()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";Hero", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";Rock", gg.TYPE_WORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM30()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";Soldier", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";c_ck", gg.TYPE_WORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM31()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";Jean", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";Cone", gg.TYPE_WORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM32()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";Derik", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";Crate", gg.TYPE_WORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM33()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";Business", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";bottle3", gg.TYPE_WORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM34()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";SpecialForcesW", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";bouncy_ball", gg.TYPE_WORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM35()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";SpecialForcesM", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";question_block", gg.TYPE_WORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM36()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";Prisoner01", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";Bush", gg.TYPE_WORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM37()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";Military", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";Barier", gg.TYPE_WORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM38()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";Engineer", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";Tire", gg.TYPE_WORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM39()
gg.setVisible(false)
gg.setRanges(gg.REGION_ANONYMOUS)
gg.clearResults()
gg.setRanges(32)
gg.searchNumber(5357803930, gg.TYPE_QWORD)
HackersHouse = gg.getResults(250000)
Offsets = {}
Offsets['FirstOffset'] = {}
Offsets['SecondOffset'] = {}
Offsets['FinalResults'] = {}
OffsetsIndex = 1
for index, value in ipairs(HackersHouse) do
	Offsets['FirstOffset'][OffsetsIndex] = {}
	Offsets['FirstOffset'][OffsetsIndex].address = HackersHouse[index].address + -16
	Offsets['FirstOffset'][OffsetsIndex].flags = gg.TYPE_QWORD
	Offsets['SecondOffset'][OffsetsIndex] = {}
	Offsets['SecondOffset'][OffsetsIndex].address = HackersHouse[index].address + -28
	Offsets['SecondOffset'][OffsetsIndex].flags = gg.TYPE_QWORD
	OffsetsIndex = OffsetsIndex + 1
end
Offsets['FirstOffset'] = gg.getValues(Offsets['FirstOffset'])
Offsets['SecondOffset'] = gg.getValues(Offsets['SecondOffset'])
OffsetsIndex = 1
for index, value in ipairs(Offsets['FirstOffset']) do
	if (Offsets['FirstOffset'][index].value == 1061208257) and (Offsets['SecondOffset'][index].value == 4561810862086072489) then
		Offsets['FinalResults'][OffsetsIndex] = {}
		Offsets['FinalResults'][OffsetsIndex] =  Offsets['FirstOffset'][index]
		OffsetsIndex = OffsetsIndex + 1
	end
end
for index, value in ipairs(Offsets['FinalResults']) do
	Offsets['FinalResults'][index].address = Offsets['FinalResults'][index].address + -68
	Offsets['FinalResults'][index].flags = 4
end
gg.loadResults(Offsets['FinalResults'])
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("99999999", gg.TYPE_DWORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM40()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("257698037761Q;60D:20", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(10000, nil, nil, nil, "60", "60", nil, nil, nil)
gg.editAll("0", gg.TYPE_DWORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM41()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";Debug", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";Santa", gg.TYPE_WORD)
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM42()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";Party", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";Dread", gg.TYPE_WORD)
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM43()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";Soldier", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";Corpse", gg.TYPE_WORD)
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM44()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";Hero", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";Swat", gg.TYPE_WORD)
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM45()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";Business", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";Butcher", gg.TYPE_WORD)
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM46()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";Disagree", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(55555, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";Backflip", gg.TYPE_WORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM47()
gg.setVisible(false)
gg.clearResults()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber(";Twerk", gg.TYPE_WORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(55555, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll(";Flair", gg.TYPE_WORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM48()
end

function ITEM49()
end

function FOLDER6()
  MN8 = gg.multiChoice({
          "⛨ Autumn chams",
          "⛨ Winter chams",
          "⛨ Black chams",
          "⛨ Raimbow chams",
          "⛨ NaN Floor",
          "⛨ No Collision Prop",
          "⛨ Air Walk",
          "⛨ Giga Chams",
          "⛨ Red Chams",
          "⛨ Green Chams",
          "⛨ Blue Chams",
          "⛨ Blue Neon",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "⛨ 𝙱𝚊𝚌𝚔"
}, nil,"ᴄᴋоᴩо...")
    if MN8 == nil then
    else
      if MN8[1] == true then
        ITEM51()
      end
      if MN8[2] == true then
        ITEM52()
      end
      if MN8[3] == true then
        ITEM53()
      end
      if MN8[4] == true then
        ITEM54()
      end
      if MN8[5] == true then
        ITEM55()
      end
      if MN8[6] == true then
        ITEM56()
      end
      if MN8[7] == true then
        ITEM57()
      end
      if MN8[8] == true then
        ITEM58()
     end
      if MN8[9] == true then
        ITEM59()
     end
     if MN8[10] == true then
       ITEM60()
     end
     if MN8[11] == true then
       ITEM61()
     end
     if MN8[12] == true then
       ITEM62()
     end
    if MN8[13] == true then
       ITEM63()
    end
    if MN8[14] == true then
       ITEM64()
    end
    if MN8[15] == true then
       ITEM65()
    end
    if MN8[16] == true then
       ITEM66()
    end
    if MN8[17] == true then
       ITEM67()
    end
    if MN8[18] == true then
       ITEM68()
     end
    if MN8[19] == true then
       ITEM69()
     end
   if  MN8[20] == true then
       ITEM70()
   end
   if MN8[21] == true then
      ITEM71()
   end
   if MN8[22] == true then
      ITEM72()
   end
   if MN8[23] == true then
     ITEM73()
   end
   if MN8[24] == true then 
     ITEM74()
   end
   if MN8[25] == true then
     HOME()
     end
   end
 SsbaxyS = -1
 end

function ITEM51()
gg.setVisible(false)
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("1073741859", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(6660, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("1073741928", gg.TYPE_DWORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM52()
gg.setVisible(false)
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("1073741859", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(6660, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("1073741910", gg.TYPE_DWORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM53()
gg.setVisible(false)
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("1073741859", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(6660, nil, nil, nil, nil, nil, nil, nil, nil)
-- this matched RaimbowCamera
gg.editAll("1073741880", gg.TYPE_DWORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM54()
gg.setVisible(false)
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("1073741859", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(6660, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("1073741903", gg.TYPE_DWORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM55()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("-9.81", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(2000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("0", gg.TYPE_FLOAT)
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ : NaN Floor Off in 10s")
gg.sleep(10000)
if revert ~= nil then gg.setValues(revert) end
gg.processResume()
end

function ITEM56()
gg.clearResults()
GetUnityMethod("OnCollisionEnter", 4)
gg.getResults(gg.getResultsCount())
gg.editAll(VOID, 4)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM57()
gg.searchNumber("-9.81", gg.TYPE_FLOAT, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(50000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("0", gg.TYPE_FLOAT)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ")
end

function ITEM58()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("1;3;4;257", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
gg.refineNumber("257", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(100, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("0", gg.TYPE_FLOAT)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ : Giga Chams")
end

function ITEM59()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("1073741895", gg.TYPE_DWORD)
gg.refineNumber("1073741895", gg.TYPE_DWORD)
gg.refineNumber("1073741895", gg.TYPE_DWORD)
local revert = gg.getResults(5000)
gg.editAll("1073741900", gg.TYPE_DWORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ : Red Chams")
end

function ITEM60()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("1073741893", gg.TYPE_DWORD)
gg.refineNumber("1073741893", gg.TYPE_DWORD)
gg.refineNumber("1073741893", gg.TYPE_DWORD)
local revert = gg.getResults(5000)
gg.editAll('1073741904', gg.TYPE_DWORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ : Green Chams")
end

function ITEM61()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("1073741894", gg.TYPE_DWORD)
gg.refineNumber("1073741894", gg.TYPE_DWORD)
gg.refineNumber("1073741894", gg.TYPE_DWORD)
local revert = gg.getResults(5000)
gg.editAll("1073741900", gg.TYPE_DWORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ : Blue Chams")
end

function ITEM62()
gg.setRanges(gg.REGION_ANONYMOUS)
gg.searchNumber("1073741898", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
gg.refineNumber("1073741898", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
gg.refineNumber("1073741898", gg.TYPE_DWORD, false, gg.SIGN_EQUAL, 0, -1, 0)
local revert = gg.getResults(2000, nil, nil, nil, nil, nil, nil, nil, nil)
gg.editAll("1073741862", gg.TYPE_DWORD)
gg.clearResults()
gg.toast("⛨ ᴀᴄᴛɪᴠᴀᴛᴇᴅ : Blue Neon")
end

function ITEM63()
end

function ITEM64()
end

function ITEM65()
end

function ITEM66()
end

function ITEM67()
end

function ITEM68()
end

function ITEM69()
end

function ITEM70()
end

function ITEM71()
end

function ITEM72()
end

function ITEM73()
end

function ITEM74()
end

function FOLDER7()
  MN8 = gg.multiChoice({
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "⛨ 𝙱𝚊𝚌𝚔"
}, nil,"ᴄᴋоᴩо...")
    if MN8 == nil then
    else
      if MN8[1] == true then
        WALL1()
      end
      if MN8[2] == true then
        WALL2()
      end
      if MN8[3] == true then
        WALL3()
      end
      if MN8[4] == true then
        WALL4()
      end
      if MN8[5] == true then
        WALL5()
      end
      if MN8[6] == true then
        WALL6()
      end
      if MN8[7] == true then
        WALL7()
      end
      if MN8[8] == true then
        WALL8()
     end
      if MN8[9] == true then
        WALL9()
     end
     if MN8[10] == true then
       WALL10()
     end
     if MN8[11] == true then
       WALL11()
     end
     if MN8[12] == true then
       WALL12()
     end
    if MN8[13] == true then
       WALL13()
    end
    if MN8[14] == true then
       WALL14()
    end
    if MN8[15] == true then
       WALL15()
    end
    if MN8[16] == true then
       WALL16()
    end
    if MN8[17] == true then
       WALL17()
    end
    if MN8[18] == true then
       WALL18()
     end
    if MN8[19] == true then
       WALL19()
     end
   if  MN8[20] == true then
       WALL20()
   end
   if MN8[21] == true then
      WALL21()
   end
   if MN8[22] == true then
      WALL22()
   end
   if MN8[23] == true then
     WALL23()
   end
   if MN8[24] == true then 
     WALL24()
   end
   if MN8[25] == true then
     HOME()
     end
   end
 SsbaxyS = -1
 end

function WALL1()
end

function WALL2()
end

function WALL3()
end

function WALL4()
end

function WALL5()
end

function WALL6()
end

function WALL7()
end

function WALL8()
end

function WALL9()
end

function WALL10()
end

function WALL11()
end

function WALL12()
end

function WALL13()
end

function WALL14()
end

function WALL15()
end

function WALL16()
end

function WALL17()
end

function WALL18()
end

function WALL19()
end

function WALL20()
end

function WALL21()
end

function WALL22()
end

function WALL23()
end

function WALL24()
end

function FOLDER8()
  MN8 = gg.multiChoice({
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "⛨ 𝙱𝚊𝚌𝚔"
}, nil,"ᴄᴋоᴩо...")
    if MN8 == nil then
    else
      if MN8[1] == true then
        WALL26()
      end
      if MN8[2] == true then
        WALL27()
      end
      if MN8[3] == true then
        WALL28()
      end
      if MN8[4] == true then
        WALL29()
      end
      if MN8[5] == true then
        WALL30()
      end
      if MN8[6] == true then
        WALL31()
      end
      if MN8[7] == true then
        WALL32()
      end
      if MN8[8] == true then
        WALL33()
     end
      if MN8[9] == true then
        WALL34()
     end
     if MN8[10] == true then
       WALL35()
     end
     if MN8[11] == true then
       WALL36()
     end
     if MN8[12] == true then
       WALL37()
     end
    if MN8[13] == true then
       WALL38()
    end
    if MN8[14] == true then
       WALL39()
    end
    if MN8[15] == true then
       WALL40()
    end
    if MN8[16] == true then
       WALL41()
    end
    if MN8[17] == true then
       WALL42()
    end
    if MN8[18] == true then
       WALL43()
     end
    if MN8[19] == true then
       WALL44()
     end
   if  MN8[20] == true then
       WALL45()
   end
   if MN8[21] == true then
      WALL46()
   end
   if MN8[22] == true then
      WALL47()
   end
   if MN8[23] == true then
     WALL48()
   end
   if MN8[24] == true then 
     WALL49()
   end
   if MN8[25] == true then
     HOME()
     end
   end
 SsbaxyS = -1
 end

function WALL26()
end

function WALL27()
end

function WALL28()
end

function WALL29()
end

function WALL30()
end

function WALL31()
end

function WALL32()
end

function WALL33()
end

function WALL34()
end

function WALL35()
end

function WALL36()
end

function WALL37()
end

function WALL38()
end

function WALL39()
end

function WALL40()
end

function WALL41()
end

function WALL42()
end

function WALL43()
end

function WALL44()
end

function WALL45()
end

function WALL46()
end

function WALL47()
end

function WALL48()
end

function WALL49()
end

function FOLDER9()
  MN8 = gg.multiChoice({
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "⛨ 𝙱𝚊𝚌𝚔"
}, nil,"ᴄᴋоᴩо...")
    if MN8 == nil then
    else
      if MN8[1] == true then
        WALL51()
      end
      if MN8[2] == true then
        WALL52()
      end
      if MN8[3] == true then
        WALL53()
      end
      if MN8[4] == true then
        WALL54()
      end
      if MN8[5] == true then
        WALL55()
      end
      if MN8[6] == true then
        WALL56()
      end
      if MN8[7] == true then
        WALL57()
      end
      if MN8[8] == true then
        WALL58()
     end
      if MN8[9] == true then
        WALL59()
     end
     if MN8[10] == true then
       WALL60()
     end
     if MN8[11] == true then
       WALL61()
     end
     if MN8[12] == true then
       WALL62()
     end
    if MN8[13] == true then
       WALL63()
    end
    if MN8[14] == true then
       WALL64()
    end
    if MN8[15] == true then
       WALL65()
    end
    if MN8[16] == true then
       WALL66()
    end
    if MN8[17] == true then
       WALL67()
    end
    if MN8[18] == true then
       WALL68()
     end
    if MN8[19] == true then
       WALL69()
     end
   if  MN8[20] == true then
       WALL70()
   end
   if MN8[21] == true then
      WALL71()
   end
   if MN8[22] == true then
      WALL72()
   end
   if MN8[23] == true then
     WALL73()
   end
   if MN8[24] == true then 
     WALL44()
   end
   if MN8[25] == true then
     HOME()
     end
   end
 SsbaxyS = -1
 end

function WALL51()
end

function WALL52()
end

function WALL53()
end

function WALL54()
end

function WALL55()
end

function WALL56()
end

function WALL57()
end

function WALL58()
end

function WALL59()
end

function WALL60()
end

function WALL61()
end

function WALL62()
end

function WALL63()
end

function WALL64()
end

function WALL65()
end

function WALL66()
end

function WALL67()
end

function WALL68()
end

function WALL69()
end

function WALL70()
end

function WALL71()
end

function WALL72()
end

function WALL73()
end

function WALL74()
end

function FOLDER10()
  MN8 = gg.multiChoice({
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "⛨ 𝙱𝚊𝚌𝚔"
}, nil,"ᴄᴋоᴩо...")
    if MN8 == nil then
    else
      if MN8[1] == true then
        LITE1()
      end
      if MN8[2] == true then
        LITE2()
      end
      if MN8[3] == true then
        LITE3()
      end
      if MN8[4] == true then
        LITE4()
      end
      if MN8[5] == true then
        LITE5()
      end
      if MN8[6] == true then
        LITE6()
      end
      if MN8[7] == true then
        LITE7()
      end
      if MN8[8] == true then
        LITE8()
     end
      if MN8[9] == true then
        LITE9()
     end
     if MN8[10] == true then
       LITE10()
     end
     if MN8[11] == true then
       LITE11()
     end
     if MN8[12] == true then
       LITE12()
     end
    if MN8[13] == true then
       LITE13()
    end
    if MN8[14] == true then
       LITE14()
    end
    if MN8[15] == true then
       LITE15()
    end
    if MN8[16] == true then
       LITE16()
    end
    if MN8[17] == true then
       LITE17()
    end
    if MN8[18] == true then
       LITE18()
     end
    if MN8[19] == true then
       LITE19()
     end
   if  MN8[20] == true then
       LITE20()
   end
   if MN8[21] == true then
      LITE21()
   end
   if MN8[22] == true then
      LITE22()
   end
   if MN8[23] == true then
     LITE23()
   end
   if MN8[24] == true then 
     LITE24()
   end
   if MN8[25] == true then
     HOME()
     end
   end
 SsbaxyS = -1
 end

function LITE1()
end

function LITE2()
end

function LITE3()
end

function LITE4()
end

function LITE5()
end

function LITE6()
end

function LITE7()
end

function LITE8()
end

function LITE9()
end

function LITE10()
end

function LITE11()
end

function LITE12()
end

function LITE13()
end

function LITE14()
end

function LITE15()
end

function LITE16()
end

function LITE17()
end

function LITE18()
end

function LITE19()
end

function LITE20()
end

function LITE21()
end

function LITE22()
end

function LITE23()
end

function LITE24()
end

function FOLDER11()
  MN8 = gg.multiChoice({
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "⛨ 𝙱𝚊𝚌𝚔"
}, nil,"ᴄᴋоᴩо...")
    if MN8 == nil then
    else
      if MN8[1] == true then
        LITE26()
      end
      if MN8[2] == true then
        LITE27()
      end
      if MN8[3] == true then
        LITE28()
      end
      if MN8[4] == true then
        LITE29()
      end
      if MN8[5] == true then
        LITE30()
      end
      if MN8[6] == true then
        LITE31()
      end
      if MN8[7] == true then
        LITE32()
      end
      if MN8[8] == true then
        LITE33()
     end
      if MN8[9] == true then
        LITE34()
     end
     if MN8[10] == true then
       LITE35()
     end
     if MN8[11] == true then
       LITE36()
     end
     if MN8[12] == true then
       LITE37()
     end
    if MN8[13] == true then
       LITE38()
    end
    if MN8[14] == true then
       LITE39()
    end
    if MN8[15] == true then
       LITE40()
    end
    if MN8[16] == true then
       LITE41()
    end
    if MN8[17] == true then
       LITE42()
    end
    if MN8[18] == true then
       LITE43()
     end
    if MN8[19] == true then
       LITE44()
     end
   if  MN8[20] == true then
       LITE45()
   end
   if MN8[21] == true then
      LITE46()
   end
   if MN8[22] == true then
      LITE47()
   end
   if MN8[23] == true then
     LITE48()
   end
   if MN8[24] == true then 
     LITE49()
   end
   if MN8[25] == true then
     HOME()
     end
   end
 SsbaxyS = -1
 end

function LITE26()
end

function LITE27()
end

function LITE28()
end

function LITE29()
end

function LITE30()
end

function LITE31()
end

function LITE32()
end

function LITE33()
end

function LITE34()
end

function LITE35()
end

function LITE36()
end

function LITE37()
end

function LITE38()
end

function LITE39()
end

function LITE40()
end

function LITE41()
end

function LITE42()
end

function LITE43()
end

function LITE44()
end

function LITE45()
end

function LITE46()
end

function LITE47()
end

function LITE48()
end

function LITE49()
end

function FOLDER12()
  MN8 = gg.multiChoice({
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "⛨ 𝙱𝚊𝚌𝚔"
}, nil,"ᴄᴋоᴩо...")
    if MN8 == nil then
    else
      if MN8[1] == true then
        LITE51()
      end
      if MN8[2] == true then
        LITE52()
      end
      if MN8[3] == true then
        LITE53()
      end
      if MN8[4] == true then
        LITE54()
      end
      if MN8[5] == true then
        LITE55()
      end
      if MN8[6] == true then
        LITE56()
      end
      if MN8[7] == true then
        LITE57()
      end
      if MN8[8] == true then
        LITE58()
     end
      if MN8[9] == true then
        LITE59()
     end
     if MN8[10] == true then
       LITE60()
     end
     if MN8[11] == true then
       LITE61()
     end
     if MN8[12] == true then
       LITE62()
     end
    if MN8[13] == true then
       LITE63()
    end
    if MN8[14] == true then
       LITE64()
    end
    if MN8[15] == true then
       LITE65()
    end
    if MN8[16] == true then
       LITE66()
    end
    if MN8[17] == true then
       LITE67()
    end
    if MN8[18] == true then
       LITE68()
     end
    if MN8[19] == true then
       LITE69()
     end
   if  MN8[20] == true then
       LITE70()
   end
   if MN8[21] == true then
      LITE71()
   end
   if MN8[22] == true then
      LITE72()
   end
   if MN8[23] == true then
     LITE73()
   end
   if MN8[24] == true then 
     LITE74()
   end
   if MN8[25] == true then
     HOME()
     end
   end
 SsbaxyS = -1
 end

function LITE51()
end

function LITE52()
end

function LITE53()
end

function LITE54()
end

function LITE55()
end

function LITE56()
end

function LITE57()
end

function LITE58()
end

function LITE59()
end

function LITE60()
end

function LITE61()
end

function LITE62()
end

function LITE63()
end

function LITE64()
end

function LITE65()
end

function LITE66()
end

function LITE67()
end

function LITE68()
end

function LITE69()
end

function LITE70()
end

function LITE71()

end

function LITE72()
end

function LITE73()
end

function LITE74()
end

function FOLDER13()
  MN8 = gg.multiChoice({
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "⛨ 𝙱𝚊𝚌𝚔"
}, nil,"ᴄᴋоᴩо...")
    if MN8 == nil then
    else
      if MN8[1] == true then
        PUBG1()
      end
      if MN8[2] == true then
        PUBG2()
      end
      if MN8[3] == true then
        PUBG3()
      end
      if MN8[4] == true then
        PUBG4()
      end
      if MN8[5] == true then
        PUBG5()
      end
      if MN8[6] == true then
        PUBG6()
      end
      if MN8[7] == true then
        PUBG7()
      end
      if MN8[8] == true then
        PUBG8()
     end
      if MN8[9] == true then
        PUBG9()
     end
     if MN8[10] == true then
       PUBG10()
     end
     if MN8[11] == true then
       PUBG11()
     end
     if MN8[12] == true then
       PUBG12()
     end
    if MN8[13] == true then
       PUBG13()
    end
    if MN8[14] == true then
       PUBG14()
    end
    if MN8[15] == true then
       PUBG15()
    end
    if MN8[16] == true then
       PUBG16()
    end
    if MN8[17] == true then
       PUBG17()
    end
    if MN8[18] == true then
       PUBG18()
     end
    if MN8[19] == true then
       PUBG19()
     end
   if  MN8[20] == true then
       PUBG20()
   end
   if MN8[21] == true then
      PUBG21()
   end
   if MN8[22] == true then
      PUBG22()
   end
   if MN8[23] == true then
     PUBG23()
   end
   if MN8[24] == true then 
     PUBG24()
   end
   if MN8[25] == true then
     HOME()
     end
   end
 SsbaxyS = -1
 end

function PUBG1()
end

function PUBG2()
end

function PUBG3()
end

function PUBG4()
end

function PUBG5()
end

function PUBG6()
end

function PUBG7()
end

function PUBG8()
end

function PUBG9()
end

function PUBG10()
end

function PUBG11()
end

function PUBG12()
end

function PUBG13()
end

function PUBG14()
end

function PUBG15()
end

function PUBG16()
end

function PUBG17()
end

function PUBG18()
end

function PUBG19()
end

function PUBG20()
end

function PUBG21()

end

function PUBG22()
end

function PUBG23()
end

function PUBG24()
end

function FOLDER14()
  MN8 = gg.multiChoice({
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "⛨ 𝙱𝚊𝚌𝚔"
}, nil,"ᴄᴋоᴩо...")
    if MN8 == nil then
    else
      if MN8[1] == true then
        PUBG26()
      end
      if MN8[2] == true then
        PUBG27()
      end
      if MN8[3] == true then
        PUBG28()
      end
      if MN8[4] == true then
        PUBG29()
      end
      if MN8[5] == true then
        PUBG30()
      end
      if MN8[6] == true then
        PUBG31()
      end
      if MN8[7] == true then
        PUBG32()
      end
      if MN8[8] == true then
        PUBG33()
     end
      if MN8[9] == true then
        PUBG34()
     end
     if MN8[10] == true then
       PUBG35()
     end
     if MN8[11] == true then
       PUBG36()
     end
     if MN8[12] == true then
       PUBG37()
     end
    if MN8[13] == true then
       PUBG38()
    end
    if MN8[14] == true then
       PUBG39()
    end
    if MN8[15] == true then
       PUBG40()
    end
    if MN8[16] == true then
       PUBG41()
    end
    if MN8[17] == true then
       PUBG42()
    end
    if MN8[18] == true then
       PUBG43()
     end
    if MN8[19] == true then
       PUBG44()
     end
   if  MN8[20] == true then
       PUBG45()
   end
   if MN8[21] == true then
      PUBG46()
   end
   if MN8[22] == true then
      PUBG47()
   end
   if MN8[23] == true then
     PUBG48()
   end
   if MN8[24] == true then 
     PUBG49()
   end
   if MN8[25] == true then
     HOME()
     end
   end
 SsbaxyS = -1
 end

function PUBG26()
end

function PUBG27()
end

function PUBG28()
end

function PUBG29()
end

function PUBG30()
end

function PUBG31()
end

function PUBG32()
end

function PUBG33()
end

function PUBG34()
end

function PUBG35()
end

function PUBG36()
end

function PUBG37()
end

function PUBG38()
end

function PUBG39()
end

function PUBG40()
end

function PUBG41()
end

function PUBG42()
end

function PUBG43()
end

function PUBG44()
end

function PUBG45()
end

function PUBG46()

end

function PUBG47()
end

function PUBG48()
end

function PUBG49()
end

function FOLDER15()
  MN8 = gg.multiChoice({
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "ᴄᴋоᴩо...",
          "⛨ 𝙱𝚊𝚌𝚔"
}, nil,"ᴄᴋоᴩо...")
    if MN8 == nil then
    else
      if MN8[1] == true then
        PUBG51()
      end
      if MN8[2] == true then
        PUBG52()
      end
      if MN8[3] == true then
        PUBG53()
      end
      if MN8[4] == true then
        PUBG54()
      end
      if MN8[5] == true then
        PUBG55()
      end
      if MN8[6] == true then
        PUBG56()
      end
      if MN8[7] == true then
        PUBG57()
      end
      if MN8[8] == true then
        PUBG58()
     end
      if MN8[9] == true then
        PUBG59()
     end
     if MN8[10] == true then
       PUBG60()
     end
     if MN8[11] == true then
       PUBG61()
     end
     if MN8[12] == true then
       PUBG62()
     end
    if MN8[13] == true then
       PUBG63()
    end
    if MN8[14] == true then
       PUBG64()
    end
    if MN8[15] == true then
       PUBG65()
    end
    if MN8[16] == true then
       PUBG66()
    end
    if MN8[17] == true then
       PUBG67()
    end
    if MN8[18] == true then
       PUBG68()
     end
    if MN8[19] == true then
       PUBG69()
     end
   if  MN8[20] == true then
       PUBG70()
   end
   if MN8[21] == true then
      PUBG71()
   end
   if MN8[22] == true then
      PUBG72()
   end
   if MN8[23] == true then
     PUBG73()
   end
   if MN8[24] == true then 
     PUBG74()
   end
   if MN8[25] == true then
     HOME()
     end
   end
 SsbaxyS = -1
 end

function PUBG51()
end

function PUBG52()
end

function PUBG53()
end

function PUBG54()
end

function PUBG55()
end

function PUBG56()
end

function PUBG57()
end

function PUBG58()
end

function PUBG59()
end

function PUBG60()
end

function PUBG61()
end

function PUBG62()
end

function PUBG63()
end

function PUBG64()
end

function PUBG65()
end

function PUBG66()
end

function PUBG67()
end

function PUBG68()
end

function PUBG69()
end

function PUBG70()
end

function PUBG71()

end

function PUBG72()
end

function PUBG73()
end

function PUBG74()
end

function EXIT()
print("ʀᴇɴᴀᴜʟᴛ - ᴅɪꜱᴀʙʟᴇᴅ ")
gg.skipRestoreState()
  os.exit()
  gg.setVisible(true)
end 

while true do
  if gg.isVisible(true) then
    SsbaxyS = 1
    gg.setVisible(false)
  end
  gg.clearResults()
  if SsbaxyS == 1 then
    HOME()
 end
 end

-- ʙᴇᴩᴄия: 1.0.0
-- ʙʏ ꜱꜱʙᴀxʏꜱ