import type {
  HeaderArchitecture,
  RawOnlyArchitecture,
} from "./binaryTargetTypes.js";

/**
 * CPU families of console formats: the raw families and the header-detected ones without ELF
 * metadata, so a console target never narrows like a MIPS/PowerPC/RISC-V ELF target.
 */
export type ConsoleArchitecture = HeaderArchitecture | RawOnlyArchitecture;

/**
 * A game-console cartridge or executable format (coding_workflow). Its file is not a flat image:
 * a dedicated Ghidra loader of the patched Ghidra (rivaborn/ghidra, module ConsoleFormats) maps
 * it the way the console does (banks as overlays, sections at their load addresses, header-given
 * entry points) and selects the language.
 */
export interface ConsoleFormatInfo {
  /** Stable format identifier, e.g. "snes", "gameboy", "dol". */
  readonly id: string;
  /** Human-readable platform, e.g. "SNES". */
  readonly platform: string;
  /** Ghidra loader that maps it (passed to analyzeHeadless as -loader). */
  readonly ghidraLoader: string;
}

/** Executable metadata for a detected console format. */
export interface ConsoleExecutableMetadata {
  readonly format: "console";
  readonly architecture: ConsoleArchitecture;
  readonly availableArchitectures: readonly ConsoleArchitecture[];
  readonly console: ConsoleFormatInfo;
}

/** Bounded read of the target file: at most `length` bytes from `offset` (shorter at the end). */
export type ConsoleByteWindow = (
  offset: number,
  length: number,
) => Promise<Buffer>;

interface ConsoleRule {
  readonly info: ConsoleFormatInfo;
  readonly architecture: ConsoleArchitecture;
  /** True when the file is this format; `prefix` is the first 4096 bytes. */
  readonly matches: (input: ConsoleProbe) => Promise<boolean>;
}

/** What a rule sees: the probed prefix, the file size and extension, and a bounded reader. */
export interface ConsoleProbe {
  readonly prefix: Buffer;
  readonly fileSize: number;
  /** Lower-case file extension without the dot, or "" when unknown. */
  readonly extension: string;
  readonly read: ConsoleByteWindow;
}

// ---- helpers -------------------------------------------------------------------------------

const u16le = (b: Buffer, o: number): number =>
  o + 2 <= b.length ? b.readUInt16LE(o) : -1;
const u32le = (b: Buffer, o: number): number =>
  o + 4 <= b.length ? b.readUInt32LE(o) : -1;
const u16be = (b: Buffer, o: number): number =>
  o + 2 <= b.length ? b.readUInt16BE(o) : -1;
const u32be = (b: Buffer, o: number): number =>
  o + 4 <= b.length ? b.readUInt32BE(o) : -1;
const lower = (b: Buffer, length: number): Buffer => b.subarray(0, length);

/** Bytes [offset, offset+length) from the prefix when it holds them, else from the file. */
const bytesAt = async (
  probe: ConsoleProbe,
  offset: number,
  length: number,
): Promise<Buffer> =>
  offset + length <= probe.prefix.length
    ? probe.prefix.subarray(offset, offset + length)
    : probe.read(offset, length);

/** The whole file, for small formats whose rule walks it (at most `max` bytes). */
const wholeFile = async (
  probe: ConsoleProbe,
  max: number,
): Promise<Buffer | undefined> => {
  if (probe.fileSize > max) return undefined;
  if (probe.fileSize <= probe.prefix.length)
    return probe.prefix.subarray(0, probe.fileSize);
  const parts: Buffer[] = [];
  for (let offset = 0; offset < probe.fileSize; offset += 65536)
    parts.push(
      await probe.read(offset, Math.min(65536, probe.fileSize - offset)),
    );
  return Buffer.concat(parts);
};

const GAMEBOY_LOGO = Buffer.from(
  "CEED6666CC0D000B03730083000C000D0008111F8889000EDCCC6EE6DDDDD999BBBB67636E0EECCCDDDC999FBBB9333E",
  "hex",
);

// ---- Nintendo ------------------------------------------------------------------------------

const isRpx = (p: ConsoleProbe): boolean => {
  const b = p.prefix;
  return (
    b.length >= 0x34 &&
    b.readUInt32BE(0) === 0x7f454c46 &&
    b[4] === 1 &&
    b[5] === 2 &&
    b[7] === 0xca &&
    b[8] === 0xfe &&
    u16be(b, 0x10) === 0xfe01 &&
    u16be(b, 0x12) === 20 &&
    u16be(b, 0x2e) === 0x28 &&
    u16be(b, 0x30) > 0 &&
    u32be(b, 0x20) + u16be(b, 0x30) * 0x28 <= p.fileSize
  );
};

const isN64 = (p: ConsoleProbe): boolean =>
  p.fileSize >= 0x1000 &&
  p.fileSize <= 256 * 1024 * 1024 &&
  [0x80371240, 0x37804012, 0x40123780].includes(u32be(p.prefix, 0));

const isPsxRam = (address: number): boolean =>
  [0, 4, 5].includes(address >>> 29) && (address & 0x1fffffff) < 0x800000;

const isPsxExe = (p: ConsoleProbe): boolean => {
  const b = p.prefix;
  if (p.fileSize < 0x800 || b.toString("latin1", 0, 8) !== "PS-X EXE")
    return false;
  const tAddr = u32le(b, 0x18);
  const tSize = u32le(b, 0x1c);
  return tSize > 0 && isPsxRam(tAddr) && isPsxRam((tAddr + tSize - 1) >>> 0);
};

const nesPrgBytes = (b: Buffer, nes2: boolean): number => {
  const high = nes2 ? b[9]! & 0x0f : 0;
  if (high === 0x0f) return 2 ** (b[4]! >> 2) * ((b[4]! & 3) * 2 + 1);
  return ((high << 8) | b[4]!) * 0x4000;
};

const isNes = (p: ConsoleProbe): boolean => {
  const b = p.prefix;
  if (p.fileSize < 16 + 0x2000 || b.length < 16) return false;
  if (b.toString("latin1", 0, 4) !== "NES\u001a") return false;
  const nes2 = (b[7]! & 0x0c) === 0x08;
  const prg = nesPrgBytes(b, nes2);
  const trainer = (b[6]! & 0x04) !== 0 ? 512 : 0;
  return prg > 0 && 16 + trainer + prg <= p.fileSize;
};

const isGameBoy = (p: ConsoleProbe): boolean =>
  p.fileSize >= 0x150 &&
  p.prefix.length >= 0x134 &&
  p.prefix.subarray(0x104, 0x134).equals(GAMEBOY_LOGO);

const isGba = (p: ConsoleProbe): boolean => {
  const b = p.prefix;
  if (p.fileSize < 0xc0 || p.fileSize > 32 * 1024 * 1024 || b.length < 0xc0)
    return false;
  if (b[0xb2] !== 0x96 || b[3] !== 0xea) return false;
  let sum = 0;
  for (let i = 0xa0; i <= 0xbc; i++) sum += b[i]!;
  return b[0xbd] === ((-sum - 0x19) & 0xff);
};

const crc16Modbus = (b: Buffer, length: number): number => {
  let crc = 0xffff;
  for (let i = 0; i < length; i++) {
    crc ^= b[i]!;
    for (let bit = 0; bit < 8; bit++)
      crc = (crc & 1) !== 0 ? (crc >>> 1) ^ 0xa001 : crc >>> 1;
  }
  return crc;
};

const isNds = (p: ConsoleProbe): boolean => {
  const b = p.prefix;
  if (p.fileSize < 0x200 || b.length < 0x200) return false;
  if (crc16Modbus(b, 0x15e) !== u16le(b, 0x15e) && u16le(b, 0x15c) !== 0xcf56)
    return false;
  const off9 = u32le(b, 0x20);
  const entry9 = u32le(b, 0x24);
  const load9 = u32le(b, 0x28);
  const size9 = u32le(b, 0x2c);
  if (size9 === 0 || off9 < 0x160 || off9 + size9 > p.fileSize) return false;
  if (load9 < 0x02000000 || load9 > 0x023fffff || load9 + size9 > 0x02400000)
    return false;
  if (entry9 < load9 || entry9 >= load9 + size9) return false;
  const off7 = u32le(b, 0x30);
  const load7 = u32le(b, 0x38);
  const size7 = u32le(b, 0x3c);
  if (size7 !== 0) {
    if (off7 < 0x160 || off7 + size7 > p.fileSize) return false;
    const mainRam = load7 >= 0x02000000 && load7 <= 0x023fffff;
    const wram = load7 >= 0x037f8000 && load7 <= 0x0380ffff;
    if (!mainRam && !wram) return false;
  }
  return true;
};

const inGekkoRam = (a: number): boolean =>
  (a >= 0x80000000 && a <= 0x817fffff) || (a >= 0x90000000 && a <= 0x93ffffff);

const isDol = (p: ConsoleProbe): boolean => {
  const b = p.prefix;
  if (p.fileSize < 0x100 || b.length < 0x100) return false;
  for (let i = 0xe4; i < 0x100; i++) if (b[i] !== 0) return false;
  const sections: { off: number; addr: number; size: number; text: boolean }[] =
    [];
  for (let i = 0; i < 18; i++) {
    const size = u32be(b, 0x90 + 4 * i);
    if (size === 0) continue;
    const off = u32be(b, 4 * i);
    const addr = u32be(b, 0x48 + 4 * i);
    if (
      off < 0x100 ||
      off + size > p.fileSize ||
      off % 4 !== 0 ||
      addr % 4 !== 0
    )
      return false;
    if (!inGekkoRam(addr) || !inGekkoRam(addr + size - 1)) return false;
    sections.push({ off, addr, size, text: i < 7 });
  }
  for (let i = 0; i < sections.length; i++)
    for (let j = i + 1; j < sections.length; j++) {
      const s = sections[i]!;
      const t = sections[j]!;
      if (s.addr < t.addr + t.size && t.addr < s.addr + s.size) return false;
      if (s.off < t.off + t.size && t.off < s.off + s.size) return false;
    }
  const entry = u32be(b, 0xe0);
  if (entry % 4 !== 0) return false;
  if (
    !sections.some((s) => s.text && entry >= s.addr && entry < s.addr + s.size)
  )
    return false;
  const bssSize = u32be(b, 0xdc);
  const bssAddr = u32be(b, 0xd8);
  return (
    bssSize === 0 || (inGekkoRam(bssAddr) && inGekkoRam(bssAddr + bssSize - 1))
  );
};

const isPowerOfTwoOrZero = (v: number): boolean =>
  v === 0 || (v <= 0x10000 && (v & (v - 1)) === 0);

const isRel = async (p: ConsoleProbe): Promise<boolean> => {
  const b = p.prefix;
  if (b.length < 0x40) return false;
  if (u32be(b, 0) === 0 || u32be(b, 4) !== 0 || u32be(b, 8) !== 0) return false;
  const version = u32be(b, 0x1c);
  if (version < 1 || version > 3) return false;
  const headerSize = [0, 0x40, 0x48, 0x4c][version]!;
  const count = u32be(b, 0x0c);
  const infoOffset = u32be(b, 0x10);
  if (count < 2 || count > 255) return false;
  if (
    infoOffset < headerSize ||
    infoOffset % 4 !== 0 ||
    infoOffset + count * 8 > p.fileSize
  )
    return false;
  const info = await bytesAt(p, infoOffset, count * 8);
  if (info.length < count * 8 || u32be(info, 0) !== 0 || u32be(info, 4) !== 0)
    return false;
  let executable = false;
  const loaded: boolean[] = [];
  for (let i = 0; i < count; i++) {
    const raw = u32be(info, 8 * i);
    const size = u32be(info, 8 * i + 4);
    const offset = raw & ~1;
    loaded.push(offset !== 0);
    if (offset === 0) continue;
    if (offset < headerSize || offset + size > p.fileSize) return false;
    if ((raw & 1) !== 0) executable = true;
  }
  if (!executable) return false;
  const impOffset = u32be(b, 0x28);
  const impSize = u32be(b, 0x2c);
  if (impSize % 8 !== 0 || impOffset + impSize > p.fileSize) return false;
  if (impSize > 0) {
    const imports = await bytesAt(p, impOffset, impSize);
    for (let i = 0; i + 8 <= imports.length; i += 8)
      if (u32be(imports, i + 4) > p.fileSize) return false;
  }
  for (const at of [0x30, 0x31, 0x32]) {
    const section = b[at]!;
    if (section !== 0 && (section >= count || !loaded[section])) return false;
  }
  if (
    version >= 2 &&
    (!isPowerOfTwoOrZero(u32be(b, 0x40)) || !isPowerOfTwoOrZero(u32be(b, 0x44)))
  )
    return false;
  return version < 3 || u32be(b, 0x48) <= p.fileSize;
};

const SNES_FIRST_OPCODES = new Set([
  0x78, 0x18, 0x38, 0x9c, 0x4c, 0x5c, 0xc2, 0xe2, 0xa9, 0xa2, 0xa0, 0x20, 0x22,
  0x80, 0x8d, 0x8f, 0xea, 0xd8, 0xfb,
]);

const isSnes = async (p: ConsoleProbe): Promise<boolean> => {
  if (p.fileSize < 0x8000 || p.fileSize > 0x1000000) return false;
  const base = p.fileSize % 1024 === 512 ? 512 : 0;
  const romSize = p.fileSize - base;
  const candidates: [number, readonly number[], (reset: number) => number][] = [
    [0x7fc0, [0, 2, 3], (reset) => reset - 0x8000],
    [0xffc0, [1, 0xa], (reset) => reset],
    [0x40ffc0, [5], (reset) => 0x400000 + reset],
  ];
  for (const [h, modes, resetOffset] of candidates) {
    if (h + 0x40 > romSize) continue;
    const header = await bytesAt(p, base + h, 0x40);
    if (header.length < 0x40) continue;
    const mode = header[0x15]!;
    const reset = u16le(header, 0x3c);
    if (
      (mode & 0xe0) !== 0x20 ||
      !modes.includes(mode & 0x0f) ||
      reset < 0x8000
    )
      continue;
    let score = 0;
    if (u16le(header, 0x1c) + u16le(header, 0x1e) === 0xffff) score += 4;
    const target = resetOffset(reset);
    if (target >= 0 && target < romSize) {
      const opcode = await bytesAt(p, base + target, 1);
      if (opcode.length === 1 && SNES_FIRST_OPCODES.has(opcode[0]!)) score += 2;
    }
    let printable = 0;
    for (let i = 0; i < 21; i++) {
      const c = header[i]!;
      if ((c >= 0x20 && c <= 0x7e) || (c >= 0xa0 && c <= 0xdf)) printable++;
    }
    score += printable === 21 ? 2 : printable >= 16 ? 1 : 0;
    const romCode = header[0x17]!;
    if (romCode >= 0x08 && romCode <= 0x0d) {
      const declared = 1024 << romCode;
      if (declared >= romSize / 2 && declared <= romSize * 2) score += 1;
    }
    if (header[0x18]! <= 7) score += 1;
    if (score >= 4) return true;
  }
  return false;
};

// ---- Sega ----------------------------------------------------------------------------------

const isMegaDrivePlain = (p: ConsoleProbe): boolean => {
  const b = p.prefix;
  if (p.fileSize < 0x200 || b.length < 0x200) return false;
  if (b.toString("latin1", 0, 14) === "SEGADISCSYSTEM") return false;
  const sega =
    b.toString("latin1", 0x100, 0x104) === "SEGA" ||
    b.toString("latin1", 0x101, 0x105) === "SEGA";
  return sega && u32be(b, 4) % 2 === 0;
};

const isMegaDriveSmd = async (p: ConsoleProbe): Promise<boolean> => {
  const b = p.prefix;
  if (
    p.fileSize <= 0x200 ||
    (p.fileSize - 0x200) % 0x4000 !== 0 ||
    b.length < 10
  )
    return false;
  if (!((b[8] === 0xaa && b[9] === 0xbb) || b[1] === 0x03)) return false;
  const block = await bytesAt(p, 0x200, 0x4000);
  if (block.length < 0x4000) return false;
  const romByte = (k: number): number =>
    k % 2 === 1 ? block[(k - 1) / 2]! : block[0x2000 + k / 2]!;
  const text = (start: number): string =>
    String.fromCharCode(
      romByte(start),
      romByte(start + 1),
      romByte(start + 2),
      romByte(start + 3),
    );
  return text(0x100) === "SEGA" || text(0x101) === "SEGA";
};

const isMasterSystem = async (p: ConsoleProbe): Promise<boolean> => {
  for (const at of [0x7ff0, 0x3ff0, 0x1ff0]) {
    if (at + 8 > p.fileSize) continue;
    if ((await bytesAt(p, at, 8)).toString("latin1") === "TMR SEGA")
      return true;
  }
  return (
    ["sms", "gg"].includes(p.extension) &&
    p.fileSize % 0x2000 === 0 &&
    p.fileSize > 0 &&
    p.fileSize <= 4 * 1024 * 1024
  );
};

/** Saturn/Dreamcast boot text at the start of user data (bare IP.BIN/ISO or a raw sector image). */
const segaDiscText = (b: Buffer, text: string): boolean => {
  const sync =
    b.length >= 16 &&
    b[0] === 0 &&
    b[11] === 0 &&
    b.subarray(1, 11).every((x) => x === 0xff);
  const start = !sync ? 0 : b[15] === 1 ? 16 : b[15] === 2 ? 24 : -1;
  return (
    start >= 0 && b.toString("latin1", start, start + text.length) === text
  );
};

// ---- Microsoft and home computers ------------------------------------------------------------

const isXbe = (p: ConsoleProbe): boolean => {
  const b = p.prefix;
  if (p.fileSize < 0x178 || b.toString("latin1", 0, 4) !== "XBEH") return false;
  const base = u32le(b, 0x104);
  const headers = u32le(b, 0x108);
  const count = u32le(b, 0x11c);
  const sectionHeaders = u32le(b, 0x120);
  return (
    base !== 0 &&
    base < 0x80000000 &&
    (base & 0xfff) === 0 &&
    headers >= 0x178 &&
    headers <= p.fileSize &&
    count >= 1 &&
    count <= 0x400 &&
    sectionHeaders >= base &&
    sectionHeaders + count * 0x38 <= base + headers
  );
};

const isXex2 = (p: ConsoleProbe): boolean => {
  const b = p.prefix;
  if (p.fileSize < 0x200 || b.toString("latin1", 0, 4) !== "XEX2") return false;
  const count = u32be(b, 0x14);
  return (
    u32be(b, 0x08) <= p.fileSize &&
    u32be(b, 0x10) + 0x184 <= p.fileSize &&
    count <= 256 &&
    0x18 + count * 8 <= p.fileSize
  );
};

const isMsxHeader = (b: Buffer, at: number): boolean => {
  if (b.length < at + 0x10 || b.toString("latin1", at, at + 2) !== "AB")
    return false;
  const fields = [2, 4, 6, 8].map((o) => u16le(b, at + o));
  if (!fields.every((v) => v === 0 || (v >= 0x4000 && v <= 0xbfff)))
    return false;
  return fields[0] !== 0 || fields[3] !== 0;
};

const isMsx = async (p: ConsoleProbe): Promise<boolean> => {
  let at = -1;
  if (isMsxHeader(p.prefix, 0)) at = 0;
  else if (p.fileSize >= 0x8000 && p.fileSize <= 0x10000) {
    const page = await bytesAt(p, 0x4000, 0x10);
    if (isMsxHeader(Buffer.concat([Buffer.alloc(0x4000), page]), 0x4000))
      at = 0x4000;
  }
  if (at < 0) return false;
  if (["rom", "mx1", "mx2"].includes(p.extension)) return true;
  const header = await bytesAt(p, at, 0x10);
  return (
    p.fileSize % 8192 === 0 && header.subarray(0x0a, 0x10).every((x) => x === 0)
  );
};

const isColecoHeader = (h: Buffer, extension: string): boolean => {
  if (h.length < 0x24) return false;
  const magic =
    (h[0] === 0xaa && h[1] === 0x55) || (h[0] === 0x55 && h[1] === 0xaa);
  if (!magic || u16le(h, 0x0a) < 0x8000) return false;
  if (["col", "rom", "bin"].includes(extension)) return true;
  let vectors = 0;
  for (let i = 0; i < 8; i++)
    if ([0xc3, 0xc9, 0xed, 0xfb, 0x00].includes(h[0x0c + 3 * i]!)) vectors++;
  return vectors >= 4;
};

const isColecoVision = async (p: ConsoleProbe): Promise<boolean> => {
  if (p.fileSize < 0x24 || p.fileSize > 1024 * 1024) return false;
  if (p.fileSize > 0x8000 && p.fileSize % 0x4000 === 0) {
    const mega = await bytesAt(p, p.fileSize - 0x4000, 0x24);
    if (isColecoHeader(mega, p.extension)) return true;
  }
  return isColecoHeader(lower(p.prefix, 0x24), p.extension);
};

const isAtariXex = async (p: ConsoleProbe): Promise<boolean> => {
  if (p.fileSize < 7 || p.fileSize > 1024 * 1024) return false;
  if (u16le(p.prefix, 0) !== 0xffff || u16le(p.prefix, 2) === 0xffff)
    return false;
  const b = await wholeFile(p, 1024 * 1024);
  if (b === undefined) return false;
  let at = 2;
  let segments = 0;
  while (at < b.length) {
    if (b.length - at <= 3 || b.subarray(at).every((x) => x === 0))
      return segments > 0;
    if (u16le(b, at) === 0xffff) {
      at += 2;
      if (at >= b.length || u16le(b, at) === 0xffff) return false; // marker at the end or a run
    }
    const start = u16le(b, at);
    const end = u16le(b, at + 2);
    if (start < 0 || end < 0 || start > end) return false;
    at += 4 + (end - start + 1);
    if (at > b.length) return false;
    segments++;
  }
  return segments > 0;
};

const isC64Prg = (p: ConsoleProbe): boolean => {
  if (p.extension !== "prg" || p.fileSize < 3 || p.fileSize > 0x10001)
    return false;
  const load = u16le(p.prefix, 0);
  return load >= 0x0400 && load <= 0xcfff;
};

// ---- the table -------------------------------------------------------------------------------

const rule = (
  id: string,
  platform: string,
  ghidraLoader: string,
  architecture: ConsoleArchitecture,
  matches: (p: ConsoleProbe) => boolean | Promise<boolean>,
): ConsoleRule => ({
  info: { id, platform, ghidraLoader },
  architecture,
  matches: async (p) => matches(p),
});

/**
 * The detection rules, most specific first. Each mirrors the detection of the Ghidra loader named
 * in its info (rivaborn/ghidra ConsoleFormats), so REA only admits a file the loader will claim.
 */
const RULES: readonly ConsoleRule[] = [
  rule("rpx", "Wii U", "RpxLoader", "powerpc32be", isRpx),
  rule("xbe", "Xbox", "XbeLoader", "x86", isXbe),
  rule("xex2", "Xbox 360", "Xex2Loader", "powerpc64be", isXex2),
  rule("n64", "Nintendo 64", "N64Loader", "mips64be", isN64),
  rule("psx-exe", "PlayStation", "PsxExeLoader", "mips32le", isPsxExe),
  rule("nes", "NES", "NesLoader", "6502", isNes),
  rule("gameboy", "Game Boy", "GameBoyLoader", "lr35902", isGameBoy),
  rule("nds", "Nintendo DS", "NdsLoader", "arm", isNds),
  rule("gba", "Game Boy Advance", "GbaLoader", "arm", isGba),
  rule("saturn", "Saturn", "SaturnLoader", "sh2", (p) =>
    segaDiscText(p.prefix, "SEGA SEGASATURN "),
  ),
  rule("dreamcast", "Dreamcast", "DreamcastLoader", "sh4", (p) =>
    segaDiscText(p.prefix, "SEGA SEGAKATANA "),
  ),
  rule("megadrive", "Mega Drive", "MegaDriveLoader", "m68k", isMegaDrivePlain),
  rule(
    "megadrive-smd",
    "Mega Drive",
    "MegaDriveLoader",
    "m68k",
    isMegaDriveSmd,
  ),
  rule("snes", "SNES", "SnesLoader", "65816", isSnes),
  rule(
    "mastersystem",
    "Master System / Game Gear",
    "SegaMasterSystemLoader",
    "z80",
    isMasterSystem,
  ),
  rule("dol", "GameCube / Wii", "DolLoader", "powerpc32be", isDol),
  rule("rel", "GameCube / Wii", "RelLoader", "powerpc32be", isRel),
  rule("msx", "MSX", "MsxRomLoader", "z80", isMsx),
  rule(
    "colecovision",
    "ColecoVision",
    "ColecoVisionLoader",
    "z80",
    isColecoVision,
  ),
  rule("atari-xex", "Atari 8-bit", "AtariXexLoader", "6502", isAtariXex),
  rule("c64-prg", "Commodore 64", "C64PrgLoader", "6502", isC64Prg),
];

/** Detect a console format, or undefined when none matches. */
export const detectConsoleFormat = async (
  prefix: Buffer,
  fileSize: number,
  path: string | undefined,
  read: ConsoleByteWindow,
): Promise<ConsoleExecutableMetadata | undefined> => {
  const dot = path === undefined ? -1 : path.lastIndexOf(".");
  const slash =
    path === undefined
      ? -1
      : Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  const extension =
    path !== undefined && dot > slash ? path.slice(dot + 1).toLowerCase() : "";
  const probe: ConsoleProbe = { prefix, fileSize, extension, read };
  for (const rule of RULES)
    if (await rule.matches(probe))
      return {
        format: "console",
        architecture: rule.architecture,
        availableArchitectures: [rule.architecture],
        console: rule.info,
      };
  return undefined;
};

/** Exported for tests: every format REA can detect. */
export const CONSOLE_FORMATS: readonly ConsoleFormatInfo[] = RULES.map(
  (rule) => rule.info,
);
