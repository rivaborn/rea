import { describe, expect, it } from "vitest";

import { detectConsoleFormat } from "./consoleFormat.js";

/** Detect from an in-memory file (synthetic bytes only). */
const detect = async (bytes: Buffer, path = "/tmp/file.bin") =>
  detectConsoleFormat(
    bytes.subarray(0, 4096),
    bytes.length,
    path,
    async (offset, length) =>
      bytes.subarray(offset, offset + Math.min(length, 65536)),
  );

const GAMEBOY_LOGO = Buffer.from(
  "CEED6666CC0D000B03730083000C000D0008111F8889000EDCCC6EE6DDDDD999BBBB67636E0EECCCDDDC999FBBB9333E",
  "hex",
);

const gameBoy = (): Buffer => {
  const b = Buffer.alloc(0x8000);
  GAMEBOY_LOGO.copy(b, 0x104);
  return b;
};

const nes = (): Buffer => {
  const b = Buffer.alloc(16 + 0x8000 + 0x2000);
  b.write("NES\u001a", 0, "latin1");
  b[4] = 2; // 2 x 16 KB PRG
  b[5] = 1; // 1 x 8 KB CHR
  return b;
};

const psxExe = (): Buffer => {
  const b = Buffer.alloc(0x1000);
  b.write("PS-X EXE", 0, "latin1");
  b.writeUInt32LE(0x80010000, 0x10); // pc0
  b.writeUInt32LE(0x80010000, 0x18); // t_addr
  b.writeUInt32LE(0x800, 0x1c); // t_size
  return b;
};

const n64 = (first: number): Buffer => {
  const b = Buffer.alloc(0x2000);
  b.writeUInt32BE(first, 0);
  return b;
};

const gba = (): Buffer => {
  const b = Buffer.alloc(0x200);
  b[3] = 0xea;
  b[0xb2] = 0x96;
  let sum = 0;
  for (let i = 0xa0; i <= 0xbc; i++) sum += b[i]!;
  b[0xbd] = (-sum - 0x19) & 0xff;
  return b;
};

const megaDrive = (): Buffer => {
  const b = Buffer.alloc(0x1000);
  b.writeUInt32BE(0x200, 4);
  b.write("SEGA MEGA DRIVE ", 0x100, "latin1");
  return b;
};

const masterSystem = (): Buffer => {
  const b = Buffer.alloc(0x8000);
  b.write("TMR SEGA", 0x7ff0, "latin1");
  return b;
};

const segaDisc = (text: string): Buffer => {
  const b = Buffer.alloc(0x8000);
  b.write(text, 0, "latin1");
  return b;
};

const xbe = (): Buffer => {
  const b = Buffer.alloc(0x2000);
  b.write("XBEH", 0, "latin1");
  b.writeUInt32LE(0x10000, 0x104); // base
  b.writeUInt32LE(0x1000, 0x108); // size of headers
  b.writeUInt32LE(2, 0x11c); // sections
  b.writeUInt32LE(0x10200, 0x120); // section headers VA
  return b;
};

const xex2 = (): Buffer => {
  const b = Buffer.alloc(0x1000);
  b.write("XEX2", 0, "latin1");
  b.writeUInt32BE(0x800, 0x08);
  b.writeUInt32BE(0x200, 0x10);
  b.writeUInt32BE(2, 0x14);
  return b;
};

const rpx = (): Buffer => {
  const b = Buffer.alloc(0x400);
  b.writeUInt32BE(0x7f454c46, 0);
  b[4] = 1;
  b[5] = 2;
  b[7] = 0xca;
  b[8] = 0xfe;
  b.writeUInt16BE(0xfe01, 0x10);
  b.writeUInt16BE(20, 0x12);
  b.writeUInt32BE(0x40, 0x20); // e_shoff
  b.writeUInt16BE(0x28, 0x2e);
  b.writeUInt16BE(2, 0x30);
  return b;
};

const atariXex = (): Buffer =>
  Buffer.from([
    0xff, 0xff, 0x00, 0x20, 0x02, 0x20, 0xa9, 0x00, 0x60, 0xe0, 0x02, 0xe1,
    0x02, 0x00, 0x20,
  ]);

const c64Prg = (): Buffer =>
  Buffer.from([
    0x01, 0x08, 0x0b, 0x08, 0x0a, 0x00, 0x9e, 0x32, 0x30, 0x36, 0x34,
  ]);

describe("console format detection", () => {
  it.each([
    ["gameboy", "GameBoyLoader", "lr35902", gameBoy(), "/tmp/game.gb"],
    ["nes", "NesLoader", "6502", nes(), "/tmp/game.nes"],
    ["psx-exe", "PsxExeLoader", "mips32le", psxExe(), "/tmp/SLUS_000.00"],
    ["n64", "N64Loader", "mips64be", n64(0x80371240), "/tmp/game.z64"],
    ["n64", "N64Loader", "mips64be", n64(0x37804012), "/tmp/game.v64"],
    ["n64", "N64Loader", "mips64be", n64(0x40123780), "/tmp/game.n64"],
    ["gba", "GbaLoader", "arm", gba(), "/tmp/game.gba"],
    ["megadrive", "MegaDriveLoader", "m68k", megaDrive(), "/tmp/game.md"],
    [
      "mastersystem",
      "SegaMasterSystemLoader",
      "z80",
      masterSystem(),
      "/tmp/game.sms",
    ],
    [
      "saturn",
      "SaturnLoader",
      "sh2",
      segaDisc("SEGA SEGASATURN "),
      "/tmp/ip.bin",
    ],
    [
      "dreamcast",
      "DreamcastLoader",
      "sh4",
      segaDisc("SEGA SEGAKATANA "),
      "/tmp/ip.bin",
    ],
    ["xbe", "XbeLoader", "x86", xbe(), "/tmp/default.xbe"],
    ["xex2", "Xex2Loader", "powerpc64be", xex2(), "/tmp/default.xex"],
    ["rpx", "RpxLoader", "powerpc32be", rpx(), "/tmp/game.rpx"],
    ["atari-xex", "AtariXexLoader", "6502", atariXex(), "/tmp/game.xex"],
    ["c64-prg", "C64PrgLoader", "6502", c64Prg(), "/tmp/game.prg"],
  ] as const)(
    "detects %s through %s",
    async (id, loader, architecture, bytes, path) => {
      const detected = await detect(bytes, path);
      expect(detected).toMatchObject({
        format: "console",
        architecture,
        console: { id, ghidraLoader: loader },
      });
    },
  );

  it("keeps ordinary and damaged files out", async () => {
    const elf = rpx();
    elf[7] = 0; // ordinary PowerPC ELF, not Cafe OS
    expect(await detect(elf)).toBeUndefined();
    const logo = gameBoy();
    logo[0x110] = (logo[0x110] ?? 0) ^ 0xff;
    expect(await detect(logo, "/tmp/game.gb")).toBeUndefined();
    const psx = psxExe();
    psx.writeUInt32LE(0x12345678, 0x18); // text outside RAM
    expect(await detect(psx)).toBeUndefined();
    expect(await detect(c64Prg(), "/tmp/game.bin")).toBeUndefined(); // PRG needs its extension
    expect(await detect(Buffer.alloc(0x10000))).toBeUndefined(); // headerless image: raw-binary
    const markers = atariXex();
    markers.writeUInt16LE(0xffff, 2); // FF FF FF FF
    expect(await detect(markers)).toBeUndefined();
  });

  it("does not take a Mega-CD disc for a Mega Drive ROM", async () => {
    const disc = megaDrive();
    disc.write("SEGADISCSYSTEM", 0, "latin1");
    expect(await detect(disc)).toBeUndefined();
  });
});
