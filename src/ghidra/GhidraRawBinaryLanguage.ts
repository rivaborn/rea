import type { RawBinaryAdmission } from "../domain/rawBinary.js";

/** Bound Ghidra language for a caller-supplied raw-binary architecture. */
export interface GhidraRawBinaryLanguage {
  readonly languageId: string;
  readonly compilerSpecId: "default" | "gcc";
  readonly defaultAddressSpace: "ram" | "RAM";
}

/**
 * Map caller-visible CPU families to generic Ghidra languages with a
 * supported generic compiler specification. These are analysis conventions,
 * not evidence of the target's original compiler. Each family has one fixed
 * byte order: m68k is big-endian and the others are little-endian. Big-endian
 * ARM, Thumb-only, Cortex-M, and other processor variants are out of scope.
 */
export const ghidraRawBinaryLanguage = (
  architecture: RawBinaryAdmission["architecture"],
): GhidraRawBinaryLanguage => {
  switch (architecture) {
    case "6502":
      return {
        languageId: "6502:LE:16:default",
        compilerSpecId: "default",
        defaultAddressSpace: "RAM",
      };
    case "m68k":
      // Ghidra's default 68000 language decodes the 68040 superset; no
      // MC68000-only variant is declared in the 68000 processor module.
      return {
        languageId: "68000:BE:32:default",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "x86":
      return {
        languageId: "x86:LE:32:default",
        compilerSpecId: "gcc",
        defaultAddressSpace: "ram",
      };
    case "x86_64":
      return {
        languageId: "x86:LE:64:default",
        compilerSpecId: "gcc",
        defaultAddressSpace: "ram",
      };
    case "arm":
      return {
        languageId: "ARM:LE:32:v7",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "arm64":
      return {
        languageId: "AARCH64:LE:64:v8A",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "mips32le":
      // PlayStation (R3000A), little-endian MIPS32
      return {
        languageId: "MIPS:LE:32:default",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "mips32be":
      // big-endian MIPS32
      return {
        languageId: "MIPS:BE:32:default",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "mips64be":
      // Nintendo 64 (VR4300): 64-bit registers, 32-bit addresses
      return {
        languageId: "MIPS:BE:64:64-32addr",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "r5900":
      // PlayStation 2 Emotion Engine; language from the patched Ghidra (rivaborn/ghidra nxdecomp-fixes)
      return {
        languageId: "MIPS:LE:64:R5900",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "powerpc32be":
      // GameCube Gekko, Wii Broadway, Wii U Espresso (paired-single instructions are not decoded)
      return {
        languageId: "PowerPC:BE:32:default",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "powerpc64be":
      // PS3 Cell PPU, Xbox 360 Xenon: 64-bit registers, 32-bit addresses
      return {
        languageId: "PowerPC:BE:64:64-32addr",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "sh2":
      // Sega Saturn and 32X (SH-2, big-endian)
      return {
        languageId: "SuperH:BE:32:SH-2",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "sh4":
      // Sega Dreamcast (SH-4, little-endian)
      return {
        languageId: "SuperH4:LE:32:default",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "z80":
      // Master System, Game Gear, ColecoVision, MSX
      return {
        languageId: "z80:LE:16:default",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "lr35902":
      // Game Boy and Game Boy Color (SM83); language from the patched Ghidra
      return {
        languageId: "LR35902:LE:16:default",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
    case "65816":
      // SNES 5A22 (WDC 65C816); language from the patched Ghidra
      return {
        languageId: "65816:LE:24:default",
        compilerSpecId: "default",
        defaultAddressSpace: "ram",
      };
  }
};
