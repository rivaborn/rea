import { describe, expect, it } from "vitest";

import { parseConfig } from "../config/parseConfig.js";
import type {
  BinaryTarget,
  MipsElfMetadata,
} from "../domain/binaryTargetTypes.js";
import { admitRawBinary } from "../domain/rawBinary.js";
import { silentLogger } from "../logger.js";
import { ghidraProfileInstallationHost as host } from "./GhidraInstallation.fixture.js";
import {
  GHIDRA_R5900_LANGUAGE_ID,
  ghidraMipsLanguageOverride,
  ghidraMipsUnsupportedReason,
  isGhidraR5900Target,
} from "./GhidraMipsProfile.js";
import { GhidraProvider } from "./GhidraProvider.js";
import { ghidraRawBinaryLanguage } from "./GhidraRawBinaryLanguage.js";

const parsed = parseConfig({ GHIDRA_INSTALL_DIR: "/ghidra" });
if (!parsed.ok) throw parsed.error;
const config = parsed.value;

/** Console CPU families admitted as raw-binary images, with their Ghidra languages. */
const CONSOLES = [
  ["mips32le", "MIPS:LE:32:default", 4, 0xffffffffn],
  ["mips32be", "MIPS:BE:32:default", 4, 0xffffffffn],
  ["mips64be", "MIPS:BE:64:64-32addr", 4, 0xffffffffn],
  ["r5900", GHIDRA_R5900_LANGUAGE_ID, 4, 0xffffffffn],
  ["powerpc32be", "PowerPC:BE:32:default", 4, 0xffffffffn],
  ["powerpc64be", "PowerPC:BE:64:64-32addr", 4, 0xffffffffn],
  ["sh2", "SuperH:BE:32:SH-2", 2, 0xffffffffn],
  ["sh4", "SuperH4:LE:32:default", 2, 0xffffffffn],
  ["z80", "z80:LE:16:default", 1, 0xffffn],
  ["lr35902", "LR35902:LE:16:default", 1, 0xffffn],
  ["65816", "65816:LE:24:default", 1, 0xffffffn],
] as const;

const rawTarget = (architecture: string, entryPoint: string): BinaryTarget =>
  ({
    path: "/tmp/console.bin",
    sha256: "a".repeat(64),
    kind: "executable",
    format: "raw-binary",
    architecture,
    availableArchitectures: [architecture],
    entryPoint,
    entryPointSource: entryPoint,
  }) as BinaryTarget;

describe("raw-binary console CPU families", () => {
  it.each(CONSOLES)(
    "admits raw %s and binds %s",
    async (architecture, languageId, alignment, max) => {
      const admitted = admitRawBinary({
        architecture,
        entryPoint: "0x1000",
        fileBytes: 16,
      });
      expect(admitted.ok).toBe(true);
      expect(ghidraRawBinaryLanguage(architecture).languageId).toBe(languageId);
      if (alignment > 1) {
        const misaligned = admitRawBinary({
          architecture,
          entryPoint: "0x1001",
          fileBytes: 16,
        });
        expect(!misaligned.ok && misaligned.error.reason).toContain(
          `${String(alignment)}-byte aligned`,
        );
      }
      const tooHigh = admitRawBinary({
        architecture,
        // aligned, and 16 bytes from it run past the top of the address space
        entryPoint: `0x${(max + 1n - BigInt(alignment)).toString(16)}`,
        fileBytes: 16,
      });
      expect(!tooHigh.ok && tooHigh.error.reason).toContain("address width");

      for (const platform of ["linux", "win32"] as const) {
        const ghidra = new GhidraProvider(
          config,
          silentLogger,
          {},
          {
            ...host,
            platform,
          },
        );
        const target = rawTarget(architecture, "0x1000");
        expect(ghidra.inspectTargetSupport(target).status).toBe("supported");
        if (platform === "linux") {
          const resolved = await ghidra.resolveAnalysisProfile(target);
          if (!resolved.ok) throw resolved.error;
          expect(resolved.value.profile?.parameters).toMatchObject({
            target_format: "raw-binary",
            architecture,
            loader: "BinaryLoader",
            language_id: languageId,
          });
        }
      }
    },
  );
});

const ps2Elf = (change: Partial<MipsElfMetadata> = {}): BinaryTarget => ({
  path: "/tmp/SLUS_000.00",
  sha256: "a".repeat(64),
  kind: "executable",
  format: "elf",
  architecture: "mips",
  availableArchitectures: ["mips"],
  mips: {
    elfClass: 32,
    byteOrder: "little",
    type: 2,
    // EF_MIPS_ARCH_3 | EF_MIPS_MACH_5900 | EF_MIPS_NOREORDER, as the PS2 toolchains write it
    flags: 0x20924001,
    gnuAttributes: null,
    abiFlags: null,
    ...change,
  },
});

describe("PlayStation 2 ELF (R5900)", () => {
  it("admits EF_MIPS_MACH_5900 executables and pins the R5900 language", () => {
    const target = ps2Elf();
    expect(isGhidraR5900Target(target)).toBe(true);
    expect(ghidraMipsUnsupportedReason(target)).toBeNull();
    expect(ghidraMipsLanguageOverride(target)).toEqual({
      languageId: GHIDRA_R5900_LANGUAGE_ID,
      compilerSpecId: "default",
    });
    for (const platform of ["linux", "win32"] as const)
      expect(
        new GhidraProvider(
          config,
          silentLogger,
          {},
          { ...host, platform },
        ).inspectTargetSupport(target).status,
      ).toBe("supported");
  });
  it.each([
    [{ byteOrder: "big" }, "big-endian"],
    [{ elfClass: 64 }, "ELF64"],
    [{ type: 1 }, "relocatable"],
  ] satisfies [Partial<MipsElfMetadata>, string][])(
    "keeps other R5900-like headers out of the PS2 lane: %j (%s)",
    (change, _label) => {
      expect(isGhidraR5900Target(ps2Elf(change))).toBe(false);
    },
  );
  it("still refuses other MIPS III executables", () => {
    const target = ps2Elf({ flags: 0x20001001 });
    expect(isGhidraR5900Target(target)).toBe(false);
    expect(ghidraMipsUnsupportedReason(target)).not.toBeNull();
  });
});
