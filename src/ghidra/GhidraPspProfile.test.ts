import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { parseConfig } from "../config/parseConfig.js";
import type { BinaryTarget } from "../domain/binaryTargetTypes.js";
import { silentLogger } from "../logger.js";
import { ghidraProfileInstallationHost as host } from "./GhidraInstallation.fixture.js";
import type { AvailableGhidraInstallation } from "./GhidraInstallation.js";
import { GhidraProvider } from "./GhidraProvider.js";
import { resolveGhidraPspExtension } from "./GhidraPspExtension.js";

// Host admission of the PSP lane: Linux x64 and Windows x64 run the caller-installed
// ghidra-allegrex extension; other platforms and architectures stay refused.
const parsed = parseConfig({ GHIDRA_INSTALL_DIR: "/ghidra" });
if (!parsed.ok) throw parsed.error;
const config = parsed.value;
const target = {
  kind: "executable",
  format: "elf",
  architecture: "mips",
  availableArchitectures: ["mips"],
  path: "/caller/psp.elf",
  sha256: "a".repeat(64),
  mips: {
    elfClass: 32,
    byteOrder: "little",
    type: 2,
    flags: 0x10a23001,
    gnuAttributes: null,
    abiFlags: {
      version: 0,
      isaLevel: 2,
      isaRevision: 0,
      gprSize: 1,
      cpr1Size: 1,
      cpr2Size: 0,
      fpAbi: 2,
      isaExtension: 0,
      ases: 0,
      flags1: 1,
      flags2: 0,
    },
  },
} satisfies BinaryTarget;

describe("PSP Allegrex host admission", () => {
  it.each([
    ["linux", "x64"],
    ["win32", "x64"],
  ] as const)("admits a PSP target on %s %s", (platform, architecture) => {
    const provider = new GhidraProvider(
      config,
      silentLogger,
      {},
      {
        ...host,
        platform,
        architecture,
      },
    );
    expect(provider.inspectTargetSupport(target).status).toBe("supported");
  });

  it.each([
    ["darwin", "x64"],
    ["darwin", "arm64"],
    ["linux", "arm64"],
    ["win32", "arm64"],
    ["win32", "ia32"],
  ] as const)(
    "does not broaden the PSP lane to %s %s",
    (platform, architecture) => {
      const provider = new GhidraProvider(
        config,
        silentLogger,
        {},
        {
          ...host,
          platform,
          architecture,
        },
      );
      const support = provider.inspectTargetSupport(target);
      expect(support.status).toBe("unsupported");
      if (support.status !== "unsupported") throw new Error("admitted");
      expect(support.reason).toBe(
        "The PSP Allegrex profile is verified on Linux x64 and Windows x64 only.",
      );
    },
  );
});

describe("PSP extension resolution by installation host", () => {
  const directories: string[] = [];
  afterEach(async () => {
    for (const directory of directories.splice(0))
      await rm(directory, { recursive: true, force: true });
  });

  const installation = async (
    platform: NodeJS.Platform,
    architecture: NodeJS.Architecture,
  ): Promise<AvailableGhidraInstallation> => {
    const installDir = await realpath(
      await mkdtemp(join(tmpdir(), "rea-psp-host-")),
    );
    directories.push(installDir);
    const root = join(installDir, "Ghidra", "Extensions", "ghidra-allegrex");
    // Synthetic installed files: this checks resolution, not Allegrex execution.
    const contents = {
      "Module.manifest": "",
      "extension.properties": "name=ghidra-allegrex\nversion=12.1.4\n",
      "data/languages/allegrex.ldefs": "synthetic language definition",
      "data/languages/allegrex.sla": "synthetic compiled processor",
      "data/languages/allegrex.pspec": "synthetic processor specification",
      "data/languages/allegrex.cspec": "synthetic compiler specification",
      "lib/ghidra-allegrex.jar": "synthetic loader artifact",
    };
    for (const [path, text] of Object.entries(contents)) {
      await mkdir(dirname(join(root, path)), { recursive: true });
      await writeFile(join(root, path), text);
    }
    return {
      status: "available",
      platform,
      architecture,
      installDir,
      analyzeHeadlessPath: join(installDir, "support", "analyzeHeadless"),
      applicationPropertiesPath: join(
        installDir,
        "Ghidra",
        "application.properties",
      ),
      configurationDirectoryName: "ghidra_12.1.4_PUBLIC",
      nativeDecompilerPath: null,
      javaCommand: "java",
      providerVersion: "12.1.4",
      javaHome: "/jdk-21",
      javaVersion: "21.0.11",
      checks: [],
    };
  };

  it.each([
    ["linux", "x64"],
    ["win32", "x64"],
  ] as const)(
    "fingerprints the installed extension for a %s %s installation",
    async (platform, architecture) => {
      const inspected = await installation(platform, architecture);
      const result = await resolveGhidraPspExtension(
        inspected,
        new ArtifactResourceScope(),
      );
      if (!result.ok) throw result.error;
      expect(result.value).toMatchObject({
        id: "ghidra-allegrex",
        root: join(
          inspected.installDir,
          "Ghidra",
          "Extensions",
          "ghidra-allegrex",
        ),
        ghidra_version: "12.1.4",
      });
      expect(result.value.sha256).toMatch(/^[a-f0-9]{64}$/u);
    },
  );

  it.each([
    ["darwin", "arm64"],
    ["win32", "arm64"],
    ["linux", "arm64"],
  ] as const)(
    "refuses a %s %s installation before reading the extension",
    async (platform, architecture) => {
      const result = await resolveGhidraPspExtension(
        await installation(platform, architecture),
        new ArtifactResourceScope(),
      );
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("admitted");
      expect(result.error.message).toContain(
        "requires a supported Linux x64 or Windows x64 Ghidra installation",
      );
    },
  );
});
