import { describe, expect, it } from "vitest";

import {
  ADDITIONAL_VERIFIED_GHIDRA_VERSIONS,
  ghidraReleaseAccepted,
  ghidraReleaseCompatibility,
  ghidraReleaseLine,
  SUPPORTED_GHIDRA_VERSION,
} from "./GhidraReleasePolicy.js";

describe("Ghidra release policy", () => {
  it("verifies the supported build and each additional verified build", () => {
    for (const raw of [
      SUPPORTED_GHIDRA_VERSION,
      ...ADDITIONAL_VERIFIED_GHIDRA_VERSIONS,
    ])
      expect(ghidraReleaseCompatibility(raw).status).toBe("verified");
  });

  it("accepts other builds of a verified release line", () => {
    expect(ghidraReleaseCompatibility("12.1.3").status).toBe("compatible");
    expect(ghidraReleaseCompatibility("12.2.1").status).toBe("compatible");
    expect(ghidraReleaseAccepted("12.2.1")).toBe(true);
  });

  it("rejects releases outside the verified lines", () => {
    expect(ghidraReleaseCompatibility("12.3").status).toBe("unsupported");
    expect(ghidraReleaseCompatibility("11.4.2").status).toBe("unsupported");
    expect(ghidraReleaseAccepted("12.3")).toBe(false);
  });

  it("names every accepted line", () => {
    expect(ghidraReleaseLine()).toBe("12.1.x or 12.2.x");
  });
});
