import { describe, expect, it } from "vitest";
import { isZoneApex, protectedRRsetPermission } from "./protected-rrsets";

const ZONE = "example.com.";

describe("isZoneApex", () => {
  it("treats @, empty and the zone name itself as the apex", () => {
    expect(isZoneApex("@", ZONE)).toBe(true);
    expect(isZoneApex("", ZONE)).toBe(true);
    expect(isZoneApex("  ", ZONE)).toBe(true);
    expect(isZoneApex("example.com.", ZONE)).toBe(true);
  });

  it("ignores case and a missing trailing dot", () => {
    expect(isZoneApex("EXAMPLE.COM.", ZONE)).toBe(true);
    expect(isZoneApex("example.com", ZONE)).toBe(true);
    expect(isZoneApex("example.com.", "EXAMPLE.COM")).toBe(true);
  });

  it("does not treat a child name as the apex", () => {
    expect(isZoneApex("www.example.com.", ZONE)).toBe(false);
    expect(isZoneApex("sub.example.com.", ZONE)).toBe(false);
    // A different zone that merely ends with the same labels.
    expect(isZoneApex("notexample.com.", ZONE)).toBe(false);
  });
});

describe("protectedRRsetPermission", () => {
  it("charges soa.update for any SOA write", () => {
    expect(protectedRRsetPermission(ZONE, "SOA", ZONE)).toBe("soa.update");
    expect(protectedRRsetPermission("@", "SOA", ZONE)).toBe("soa.update");
    expect(protectedRRsetPermission(ZONE, "soa", ZONE)).toBe("soa.update");
  });

  it("charges record.update.apex-ns for the apex NS RRset", () => {
    expect(protectedRRsetPermission(ZONE, "NS", ZONE)).toBe("record.update.apex-ns");
    expect(protectedRRsetPermission("@", "NS", ZONE)).toBe("record.update.apex-ns");
    expect(protectedRRsetPermission("", "ns", ZONE)).toBe("record.update.apex-ns");
  });

  it("leaves a child delegation as an ordinary record", () => {
    // NS below the apex is content this zone serves, not its own
    // delegation - `record.*` alone covers it.
    expect(protectedRRsetPermission("sub.example.com.", "NS", ZONE)).toBeNull();
  });

  it("leaves ordinary records alone, apex or not", () => {
    expect(protectedRRsetPermission("www.example.com.", "A", ZONE)).toBeNull();
    expect(protectedRRsetPermission(ZONE, "A", ZONE)).toBeNull();
    expect(protectedRRsetPermission("@", "MX", ZONE)).toBeNull();
    expect(protectedRRsetPermission(ZONE, "TXT", ZONE)).toBeNull();
  });
});
