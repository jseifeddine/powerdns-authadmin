/**
 * lib/rbac/protected-rrsets.fuzz.test.ts
 *
 * Property-based (fuzz) tests for the protected-RRset classifier. It runs on
 * every RRset write with a name and type the requester chose, so it takes
 * untrusted string input on an authorization path - the case CONTRIBUTING
 * names for fast-check.
 *
 * The invariants are the ones an attacker would go after:
 *   - it never throws, so a hostile name can't turn the permission check into
 *     a 500 that skips it;
 *   - it never answers `null` (= "ordinary record, record.* is enough") for a
 *     spelling of the apex NS or for any SOA;
 *   - the answer is stable across the spellings that all normalize to the same
 *     RRset, so no casing or trailing-dot trick reaches a different verdict.
 */

import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { isZoneApex, protectedRRsetPermission } from "./protected-rrsets";

const RUNS = { numRuns: 1000 };

/** Zone names shaped like the real ones, plus adversarial free-form strings. */
const zoneNameArbitrary = fc.oneof(
  fc.constantFrom("example.com.", "EXAMPLE.COM.", "a.", "sub.zone.example.org.", "xn--80ak6aa92e."),
  fc.string({ unit: "binary" }),
);

/**
 * A name built from the characters a DNS label can actually hold. Used where
 * the property is about the SPELLINGS of one name (case, trailing dot) rather
 * than about surviving hostile input - `"a\t"` and `"a\t."` differ by a tab
 * before the dot, so they are two different names, not two spellings of one.
 */
const dnsNameArbitrary = fc
  .array(
    fc.stringMatching(/^[a-zA-Z0-9-]{1,20}$/).filter((label) => label.length > 0),
    { minLength: 1, maxLength: 4 },
  )
  .map((labels) => labels.join("."));

const recordTypeArbitrary = fc.oneof(
  fc.constantFrom("A", "AAAA", "NS", "ns", "Ns", "SOA", "soa", "CNAME", "MX", "TXT", "DS"),
  fc.string({ unit: "binary" }),
);

describe("protectedRRsetPermission - fuzz", () => {
  it("never throws, and answers only with a known permission or null", () => {
    fc.assert(
      fc.property(
        fc.string({ unit: "binary" }),
        recordTypeArbitrary,
        zoneNameArbitrary,
        (name, type, zone) => {
          const out = protectedRRsetPermission(name, type, zone);
          expect(out === null || out === "soa.update" || out === "record.update.apex-ns").toBe(
            true,
          );
        },
      ),
      RUNS,
    );
  });

  it("never lets a SOA through as an ordinary record", () => {
    // Any casing or surrounding whitespace of the mnemonic, at any name.
    fc.assert(
      fc.property(
        fc.string({ unit: "binary" }),
        zoneNameArbitrary,
        fc.constantFrom("SOA", "soa", "Soa", " SOA ", "sOa"),
        (name, zone, type) => {
          expect(protectedRRsetPermission(name, type, zone)).toBe("soa.update");
        },
      ),
      RUNS,
    );
  });

  it("never lets an apex NS through as an ordinary record", () => {
    fc.assert(
      fc.property(zoneNameArbitrary, fc.constantFrom("NS", "ns", "Ns", " ns "), (zone, type) => {
        // Every spelling `normalizeName` in the RRset route can resolve to the
        // apex must reach the same verdict.
        for (const apexSpelling of ["@", "", "  ", zone, zone.toUpperCase()]) {
          expect(protectedRRsetPermission(apexSpelling, type, zone)).toBe("record.update.apex-ns");
        }
      }),
      RUNS,
    );
  });

  it("agrees with isZoneApex on every NS name", () => {
    fc.assert(
      fc.property(fc.string({ unit: "binary" }), zoneNameArbitrary, (name, zone) => {
        const expected = isZoneApex(name, zone) ? "record.update.apex-ns" : null;
        expect(protectedRRsetPermission(name, "NS", zone)).toBe(expected);
      }),
      RUNS,
    );
  });

  it("is case- and trailing-dot-insensitive about the apex", () => {
    fc.assert(
      fc.property(dnsNameArbitrary, (bare) => {
        const zone = `${bare}.`;
        // Four spellings of one name, all denoting the same RRset. PowerDNS is
        // case-insensitive here and inconsistent about the trailing dot across
        // endpoints, so all four have to reach the same verdict.
        const verdicts = [zone, zone.toUpperCase(), bare, bare.toUpperCase()].map((spelling) =>
          protectedRRsetPermission(spelling, "NS", zone),
        );
        expect(new Set(verdicts)).toEqual(new Set(["record.update.apex-ns"]));
      }),
      RUNS,
    );
  });

  it("keeps a child name out of the apex verdict, however it is spelled", () => {
    fc.assert(
      fc.property(dnsNameArbitrary, dnsNameArbitrary, (child, bare) => {
        const zone = `${bare}.`;
        // `child.zone.` is inside the zone but below its apex - an ordinary
        // delegation, which `record.*` alone covers.
        expect(protectedRRsetPermission(`${child}.${zone}`, "NS", zone)).toBeNull();
        // And a zone whose name merely ENDS with the same labels is not this
        // zone's apex either.
        expect(protectedRRsetPermission(`x${zone}`, "NS", zone)).toBeNull();
      }),
      RUNS,
    );
  });
});
