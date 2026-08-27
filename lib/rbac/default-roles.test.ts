import { describe, expect, it } from "vitest";
import { DEFAULT_ROLES, SUPER_ADMIN_SLUG } from "./default-roles";
import { PERMISSIONS, type Permission } from "./permissions";

function permissionsOf(slug: string): Permission[] {
  const role = DEFAULT_ROLES.find((r) => r.slug === slug);
  if (!role) throw new Error(`no seeded role "${slug}"`);
  return role.permissions;
}

describe("seeded system roles", () => {
  it("Super Admin holds every permission in the vocabulary", () => {
    // The seed relies on this: a permission added to the codebase must be
    // reachable by someone on the very next boot.
    const superAdmin = new Set<string>(permissionsOf(SUPER_ADMIN_SLUG));
    expect(PERMISSIONS.filter((p) => !superAdmin.has(p))).toEqual([]);
  });

  it("lists no permission twice", () => {
    for (const role of DEFAULT_ROLES) {
      expect(new Set(role.permissions).size, `${role.slug} has a duplicate`).toBe(
        role.permissions.length,
      );
    }
  });

  // #119: the hosting-provider case. Zone Editor is the role handed to a
  // customer who manages their own records; it must not reach the RRsets
  // and settings that decide the zone's authority.
  describe("Zone Editor is safe to hand to a self-service customer", () => {
    const zoneEditor = new Set<string>(permissionsOf("zone-editor"));

    it("can manage ordinary records", () => {
      expect(zoneEditor.has("record.create")).toBe(true);
      expect(zoneEditor.has("record.update")).toBe(true);
      expect(zoneEditor.has("record.delete")).toBe(true);
    });

    it("cannot rewrite the SOA or the apex NS", () => {
      expect(zoneEditor.has("soa.update")).toBe(false);
      expect(zoneEditor.has("record.update.apex-ns")).toBe(false);
    });

    it("cannot change the zone object or delete the zone", () => {
      expect(zoneEditor.has("zone.update")).toBe(false);
      expect(zoneEditor.has("zone.delete")).toBe(false);
      expect(zoneEditor.has("metadata.write")).toBe(false);
    });

    it("still SEES both surfaces - hiding them is a role edit, not the default", () => {
      expect(zoneEditor.has("soa.read")).toBe(true);
      expect(zoneEditor.has("zone.settings.read")).toBe(true);
    });
  });

  it("Operator owns the zone's shape: SOA, apex NS and the zone object", () => {
    const operator = new Set<string>(permissionsOf("operator"));
    expect(operator.has("soa.update")).toBe(true);
    expect(operator.has("record.update.apex-ns")).toBe(true);
    expect(operator.has("zone.update")).toBe(true);
  });

  it("Read Only sees every zone surface and writes none of them", () => {
    const readOnly = new Set<string>(permissionsOf("read-only"));
    expect(readOnly.has("soa.read")).toBe(true);
    expect(readOnly.has("zone.settings.read")).toBe(true);
    expect(readOnly.has("soa.update")).toBe(false);
    expect(readOnly.has("record.update.apex-ns")).toBe(false);
  });
});
