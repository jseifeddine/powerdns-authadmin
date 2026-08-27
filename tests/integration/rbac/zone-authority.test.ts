/**
 * tests/integration/rbac/zone-authority.test.ts
 *
 * The three surfaces that decide a zone's standing in DNS - its SOA, its
 * apex NS, and the zone-settings object (kind / masters / SOA-EDIT* /
 * API-RECTIFY) - are held apart from ordinary record editing (#119).
 *
 * The persona under test is the one the discussion describes: a hosting
 * customer who may freely manage A/AAAA/CNAME/MX/TXT in their own zone
 * and must not be able to break its authority or its transfers. That is
 * exactly the seeded Zone Editor role from 1.5.6 on.
 *
 * A zone_grant carrying the explicit permission has to open the same
 * doors a global role does - the two are ORed by `canActOnZone`, and a
 * regression in either half would leave one path silently permissive.
 */

import { beforeEach, describe, expect, it } from "vitest";
import { createAndLogin, loginAsBootstrap, SYSTEM_ROLES, uniqueEmail } from "../helpers/auth";
import { getZone, PDNS_BY_TOPOLOGY } from "../helpers/pdns";
import { resetState } from "../helpers/reset";
import { type TestHttp } from "../helpers/http";

const NS = ["ns1.example.com.", "ns2.example.com."] as const;

function randomZone(prefix: string): string {
  const tag = Math.random().toString(36).slice(2, 8);
  return `${prefix}-${Date.now()}-${tag}.example.com.`;
}

async function createZone(admin: TestHttp, name: string): Promise<void> {
  await admin.sendJson("POST", "/api/admin/pdns/zones", {
    serverSlug: "standalone",
    name,
    kind: "Master",
    nameservers: NS,
  });
}

async function getStandaloneId(admin: TestHttp): Promise<string> {
  const { servers } = await admin.getJson<{
    servers: Array<{ id: string; slug: string }>;
  }>("/api/admin/pdns-servers");
  const standalone = servers.find((s) => s.slug === "standalone");
  if (!standalone) throw new Error("standalone server not found");
  return standalone.id;
}

function patchRRset(
  client: TestHttp,
  zone: string,
  change: Record<string, unknown>,
): Promise<Response> {
  return client.call(`/api/admin/pdns/zones/${encodeURIComponent(zone)}/rrsets`, {
    method: "PATCH",
    json: { serverSlug: "standalone", changes: [change] },
  });
}

const soaUpsert = (zone: string): Record<string, unknown> => ({
  kind: "upsert",
  name: zone,
  type: "SOA",
  ttl: 3600,
  records: [{ content: `ns1.example.com. hostmaster.example.com. 1 10800 3600 604800 3600` }],
});

const apexNsUpsert = (zone: string): Record<string, unknown> => ({
  kind: "upsert",
  name: zone,
  type: "NS",
  ttl: 3600,
  records: [{ content: "ns1.example.com." }, { content: "ns3.example.com." }],
});

const ordinaryUpsert = (zone: string): Record<string, unknown> => ({
  kind: "upsert",
  name: `www.${zone}`,
  type: "A",
  ttl: 60,
  records: [{ content: "192.0.2.40" }],
});

describe("zone authority - SOA, apex NS and zone settings are held apart from record editing", () => {
  beforeEach(async () => {
    await resetState();
  });

  it("zone-editor edits records but is refused the SOA, the apex NS and zone settings", async () => {
    const admin = await loginAsBootstrap();
    const zone = randomZone("authority");
    await createZone(admin, zone);

    const { client } = await createAndLogin(admin, {
      email: uniqueEmail("client"),
      name: "Hosting customer",
      password: "hosting-client-pw-1234",
      roleSlug: SYSTEM_ROLES.zoneEditor,
    });

    expect((await patchRRset(client, zone, ordinaryUpsert(zone))).status).toBe(200);

    expect((await patchRRset(client, zone, soaUpsert(zone))).status).toBe(403);
    expect((await patchRRset(client, zone, apexNsUpsert(zone))).status).toBe(403);
    expect(
      (await patchRRset(client, zone, { kind: "delete", name: zone, type: "NS" })).status,
    ).toBe(403);

    const settings = await client.call(
      `/api/admin/pdns/zones/${encodeURIComponent(zone)}/settings`,
      { method: "PUT", json: { serverSlug: "standalone", soa_edit_api: "EPOCH" } },
    );
    expect(settings.status).toBe(403);
  }, 30_000);

  it("a batch is rejected whole when one change touches the SOA", async () => {
    const admin = await loginAsBootstrap();
    const zone = randomZone("batch");
    await createZone(admin, zone);

    const { client } = await createAndLogin(admin, {
      email: uniqueEmail("batch"),
      name: "Batch editor",
      password: "batch-editor-pw-1234",
      roleSlug: SYSTEM_ROLES.zoneEditor,
    });

    const res = await client.call(`/api/admin/pdns/zones/${encodeURIComponent(zone)}/rrsets`, {
      method: "PATCH",
      json: {
        serverSlug: "standalone",
        changes: [ordinaryUpsert(zone), soaUpsert(zone)],
      },
    });
    expect(res.status).toBe(403);

    // The permitted half of the batch must not have landed either - the
    // refusal happens before anything reaches PowerDNS.
    const after = await getZone(PDNS_BY_TOPOLOGY.standalone, zone);
    const rrsets = after.rrsets ?? [];
    expect(rrsets.some((rr) => rr.name === `www.${zone}` && rr.type === "A")).toBe(false);
  }, 30_000);

  it("operator holds soa.update and record.update.apex-ns, so both writes land", async () => {
    const admin = await loginAsBootstrap();
    const zone = randomZone("operator");
    await createZone(admin, zone);

    const { client } = await createAndLogin(admin, {
      email: uniqueEmail("operator"),
      name: "Operator",
      password: "operator-test-pw-1234",
      roleSlug: SYSTEM_ROLES.operator,
    });

    expect((await patchRRset(client, zone, soaUpsert(zone))).status).toBe(200);
    expect((await patchRRset(client, zone, apexNsUpsert(zone))).status).toBe(200);
  }, 30_000);

  it("a zone_grant carrying soa.update opens the SOA on that zone only", async () => {
    const admin = await loginAsBootstrap();
    const standaloneId = await getStandaloneId(admin);
    const granted = randomZone("granted-soa");
    const otherZone = randomZone("ungranted-soa");
    await createZone(admin, granted);
    await createZone(admin, otherZone);

    const { user, client } = await createAndLogin(admin, {
      email: uniqueEmail("soa-grantee"),
      name: "SOA grantee",
      password: "soa-grantee-pw-1234",
      roleSlug: SYSTEM_ROLES.readOnly,
    });

    await admin.sendJson("POST", `/api/admin/users/${user.id}/zone-grants`, {
      serverId: standaloneId,
      zoneName: granted,
      permissions: ["zone.read", "soa.read", "soa.update"],
    });

    expect((await patchRRset(client, granted, soaUpsert(granted))).status).toBe(200);
    expect((await patchRRset(client, otherZone, soaUpsert(otherZone))).status).toBe(403);
    // The grant carries no record.* permission, so ordinary records stay shut.
    expect((await patchRRset(client, granted, ordinaryUpsert(granted))).status).toBe(403);
  }, 30_000);
});
