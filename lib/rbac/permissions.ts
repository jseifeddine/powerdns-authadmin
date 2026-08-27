/**
 * lib/rbac/permissions.ts
 *
 * The master list of permissions. Every authorization check anywhere in the
 * app names one of these strings; new permissions go through code review here
 * before they appear in role definitions or `can()` checks.
 *
 * Naming convention: `<resource>.<action>`. Resources are singular nouns
 * (zone, record, user). Actions are simple verbs (read, create, update,
 * delete, configure).
 *
 * To add a permission:
 *   1. Add the string to the `PERMISSIONS` array below.
 *   2. Add it to the default role(s) in `lib/rbac/default-roles.ts` that
 *      should have it.
 *   3. Update any docs that list the vocabulary.
 */

import "server-only";

/**
 * The canonical permission list. The `as const` makes it a literal-typed
 * tuple from which we derive the `Permission` type.
 */
export const PERMISSIONS = [
  // === Zones ===
  "zone.read",
  "zone.create",
  "zone.update",
  "zone.delete",
  "zone.export",
  "zone.import",
  // Read-only view of the Zone settings tab (kind, masters, SOA-EDIT,
  // SOA-EDIT-API, API-RECTIFY, horizon). Held separately from
  // `zone.update` so a role can be given record editing without ever
  // seeing - let alone changing - the knobs that decide the zone's
  // authority and how it transfers. Without it the tab is not rendered
  // and `?tab=settings` falls back to Records.
  "zone.settings.read",

  // === Records ===
  "record.read",
  "record.create",
  "record.update",
  "record.delete",
  // ADDITIONAL permission, required on top of the matching
  // `record.create/update/delete`, to write an NS RRset at the zone
  // apex. Apex NS is the zone's delegation: an operator who removes or
  // repoints it takes the zone off the internet as surely as a bad SOA
  // does, so a self-service editor gets the record permissions without
  // this one. NS records BELOW the apex (child delegations) are
  // ordinary records and need only `record.*`. ADR-0023 covers why this one
  // is additive while `soa.update` replaces the record permission.
  "record.update.apex-ns",

  // === SOA ===
  // The SOA RRset is its own resource, not a `record.*` action (ADR-0023): it
  // carries the zone's authority and transfer timers, has a dedicated
  // editor tab, and is the one RRset a zone cannot exist without.
  // `soa.read` gates the SOA tab; `soa.update` gates every write to
  // the SOA RRset, whether it arrives from the SOA panel or a
  // hand-rolled PATCH.
  "soa.read",
  "soa.update",

  // === DNSSEC ===
  "dnssec.read",
  "dnssec.configure",

  // === Zone metadata ===
  "metadata.read",
  "metadata.write",

  // === TSIG keys ===
  // `tsig.read` gates the listing (name + algorithm only - never
  // the secret). `tsig.manage` gates create / regenerate / delete
  // AND reveal-secret. Splitting them lets operators audit the
  // configured key inventory without granting access to the
  // shared-secret material itself.
  "tsig.read",
  "tsig.manage",

  // === Autoprimaries ===
  "autoprimary.manage",

  // === Templates ===
  "template.use",
  "template.manage",

  // === Identity ===
  "user.read",
  "user.create",
  "user.update",
  "user.delete",
  "user.disable",
  "user.reset-password",

  // === Teams ===
  "team.read",
  "team.create",
  "team.update",
  "team.delete",
  "team.manage-members",

  // === Roles ===
  "role.read",
  "role.create",
  "role.update",
  "role.delete",
  "role.assign",

  // === Servers ===
  "server.read",
  "server.create",
  "server.update",
  "server.delete",

  // === API tokens ===
  "token.read.own",
  "token.create.own",
  "token.delete.own",
  "token.read.all",
  "token.delete.all",

  // === Audit + settings ===
  "audit.read",
  "settings.read",
  "settings.write",

  // === Authentication providers (OIDC, SAML, LDAP) ===
  // One permission pair for all three protocols. Gated by the unified
  // `/admin/authentication` admin surface.
  "auth.read",
  "auth.manage",

  // === System / backup ===
  // App-DB export + restore. Reveals every configured admin object
  // (users, providers, settings, audit) and can wholesale replace them
  // on restore. Default-granted only to the seeded Super Admin role.
  "system.backup",
] as const;

/** Union type of every valid permission. */
export type Permission = (typeof PERMISSIONS)[number];
