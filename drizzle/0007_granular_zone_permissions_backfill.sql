-- Granular zone permissions (#119) - data-only backfill, no schema change.
--
-- 1.5.6 splits three capabilities out of the permissions that used to imply
-- them:
--
--   soa.read              was implied by zone.read       (the SOA tab rendered
--                                                         for anyone who could
--                                                         open the zone)
--   zone.settings.read    was implied by zone.read       (ditto, Zone settings)
--   soa.update            was implied by record.update   (the SOA panel PATCHed
--                                                         the RRset route)
--   record.update.apex-ns was implied by record.create /
--                         record.update / record.delete  (apex NS was an
--                                                         ordinary record)
--
-- An upgrade must not silently change what an existing role can do, so every
-- operator-defined role, zone grant and API token that held the implying
-- permission gets the new explicit one. Tightening is then an opt-in edit:
-- untick soa.update on the role and the SOA becomes read-only for it.
--
-- SYSTEM roles are deliberately excluded - `scripts/seed.ts` upserts them from
-- `lib/rbac/default-roles.ts` on every boot, and 1.5.6 intentionally changes
-- what Zone Editor grants (records yes, SOA and apex NS no). Backfilling them
-- here would be overwritten on the next boot anyway.

-- === roles (operator-defined only) =========================================

UPDATE "roles" SET "permissions" = "permissions" || '["soa.read"]'::jsonb
WHERE "is_system" = false
  AND "permissions" @> '"zone.read"'::jsonb
  AND NOT ("permissions" @> '"soa.read"'::jsonb);
--> statement-breakpoint

UPDATE "roles" SET "permissions" = "permissions" || '["zone.settings.read"]'::jsonb
WHERE "is_system" = false
  AND "permissions" @> '"zone.read"'::jsonb
  AND NOT ("permissions" @> '"zone.settings.read"'::jsonb);
--> statement-breakpoint

UPDATE "roles" SET "permissions" = "permissions" || '["soa.update"]'::jsonb
WHERE "is_system" = false
  AND "permissions" @> '"record.update"'::jsonb
  AND NOT ("permissions" @> '"soa.update"'::jsonb);
--> statement-breakpoint

UPDATE "roles" SET "permissions" = "permissions" || '["record.update.apex-ns"]'::jsonb
WHERE "is_system" = false
  AND ("permissions" @> '"record.create"'::jsonb
       OR "permissions" @> '"record.update"'::jsonb
       OR "permissions" @> '"record.delete"'::jsonb)
  AND NOT ("permissions" @> '"record.update.apex-ns"'::jsonb);
--> statement-breakpoint

-- === zone_grants ============================================================
-- Per-(user|team, server, zone) literal permission lists. Same rules; there is
-- no system/custom distinction here, every row is operator-issued.

UPDATE "zone_grants" SET "permissions" = "permissions" || '["soa.read"]'::jsonb
WHERE "permissions" @> '"zone.read"'::jsonb
  AND NOT ("permissions" @> '"soa.read"'::jsonb);
--> statement-breakpoint

UPDATE "zone_grants" SET "permissions" = "permissions" || '["zone.settings.read"]'::jsonb
WHERE "permissions" @> '"zone.read"'::jsonb
  AND NOT ("permissions" @> '"zone.settings.read"'::jsonb);
--> statement-breakpoint

UPDATE "zone_grants" SET "permissions" = "permissions" || '["soa.update"]'::jsonb
WHERE "permissions" @> '"record.update"'::jsonb
  AND NOT ("permissions" @> '"soa.update"'::jsonb);
--> statement-breakpoint

UPDATE "zone_grants" SET "permissions" = "permissions" || '["record.update.apex-ns"]'::jsonb
WHERE ("permissions" @> '"record.create"'::jsonb
       OR "permissions" @> '"record.update"'::jsonb
       OR "permissions" @> '"record.delete"'::jsonb)
  AND NOT ("permissions" @> '"record.update.apex-ns"'::jsonb);
--> statement-breakpoint

-- === api_tokens =============================================================
-- Token scopes are a FLOOR over the user's own permissions, so a token that
-- listed record.update would otherwise lose SOA editing the moment the split
-- lands. An EMPTY scopes array means "everything the user currently has" and
-- must stay empty - jsonb_array_length filters those out.

UPDATE "api_tokens" SET "scopes" = "scopes" || '["soa.read"]'::jsonb
WHERE jsonb_array_length("scopes") > 0
  AND "scopes" @> '"zone.read"'::jsonb
  AND NOT ("scopes" @> '"soa.read"'::jsonb);
--> statement-breakpoint

UPDATE "api_tokens" SET "scopes" = "scopes" || '["zone.settings.read"]'::jsonb
WHERE jsonb_array_length("scopes") > 0
  AND "scopes" @> '"zone.read"'::jsonb
  AND NOT ("scopes" @> '"zone.settings.read"'::jsonb);
--> statement-breakpoint

UPDATE "api_tokens" SET "scopes" = "scopes" || '["soa.update"]'::jsonb
WHERE jsonb_array_length("scopes") > 0
  AND "scopes" @> '"record.update"'::jsonb
  AND NOT ("scopes" @> '"soa.update"'::jsonb);
--> statement-breakpoint

UPDATE "api_tokens" SET "scopes" = "scopes" || '["record.update.apex-ns"]'::jsonb
WHERE jsonb_array_length("scopes") > 0
  AND ("scopes" @> '"record.create"'::jsonb
       OR "scopes" @> '"record.update"'::jsonb
       OR "scopes" @> '"record.delete"'::jsonb)
  AND NOT ("scopes" @> '"record.update.apex-ns"'::jsonb);
