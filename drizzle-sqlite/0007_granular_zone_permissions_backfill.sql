-- Granular zone permissions (#119) - data-only backfill, no schema change.
-- SQLite mirror of drizzle/0007_granular_zone_permissions_backfill.sql; see
-- that file for why each rule exists.
--
--   soa.read              was implied by zone.read
--   zone.settings.read    was implied by zone.read
--   soa.update            was implied by record.update
--   record.update.apex-ns was implied by record.create/update/delete
--
-- System roles are excluded: `scripts/seed.ts` re-upserts them from
-- `lib/rbac/default-roles.ts` on every boot, and 1.5.6 deliberately changes
-- what Zone Editor grants.

-- === roles (operator-defined only) =========================================
UPDATE "roles" SET "permissions" = json_insert("permissions", '$[#]', 'soa.read')
WHERE "is_system" = 0
  AND EXISTS (SELECT 1 FROM json_each("roles"."permissions") WHERE "value" = 'zone.read')
  AND NOT EXISTS (SELECT 1 FROM json_each("roles"."permissions") WHERE "value" = 'soa.read');
--> statement-breakpoint

UPDATE "roles" SET "permissions" = json_insert("permissions", '$[#]', 'zone.settings.read')
WHERE "is_system" = 0
  AND EXISTS (SELECT 1 FROM json_each("roles"."permissions") WHERE "value" = 'zone.read')
  AND NOT EXISTS (SELECT 1 FROM json_each("roles"."permissions") WHERE "value" = 'zone.settings.read');
--> statement-breakpoint

UPDATE "roles" SET "permissions" = json_insert("permissions", '$[#]', 'soa.update')
WHERE "is_system" = 0
  AND EXISTS (SELECT 1 FROM json_each("roles"."permissions") WHERE "value" = 'record.update')
  AND NOT EXISTS (SELECT 1 FROM json_each("roles"."permissions") WHERE "value" = 'soa.update');
--> statement-breakpoint

UPDATE "roles" SET "permissions" = json_insert("permissions", '$[#]', 'record.update.apex-ns')
WHERE "is_system" = 0
  AND (
    EXISTS (SELECT 1 FROM json_each("roles"."permissions") WHERE "value" = 'record.create')
    OR EXISTS (SELECT 1 FROM json_each("roles"."permissions") WHERE "value" = 'record.update')
    OR EXISTS (SELECT 1 FROM json_each("roles"."permissions") WHERE "value" = 'record.delete')
  )
  AND NOT EXISTS (SELECT 1 FROM json_each("roles"."permissions") WHERE "value" = 'record.update.apex-ns');
--> statement-breakpoint

-- === zone_grants ============================================================
UPDATE "zone_grants" SET "permissions" = json_insert("permissions", '$[#]', 'soa.read')
WHERE EXISTS (SELECT 1 FROM json_each("zone_grants"."permissions") WHERE "value" = 'zone.read')
  AND NOT EXISTS (SELECT 1 FROM json_each("zone_grants"."permissions") WHERE "value" = 'soa.read');
--> statement-breakpoint

UPDATE "zone_grants" SET "permissions" = json_insert("permissions", '$[#]', 'zone.settings.read')
WHERE EXISTS (SELECT 1 FROM json_each("zone_grants"."permissions") WHERE "value" = 'zone.read')
  AND NOT EXISTS (SELECT 1 FROM json_each("zone_grants"."permissions") WHERE "value" = 'zone.settings.read');
--> statement-breakpoint

UPDATE "zone_grants" SET "permissions" = json_insert("permissions", '$[#]', 'soa.update')
WHERE EXISTS (SELECT 1 FROM json_each("zone_grants"."permissions") WHERE "value" = 'record.update')
  AND NOT EXISTS (SELECT 1 FROM json_each("zone_grants"."permissions") WHERE "value" = 'soa.update');
--> statement-breakpoint

UPDATE "zone_grants" SET "permissions" = json_insert("permissions", '$[#]', 'record.update.apex-ns')
WHERE (
    EXISTS (SELECT 1 FROM json_each("zone_grants"."permissions") WHERE "value" = 'record.create')
    OR EXISTS (SELECT 1 FROM json_each("zone_grants"."permissions") WHERE "value" = 'record.update')
    OR EXISTS (SELECT 1 FROM json_each("zone_grants"."permissions") WHERE "value" = 'record.delete')
  )
  AND NOT EXISTS (SELECT 1 FROM json_each("zone_grants"."permissions") WHERE "value" = 'record.update.apex-ns');
--> statement-breakpoint

-- === api_tokens =============================================================
-- An EMPTY scopes array means "everything the user currently has" and must
-- stay empty, hence the json_array_length guard.
UPDATE "api_tokens" SET "scopes" = json_insert("scopes", '$[#]', 'soa.read')
WHERE json_array_length("scopes") > 0
  AND EXISTS (SELECT 1 FROM json_each("api_tokens"."scopes") WHERE "value" = 'zone.read')
  AND NOT EXISTS (SELECT 1 FROM json_each("api_tokens"."scopes") WHERE "value" = 'soa.read');
--> statement-breakpoint

UPDATE "api_tokens" SET "scopes" = json_insert("scopes", '$[#]', 'zone.settings.read')
WHERE json_array_length("scopes") > 0
  AND EXISTS (SELECT 1 FROM json_each("api_tokens"."scopes") WHERE "value" = 'zone.read')
  AND NOT EXISTS (SELECT 1 FROM json_each("api_tokens"."scopes") WHERE "value" = 'zone.settings.read');
--> statement-breakpoint

UPDATE "api_tokens" SET "scopes" = json_insert("scopes", '$[#]', 'soa.update')
WHERE json_array_length("scopes") > 0
  AND EXISTS (SELECT 1 FROM json_each("api_tokens"."scopes") WHERE "value" = 'record.update')
  AND NOT EXISTS (SELECT 1 FROM json_each("api_tokens"."scopes") WHERE "value" = 'soa.update');
--> statement-breakpoint

UPDATE "api_tokens" SET "scopes" = json_insert("scopes", '$[#]', 'record.update.apex-ns')
WHERE json_array_length("scopes") > 0
  AND (
    EXISTS (SELECT 1 FROM json_each("api_tokens"."scopes") WHERE "value" = 'record.create')
    OR EXISTS (SELECT 1 FROM json_each("api_tokens"."scopes") WHERE "value" = 'record.update')
    OR EXISTS (SELECT 1 FROM json_each("api_tokens"."scopes") WHERE "value" = 'record.delete')
  )
  AND NOT EXISTS (SELECT 1 FROM json_each("api_tokens"."scopes") WHERE "value" = 'record.update.apex-ns');
