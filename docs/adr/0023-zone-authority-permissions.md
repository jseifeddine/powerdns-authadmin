# ADR 0023 - Zone authority is a separate permission from zone records

- **Status:** Accepted
- **Date:** 2026-08-27
- **Deciders:** @jseifeddine

## Context

The permission vocabulary modelled a zone as two things: the zone object (`zone.*`) and the records
inside it (`record.*`). That split does not survive contact with the case that prompted this: a
hosting provider giving each customer their own zone, so the customer can point an A record at a new
box without filing a ticket (#119).

Three surfaces sat on the wrong side of the line.

The **SOA** is an RRset, so it answered to `record.update` like any other. It is also the record that
decides who is authoritative for the zone and how often every secondary refreshes, retries, and
expires it - a customer who edits it can stall transfers or expire the zone off its secondaries.

The **apex NS** RRset is the zone's delegation. It too was an ordinary record, so `record.delete`
removed it and took the zone off the internet, more completely than any SOA mistake would.

The **Zone settings** tab - kind, masters, `SOA-EDIT`, `SOA-EDIT-API`, `API-RECTIFY` - had no read
permission at all. It rendered for anyone who could open the zone, which is anyone with `zone.read`.
Its writes did answer to `zone.update`, but the page enabled the panel's inputs on `record.update`,
so a record editor got a fully interactive form whose Save then 403'd.

There was no permission an operator could withhold to close any of this. `record.update` was
load-bearing for the customer's actual job, and everything above rode along with it.

## Decision

We will model a zone's **authority** - the SOA, the apex NS, and the zone-settings object - as
distinct from its **records**, with four permissions:

| Permission              | Gates                                                  |
| ----------------------- | ------------------------------------------------------ |
| `soa.read`              | The SOA tab.                                           |
| `soa.update`            | Every write to the SOA RRset.                          |
| `zone.settings.read`    | The Zone settings tab. Writing it stays `zone.update`. |
| `record.update.apex-ns` | Writing the apex NS RRset.                             |

Three rules make them compose predictably:

1. **The SOA is its own resource.** `soa.update` _replaces_ the `record.*` requirement rather than
   adding to it - `soa.update` alone edits the SOA, and no amount of `record.*` substitutes for it.
   `Soa` joins the `SubjectType` union in `lib/rbac/ability.ts` alongside `Dnssec` and `Metadata`,
   which are likewise facets of a zone rather than tables.
2. **The apex NS stays a record.** `record.update.apex-ns` is an _additional_ requirement layered on
   top of the matching `record.create` / `record.update` / `record.delete`. NS below the apex is
   content the zone serves, not the zone's own standing, so `record.*` alone covers it.
3. **A missing read permission removes the surface, not just its Save button.** The tab is not
   rendered and a direct `?tab=` link falls back to Records.

One pure module, `lib/rbac/protected-rrsets.ts`, answers "does writing this (name, type) cost more
than `record.*`?". The RRset route runs it over every change **against the normalized name the patch
will carry**, before anything reaches PowerDNS; the record editor imports the same function to lock
apex NS rows. It carries no `import "server-only"` precisely so the client component can share it.

## Rationale

Putting the classifier in one pure function is the load-bearing part. The alternative - each panel
deciding what it is allowed to send - is how a UI lock and a server check drift apart, and the drift
is always in the permissive direction because the UI is what gets tested by hand. A shared predicate
run on the server means a hand-rolled `PATCH` gets exactly what the UI gets, and the editor's lock
cannot claim more or less than the route enforces.

Modelling the SOA as its own resource rather than as `record.update.soa` is the trade we thought
hardest about. `record.update.soa` would have kept everything under one prefix and read as a
narrowing of `record.update`. But it would have made the SOA permission _additive_, so editing the
SOA would require `record.update` as well - and a role whose whole point is "may fix the SOA, may
not touch records" would be unexpressible. Making it a resource costs a `SubjectType` entry and a
line of documentation about the asymmetry with `record.update.apex-ns`; that asymmetry is the honest
shape of the domain, since one of these is a record and the other is the zone's identity.

The downside we accept: the vocabulary now has two composition rules instead of one, and an operator
reading the checkbox list cannot tell which is which. Documentation carries that weight
(`docs/07-RBAC.md`, `provisioning.example.yaml`), and the permission picker is grouped by resource,
so `soa.*` at least appears as its own box.

## Alternatives considered

- **A UI-only fix - hide the tabs, keep the permissions.** Was what the report literally asked for.
  Rejected: the RRset route would still have accepted a SOA write from anyone with `record.update`,
  so the guarantee would have been cosmetic. A permission an operator can reason about has to be one
  the server enforces.
- **`record.update.soa`, additive like the apex-NS one.** Rejected for the reason above - it makes
  "may fix the SOA, may not touch records" unexpressible, and that separation is the entire point.
- **Deny SOA and apex-NS writes to everyone below Operator, with no new permission.** Simpler, and
  needs no migration. Rejected: it hard-codes one org's policy. Operators who deliberately let a
  Zone Editor set the SOA would have had no way back, and per-zone grants could not express "this
  one customer may".
- **A boolean on the role ("may edit zone authority").** Rejected: it does not compose with
  `zone_grants`, which store literal permission strings, so it would have been global-only - exactly
  the granularity the report was asking us to escape.
- **Reuse `metadata.write` for the settings tab.** Rejected: `SOA-EDIT` and friends are written
  through `PUT /zones/{id}`, not the metadata endpoint (PowerDNS 4.9 rejects them there), and the
  two are separately grantable today. Conflating them would silently widen `metadata.write`.

## Consequences

**Easier.** A self-service role is now `[zone.read, record.read, record.create, record.update,
record.delete, dnssec.read]` and nothing else - records visible and writable, the zone's authority
neither shown nor writable. All four permissions are grantable per-zone, so `soa.update` can be
opened on one customer's zone without going fleet-wide.

**Harder.** Two composition rules to explain instead of one. And every future "protected RRset" must
be added to `protected-rrsets.ts` rather than to a route - the right place, but a less obvious one
for someone patching a single handler. `DNSKEY` and `CDS`/`CDNSKEY` are the likely next candidates
if operators ask, and they should follow the apex-NS shape, not the SOA one.

**Upgrade.** Behaviour is preserved rather than tightened by default: migration
`0007_granular_zone_permissions_backfill` (data-only, both dialects) gives every operator-defined
role, zone grant and API token the new permission implied by the one it already held. Tightening is
then an opt-in edit. The seeded system roles do change, because the seed re-upserts them on every
boot: Zone Editor keeps both read permissions and loses both writes, which move to Operator and
above. That is a deliberate change of what the seeded role means, and it is the one thing an
operator has to read the release notes for.

**Not covered.** Zone creation and zonefile import write an SOA and apex NS as part of creating a
whole zone; they stay on `zone.create` / `zone.import`. Splitting those would gate the creation of a
zone on permission to edit a zone that does not exist yet.

## References

- Discussion [#119](https://github.com/PowerDNS-AuthAdmin/powerdns-authadmin/discussions/119) -
  the report, and the self-service hosting scenario behind it.
- [ADR 0004](./0004-three-layer-architecture.md) - the auth → RBAC → business-logic ordering this
  check sits inside.
- [ADR 0014](./0014-backend-capability-model.md) - per-zone authority as the app already models it.
- `docs/07-RBAC.md` § Splitting record editing from a zone's authority.
- RFC 1035 § 3.3.13 (SOA), RFC 1034 § 4.2.1 (apex NS as the zone's delegation).
