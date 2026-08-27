## lib/rbac

Authorization policy: permission vocabulary, CASL ability building, target
ceilings, default roles, zone-grant permission helpers, and the classifier for
RRsets that cost more than `record.*` (the SOA and the apex NS - ADR-0023).

Most modules here are `server-only`. Two deliberately are not:
`zone-permissions.ts` (so it unit-tests without a `pg` import) and
`protected-rrsets.ts` (so the record editor, a client component, decides which
rows to lock with the same predicate the write route enforces). Keep them free
of imports that would pull `server-only` back in.

RBAC decides what an already-authenticated actor can do. It should not query the
database directly from repositories, render UI, or talk to PowerDNS.
