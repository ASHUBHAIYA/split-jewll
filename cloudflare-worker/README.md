# ATITS Cloudflare Worker (licenses + Tally relay)

| Piece | Where | Purpose |
|---|---|---|
| D1 `jwellery_db` (`DATABASE`) | `schema.sql` | admin PIN (hashed) and licenses only |
| Durable Object `RelayRoom` (`RELAY_ROOM`) | `src/index.js` | one per license: job queue, bridge connection, "online" state |
| Worker | `src/index.js` | routes, license/PIN checks |

## Why this is cheap
- The bridge keeps **one WebSocket** open (old bridges long-poll every ~22 s instead of every 2 s). Keep-alive pings are answered by the runtime, with no database write and no object wake-up.
- "Bridge online" lives in memory. Nothing is written to D1 while idle.
- Licenses are cached 60 s in the Worker, so a push costs at most one indexed D1 read.
- Jobs and Tally responses live in the Durable Object and are deleted 10 minutes after they finish. Nothing grows forever.
- The browser waits for results with a ~20 s long-poll (1-2 requests per job instead of up to 20).

## Deploy (existing Worker `atits-auth`)
```bash
cd cloudflare-worker
# 1. put your D1 database id into wrangler.toml (npx wrangler d1 list)
# 2. one-time schema (also drops the old relay_queue / daemon_heartbeats tables)
npx wrangler d1 execute jwellery_db --remote --file=schema.sql
# 3. deploy (creates the RelayRoom Durable Object class)
npx wrangler deploy
# 4. recommended: keep the admin PIN out of D1
npx wrangler secret put ADMIN_PIN
```
Then set `ALLOWED_ORIGIN` in `wrangler.toml` to your site's origin(s) and redeploy.

Old `tally-bridge.exe` builds keep working unchanged (long-poll). Rebuild the bridge (see `../tally-bridge/README.md`) to switch it to WebSocket.

## Admin security
- `/set` and `/create-key` need the admin PIN in the `X-Admin-PIN` header (the app sends it after you unlock the admin panel).
- PINs are stored salted + hashed; an old plain-text PIN is upgraded the first time it is used.
- 5 wrong PINs from one IP block that IP for 10 minutes.
- With the `ADMIN_PIN` secret set, the PIN is never read from D1 and the in-app "change PIN" is disabled.
- A revoked/expired license stops working for pushes within ~60 s; a connected bridge notices at its next reconnect (every 6 h at most).

## Behaviour notes
- A job nobody picks up within 45 s is dropped and the browser is told the bridge is offline (so it cannot import later by surprise).
- A job the bridge took but never answered is marked unknown after 5 min; the app tells the user to check Tally's Day Book.
- Payloads over ~1.8 MB are rejected (Durable Object / D1 row limit). Split large pushes.
