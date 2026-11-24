# Nearby MeshCore Scopes Service

This Cloudflare Worker adds optional nearby scope search to the GitHub Pages
flasher. GitHub Pages receives only the public Worker URL, never a MeshMapper key.
The Worker estimates IP location from Cloudflare request metadata and queries
cached observations. It does not send a visitor's IP or coordinates to MeshMapper,
write them to storage, or log them in the application. For manual search, the
flasher rounds coordinates to two decimal places before sending them. Both modes
are opt-in. Disable request/body logging that could retain visitor data.

## Set up

1. Get a [MeshMapper integration key](https://wiki.meshmapper.net/api-keys/) with
   permission to use the documented Zones/boundary and Repeaters endpoints for
   the regions you plan to show. Confirm that publishing the derived counts is
   permitted. A group-wide boundary request requires permission for the entire
   group. Do not reuse an app key or scrape the map.
2. In `services/nearby-scopes`, sign in with Wrangler and create a KV namespace
   (`npx wrangler kv namespace create SCOPE_SNAPSHOTS`). Copy
   `wrangler.example.toml` to `wrangler.toml`, set its namespace ID, and replace
   `MESHMAPPER_MAPS` with the authorized list of region or group host prefixes
   (comma-separated, up to 12; e.g. `pnw`). Results cover these feeds only.
3. Run `npx wrangler secret put MESHMAPPER_API_KEY` and enter the key at the
   prompt. Deploy with `npx wrangler deploy`. Allow the next scheduled refresh
   to populate KV. Inspect the scheduled run for errors before public use.
   Choose a Workers plan with adequate CPU for your feed size and add edge rate
   limits as needed; browser CORS is not authentication.
4. Set **Settings > Secrets and variables > Actions > Variables** in
   `mikecarper/meshfirmware` to `NEARBY_SCOPES_URL=https://YOUR-WORKER/nearby-scopes`.
   Re-run the Browser USB flasher Pages workflow. The public endpoint must be
   HTTPS. Without that variable the panel still offers approximate IP location
   through GeoJS and a centered MeshMapper link. It does not display forwarding
   results until the Worker is configured.

`https://mikecarper.github.io` is the allowed browser origin. For local testing,
set `EXTRA_ORIGIN` on a test Worker to the exact Vite origin and set
`VITE_NEARBY_SCOPES_URL` when starting Vite. Do not add production secrets to the
flasher build or commit `wrangler.toml`, `.dev.vars`, or `.env` files.

## Evidence

Refresh uses only MeshMapper's [boundaries](https://wiki.meshmapper.net/zones-api/#region-boundary)
and [repeaters](https://wiki.meshmapper.net/repeaters-api/#mesh-scopes) interfaces.
It is scheduled, not triggered by visitor requests. A failed refresh retains the
previous good snapshot, for up to 48 hours. Regions mean boundaries containing
the search point. Scopes count unique active, fixed, positioned repeaters within
the radius whose forwarding was observed in the last seven days. Repeater
reports, uploader reports, and default advert scope alone are not counted.
The last-seen time is evidence of forwarding, not a live reachability guarantee.

Only derived region names and scope counts/timestamps are returned. There are
no public snapshot download or upstream proxy routes. Data outside the authorized
feeds and unobserved traffic are unknown; an empty result is not proof that a
scope is blocked. This service never connects to a radio.
