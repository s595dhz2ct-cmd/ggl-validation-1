# Landing and waitlist concept template

Reviewed static HTML/CSS and minimal vanilla JS. Build it with Foundry's typed
`LandingProps` renderer; prose is escaped, never script, links or dependencies.
Render the six public files into `public/`; only that directory is the public
artifact. CI and license/control metadata stay beside it. Integrity checks require
exact manifest coverage and reject extra files, directories and links. The
fixture concept uses original CSS/SVG and system fonts.

Collection stays closed until reviewed encrypted transport, rights contact and
the exact owner gates pass. No payment, tracking, mail automation or deploy code
is included. `ci/pins.json` records known pins and explicit unresolved owner
decisions. Browser jobs use the reviewed digest-pinned official Playwright Noble
image with Node major 24 and Chromium system libraries; other jobs use Python.
The existing Node base remains recorded. All eight jobs run as uid/gid 1001,
matching the GitHub runner's writable temp/workspace, with all capabilities
dropped and no new privileges. The Node helper checks major 24 and both browser
jobs' declared images against the reviewed browser pin.
Installers verify SHA-256/npm integrity before offline, script-disabled npm or
hash-required pip installs from complete locks. Chromium's verified ZIP is
extracted with bounded Node built-ins; no system archive tool is required.
Both tools select our SHA-256-verified Chrome-for-Testing shell, never the image's
`/ms-playwright` browsers. Keep `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1` and our
complete npm closure.
OSV queries its live database and logs the scan version/time. Missing tools or
vulnerability coverage fail CI. The 2026-10-15 evidence records fixed tool closures
and Semgrep 1.179.0's 13-day security-fix exception, approved by Claude because
pyjwt <2.14 has published advisories. The owner's `keep_ci_only` license decision
still applies; Semgrep is excluded from public assets. Native browser/scanner
acceptance remains separate from offline checks. GitHub runs only the eight checks
and the owner's PR review/merge. After merge, Foundry verifies the exact complete
tree locally, requests a separate phone deployment approval, uploads only verified
`public/` bytes using pinned Wrangler in an M4 sandbox, then independently checks
the served hashes. The deploy token is held only in the owner's local age store.
No GitHub production job, Environment credential, OIDC or CI tailnet access is used.

Operational and HUMAN steps: `docs/runbooks/m72-landing-builder.md` in Foundry.
