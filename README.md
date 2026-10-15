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
decisions. All eight workflow jobs block at the null CI image digest;
their scanner steps are skipped with a reason. Three local deterministic checks
pass; native browser/Lighthouse/scanner acceptance is open. Missing tools or
vulnerability database coverage never count as passing CI. Tool artifacts and Actions
have verified 2026-10-11 evidence pins. Prepared installers check SHA-256/npm
integrity and use offline, script-disabled npm or hash-required pip installs.
Complete tool dependency locks, Chromium's binary hash and the OSV database remain
unresolved. Semgrep is CI-only with an owner license decision required; it is
excluded from public assets. Release images, target manifest and workflow commit
remain null and production deployment stays blocked.

Operational and HUMAN steps: `docs/runbooks/m72-landing-builder.md` in Foundry.
