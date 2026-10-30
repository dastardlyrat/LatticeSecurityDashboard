# Lattice v0.3.0 Change Log

## Repository privacy preparation

- Removed the unused top-level computer-name field from collector output.
- Excluded Python caches, local secrets, captured snapshots, logs, and common
  capture/export directories from version control.
- Reviewed all project files and four PNG assets for embedded private details;
  preserved the project artwork and labeled synthetic previews.
- Expanded repository setup, privacy boundaries, validation guidance, and
  contributor entry points. Live Windows sensor validation remains outstanding.

## Original v0.3.0 build

- Created Windows PowerShell 5.1 read-only collectors for 19 telemetry families.
- Switched production launch to direct Windows telemetry, not synthetic/mock events.
- Added responsive full-viewport browser command deck with green attention, multi-panel views, source inspection, and real bounded trend history.
- Added local-only Python standard-library server with no writable API endpoints and strict Host checking.
- Added per-sensor failure isolation, bounded polling, stale reading rejection, bounded event sample semantics and explicit evidence source strings.
- Added service, SMB, and event-channel readings; Group Policy mining excluded.
- Added 10 unit tests plus headless Chromium UI smoke checks using explicitly synthetic screenshots.

Known status: Windows PowerShell runtime validation is pending execution on an actual Windows target. Never treat screenshot values as measured host readings.
