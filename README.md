# NSTP Attendance

A local full-stack attendance app with student authentication, admin session management, check-in/check-out, and QR codes that expire after 10 minutes.

## Requirements

- Node.js 20 or newer
- npm

## Run locally

1. Open this folder in VS Code.
2. Copy `.env.example` to `.env` and change the admin username, email, password, and session secret. `ADMIN_USERNAME`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD` configure the initial administrator account created on first startup. Without these settings, local development uses username `admin`, email `admin@nstp.local`, and password `Admin12345!`. Set `ADMIN_EMAIL_MFA=true` to require an email verification code at every admin sign-in; configure SMTP first.
3. In this folder, run `npm install`, then `npm start`.
4. Visit `http://localhost:3000`. Do not open `public/index.html` with VS Code Live Server; the app needs its Node.js server for the verification-code and other API requests.

## Mobile and offline use

Open the site URL in a supported mobile browser. The app shell may load offline after a visit, but signing in, attendance, and other server features still require a network connection. The app does not show an in-app installation button or automatic installation prompt.

Public registration only creates student accounts. The app uses one administrator account, configured with `ADMIN_USERNAME`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD` on first startup; additional admin accounts cannot be created. Students register with their personal email, ISU student number, section, and a password they choose (10–128 characters). The personal email is used to sign in and recover the account; the student number identifies the account and is never used as its password. Students type their section name during registration; an existing section with the same name is reused, otherwise the section is created and appears in the admin rosters. The initial ISU section is `BSIT 1A WMAD`; admins can add sections. Students can update their name, email, and JPG/PNG/WebP profile picture (up to 5 MB) from the dashboard profile control; the email remains unique and is used to sign in. The dashboard greets students using their surname. Students and admins can request a password reset from the sign-in form after choosing the matching account type. On localhost in non-production mode, the reset form opens directly if email delivery is unavailable; this local-only fallback is not exposed in production. For real deployments, configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_FROM`, and `APP_BASE_URL` in `.env`; if the SMTP server requires authentication, also set `SMTP_USER` and `SMTP_PASS`. Reset links are single-use and expire after 30 minutes. Sign-in and registration require a random six-character letters-and-numbers CAPTCHA, verified case-insensitively on the server and expiring after five minutes. Admin sign-in codes expire after five minutes, are rate-limited, and are only sent when `ADMIN_EMAIL_MFA=true`.

Admins can create sections, review each section’s alphabetically sorted roster in its own expandable group, and assign existing accounts that registered before sections were added. Admin session cards, tasks, attendance reports, low-attendance alerts, and top-student lists are also grouped into expandable section folders to keep each section’s records together. Section-specific attendance sessions show present/absent status for every student in alphabetical order in the target section. Students can show a personal QR code (valid for 10 minutes) for an admin to scan for check-in or check-out. Students can also scan the facilitator’s expiring session QR. Camera scanning requires a secure context (localhost or HTTPS) and a browser with `BarcodeDetector`; QR values can alternatively be pasted in. Admins can post due-dated tasks for a section or all sections. Students can submit PDF files up to 10 MB and replace their latest submission; admins can download submissions.

The admin dashboard automatically calculates attendance rates from completed sessions and each student’s eligible sessions. It highlights students below 75% attendance and shows completed-session summaries. Admins can download a CSV attendance report for all sections or a selected section. Attendance rates count a session as completed on its event date; future sessions are excluded. The dashboard also shows total students, daily present/late/absent counts, attendance percentage, a pie chart, and a per-session bar chart. Daily counts are for unique students assigned to sessions that have started today; when a student is in multiple sessions, an on-time check-in takes priority over a late check-in. New sessions require a start time, and a check-in after that time is marked late. Existing sessions without a start time can be edited to set one; until then, recorded check-ins are treated as on time. Daily dashboard data refreshes once per minute.

Admins can edit or remove a recorded attendance entry from its session roster. Each change requires a reason and writes the actor, reason, and before/after details to the system activity log. The session roster and attendance dashboard are responsive on narrow screens; tables can be scrolled horizontally when needed.

## QR behavior

Each generated QR carries a cryptographically random token. The server stores only its SHA-256 hash and rejects it at or after its server-side expiration timestamp (10 minutes from generation), for inactive sessions, or for invalid student state. The same live session code supports separate IN and OUT actions, and a student can only check in/out once per session. Generate another QR at any time to create a fresh 10-minute token.

## Backup and restore

The admin dashboard's backup includes `backup.json`, submissions, and profile pictures. It omits live QR and password-reset tokens. Backups also contain password hashes and private student data; keep them encrypted or in access-controlled storage.

To run a restore drill without touching live data, download a backup and run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-backup.ps1 -BackupPath .\nstp-backup.zip
```

The script validates the archive, checks referenced upload files, and reconstructs a staged data directory under your temporary-files folder. It never writes to the app's live `data/` directory. Use the printed path to start the app against this restored copy:

```powershell
$env:DATA_DIR = 'C:\path\printed\by\the\script'
$env:PORT = '3001'
npm start
```

Use the same `SESSION_SECRET` as the backed-up installation, sign in with an account from the backup, and check a roster/report and any available submission or profile-picture files. Stop the test server, then clear the overrides with `Remove-Item Env:DATA_DIR, Env:PORT`. Repeat this drill periodically and after backup-format changes.

For an actual restore, stop the app, make a separate copy of the current `data/` directory, run the verification script, then replace `data/` with the complete staged directory printed by the script. Start the app and verify sign-in and records before resuming normal use. Keep the preserved copy until the restored data is confirmed.

## Data and deployment notes

Attendance data and PDF submissions are stored under `data/` (excluded from source control), so no native database compiler is required. Set `DATA_DIR` to use an alternate data directory for isolated restore drills. Passwords use bcrypt hashes, reset tokens and student QR credentials are stored as hashes, sessions are server-side but held in memory and are cleared when the server restarts, cookies are HttpOnly/SameSite=Strict, writes require a per-session CSRF token, and authentication/reset/upload endpoints are rate-limited. This file-backed store and the default in-memory session store are intended for local use; before deploying for real users, replace them with a durable database and persistent session store. Set `NODE_ENV=production`, use HTTPS, configure SMTP for password recovery and (if enabled) admin email MFA, and configure a unique `SESSION_SECRET` (32+ characters) before deploying. For deployment behind a reverse proxy, configure Express trust proxy according to your hosting provider.
