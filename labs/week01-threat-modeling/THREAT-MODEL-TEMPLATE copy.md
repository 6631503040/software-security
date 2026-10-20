# Threat Model — <app name>
## Part 1 — Student Information
| Name | Student ID | Date | Group |
|---|---|---|---|
| Sadayu Suriya | 6631503040  | 15/8/2569 |  -  |

## Part 2 — Lecture Questions
Answer in your own words (2–4 sentences each).
1. Define the CIA triad and give one concrete failure example for each of the three properties.
Answer: C(Confidentiality) ex. hacker come into website and leak private data , I(Integrity) ex. attacker cone into website db to change user data,  A(Availability) ex. web server shutdown when user come in website a lot 
2. What is a *trust boundary*, and why does data crossing one deserve extra scrutiny?
Answer: s the boundary where data crosses between components of different privilege levels, Outside the boundary, you cannot trust anything. An attacker can send malicious inputs, fake parameters
3. Explain "attack surface." Name two things that increase it in a web app.
Answer:  attack surface is area or field that attacker can use to attack buissness example HTTP params, headers, cookies, file uploads, APIs, env vars, dependencies
4. What does each STRIDE letter map to, and which security property does each threat violate?
Answer: S(Spoofing) - Authentication, T(Tampering) - Integrity, R(Repudiation) - Non-repudiation, I(information disclosure) - Confidentiality, D(Denial of service) - Avaliability and E(Elevation of privilege) - Authorzition
5. What does "Secure by Design" (CISA) mean, and how does it differ from bolting security on after release?
Answer: building software to be safe right from the start so entire bug types are prevented before code is written. This contrasts with the old model of rushing a product out and patching individual bugs only after release.

## Task 0 — Onboarding
 [labs\week01-threat-modeling\img\task0.png]

## 1. Data-flow diagram

 Task 1  DFD [labs\week01-threat-modeling\img\task1.png]

## 2. Elements & trust boundaries
| Element | Type (process/store/entity/flow) | Trust boundary crossed? |
|---|---|---|
| Web client | external entity | yes (Internet → app) |
| Flask app | process | no (resides in Application Tier) |
| SQLite DB (`notes.db`) | data store | yes (App → Data Tier) |
| `uploads/` | data store | yes (App → Data Tier) |


## 3. STRIDE analysis

### Task 2 — STRIDE the elements

| Element | S | T | R | I | D | E |
|---|---|---|---|---|---|---|
| `/notes` | The endpoint accepts a client-supplied `owner` field without any authentication, allowing attackers to easily impersonate anyone. | An attacker can submit malicious payloads in the note body because the application does not sanitize the input before saving it. | There is no logging mechanism implemented to record who creates the notes, making the action untraceable. | Anyone can view all notes in the database since there is no access control, potentially exposing private data. | An attacker can continuously send POST requests to create notes and exhaust the SQLite database storage. | - |
| `/upload` | The system allows completely anonymous users to upload files to the server without verifying their identity. | The app saves the raw `f.filename` without sanitization, enabling arbitrary file writes via path traversal. | The server does not log any file upload activities, making it impossible to trace who uploaded a malicious payload. | The server response explicitly echoes the resolved save path, leaking the internal directory structure to the user. | The endpoint lacks file size and rate limits, allowing an attacker to fill the server's disk space completely. | An attacker could use path traversal to overwrite critical server scripts, potentially gaining remote code execution (RCE) capabilities. |
| `/files/<name>` | Anyone can request and download files without needing to authenticate or prove ownership of the file. | - | The system does not log file access requests, so unauthorized file downloads remain completely unrecorded. | While comparatively defended against path traversal, any successfully uploaded file is publicly accessible to anyone who knows its name. | An attacker can repeatedly request large files to exhaust the server's bandwidth and computing resources. | - |

### Task 3 — Elevation of Privilege game

Carded threats found (score: 8):
1. **Spoofing (client card)** — `/notes` never checks who the caller is, so any client can claim to be `owner: "admin"`. Ties to the same Spoofing cell already in the STRIDE table, confirms it independently.
2. **Tampering (data store card)** — `notes.db` has no integrity check (no checksum, no WAL protection assumed by the app); if an attacker gets filesystem access via the `/upload` traversal, they can overwrite `notes.db` directly, bypassing the app entirely.
3. **Repudiation (process card)** — the Flask process has no request logging middleware, so there is no way to prove which client hit `/upload` or `/notes` after the fact — confirmed for all three endpoints, not just one.
4. **Information disclosure (data flow card)** — the `/upload` response body (`{"saved": f.filename}`) leaks the exact filename it wrote, which is also the traversal proof-of-concept an attacker needs to confirm a write landed outside `uploads/`.
5. **Denial of service (external interactor card)** — nothing stops one client from opening many simultaneous connections to `/notes` (`GET`) since Flask's dev server is single-threaded by default in this app — a slow client can starve every other request.
6. **Spoofing (data flow card)** — there is no CSRF protection on the `POST /notes` and `POST /upload` flows, so a malicious page in a victim's browser could submit these requests on the victim's behalf.
7. **Tampering (external interactor card)** — file *content* is never validated (only the path is attacker-controlled today), so a client can upload an executable/script disguised as any extension; if the deployment ever serves `uploads/` as static content with execution enabled, this becomes a stored-content attack.
8. **Elevation of privilege (process card)** — because the Flask process, `notes.db`, and `uploads/` all run under the same OS user with no sandboxing, any single-endpoint compromise elevates to full control of both data stores at once (see Task 3b).

### Task 3b — Systems-level pass

- **Trust boundaries end-to-end.** A request from the client crosses two boundaries: (1) Internet → Flask app (the dashed line in the DFD), and (2) Flask app → data tier (`notes.db` / `uploads/`). Crossing (1) has **no check at all** — no auth, no CSRF token, no input validation gate before the request reaches app logic. Crossing (2) is nominally "trusted" but is really just "same process, same OS user" — there is no independent authorization layer between the app and its own data stores.
- **Assume one element is fully owned.**
  - *Flask process owned:* the attacker now reaches everything the process can reach — full read/write on `notes.db`, full read/write on `uploads/`, the process's environment variables, and (since nothing sandboxes the container beyond default Docker isolation) a foothold to pivot toward the host if the container is misconfigured.
  - *`uploads/` store owned:* even without owning the process, an attacker who can write arbitrary files there (via the `/upload` traversal) can plant a file that `/files/<name>` will later serve to any other visitor — turning a storage-only compromise into a distribution channel for malicious content to other users.
- **Chain two "low" findings.** `/upload`'s information-disclosure of the resolved save path (rated low on its own — it "only" reveals directory layout) chains with `/upload`'s unsanitized-filename tampering (also individually contained): **A (path disclosure confirms the exact on-disk layout) → B (attacker now knows precisely how many `../` are needed to reach a target like `app.py`) → consequence (a traversal write overwrites server source, and the next process restart executes attacker-controlled code).** Neither finding alone is more than "minor"; together they produce RCE.
- **One-line system claim.** Even if every element-level mitigation in Task 8 is implemented, this system still fails if **the Flask process, `notes.db`, and `uploads/` continue to share one OS identity with no isolation between them** — a compromise of any single endpoint still grants the attacker everything the process can touch, regardless of how well each individual endpoint is patched.

### Task 4 — Abuse cases & attacker personas

**Persona A — "Nosy Coworker"**: has legitimate network access to the app (e.g., same office Wi-Fi or VPN) and basic tooling (`curl`, browser). Motivated by curiosity, not profit.
1. Sends `GET /notes` to read every note in the database, including notes never intended for them — there is no per-owner access control, only a client-supplied `owner` string.
2. Sends `POST /notes` with `owner: "alice"` to plant a note that looks like it came from Alice, since `owner` is trusted from the request body with no verification.

**Persona B — "Anonymous Internet Attacker"**: a remote, unauthenticated attacker scanning for exposed Flask apps. Motivated by gaining a foothold on the host.
1. Uploads a file via `/upload` with `filename` set to a traversal payload (e.g. `../sample-app/app.py`) aiming to overwrite the running application's source so the next restart executes attacker-controlled code.
2. Repeatedly `POST`s large files to `/upload` with no size limiting, filling the container's disk until the app and its database writes start failing (DoS via storage exhaustion).

### Task 5 — Path-traversal deep-dive

**Data flow:** client → `POST /upload` (`f.save(os.path.join(UPLOAD_DIR, f.filename))`) → `uploads/` → client → `GET /files/<name>` (`send_from_directory(UPLOAD_DIR, name)`) → client.

**Why `../` escapes `uploads/` on write:** `f.filename` is taken verbatim from the multipart upload with no sanitization. `os.path.join("uploads", f.filename)` does a naive string join — if `f.filename` is `"../../sample-app/app.py"`, the joined path is `"uploads/../../sample-app/app.py"`, which the OS resolves by walking *up* out of `uploads/` before going back down into `sample-app/`. `f.save()` then writes wherever that resolved path points, anywhere the process's OS user has write permission.

**Why `/files/<name>` is comparatively defended:** `send_from_directory()` internally resolves the requested path and verifies it stays inside `UPLOAD_DIR` (Werkzeug's `safe_join`), returning 404 if the resolved path would escape — so *reading back* via `/files/<name>` cannot itself be used for traversal, even though the file may have been *written* outside `uploads/` in the first place.

**Secure design:**
- Run the filename through `werkzeug.utils.secure_filename()` before ever using it in a path, stripping `/`, `\`, and `..` segments.
- Store uploads outside the application's own source tree (a dedicated, non-executable volume), so even a successful traversal can't reach `app.py` or other server code.
- Allow-list acceptable extensions/content-types (e.g. `.txt`, `.png`, `.pdf`) and reject everything else server-side (not just by checking the extension string, but by validating actual file content/magic bytes).
- Best class fix: generate an opaque, server-side filename (e.g. a UUID) for storage, and keep the user-supplied name only as metadata — so **no user-supplied string ever becomes a path component**.

### Task 6 — Threat-model the project target (NoteVault)

**Quick DFD (text form — replace with your own screenshot after running `docker compose up` in `project/starter-app`):**
- External entity: web client (browser).
- Process: NoteVault Flask app.
- Data store: `/tmp/notevault.db` (SQLite — `users`, `notes` tables).
- Flows crossing the Internet→App boundary: `POST /login`, `POST /register`, `POST /notes`, `GET /api/notes/<id>`, `GET /search`, `GET /admin`, `GET /export`, all terminating in reads/writes to the SQLite store.

**Top 3 STRIDE threats to investigate:**
1. **SQL injection (Tampering / Information disclosure)** — `/login` and `/search` build queries with Python `%`-string formatting instead of parameters (`"...WHERE username = '%s' AND password = '%s'" % (...)`), so crafted input can bypass authentication or dump the entire `notes`/`users` tables.
2. **Authentication bypass via JWT (Spoofing / Elevation of privilege)** — `current_user()` calls `jwt.decode(tok, SECRET, algorithms=["HS256", "none"])`, accepting the `none` algorithm; an attacker can forge a session cookie for `sub: "admin"` with no valid signature at all.
3. **Privilege escalation via `/register` (Elevation of privilege)** — `register()` takes a client-supplied `role` field and inserts it directly into the `users` table, so anyone can self-register as `role: "admin"` and reach `/admin`.

## 4. Top 5 risks (likelihood × impact) + mitigation

### Task 7 — Security requirements

1. The system must derive the note `owner` from a server-verified session, never from a client-supplied field, so that `POST /notes` cannot be used to forge notes under another user's identity. *(maps to Task 2 — Spoofing on `/notes`)*
2. The system must sanitize and allow-list any client-supplied filename before using it as a path component in `/upload`, so that no request can write outside the `uploads/` directory. *(maps to Task 2 — Tampering on `/upload`)*
3. The system must reject any JWT whose algorithm was not the one the server issued (in particular, never accept `alg: none`), so that a forged token cannot authenticate as another user, including `admin`. *(maps to Task 6 — Spoofing/Elevation of privilege on NoteVault login)*

### Task 8 — Defend / fix it: rank & mitigate

| Rank | Threat | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | `/upload` path traversal (Tampering) | High | Critical — arbitrary file write, path to RCE | `secure_filename()` + store outside web root + extension allow-list |
| 2 | `/notes` no authentication (Spoofing) | High | Medium — impersonation, data pollution | Require a session/auth token; set `owner` server-side from the authenticated identity |
| 3 | No size/rate limits on `/upload` (DoS) | Medium | Medium — disk exhaustion, service outage | Enforce `MAX_CONTENT_LENGTH` + per-IP rate limiting |
| 4 | `/upload` echoes resolved save path (Info. disclosure) | High | Low — reveals internal directory layout | Return only the filename/an opaque id, never the resolved server path |
| 5 | No request logging anywhere (Repudiation) | High | Medium — no accountability, hinders incident response | Add structured request logging (who/when/what) on `/notes` and `/upload` |

**Implementation (pick one and actually implement it):**
> Not done yet — this needs real code changes on your `wk01` branch plus before/after evidence (see worksheet Task 8 deliverables 1–3). Tell me which of the five above you want to implement and I'll make the change, run the before/after requests, and prepare the diff.

## Part 4 — Reflection

1. **CWE / OWASP mapping.** The top finding (`/upload` path traversal) maps to **CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)** and **OWASP A06 (Insecure Design)** because the flaw is not a missing patch on otherwise-sound logic — the design itself never established "no user string becomes a path component" as a rule, so the vulnerability was baked in from the first line of code.
2. **Real-world breach.** The 2017 Equifax breach was ultimately an unpatched Struts CVE, but a closer design-flaw example is **Capital One (2019)**: a misconfigured WAF role with overly broad IAM permissions let a former employee's SSRF request reach internal metadata and pull S3 credentials — a *design* failure (excess trust granted to the WAF role, no boundary between "can make a request" and "can read all customer data"), not a missing patch. The control that would have prevented it is least-privilege IAM scoping combined with strict SSRF egress filtering, decided at design time rather than bolted on after.
3. **Best risk-reduction-per-effort mitigation.** Sanitizing the `/upload` filename with `secure_filename()` gives the most risk reduction per unit of effort — it is a one-line change that closes the highest-impact finding (arbitrary file write → possible RCE) and requires no new infrastructure, unlike auth (needs a session layer) or logging (needs a logging pipeline).


## Evidence & Integrity (required)

> ⚠️ This section cannot be filled in on your behalf. Every screenshot must show **your own terminal** running
> `printf '%s | %s | ' "$(whoami)" '6631503040'; date '+%F %T %Z'` in the same frame as the evidence
> (browser/DevTools beside it, whole screen captured). Task 0 and Task 1 images are already in `img/` —
> confirm they include this identity stamp; if not, recapture them. Do the same for any Task 8 before/after
> evidence once you've picked and implemented a mitigation.

- **Identity proof:** *(you must capture this yourself — see above)*
- **Personalized flag (if this lab issues one):** ____________________
- **Explain in your own words:**
  1. What did you do, and why did the vulnerability work? — *The riskiest flow tested was `/upload` → `/files/<name>`. It works because `f.filename` is trusted verbatim and joined into a filesystem path with no sanitization, so a filename containing `../` walks the resolved path outside `uploads/` before Flask ever writes the file.*
  2. Why does your fix actually stop it, and what could still break it? — *(fill in once you implement Task 8 — the answer depends on which of the five mitigations you pick; for the path-traversal fix specifically: `secure_filename()` strips `/`, `\` and `..` so the join can no longer escape `uploads/`; it would still break if a future code path joined a raw, unrelated user string into a filesystem path elsewhere without calling the same sanitizer — which is why the class fix is "no user-supplied string ever becomes a path component," not "sanitize this one endpoint.")*

---

## 🤖 Audit the AI (required)

> ⚠️ This task requires *your own* separate conversation with an AI assistant, pasted verbatim, then your critique of it —
> having this document's assistant grade itself would defeat the exercise. Suggested prompt to run yourself:
> *"Fix the path traversal vulnerability in this Flask upload endpoint: `f.save(os.path.join(UPLOAD_DIR, f.filename))`."*
> Paste the AI's full answer, then look specifically for: does it only call `secure_filename()` (an instance fix that
> still trusts the filename as a path root) without also moving storage outside the web root or allow-listing
> extensions? Does it invent a function/flag that doesn't exist in Werkzeug? Quote the exact line you're critiquing,
> then write your own corrected version.

1. AI's answer: *(paste here)*
2. What's wrong/risky in it: *(quote exact lines)*
3. Your corrected, verified version: *(your own code + why the AI's was insufficient)*

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).**
The `/upload` endpoint takes whatever filename the client sends and writes the file to disk using that name unchanged. Because nothing strips `../` sequences, a client can send a filename that walks back out of the `uploads/` folder and lands anywhere else on the server the process can write to — turning a "save my file" feature into a way to overwrite arbitrary files on the host.

**B. Prompt Problem.**
> ⚠️ Run this yourself and paste the verified result — I can draft the prompt, but you need to execute it against
> an AI assistant and confirm the exploit fails afterward for the deliverable to be valid evidence of *your* verification.

Suggested final prompt: *"Here is a Flask upload endpoint: `f = request.files["file"]; f.save(os.path.join(UPLOAD_DIR, f.filename))`. Rewrite it so that no value derived from the client-supplied filename can ever be used as a directory path component — reject path separators and `..`, allow-list file extensions, and store the file under a server-generated name. Show the corrected code only."*

Final prompt + verified result: *(fill in after you run it)*
