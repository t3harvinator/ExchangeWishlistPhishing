# Static analysis report

## Verdict

The supplied command is a macOS JavaScript-for-Automation (JXA) malware
loader. It downloads an obfuscated JXA stage and pipes it directly into
`osascript -l JavaScript`. The recovered stage performs anti-analysis and
region-exclusion checks, decrypts an embedded loader only on the intended
host profile, downloads an executable, disguises it as Finder, and launches
it. Static analysis of the recovered universal Mach-O identifies the final
payload as a macOS information stealer. It seeks Full Disk Access, establishes
Login Items persistence, collects browser credentials and cookies, enumerates
files, and communicates with randomized subdomains of `cdn-apple.com` over
port 443.

No captured JavaScript was executed during this analysis. String decoding,
environment-key enumeration, RC4-like decryption, and integrity validation
were reimplemented in Python. The Mach-O payload was imported into Ghidra and
analyzed statically; it was not executed.

## Infection chain

1. `initial_drop.txt` Base64-decodes the first URL.
2. `curl -sf` retrieves a 113,451-byte obfuscated JXA program.
3. `osascript -l JavaScript` would execute that response directly from stdin.
4. Stage 2 imports Cocoa, IOKit, and CoreFoundation and evaluates:
   - hypervisor presence (`kern.hv_vmm_present`);
   - VM-related hardware strings (`virtual`, `vmware`, `qemu`, `utm`, etc.);
   - System Integrity Protection state (`csr_get_active_config`);
   - AppleSMC characteristics;
   - debugger/instrumentation indicators (`ptrace`, `DYLD_*`, `LLDB_*`, etc.);
   - locale, country, keyboard language, and timezone.
5. Those results derive the key for three integrity-protected encrypted blobs.
   Exhaustive static enumeration of all 768 possible outcome combinations
   yielded exactly one key that validated all three blobs.
6. The decrypted loader downloads an executable to:

   `~/Library/Application Support/com.apple.finder.agent/Finder.app/Contents/MacOS/C6690F41`

7. It makes the executable mode `0755`, copies Finder's icon, writes a forged
   `Info.plist` with bundle ID `com.apple.finder.agent`, hides the application
   from the Dock (`LSUIElement`, `LSBackgroundOnly`), creates a misspelled
   `.Cheked` marker, opens the fake `Finder.app`, and prints a fake installation
   failure message.

## Final payload analysis

The recovered `C6690F41.quarantine` file is a universal macOS Mach-O containing
x86-64 and arm64 slices. The x86-64 slice is a heavily obfuscated Rust program.
Most operational strings are encrypted and reconstructed only when needed,
and sensitive macOS APIs are resolved dynamically with `dlopen` and `dlsym`.

### Permissions and persistence

- The payload opens this System Settings URL through `NSWorkspace`:

  `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles`

  This takes the victim directly to the Full Disk Access pane.
- It repeatedly checks whether protected paths are accessible and continues
  after the required permission appears to have been granted.
- It derives the path of its own disguised application bundle and uses
  dynamically resolved CoreServices/CoreFoundation functions in the pattern
  used to register an application as a Login Item. This is the payload's
  persistence mechanism.
- It monitors Darwin session notifications and contains a 900-second
  (15-minute) timing condition, likely delaying activity or coordinating it
  with screen lock/unlock state.

### Credential and browser collection

The browser collector contains the decoded identifiers `chromium`, `gecko`,
`Default`, `Chrome`, and `Google Chrome`. Confirmed target paths and database
objects include:

- `Library/Application Support/Google/Chrome/`
- `/Applications/Chromium.app`
- `/Login Data`
- `/Cookies`
- SQLite table `logins`
- SQLite table `cookies`

The SQLite helper constructs `SELECT COUNT(*) FROM ` and appends the target
table name. The surrounding collector enumerates browser profiles, opens the
associated SQLite databases, traverses files and directories, and parses JSON.
Together, this establishes that the payload targets saved browser credentials,
cookies/session material, and browser-profile or extension data. The `gecko`
collector identifier indicates support for Firefox-family data, although the
exact Gecko paths and queries have not yet been completely decoded.

### Command-and-control communications

The network resolver decrypts the character set
`abcdefghijklmnopqrstuvwxyz0123456789`, generates a random hostname label, and
appends `.cdn-apple.com:443`. The resulting target is therefore
`<random-alphanumeric-label>.cdn-apple.com:443`. This is consistent with a
rotating per-run command-and-control hostname. The program contains a native
network stack and hostname-resolution logic suitable for transferring the
collected data over an encrypted connection.

### Anti-analysis behavior

- The payload calls `sysctl` for its own PID and tests the traced/debugged
  process flag, allowing it to detect an attached debugger.
- Operational strings, SQL fragments, framework paths, Objective-C classes,
  selectors, and the C2 suffix are encrypted with many different inline
  decoding routines.
- Framework and persistence symbols are dynamically resolved, reducing the
  usefulness of a simple import-table scan.
- The earlier JXA stage separately checks for hypervisors, common VM hardware,
  debuggers, instrumentation variables, SIP state, locale, keyboard language,
  timezone, and excluded geographic regions before decrypting this payload.

### Relevant x86-64 functions

- `0x1000641e7`: Login Items persistence logic
- `0x10006795b`: opens the Full Disk Access settings pane
- `0x100058b4c`: browser/profile collection configuration
- `0x10009f109`: browser SQLite table-query helper
- `0x1000156f6`: randomized C2 hostname generation and resolution
- `0x1000a0ed4`: anti-debugging check

## Indicators

- Initial URL: `hxxps://gretgerherhdf[.]it[.]com/kug2gn/g6VY3Wp3BZlG`
- Next-stage URL: `hxxps://gretgerherhdf[.]it[.]com/kug2gn/t7sDAzFPAA2v`
- Hostname: `gretgerherhdf[.]it[.]com`
- Resolved Cloudflare addresses at analysis time: `172.67.130[.]64`,
  `104.21.3[.]50` (shared infrastructure; do not block broadly)
- Install directory: `~/Library/Application Support/com.apple.finder.agent`
- Fake application: `Finder.app`
- Executable: `C6690F41`
- Bundle identifier: `com.apple.finder.agent`
- Marker: `.Cheked`
- C2 base domain: `cdn-apple[.]com`
- C2 hostname pattern: `<random-alphanumeric-label>.cdn-apple[.]com:443`
- Initial-drop SHA-256:
  `ab8f55d245298dd18b6c90d69ac87682d37be82b622f6c05ed940b7d6de02a30`
- Stage-2 SHA-256:
  `5c3d49f29f7c4078cbdf7e2e56c0ea12b96ef0b1e1fe5ac5f4bb2b055a6b2c01`
- Final universal Mach-O SHA-256:
  `1a663cc6c7c919607025b006b27b446dcd78d2b6244d20bfe7ffded251d47329`

## Produced artifacts

- `stage2.deobfuscated.js`: exact stage-2 source with 302 arithmetic/XOR
  string builders constant-folded. Its encrypted byte arrays remain present.
- `stage2.embedded.json`: the unique validated environment outcome, derived
  key, and all three decrypted embedded values.
- `stage3.loader.deobfuscated.js`: formatted, readable recovered loader. Its
  malicious invocation is commented out for analysis safety.
- `static_deobfuscate.py`: allow-listed static string decoder.
- `decrypt_embedded_stage.py`: Python reimplementation of key derivation,
  RC4-like transforms, enumeration, and integrity checking.
- `C6690F41.quarantine`: recovered universal Mach-O payload. It was inspected
  statically and was not executed.
