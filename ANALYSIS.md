# macOS information-stealer analysis

## Executive summary

This sample is a multi-stage macOS information stealer delivered through a
JavaScript-for-Automation (JXA) loader. The initial command downloads an
obfuscated JXA program and pipes it directly into `osascript -l JavaScript`.
That stage profiles the host for virtualization, debugging, security settings,
locale, and excluded regions before decrypting a second loader.

The loader installs a universal Mach-O executable inside a forged `Finder.app`
bundle, launches it, and displays a fake installation-failure message. Static
analysis of the final payload shows that it:

- masquerades as an Apple Finder component;
- attempts to persist through macOS Login Items;
- directs the victim to grant Full Disk Access and polls for access;
- targets browser credentials, cookies, sessions, profiles, and likely
  extension data;
- enumerates files and parses JSON data;
- detects attached debuggers and heavily encrypts operational strings;
- monitors session or screen-lock notifications and contains a 15-minute
  timing condition; and
- communicates with randomized subdomains of `cdn-apple.com` over port 443.

The overall chain is designed to evade automated analysis, obtain access to
protected user data, steal browser secrets and files, and transmit the
collected material to attacker-controlled infrastructure.

No malicious JavaScript or native payload was executed during this analysis.
All stages were recovered and examined statically.

## Attack lifecycle

1. The command in `initial_drop.txt` Base64-decodes an initial URL.
2. `curl -sf` downloads a 113,451-byte obfuscated JXA program.
3. The command pipes that response directly into
   `osascript -l JavaScript`, which would execute it from standard input.
4. The JXA stage imports Cocoa, IOKit, and CoreFoundation and profiles the host
   for analysis environments, security settings, locale, and geography.
5. Those results determine the key for three encrypted, integrity-protected
   blobs. Exactly one of the 768 possible environment-result combinations
   successfully validates and decrypts all three blobs.
6. The recovered loader downloads a universal Mach-O executable and constructs
   the following fake application bundle:

   `~/Library/Application Support/com.apple.finder.agent/Finder.app`

7. The loader places the payload at:

   `~/Library/Application Support/com.apple.finder.agent/Finder.app/Contents/MacOS/C6690F41`

8. It sets executable mode `0755`, copies Finder's icon, writes a forged
   `Info.plist`, and launches the fake application.
9. It prints a fake installation-failure message while the native payload runs
   in the background.
10. The native payload attempts Login Items persistence, prompts for Full Disk
    Access, collects browser and filesystem data, and communicates with a
    randomized `cdn-apple.com` hostname over port 443.

## Stage 1: initial command

The initial command is a compact downloader and execution cradle. It decodes
its URL from Base64, retrieves the next stage with `curl -sf`, and passes the
response directly to the JXA interpreter. Executing from standard input avoids
the need to save the JavaScript stage as an obvious script file before it runs.

Initial URL:

`hxxps://gretgerherhdf[.]it[.]com/kug2gn/g6VY3Wp3BZlG`

## Stage 2: host profiling and environment-keyed decryption

The downloaded JXA stage is heavily obfuscated. It imports Cocoa, IOKit, and
CoreFoundation and evaluates the following host characteristics:

- hypervisor presence through `kern.hv_vmm_present`;
- VM-related hardware strings such as `virtual`, `vmware`, `qemu`, and `utm`;
- System Integrity Protection state through `csr_get_active_config`;
- AppleSMC characteristics;
- debugger and instrumentation indicators including `ptrace`, `DYLD_*`, and
  `LLDB_*` values;
- locale and country;
- keyboard language; and
- timezone.

These results are used as cryptographic input rather than only as conventional
branch conditions. Static enumeration of all 768 possible outcome combinations
produced exactly one key that passed the integrity checks for all three
encrypted blobs. This recovered the next-stage loader without executing the
JXA program.

The stage also performs geographic and environment exclusions before allowing
the final payload to be recovered and launched.

## Stage 3: native-payload installer

The decrypted loader downloads the final executable from:

`hxxps://gretgerherhdf[.]it[.]com/kug2gn/t7sDAzFPAA2v`

It disguises the payload as Finder using the following artifacts:

- install directory: `~/Library/Application Support/com.apple.finder.agent`;
- application name: `Finder.app`;
- executable name: `C6690F41`;
- forged bundle identifier: `com.apple.finder.agent`;
- copied Finder icon;
- `LSUIElement` and `LSBackgroundOnly` properties to keep it out of the Dock;
- executable permissions set to `0755`; and
- a misspelled `.Cheked` marker file.

After constructing the application, the loader opens it and displays a fake
installation-failure message. The apparent failure therefore does not indicate
that execution failed.

## Stage 4: native information stealer

### Binary profile

The recovered `C6690F41.quarantine` file is a universal macOS Mach-O containing
x86-64 and arm64 slices. The analyzed x86-64 slice is a heavily obfuscated Rust
program. It is ad hoc signed and uses many different inline string-decryption
routines.

Sensitive framework paths, Objective-C classes and selectors, SQL fragments,
browser paths, and the command-and-control suffix are reconstructed only when
needed. The payload also resolves sensitive macOS functions dynamically with
`dlopen` and `dlsym`, reducing the visibility provided by a basic import-table
scan.

### Full Disk Access

The payload uses `NSWorkspace` to open this System Settings URL:

`x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles`

This takes the victim directly to the Full Disk Access pane. The payload
derives the user's home directory from `HOME`, with `/Users/Shared` as a
fallback, and tests protected paths to determine whether access has been
granted. A worker loop continues polling while System Settings is open.

This permission is important because browser databases and other protected
user files may otherwise be unavailable to the process.

### Persistence

The payload determines the path of its own disguised application bundle and
loads CoreServices and CoreFoundation dynamically. It resolves and invokes the
API pattern used to register an application as a macOS Login Item, then releases
the associated CoreFoundation objects.

This behavior is consistent with registering the forged `Finder.app` so that it
starts again when the user logs in.

### Browser and credential collection

The browser collector contains the decoded identifiers:

- `chromium`
- `gecko`
- `Default`
- `Chrome`
- `Google Chrome`

Confirmed target paths and database objects include:

- `Library/Application Support/Google/Chrome/`
- `/Applications/Chromium.app`
- `/Login Data`
- `/Cookies`
- SQLite table `logins`
- SQLite table `cookies`

The SQLite helper constructs the query prefix `SELECT COUNT(*) FROM ` and
appends either `logins` or `cookies`. The surrounding collector enumerates
browser profiles, opens SQLite databases, traverses files and directories, and
parses JSON.

These behaviors establish that the payload targets saved browser credentials,
cookies and authenticated-session material, and browser-profile or extension
data. The `gecko` collector identifier indicates Firefox-family support,
although the exact Gecko paths and queries have not yet been completely
decoded.

### Filesystem collection

The payload includes recursive directory traversal and file inspection through
functions such as `opendir`, `readdir`, `fstatat`, and user-home discovery APIs.
The collection routines process both filesystem objects and JSON structures,
allowing them to gather browser-profile data and additional configured files.

The precise complete file-target list remains heavily obfuscated and has not
yet been exhaustively decoded.

### Command-and-control communications

The native resolver decrypts this hostname alphabet:

`abcdefghijklmnopqrstuvwxyz0123456789`

It generates a random alphanumeric label and appends
`.cdn-apple.com:443`, producing a target of the form:

`<random-alphanumeric-label>.cdn-apple.com:443`

The payload then resolves the generated hostname. Its native networking code is
suitable for transferring collected data over an encrypted connection. The
random label provides a different apparent C2 hostname between runs while
retaining the same attacker-controlled base domain.

### Session monitoring and delayed activity

Two worker routines dynamically load CoreFoundation and register with the
Darwin notification center. Their behavior is consistent with monitoring
screen-lock, screen-unlock, or session-state notifications.

One path tracks a 900-second interval before invoking additional operational
logic. This may delay collection or transmission, avoid short-lived sandboxes,
or coordinate activity with the user's session state. The exact notification
names remain runtime-obfuscated, so the screen-lock interpretation is strongly
supported but not yet fully proven.

### Anti-analysis behavior

The final payload calls `sysctl` for its own PID and examines the traced process
flag, allowing it to detect an attached debugger. It combines this with:

- extensive runtime string decryption;
- dynamically resolved framework and persistence APIs;
- indirect calls and function-pointer dispatch;
- Rust-generated control flow and data structures that complicate
  decompilation; and
- the JXA stage's earlier VM, debugger, SIP, locale, timezone, and geographic
  checks.

## Behavioral assessment

The confirmed behavior supports the following end-to-end objective:

1. Evade automated analysis and excluded environments.
2. Install under an Apple-like name and icon.
3. Remain hidden from the Dock and persist at login.
4. Socially engineer the victim into granting Full Disk Access.
5. Locate browser profiles and protected user data.
6. Collect credentials, cookies, sessions, extension/profile data, and selected
   files.
7. Transmit the results to a randomized subdomain beneath `cdn-apple.com`.

The fake installation error is part of the deception: it gives the victim a
reason to believe nothing was installed while the background payload proceeds.

## Indicators of compromise

### Network indicators

- Initial URL:
  `hxxps://gretgerherhdf[.]it[.]com/kug2gn/g6VY3Wp3BZlG`
- Native-payload URL:
  `hxxps://gretgerherhdf[.]it[.]com/kug2gn/t7sDAzFPAA2v`
- Delivery hostname: `gretgerherhdf[.]it[.]com`
- C2 base domain: `cdn-apple[.]com`
- C2 hostname pattern:
  `<random-alphanumeric-label>.cdn-apple[.]com:443`
- Delivery-host addresses resolved at analysis time:
  `172.67.130[.]64`, `104.21.3[.]50`

The two IP addresses are shared Cloudflare infrastructure and should not be
blocked broadly without additional scoping.

### Host indicators

- Install directory:
  `~/Library/Application Support/com.apple.finder.agent`
- Fake application: `Finder.app`
- Payload executable: `C6690F41`
- Full payload path:
  `~/Library/Application Support/com.apple.finder.agent/Finder.app/Contents/MacOS/C6690F41`
- Bundle identifier: `com.apple.finder.agent`
- Marker file: `.Cheked`
- Full Disk Access URL:
  `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles`

### Cryptographic hashes

- Initial-drop SHA-256:
  `ab8f55d245298dd18b6c90d69ac87682d37be82b622f6c05ed940b7d6de02a30`
- Stage-2 SHA-256:
  `5c3d49f29f7c4078cbdf7e2e56c0ea12b96ef0b1e1fe5ac5f4bb2b055a6b2c01`
- Final universal Mach-O SHA-256:
  `1a663cc6c7c919607025b006b27b446dcd78d2b6244d20bfe7ffded251d47329`

## Ghidra reference points

The following x86-64 functions contain the principal confirmed behaviors:

- `0x1000641e7`: Login Items persistence logic
- `0x10006795b`: opens the Full Disk Access settings pane
- `0x1000681e9`: checks access to protected paths
- `0x10006817a`: derives the current executable/application path
- `0x100058b4c`: browser and profile collection configuration
- `0x1000600ea`: high-level filesystem and data-collection logic
- `0x10009f109`: browser SQLite table-query helper
- `0x1000156f6`: randomized C2 hostname generation and resolution
- `0x1000a0ed4`: debugger detection through `sysctl`

## Confidence and remaining unknowns

High-confidence conclusions are based on decoded plaintext, imported APIs,
decompiled control flow, and cross-references. These include the installation
path, fake bundle identity, Full Disk Access prompt, Login Items behavior,
Chrome database targets, SQLite table names, anti-debugging check, and C2
hostname construction.

The following interpretations are strongly supported but not completely
resolved:

- exact Firefox/Gecko profile paths and SQL queries;
- the complete list of non-browser files collected;
- exact Darwin notification names and their effect on execution timing;
- the complete application-layer C2 protocol and uploaded record format; and
- whether the 15-minute condition is strictly a sandbox delay, a session-state
  condition, or both.

## Analysis method and safety

No captured JavaScript or Mach-O code was executed. The analysis used:

- allow-listed static evaluation of arithmetic and XOR string builders;
- reimplementation of environment-key derivation and RC4-like transforms;
- exhaustive enumeration of the 768 environment-result combinations;
- integrity validation of decrypted embedded blobs;
- static Mach-O inspection; and
- Ghidra decompilation, call-graph tracing, cross-references, and manual
  evaluation of inline string decoders.

The downloaded payload was imported into Ghidra only. It was not launched.

## Produced artifacts

- `stage2.deobfuscated.js`: exact stage-2 source with 302 arithmetic/XOR
  string builders constant-folded; encrypted byte arrays remain present.
- `stage2.embedded.json`: unique validated environment outcome, derived key,
  and all three decrypted embedded values.
- `stage3.loader.deobfuscated.js`: formatted recovered loader with its malicious
  invocation commented out for analysis safety.
- `static_deobfuscate.py`: allow-listed static string decoder.
- `decrypt_embedded_stage.py`: Python reimplementation of key derivation,
  RC4-like transforms, enumeration, and integrity checking.
- `C6690F41.quarantine`: recovered universal Mach-O payload, retained for static
  analysis and never executed.
