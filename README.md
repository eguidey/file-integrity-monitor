# fim: File Integrity Monitor in C

A small command-line file integrity monitor. It records a SHA-256 baseline of a
directory tree, then reports any file that was **added**, **modified**, or
**removed**. This is the same idea behind Tripwire, AIDE, and OSSEC's syscheck.

![build](../../actions/workflows/ci.yml/badge.svg)

## Why this matters for security
File integrity monitoring is a control in PCI DSS (req. 11.5), CIS Controls, and
NIST 800-53 (SI-7). Attackers who gain access often modify binaries, config
files, or cron jobs for persistence. An FIM is how defenders notice.

## Usage
```bash
make
./fim baseline /etc ./etc.baseline    # record known-good state
./fim check    /etc ./etc.baseline    # compare later
```
Example output:
```
ADDED     /etc/cron.d/backdoor
MODIFIED  /etc/ssh/sshd_config
REMOVED   /etc/hosts.deny

3 change(s) detected
```
Exit codes: `0` no changes, `2` changes found, `1` error. That makes it easy to
use from cron or a SIEM wrapper script.

## What I practiced (C concepts)
| Concept | Where |
|---|---|
| Streaming file I/O with a fixed buffer | `sha256_file()` |
| Cryptographic hashing with OpenSSL EVP API | `sha256_file()` |
| Recursive directory traversal (`opendir`/`readdir`/`lstat`) | `walk()` |
| Writing my own hash table (open addressing, djb2) | `struct map` |
| Manual memory management, no leaks | `map_free()`, checked with Valgrind |
| Bounds-safe string handling (`snprintf`, length checks) | throughout |
| Secure temp files (`mkstemp`, not `tmpnam`) | `do_check()` |

## Security decisions
- **SHA-256**, not MD5/SHA-1, which are collision-broken.
- **`lstat`, not `stat`**, and symlinks are skipped, so a symlink can't trick the scanner into hashing files outside the target tree.
- **Every `snprintf` result and allocation is checked**; long paths are skipped with a warning rather than truncated silently.
- Compiled with `-Wall -Wextra -Werror`; developed with AddressSanitizer/UBSan (`make debug`) and Valgrind (`make memcheck`).

## Testing
```bash
make test       # integration tests (baseline, clean, add/modify/remove)
make memcheck   # Valgrind leak/error check
make debug      # ASan + UBSan build
```

## Known limitations (good next steps)
- The baseline file isn't itself protected. A real deployment should sign it or store it read-only/off-host.
- No permission/owner/mtime tracking, only content hashes.
- Baseline parsing splits on two spaces, so paths containing newlines aren't supported.
- Fixed-size hash map (4096 slots); needs resizing for large trees.
- Ideas: real-time watching with `inotify`, JSON output, an ignore list, HMAC-signed baselines.
