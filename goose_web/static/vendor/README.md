# Vendored third-party libraries

Loaded locally (no CDN at runtime, CSP `script-src 'self'`). License headers are kept in each file.

| File | Library | Version | License | Source |
|---|---|---|---|---|
| `marked.esm.js` | marked (Markdown parser, ESM build) | 15.0.12 | MIT | https://cdn.jsdelivr.net/npm/marked@15/lib/marked.esm.js |
| `purify.es.mjs` | DOMPurify (HTML sanitizer, ES module) | 3.4.17 | Apache-2.0 OR MPL-2.0 | https://cdn.jsdelivr.net/npm/dompurify@3/dist/purify.es.mjs |
| `highlight.min.js` | highlight.js common languages, ES build | 11.12.0 | BSD-3-Clause | https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11/build/es/highlight.min.js |
| `hljs-dark.css` | highlight.js theme "github-dark" | 11.12.0 | BSD-3-Clause | https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11/build/styles/github-dark.min.css |
| `hljs-light.css` | highlight.js theme "github" | 11.12.0 | BSD-3-Clause | https://cdn.jsdelivr.net/gh/highlightjs/cdn-release@11/build/styles/github.min.css |
| `qrcode.esm.js` | qrcode-generator (Kazuhiko Arase) | 1.4.4 | MIT | https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.js |

Local modifications:

* `marked.esm.js`, `purify.es.mjs`: the trailing `//# sourceMappingURL=...` comment was removed (no map files are shipped).
* `qrcode.esm.js`: the original UMD file with `export default qrcode;` appended so it can be imported as an ES module. The UMD tail is a no-op in the browser.

To update: download the new versions from the URLs above, re-apply the modifications, save as UTF-8 without BOM, and bump the versions in this table and the `VERSION` constant in `/static/sw.js`. Then regenerate `SHA256SUMS` (below).

## Integrity (`SHA256SUMS`)

`SHA256SUMS` lists the SHA-256 of every vendored file in `sha256sum` format (LF line endings, sorted by
file name; this README and `SHA256SUMS` itself are not listed). `tests/test_platform_hardening.py` fails when a
file is changed, added or removed without updating it, so a tampered or accidentally edited library is caught
in CI.

Verify (from this folder). Goose Web runs on Windows only (README), so PowerShell is the normal way:

```powershell
# Windows PowerShell
Get-Content SHA256SUMS | ForEach-Object { $h, $f = $_ -split '\s+', 2
  if ((Get-FileHash $f -Algorithm SHA256).Hash -ne $h.ToUpper()) { "MISMATCH $f" } else { "OK $f" } }
```

To check a clone on another system (Git Bash on Windows has `sha256sum` too):

```sh
sha256sum -c SHA256SUMS                    # macOS: shasum -a 256 -c SHA256SUMS
```

Update after changing a vendored file (from this folder, in Git Bash or another POSIX shell, then review the diff):

```sh
LC_ALL=C sha256sum $(LC_ALL=C ls | grep -v -e '^README.md$' -e '^SHA256SUMS$') > SHA256SUMS
```

The sums are over the files with LF line endings. A Windows clone with `core.autocrlf=true` checks the files
out with CRLF, so `sha256sum -c` reports mismatches there (the test compares the LF-normalised content in that
case); clone with `git -c core.autocrlf=false -c core.eol=lf` to verify byte for byte.
