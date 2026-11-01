# publish-gate

A conservative, local publication gate for text trees. It never publishes files.
A detector that recognizes source-code keys can miss credentials in prose or
HTML. This tool combines independent detectors, private denylist matching, and
two fresh agent reviews. A clean result is evidence of these checks, not a proof
that all sensitive information has been removed.

## Install

Requires Python, Homebrew, and authenticated Claude and Codex CLIs for the default
judges. Run `sh install.sh` to install missing gitleaks and TruffleHog executables,
create a project `.venv`, and install Presidio, spaCy, and the English language
model. Then run `./publish-gate selftest`.

## Usage

```sh
./publish-gate check candidate --denylist ../private-rules.txt --out ../evidence/run.json
./publish-gate loop candidate --denylist ../private-rules.txt --fix-cmd 'repair-agent' --max-rounds 3 --out ../evidence/loop.json
```

The denylist must be outside the candidate tree. Copy `denylist.example` outside
this repository and replace its fake entries. Each non-comment line is a
case-insensitive Python regular expression. An optional category and literal TAB
can precede it. A third TAB-separated field may contain a comment starting with #. Category comments apply to following lines. Recognized categories
are listed in the example; unknown labels become `other` before reaching judges.
Empty lists and invalid expressions fail closed.

## Four stages

1. gitleaks, TruffleHog filesystem scanning with verification enabled, Presidio
   English recognizers, and built-in patterns. The built-in pass covers 13 key
   families, credential labels, stripped HTML, capability links, private network
   addresses, home paths, email and phone shapes. All hard findings block publication,
   including unverified credentials. Verification can contact vendor endpoints.
2. External denylist expressions match both file names and contents, including
   HTML-stripped contents. Use it for Japanese identities and private vocabulary.
3. Two fresh judges see file paths, contents, denylist categories, and numbered Presidio review items.
   Default adapters use Claude Sonnet without tools and Codex in a read-only
   sandbox with isolated configuration. Their services receive the candidate
   content; authentication and service billing are managed by the operator.
4. Any finding, missing dependency, timeout, malformed verdict or detected tree
   change makes the run fail. Exit 0 means PASS; 1 means findings; 2 means an
   input/execution error. No push, upload, or release command exists.

`--judge-cmd` can be repeated exactly twice to replace both adapters. Commands
are tokenized without a shell. Each receives one batch review request on
stdin and must emit only JSON to stdout. Use independently configured reviewers;
distinct command strings alone cannot prove independence. Custom commands are
trusted local programs: the caller must enforce their read-only execution and
context isolation. Default adapters must also be checked against installed CLI
versions and organizational managed settings.

Presidio drops URL, DATE_TIME and NRP. PERSON, LOCATION, ORGANIZATION and
US_DRIVER_LICENSE require individual review. Every other entity type, including
unknown identifier types, is a hard failure. Both judges must PASS every review
item: only public figures/organizations/places or false positives that do not
lead to the author identity, employer, clients or location qualify.
Missing, duplicated or extra item IDs and any FAIL block the final stage.

Judge schema:

```json
{"verdict":"PASS","findings":[],"review_items":[{"id":1,"verdict":"PASS","reason":"False positive in generic prose."}]}
```

A PASS requires an empty findings array. Overall finding reasons are restricted to `secret`,
`identity`, `infrastructure`, `capability`, or `other`. Never quote values.

The repair command receives the evidence on stdin and its path through
`PUBLISH_GATE_FINDINGS`; `PUBLISH_GATE_TREE` identifies the candidate. It must only
remove or generalize flagged content. Never weaken the gate, denylist, or config.
The loop checks gate files and denylist integrity after repairs. It is not an OS
sandbox for arbitrary repair programs; run untrusted repair agents in a separate
restricted environment. The round limit counts checks (so 3 rounds permit at
most 2 repairs). Exhaustion retains the last findings and exits nonzero.

## Evidence and scope

Evidence is JSON with schema, UTC timestamp, deterministic SHA-256, per-stage
PASS/FAIL, counts and findings, tool versions, and sanitized judge verdict paths.
Hard findings contain only relative file, line and rule ID. The private evidence
review_items list contains id, file, line, entity and matched text; judge JSON
contains each item ID, verdict and a one-line reason. Raw judge output and
numeric risk scores are not retained. Keep
evidence private: file names themselves can identify sensitive content.

The hash frames sorted UTF-8 relative paths and bytes with unsigned 64-bit
big-endian lengths and a file/link type marker. Files are checked from a snapshot;
the original and snapshot hashes are rechecked before a result is issued. This
is a working-tree gate, not a Git history audit. `.git`, `.venv`, and
`__pycache__` directories are excluded only at the root. The evidence publication_manifest lists the exact reviewed files. The publisher must export only this manifest, reject symlinks, and recheck the hash; never publish the source tree wholesale or include excluded directories. No ignore file can waive a finding. Symlinks, binary or
non-UTF-8 content block publication; use a text-only export and review other
formats separately. False positives are expected, including when checking this
tool's own detector source. There is no suppression switch. A PASS applies only
to the exact hash; final publication must compare it again.

## Self-test

Fixtures are created in a temporary directory using fake values assembled at
runtime. Every named key family and additional pattern has its own assertion.
HTML splitting, Japanese names and addresses, detector errors, a clean stage
1–2 control, changed hashes, and failed judges are checked. The self-test needs
the actual detector dependencies but does not call paid agent judges.

Images: PNG, JPEG, WebP and GIF are detected by signature. Maximum 5 MiB each; 100 frames and 20 million total rendered pixels. Unknown binaries, unknown metadata extensions and all ICC profiles fail closed. Printable ASCII in metadata and unconsumed bytes is scanned by the existing detectors and denylist. Compressed pixel streams are excluded from text scanning; all frames remain subject to both visual judges. Both judges review every frame, with per-file image_items verdicts; missing, duplicate or failing verdicts prevent publication.

Use `./publish-gate strip input.png output.png` to re-render as metadata-free PNG. Animations become APNG at 100 ms per frame; inspect appearance and timing before replacing an asset. Color profiles are discarded. Input and output may be the same file. The gate never strips automatically. Claude receives base64 PNG frames using print mode stream-json input; Codex receives each frame with --image. Custom judge commands receive repeated --image path arguments.

JPEG/WebP/GIF require a byte-exact decode/re-encode match because their decoders do not expose consumed byte counts. Valid images from other encoders may fail with `image-noncanonical-stream-use-strip`; use the strip command to produce PNG. PNG compressed streams must end exactly, without hidden trailing payload.

## Batch controls and committed scope

`--judge-batch-size 25` limits review items per call; each call carries one full
file and at most one image (all its frames). A file with more items is repeated
in full, while each item and image gets exactly one verdict from each judge.
`--judge-timeout 600` sets the per-call deadline in seconds. Any batch failure
fails the entire gate. Judge JSON retains batch verdicts and redacted failure
class, exit code, elapsed seconds and the last 20 stderr lines. Usage-limit
failures require an operator rerun from an environment with quota; the gate
never changes accounts. Reasons and diagnostics are private evidence.

`--git-tracked` reads committed blobs at HEAD into a temporary export, ignoring
working edits and untracked files. It excludes node_modules, dist, .git, .venv
and __pycache__ at every depth. Submodules and symlinks fail closed. The manifest
and hash refer to this export, with source_head recorded in evidence. This does
not audit history. The publisher must export those same HEAD blobs and compare
the manifest and hash. Use check rather than loop when editing working files:
repairs are invisible to HEAD export until the operator commits them.

Files larger than 64,000 text characters fail closed before judge invocation. Split them into smaller publication files and rerun; full file text is never silently truncated.

Default adapters use 80% of the outer per-call deadline for the CLI, reserving the remainder for process cleanup and redacted diagnostics, including unterminated stderr lines.
