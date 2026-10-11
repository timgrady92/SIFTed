# Case evidence and file triage

The evidence workspace presents disk investigation as a sequence over the existing adapters, persistent queue and published results:

```text
Analysis: map disk → describe filesystem → build recursive inventory
File triage: browse/search → inspect metadata → extract/recover
Examine files: identify captured content → choose relevant examination
```

Direct tool pages and URLs remain available for A/B evaluation. Clicking an evidence label in Cases opens that specific input. Disk and filesystem images start on Analysis; other inputs offer content-specific examinations in that tab. Overview holds evidence identity and classification. Activity holds processing history, including examinations of captured files.

## Filesystem preparation

Allocated regions from the latest verified `mmls` map carry their partition start and observed sector size into `fsstat` and recursive `fls -r -p`. Each card shows existing filesystem characterization and inventory results, with one primary next action. Building an inventory directly remains possible if `fsstat` is unavailable. Filesystem images can start at offset zero without a partition map. Existing examined geometries remain selectable.

Only a successful, recursive, whole-filesystem inventory containing all listing states marks a filesystem prepared. A directory-scoped or deleted-only listing cannot silently replace that inventory. When several filesystems are ready, Triage requires an explicit selection; a single prepared filesystem can be selected automatically without executing anything.

## Inventory browsing

The worker builds a SQLite index from the parsed `fls.csv`, retaining the raw `fls.txt` and any `unparsed.txt`. It publishes the index as an ordinary hashed output. Triage verifies that manifest before reading it through a read-only connection. It does not rerun `fls` to search or enter a directory.

Search accepts up to 256 characters and covers either the current directory or entire selected inventory. Filters distinguish files, directories and other entries; not marked deleted, deleted and reallocated states remain independent observations. Results use 100-row pages with deterministic ordering. Breadcrumbs open known inventory directories. A nonrecursive listing remains usable as a scoped listing; entering a directory runs a validated recursive `fls` listing inside the workspace rather than pretending its descendants were indexed.

Each metadata or extraction action retains the original image, filesystem offset, sector size, inventory run and selected entry ID. `istat` receives the inode component; `icat` retains an NTFS stream address where present. The backend validates the selected entry at preview/submission and again after queue waiting. Extraction keeps the listed filename and enables recovery for entries marked deleted. Invalid selections, changed inventories and mismatched addresses or options are rejected. The saved primary input record includes the selected entry. Duplicate directory paths open a fresh native listing by the selected metadata address, since a flat recursive listing cannot assign those children to a unique directory entry.

## Continuity and captured content

Mapping, filesystem characterization, inventory creation, metadata inspection, extraction and basic content examinations run inside the workspace through the existing native execution APIs. Analysis shows the next useful preparation action. A completed recursive listing offers **Explore files**; a completed capture offers **Examine captured file**. The analyst explicitly continues to the next stage. Background completion never changes the active tab. Filesystem details and metadata reports display inline; block examination stays in Analysis. Routine geometry and recovery flags come from the selected evidence. Geometry overrides, repeat runs, block actions, search filters and optional examination settings stay behind disclosures. CLI disclosures show simple, literal commands an analyst can run directly on SIFT. Single-choice selectors are omitted. Tabs support arrow keys and Home/End, with the active tab kept visible on narrow screens.

Tab navigation retains each tab's selected filesystem, directory, search scope, filters and page in session storage and the URL. Browser back/forward navigation restores the corresponding view. Requests use a generation counter so a stale response cannot replace a newer selection. Examination forms and results stay inside their originating filesystem card, file inspection or examination section. Tab updates preserve the relevant open disclosures, viewport anchor and keyboard focus; background completion also preserves an unfinished search. File rows have one Inspect action, which expands the row and reads metadata through `istat` or reopens its completed report. Reopening the entry reuses captures and metadata only when the source hash, inventory run and entry identity match. Active jobs are reconstructed from durable runs after reload; polling retries transient failures without submitting another job. Preparation results update the disk cards automatically, keeping raw reports behind explicit result buttons.

Derived files are scoped to descendants of the selected evidence, rather than every report or every unrelated input in the case. Selecting a captured file identifies its bytes and presents relevant examinations in Examine files, while keeping the source disk selected. Metadata, extracted-file examination and completed reports do not require navigation to a tool page. Producing runs can be reopened inside the workspace. Block samples remain blocks even if their bytes contain recognizable document headers. Advanced carving, timeline and memory configuration is still available through the standalone interfaces for A/B evaluation.

Inline report reading checks case and evidence ownership, accepts only complete published reports, rejects symlinks and nonregular files, escapes report content and reads at most 128 KiB. Full reports and execution logs open separately when requested. These display limits do not truncate the persisted tool output.

## Limits

An inventory contains names, metadata addresses and flags reported by the filesystem. It does not determine file content type, execution, historical ownership or whether a deleted file can be recovered completely. Triage exposes reallocation separately and warns about unparsed listing lines. Disk-sector offsets, inode/stream addresses and filesystem data-unit addresses are distinct. Block examination remains in Analysis rather than the directory browser.

Existing reports remain viewable. A new inventory run is required to create an index; SIFTed does not reinterpret or mutate historical outputs. Index creation and publication use the worker's existing timeout, cancellation and storage budget. Verification streams the index with bounded memory; large inventories incur hash verification on each view. Search scans the index but only returns the requested page.

## Verification

`test_file_triage.py` exercises nested browsing, literal searches, filters, pagination, selected-entry provenance, case/geometry isolation, changed and symlinked indexes, missing tools and derived-input scope. `test_browser.py` follows the desktop and mobile disk journey entirely within one document, including reload during a queued job, a failed status request, recovery, captured-file examination, preserved filters and reopening results. Long-inventory checks cover stable scrolling during metadata completion, retained draft search text and focus, keyboard tabs and browser history. `test_live_evidence_workspace.py` follows real partitioned ext4 images at 512-byte and 4,096-byte sector sizes through nested-directory triage, exact PDF extraction and native text examination; `test_live_disk_tools.py` verifies the underlying Sleuth Kit tools and binary extraction.

Native checks run in an isolated checkout and temporary case database on the connected SIFT workstation, with synthetic evidence and output paths containing spaces. They do not create jobs in the production case database.

The native journey also uses `/cases/nps-2009-canon2-gen6.E01`: its FAT16 filesystem is characterized and indexed, an allocated file is extracted through a selected triage entry, its bytes are compared with an independent native `icat` invocation, and the acquisition's SHA-256 is checked for changes. Set `SIFTED_TEST_DISK_IMAGE` to an available acquisition to enable that optional test.

The streamlined workspace passed 361 local checks (including 12 Chromium journeys); 147 native checks skipped where tools or fixtures were unavailable. The final affected browser/workspace checks passed after the visual cleanup. A separate Chromium session connected to an isolated app and worker on SIFT followed the real E01 through all six operations without replacing the browser document: `mmls`, `fsstat`, recursive `fls`, `istat`, `icat`, and `xxd`. It filtered 33 allocated JPEG entries, extracted `IMG_0003.JPG` (840,101 bytes), verified equality with independent native `icat` output, confirmed the original image hash was unchanged, and checked the captured-file provenance and mobile layout. The production case database was not used for these tests.
