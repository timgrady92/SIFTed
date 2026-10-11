# Case evidence and file triage

The evidence workspace presents disk investigation as a sequence over the existing adapters, persistent queue and published results:

```text
Analysis: map disk → describe filesystem → build recursive inventory
File triage: browse/search → inspect metadata → extract/recover
Derived files: identify captured content → choose relevant examination
```

Direct tool pages and URLs remain available for A/B evaluation. Clicking an evidence label in Cases opens that specific input. Disk and filesystem images start on Analysis; other inputs start with their content-specific Tools view.

## Filesystem preparation

Allocated regions from the latest verified `mmls` map carry their partition start and observed sector size into `fsstat` and recursive `fls -r -p`. Each card shows existing filesystem characterization and inventory results, with one primary next action. Building an inventory directly remains possible if `fsstat` is unavailable. Filesystem images can start at offset zero without a partition map. Existing examined geometries remain selectable.

Only a successful, recursive, whole-filesystem inventory containing all listing states marks a filesystem prepared. A directory-scoped or deleted-only listing cannot silently replace that inventory. When several filesystems are ready, Triage requires an explicit selection; a single prepared filesystem can be selected automatically without executing anything.

## Inventory browsing

The worker builds a SQLite index from the parsed `fls.csv`, retaining the raw `fls.txt` and any `unparsed.txt`. It publishes the index as an ordinary hashed output. Triage verifies that manifest before reading it through a read-only connection. It does not rerun `fls` to search or enter a directory.

Search accepts up to 256 characters and covers either the current directory or entire selected inventory. Filters distinguish files, directories and other entries; not marked deleted, deleted and reallocated states remain independent observations. Results use 100-row pages with deterministic ordering. Breadcrumbs open known inventory directories. A nonrecursive listing remains usable as a scoped listing; entering a directory opens a validated recursive `fls` workflow rather than pretending its descendants were indexed.

Each metadata or extraction action retains the original image, filesystem offset, sector size, inventory run and selected entry ID. `istat` receives the inode component; `icat` retains an NTFS stream address where present. The backend validates the selected entry at preview/submission and again after queue waiting. Extraction keeps the listed filename and enables recovery for entries marked deleted. Invalid selections, changed inventories and mismatched addresses or options are rejected. The saved primary input record includes the selected entry. Duplicate directory paths open a fresh native listing by the selected metadata address, since a flat recursive listing cannot assign those children to a unique directory entry.

## Continuity and captured content

Tool pages retain the normal editable controls and simple native CLI examples. Return links preserve the selected filesystem, directory, search scope, filters and result page through the resulting analysis page. Background updates announce changed jobs without replacing active controls or navigating the analyst away.

Derived files are scoped to descendants of the selected evidence, rather than every report or every unrelated input in the case. Each file links to its producing run and source evidence. Selecting it uses the existing bounded content identification and contextual action resolver; matching tools and previously completed results are presented together. Block samples remain blocks even if their bytes contain recognizable document headers.

## Limits

An inventory contains names, metadata addresses and flags reported by the filesystem. It does not determine file content type, execution, historical ownership or whether a deleted file can be recovered completely. Triage exposes reallocation separately and warns about unparsed listing lines. Disk-sector offsets, inode/stream addresses and filesystem data-unit addresses are distinct. Block examination remains in Analysis rather than the directory browser.

Existing reports remain viewable. A new inventory run is required to create an index; SIFTed does not reinterpret or mutate historical outputs. Index creation and publication use the worker's existing timeout, cancellation and storage budget. Verification streams the index with bounded memory; large inventories incur hash verification on each view. Search scans the index but only returns the requested page.

## Verification

`test_file_triage.py` exercises nested browsing, literal searches, filters, pagination, selected-entry provenance, case/geometry isolation, changed and symlinked indexes, missing tools and derived-input scope. `test_browser.py` follows the mobile disk journey through recovery and captured-file examination while checking preserved filters. `test_live_evidence_workspace.py` follows real partitioned ext4 images at 512-byte and 4,096-byte sector sizes through nested-directory triage, exact PDF extraction and native text examination; `test_live_disk_tools.py` verifies the underlying Sleuth Kit tools and binary extraction.

Native checks run in an isolated checkout and temporary case database on the connected SIFT workstation, with synthetic evidence and output paths containing spaces. They do not create jobs in the production case database.

The October 11, 2026 validation passed 354 local checks, including all eight Chromium journeys, and 45 checks on SIFT. The native run also used `/cases/nps-2009-canon2-gen6.E01`: its FAT16 filesystem was characterized and indexed, an allocated file was extracted through a selected triage entry, its bytes matched an independent native `icat` invocation, and the acquisition's SHA-256 remained unchanged. Set `SIFTED_TEST_DISK_IMAGE` to an available acquisition to enable that optional test.
