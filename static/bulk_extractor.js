const tooling = window.SiftedTooling;

// Get common elements using helper
const common = tooling?.getCommonElements() || {};
const imagePath = common.imagePath;
const outputPath = common.outputPath;
const commandPreview = common.commandPreview;
const caseSelect = common.caseSelect;
const runStatus = common.runStatus;

// Tool-specific elements
const runButton = document.getElementById("runBulk");
const infoMode = document.getElementById("infoMode");
const histograms = document.getElementById("histograms");
const scannerPreset = document.getElementById("scannerPreset");

let currentRunId = "";

const applyPreset = (preset) => {
  const focusChecks = Array.from(
    document.querySelectorAll(".focus-scanners input"),
  );
  const advancedChecks = Array.from(
    document.querySelectorAll(".advanced-scanners input"),
  );

  const focusSets = {
    triage: ["email", "accts", "httplogs", "exif", "pdf", "zip"],
    standard: ["email", "accts", "httplogs", "exif", "pdf", "zip", "winlnk", "winprefetch"],
    deep: ["email", "accts", "httplogs", "exif", "pdf", "zip", "winlnk", "winprefetch"],
  };
  const advancedSets = {
    triage: [],
    standard: ["wordlist"],
    deep: ["wordlist", "facebook", "outlook", "xor"],
  };

  const focusSet = new Set(focusSets[preset] || []);
  const advancedSet = new Set(advancedSets[preset] || []);

  focusChecks.forEach((input) => {
    input.checked = focusSet.has(input.value);
  });
  advancedChecks.forEach((input) => {
    input.checked = advancedSet.has(input.value);
  });
};

const buildCommand = () => {
  const focusScanners = Array.from(
    document.querySelectorAll(".focus-scanners input:checked"),
  ).map((input) => input.value);
  const advancedScanners = Array.from(
    document.querySelectorAll(".advanced-scanners input:checked"),
  ).map((input) => input.value);

  const args = [
    "bulk_extractor",
    "-o",
    outputPath?.value.trim() || "<output_dir>",
  ];

  if (infoMode?.checked) {
    args.push("-i");
  }

  if (!histograms?.checked) {
    args.push("-S", "enable_histograms=NO");
  }

  if (focusScanners.length) {
    args.push("-x", "all");
    focusScanners.forEach((scanner) => args.push("-e", scanner));
  }
  advancedScanners.forEach((scanner) => args.push("-e", scanner));

  args.push(imagePath?.value.trim() || "<image_path>");

  if (commandPreview) {
    commandPreview.textContent = args.join(" ");
  }
};

const buildPayload = () => {
  const focusScanners = Array.from(
    document.querySelectorAll(".focus-scanners input:checked"),
  ).map((input) => input.value);
  const advancedScanners = Array.from(
    document.querySelectorAll(".advanced-scanners input:checked"),
  ).map((input) => input.value);

  return {
    tool: "bulk-extractor",
    case_id: caseSelect?.value || "",
    image_path: imagePath?.value.trim() || "",
    output_path: outputPath?.value.trim() || "",
    focus_scanners: focusScanners,
    advanced_scanners: advancedScanners,
    info_mode: infoMode?.checked || false,
    histograms: histograms?.checked ?? true,
  };
};

// Initialize drawers using helper
if (tooling) {
  tooling.initializeDrawers({
    ...common,
    getRunId: () => currentRunId,
    onSelectPath: (path) => {
      if (imagePath) {
        imagePath.value = path;
      }
      buildCommand();
    },
  });

  // Create run handler using factory
  tooling.createRunHandler({
    runButton,
    runStatus,
    apiEndpoint: "/api/bulk-extractor/run",
    toolName: "Bulk Extractor",
    buildPayload,
    setRunIdRef: (id) => {
      currentRunId = id;
    },
    onSuccess: (data) => {
      if (commandPreview) {
        commandPreview.textContent = data.command || commandPreview.textContent;
      }
      if (data.output_path && outputPath) {
        outputPath.value = data.output_path;
      }
    },
  });
}

// Attach input listeners using helper
if (tooling) {
  tooling.attachInputListeners(
    [imagePath, outputPath, infoMode, histograms],
    buildCommand,
  );
  tooling.attachChipListeners(".chip input", buildCommand);
}

if (scannerPreset) {
  scannerPreset.addEventListener("change", () => {
    applyPreset(scannerPreset.value);
    buildCommand();
  });
}

applyPreset(scannerPreset?.value || "triage");
buildCommand();
