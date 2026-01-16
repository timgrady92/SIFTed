const imagePath = document.getElementById("imagePath");
const outputPath = document.getElementById("outputPath");
const commandPreview = document.getElementById("commandPreview");
const openBrowser = document.getElementById("openBrowser");
const closeBrowser = document.getElementById("closeBrowser");
const browserDrawer = document.getElementById("browserDrawer");
const manualPath = document.getElementById("manualPath");
const useManualPath = document.getElementById("useManualPath");
const drawerList = document.getElementById("drawerList");
const drawerError = document.getElementById("drawerError");
const currentPathLabel = document.getElementById("currentPath");
const pathChips = Array.from(document.querySelectorAll(".path-chip"));
const caseSelect = document.getElementById("caseSelect");
const runButton = document.getElementById("runBulk");
const runStatus = document.getElementById("runStatus");
const openLog = document.getElementById("openLog");
const closeLog = document.getElementById("closeLog");
const logDrawer = document.getElementById("logDrawer");
const logDrawerContent = document.getElementById("logDrawerContent");
const logDrawerStatus = document.getElementById("logDrawerStatus");
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
    outputPath.value.trim() || "<output_dir>",
  ];

  if (infoMode.checked) {
    args.push("-i");
  }

  if (!histograms.checked) {
    args.push("-S", "enable_histograms=NO");
  }

  if (focusScanners.length) {
    args.push("-x", "all");
    focusScanners.forEach((scanner) => args.push("-e", scanner));
  }
  advancedScanners.forEach((scanner) => args.push("-e", scanner));

  args.push(imagePath.value.trim() || "<image_path>");

  commandPreview.textContent = args.join(" ");
};

const setRunStatus = (message, tone) => {
  if (!runStatus) {
    return;
  }
  runStatus.textContent = message;
  runStatus.dataset.tone = tone || "neutral";
};

const tooling = window.SiftedTooling;
if (tooling) {
  tooling.setupLogDrawer({
    openButton: openLog,
    closeButton: closeLog,
    drawer: logDrawer,
    content: logDrawerContent,
    status: logDrawerStatus,
    getRunId: () => currentRunId,
  });

  tooling.setupBrowseDrawer({
    openButton: openBrowser,
    closeButton: closeBrowser,
    drawer: browserDrawer,
    drawerList,
    drawerError,
    currentPathLabel,
    pathChips,
    manualPath,
    useManualPath,
    onSelectPath: (path) => {
      imagePath.value = path;
      buildCommand();
    },
  });
}

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
    image_path: imagePath.value.trim(),
    output_path: outputPath.value.trim(),
    focus_scanners: focusScanners,
    advanced_scanners: advancedScanners,
    info_mode: infoMode.checked,
    histograms: histograms.checked,
  };
};

runButton.addEventListener("click", async () => {
  runButton.disabled = true;
  runButton.textContent = "Running...";
  setRunStatus("Running Bulk Extractor...", "neutral");
  try {
    const response = await fetch("/api/bulk-extractor/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildPayload()),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Unable to run Bulk Extractor.");
    }
    commandPreview.textContent = data.command || commandPreview.textContent;
    if (data.output_path) {
      outputPath.value = data.output_path;
    }
    currentRunId = data.run_id || "";
    if (currentRunId && window.registerActiveJob) {
      window.registerActiveJob({ id: currentRunId, tool: "Bulk Extractor" });
    }
    setRunStatus("Running Bulk Extractor...", "neutral");
    if (currentRunId && tooling && window.EventSource) {
      tooling.attachRunEvents(currentRunId, {
        onStatus: (payload) => {
          setRunStatus(payload.message || "Running...", "neutral");
        },
        onDone: (payload) => {
          const exitCode = Number(payload.message || 0);
          setRunStatus(
            exitCode === 0 ? "Run completed." : "Run completed with errors.",
            exitCode === 0 ? "success" : "error",
          );
          runButton.textContent = "Run Bulk Extractor";
          runButton.disabled = false;
        },
        onError: () => {
          setRunStatus("Run failed.", "error");
          runButton.textContent = "Run Bulk Extractor";
          runButton.disabled = false;
        },
      });
    } else {
      setRunStatus("Run started. Refresh to see results.", "neutral");
      runButton.textContent = "Run Bulk Extractor";
      runButton.disabled = false;
    }
  } catch (error) {
    setRunStatus(error.message || "Run failed.", "error");
    runButton.textContent = "Run Bulk Extractor";
    runButton.disabled = false;
  }
});

[imagePath, outputPath, infoMode, histograms].forEach((input) => {
  input.addEventListener("input", buildCommand);
  input.addEventListener("change", buildCommand);
});

document.querySelectorAll(".chip input").forEach((input) => {
  input.addEventListener("change", buildCommand);
});

if (scannerPreset) {
  scannerPreset.addEventListener("change", () => {
    applyPreset(scannerPreset.value);
    buildCommand();
  });
}

applyPreset(scannerPreset?.value || "triage");
buildCommand();
