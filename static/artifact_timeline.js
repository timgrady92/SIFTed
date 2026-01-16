const imagePath = document.getElementById("imagePath");
const outputPath = document.getElementById("outputPath");
const timezoneInput = document.getElementById("timelineTimezone");
const commandPreview = document.getElementById("commandPreview");
const runButton = document.getElementById("runTimeline");
const runStatus = document.getElementById("runStatus");
const openLog = document.getElementById("openLog");
const closeLog = document.getElementById("closeLog");
const logDrawer = document.getElementById("logDrawer");
const logDrawerContent = document.getElementById("logDrawerContent");
const logDrawerStatus = document.getElementById("logDrawerStatus");
const runResults = document.getElementById("runResults");
const runResultsLinks = document.getElementById("runResultsLinks");
const openBrowser = document.getElementById("openBrowser");
const closeBrowser = document.getElementById("closeBrowser");
const browserDrawer = document.getElementById("browserDrawer");
const manualPath = document.getElementById("manualPath");
const useManualPath = document.getElementById("useManualPath");
const drawerList = document.getElementById("drawerList");
const drawerError = document.getElementById("drawerError");
const currentPathLabel = document.getElementById("currentPath");
const pathChips = Array.from(document.querySelectorAll(".path-chip"));

let currentRunId = "";

const buildCommand = () => {
  const sourcePath = imagePath.value.trim() || "<evidence_path>";
  const outputDir = outputPath.value.trim() || "<output_dir>";
  const timezone = timezoneInput?.value.trim() || "UTC";
  const storagePath = `${outputDir}/timeline.plaso`;
  const timelinePath = `${outputDir}/timeline.csv`;

  const log2timeline = ["log2timeline.py", "--storage_file", storagePath, sourcePath];
  const psort = [
    "psort.py",
    "-o",
    "l2tcsv",
    "-w",
    timelinePath,
    "--output_time_zone",
    timezone,
    storagePath,
  ];

  if (commandPreview) {
    commandPreview.textContent = `${log2timeline.join(" ")} && ${psort.join(" ")}`;
  }
};

const setRunStatus = (message, tone) => {
  if (!runStatus) {
    return;
  }
  runStatus.textContent = message;
  runStatus.dataset.tone = tone || "neutral";
};

const renderResultsLink = (outputDir) => {
  if (!runResults || !runResultsLinks) {
    return;
  }
  if (!outputDir) {
    runResults.hidden = true;
    runResultsLinks.innerHTML = "";
    return;
  }
  const timelinePath = `${outputDir}/timeline.csv`;
  runResultsLinks.innerHTML = "";
  const link = document.createElement("a");
  link.className = "run-result-link";
  link.href = `/view-file?path=${encodeURIComponent(timelinePath)}`;
  link.textContent = "timeline.csv";
  runResultsLinks.appendChild(link);
  runResults.hidden = false;
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

const buildPayload = () => ({
  tool: "artifact-triage",
  case_id: document.getElementById("caseSelect")?.value || "",
  image_path: imagePath.value.trim(),
  output_path: outputPath.value.trim(),
  timezone: timezoneInput?.value.trim() || "UTC",
});

if (runButton) {
  runButton.addEventListener("click", async () => {
    if (runResults) {
      runResults.hidden = true;
    }
    runButton.disabled = true;
    runButton.textContent = "Running...";
    setRunStatus("Running timeline...", "neutral");
    try {
      const payload = buildPayload();
      const response = await fetch("/api/artifact-triage/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Unable to run timeline.");
      }
      commandPreview.textContent = data.command || commandPreview.textContent;
      if (data.output_path) {
        outputPath.value = data.output_path;
      }
      renderResultsLink(data.output_path);
      currentRunId = data.run_id || "";
      if (currentRunId && window.registerActiveJob) {
        window.registerActiveJob({ id: currentRunId, tool: "Artifact Triage" });
      }
      setRunStatus("Running timeline...", "neutral");
      if (currentRunId && tooling && window.EventSource) {
        tooling.attachRunEvents(currentRunId, {
          onMilestone: (payload) => {
            setRunStatus(payload.message || "Running...", "neutral");
          },
          onStatus: (payload) => {
            setRunStatus(payload.message || "Running...", "neutral");
          },
          onDone: (payload) => {
            const exitCode = Number(payload.message || 0);
            setRunStatus(
              exitCode === 0 ? "Run completed." : "Run completed with errors.",
              exitCode === 0 ? "success" : "error",
            );
            runButton.textContent = "Run timeline";
            runButton.disabled = false;
          },
          onError: () => {
            setRunStatus("Run failed.", "error");
            runButton.textContent = "Run timeline";
            runButton.disabled = false;
          },
        });
      } else {
        setRunStatus("Run started. Refresh to see results.", "neutral");
        runButton.textContent = "Run timeline";
        runButton.disabled = false;
      }
    } catch (error) {
      setRunStatus(error.message || "Run failed.", "error");
      runButton.textContent = "Run timeline";
      runButton.disabled = false;
    }
  });
}

[imagePath, outputPath, timezoneInput].forEach((input) => {
  if (!input) {
    return;
  }
  input.addEventListener("input", buildCommand);
  input.addEventListener("change", buildCommand);
});

buildCommand();
