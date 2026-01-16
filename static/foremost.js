const imagePath = document.getElementById("imagePath");
const outputPath = document.getElementById("outputPath");
const quickFlag = document.getElementById("quickFlag");
const verboseFlag = document.getElementById("verboseFlag");
const safeMode = document.getElementById("safeMode");
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
const runButton = document.getElementById("runForemost");
const resultCarved = document.getElementById("resultCarved");
const resultAudit = document.getElementById("resultAudit");
const resultSummary = document.getElementById("resultSummary");
const runStatus = document.getElementById("runStatus");
const runLog = document.getElementById("runLog");
const milestonesList = document.getElementById("milestoneList");
const openLog = document.getElementById("openLog");
const closeLog = document.getElementById("closeLog");
const logDrawer = document.getElementById("logDrawer");
const logDrawerContent = document.getElementById("logDrawerContent");
const logDrawerStatus = document.getElementById("logDrawerStatus");

let currentRunId = "";

const buildCommand = () => {
  const types = Array.from(document.querySelectorAll(".chip input:checked"))
    .map((input) => mapType(input.value))
    .join(",");

  const args = [
    "foremost",
    "-i",
    imagePath.value.trim() || "<image_path>",
    "-o",
    outputPath.value.trim() || "<output_dir>",
  ];

  if (types) {
    args.push("-t", types);
  }

  if (quickFlag.checked) {
    args.push("-q");
  }

  if (verboseFlag.checked) {
    args.push("-v");
  }

  if (safeMode && safeMode.checked) {
    args.push("-T");
    args.push("# safe mode: 10s per type");
  }

  commandPreview.textContent = args.join(" ");
};

const mapType = (value) => {
  if (value === "jpeg") {
    return "jpg";
  }
  return value;
};

const buildPayload = () => ({
  tool: "foremost",
  case_id: caseSelect?.value || "",
  image_path: imagePath.value.trim(),
  output_path: outputPath.value.trim(),
  types: Array.from(document.querySelectorAll(".chip input:checked")).map(
    (input) => mapType(input.value),
  ),
  quick: quickFlag.checked,
  verbose: verboseFlag.checked,
  safe_mode: safeMode?.checked || false,
});

const setRunStatus = (message, tone) => {
  if (!runStatus) {
    return;
  }
  runStatus.textContent = message;
  runStatus.dataset.tone = tone || "neutral";
};

const setRunLog = (text) => {
  if (!runLog) {
    return;
  }
  runLog.textContent = text || "";
};

const appendMilestone = (message) => {
  if (!milestonesList) {
    return;
  }
  const item = document.createElement("li");
  item.textContent = message;
  milestonesList.prepend(item);
  const items = milestonesList.querySelectorAll("li");
  if (items.length > 6) {
    items[items.length - 1].remove();
  }
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

[runButton].forEach((button) => {
  button.addEventListener("click", async () => {
    button.disabled = true;
    button.textContent = "Running...";
    setRunStatus("Running Foremost...", "neutral");
    setRunLog("");
    try {
      const response = await fetch("/api/foremost/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildPayload()),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Unable to run Foremost.");
      }
      commandPreview.textContent = data.command || commandPreview.textContent;
      if (data.output_path) {
        outputPath.value = data.output_path;
      }
      currentRunId = data.run_id || "";
      if (currentRunId && window.registerActiveJob) {
        window.registerActiveJob({ id: currentRunId, tool: "Foremost" });
      }
      if (resultCarved) {
        resultCarved.textContent = `${data.output_path || outputPath.value}/`;
      }
      if (resultAudit) {
        resultAudit.textContent = "audit.txt";
      }
      if (resultSummary) {
        resultSummary.textContent = "output.txt";
      }
      if (milestonesList) {
        milestonesList.innerHTML = "";
      }
      setRunStatus("Running Foremost...", "neutral");

      if (currentRunId && tooling && window.EventSource) {
        tooling.attachRunEvents(currentRunId, {
          onMilestone: (payload) => {
            appendMilestone(payload.message || "Milestone");
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
            button.textContent = "Run Foremost";
            button.disabled = false;
          },
          onError: () => {
            setRunStatus("Run failed.", "error");
            button.textContent = "Run Foremost";
            button.disabled = false;
          },
        });
      } else {
        setRunStatus("Run started. Refresh to see results.", "neutral");
        button.textContent = "Run Foremost";
        button.disabled = false;
      }
    } catch (error) {
      setRunStatus(error.message || "Run failed.", "error");
      setRunLog("");
      button.textContent = "Run Foremost";
      button.disabled = false;
    }
  });
});

[imagePath, outputPath, quickFlag, verboseFlag, safeMode].forEach((input) => {
  input.addEventListener("input", buildCommand);
  input.addEventListener("change", buildCommand);
});

document.querySelectorAll(".chip input").forEach((input) => {
  input.addEventListener("change", buildCommand);
});

buildCommand();
