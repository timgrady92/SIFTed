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
const runButton = document.getElementById("runScalpel");
const runStatus = document.getElementById("runStatus");
const openLog = document.getElementById("openLog");
const closeLog = document.getElementById("closeLog");
const logDrawer = document.getElementById("logDrawer");
const logDrawerContent = document.getElementById("logDrawerContent");
const logDrawerStatus = document.getElementById("logDrawerStatus");
const organizeByType = document.getElementById("organizeByType");

let currentRunId = "";

const gatherTypes = () => {
  const types = [];
  document.querySelectorAll(".focus-types input:checked").forEach((input) => {
    const typeList = input.dataset.types || "";
    typeList.split(",").forEach((entry) => {
      const trimmed = entry.trim();
      if (trimmed) {
        types.push(trimmed);
      }
    });
  });
  return types;
};

const buildCommand = () => {
  const types = gatherTypes();
  const args = [
    "scalpel",
    "-c",
    "<generated_config>",
    "-o",
    outputPath.value.trim() || "<output_dir>",
  ];
  if (!organizeByType.checked) {
    args.push("-O");
  }
  args.push(imagePath.value.trim() || "<image_path>");
  if (types.length) {
    args.push(`# ${types.join(", ")}`);
  }
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
  return {
    tool: "scalpel",
    case_id: caseSelect?.value || "",
    image_path: imagePath.value.trim(),
    output_path: outputPath.value.trim(),
    types: gatherTypes(),
    organize: organizeByType.checked,
  };
};

runButton.addEventListener("click", async () => {
  runButton.disabled = true;
  runButton.textContent = "Running...";
  setRunStatus("Running Scalpel...", "neutral");
  try {
    const response = await fetch("/api/scalpel/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(buildPayload()),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Unable to run Scalpel.");
    }
    commandPreview.textContent = data.command || commandPreview.textContent;
    if (data.output_path) {
      outputPath.value = data.output_path;
    }
    currentRunId = data.run_id || "";
    if (currentRunId && window.registerActiveJob) {
      window.registerActiveJob({ id: currentRunId, tool: "Scalpel" });
    }
    setRunStatus("Running Scalpel...", "neutral");
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
          runButton.textContent = "Run Scalpel";
          runButton.disabled = false;
        },
        onError: () => {
          setRunStatus("Run failed.", "error");
          runButton.textContent = "Run Scalpel";
          runButton.disabled = false;
        },
      });
    } else {
      setRunStatus("Run started. Refresh to see results.", "neutral");
      runButton.textContent = "Run Scalpel";
      runButton.disabled = false;
    }
  } catch (error) {
    setRunStatus(error.message || "Run failed.", "error");
    runButton.textContent = "Run Scalpel";
    runButton.disabled = false;
  }
});

[imagePath, outputPath, organizeByType].forEach((input) => {
  input.addEventListener("input", buildCommand);
  input.addEventListener("change", buildCommand);
});

document.querySelectorAll(".chip input").forEach((input) => {
  input.addEventListener("change", buildCommand);
});

buildCommand();
