const imagePath = document.getElementById("imagePath");
const outputPath = document.getElementById("outputPath");
const symbolPath = document.getElementById("symbolPath");
const commandPreview = document.getElementById("commandPreview");
const jsonOutput = document.getElementById("jsonOutput");
const tableOutput = document.getElementById("tableOutput");
const runButton = document.getElementById("runVolatility");
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
const tabButtons = Array.from(document.querySelectorAll("[data-tab]"));
const tabPanels = Array.from(document.querySelectorAll("[data-tab-panel]"));
const bundleButtons = Array.from(
  document.querySelectorAll("[data-bundle-plugins]"),
);
const pluginSearch = document.getElementById("pluginSearch");
const pluginSelectedOnly = document.getElementById("pluginSelectedOnly");
const pluginCount = document.getElementById("pluginCount");
const toggleCommandView = document.getElementById("toggleCommandView");
const commandSummary = document.getElementById("commandSummary");

let currentRunId = "";
let showFullCommands = false;
let commandList = [];

const renderCommandPreview = () => {
  if (!commandPreview) {
    return;
  }
  if (!commandList.length) {
    commandPreview.textContent = "Select plugins to build the command list.";
    if (commandSummary) {
      commandSummary.textContent = "";
    }
    if (toggleCommandView) {
      toggleCommandView.disabled = true;
      toggleCommandView.textContent = "Show full list";
    }
    return;
  }

  if (commandSummary) {
    const plural = commandList.length === 1 ? "" : "s";
    const base = `${commandList.length} command${plural} generated.`;
    commandSummary.textContent =
      showFullCommands || commandList.length <= 3
        ? base
        : `${base} Showing first 3.`;
  }

  if (toggleCommandView) {
    toggleCommandView.disabled = commandList.length <= 3;
    toggleCommandView.textContent = showFullCommands ? "Show condensed" : "Show full list";
  }

  if (showFullCommands || commandList.length <= 3) {
    commandPreview.textContent = commandList.join("\n\n");
    return;
  }

  const visible = commandList.slice(0, 3);
  const remaining = commandList.length - visible.length;
  visible.push(`... ${remaining} more command${remaining === 1 ? "" : "s"} hidden ...`);
  commandPreview.textContent = visible.join("\n\n");
};

const buildCommand = () => {
  const args = ["python3", "volatility3/vol.py", "--offline", "-q"];
  const imageValue = imagePath.value.trim() || "<image_path>";
  args.push("-f", imageValue);

  if (symbolPath && symbolPath.value.trim()) {
    args.push("-s", symbolPath.value.trim());
  } else {
    args.push("-s", "<symbol_cache>");
  }

  if (outputPath && outputPath.value.trim()) {
    args.push("-o", outputPath.value.trim());
  }

  if (jsonOutput && jsonOutput.checked) {
    args.push("-r", "json");
  } else if (tableOutput && tableOutput.checked) {
    args.push("-r", "pretty");
  }

  const plugins = Array.from(
    document.querySelectorAll(".chip input[data-plugin]:checked"),
  ).map((input) => input.dataset.plugin);

  if (!plugins.length) {
    commandList = [];
    if (commandPreview) {
      commandPreview.textContent = [...args, "<plugin>"].join(" ");
    }
    if (commandSummary) {
      commandSummary.textContent = "Select plugins to build the command list.";
    }
    if (toggleCommandView) {
      toggleCommandView.disabled = true;
      toggleCommandView.textContent = "Show full list";
    }
    return;
  }
  commandList = plugins.map((plugin) => [...args, plugin].join(" "));
  renderCommandPreview();
};

const setRunStatus = (message, tone) => {
  if (!runStatus) {
    return;
  }
  runStatus.textContent = message;
  runStatus.dataset.tone = tone || "neutral";
};

const renderResultsLinks = (outputPath, plugins, renderer) => {
  if (!runResults || !runResultsLinks) {
    return;
  }
  if (!outputPath || !plugins.length) {
    runResults.hidden = true;
    runResultsLinks.innerHTML = "";
    return;
  }
  const extension = renderer === "json" ? "json" : "txt";
  const viewMode = renderer === "json" ? "&view=table" : "";
  runResultsLinks.innerHTML = "";
  plugins.forEach((plugin) => {
    const safeName = plugin.replace(/\./g, "_");
    const filePath = `${outputPath}/results/${safeName}.${extension}`;
    const link = document.createElement("a");
    link.className = "run-result-link";
    link.href = `/view-file?path=${encodeURIComponent(filePath)}${viewMode}`;
    link.textContent = safeName;
    runResultsLinks.appendChild(link);
  });
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

const setActiveTab = (tabId, persist = true) => {
  tabButtons.forEach((button) => {
    const isActive = button.dataset.tab === tabId;
    button.classList.toggle("active", isActive);
    button.setAttribute("aria-selected", String(isActive));
  });
  tabPanels.forEach((panel) => {
    const isActive = panel.dataset.tabPanel === tabId;
    panel.hidden = !isActive;
  });
  if (persist) {
    localStorage.setItem("sifted.volatility.tab", tabId);
  }
  filterPlugins();
};

const getActiveOs = () =>
  tabButtons.find((button) => button.classList.contains("active"))?.dataset.tab ||
  tabButtons[0]?.dataset.tab ||
  "windows";

const filterPlugins = () => {
  const activeOs = getActiveOs();
  const panel = document.querySelector(`[data-tab-panel="${activeOs}"]`);
  if (!panel) {
    return;
  }
  const query = pluginSearch?.value.trim().toLowerCase() || "";
  const selectedOnly = Boolean(pluginSelectedOnly?.checked);
  const chips = Array.from(panel.querySelectorAll(".chip"));
  let total = 0;
  let selected = 0;
  let visible = 0;

  chips.forEach((chip) => {
    const input = chip.querySelector("input[data-plugin]");
    if (!input) {
      return;
    }
    total += 1;
    const name = (input.dataset.plugin || "").toLowerCase();
    const isSelected = input.checked;
    if (isSelected) {
      selected += 1;
    }
    const matchesSearch = !query || name.includes(query);
    const shouldShow = matchesSearch && (!selectedOnly || isSelected);
    chip.hidden = !shouldShow;
    if (shouldShow) {
      visible += 1;
    }
  });

  const emptyState = panel.querySelector("[data-plugin-empty]");
  if (emptyState) {
    if (!total) {
      emptyState.hidden = true;
    } else if (visible) {
      emptyState.hidden = true;
    } else if (selectedOnly && !query) {
      emptyState.textContent =
        'No plugins selected. Turn off "Selected only" to browse everything.';
      emptyState.hidden = false;
    } else {
      emptyState.textContent = "No plugins match the current filters.";
      emptyState.hidden = false;
    }
  }

  if (pluginCount) {
    pluginCount.textContent = total
      ? `${selected} selected / ${total} total`
      : "No plugins loaded";
  }
};

const buildPayload = () => {
  const plugins = Array.from(
    document.querySelectorAll(".chip input[data-plugin]:checked"),
  ).map((input) => input.dataset.plugin);
  return {
    tool: "volatility",
    case_id: document.getElementById("caseSelect")?.value || "",
    image_path: imagePath.value.trim(),
    output_path: outputPath.value.trim(),
    symbol_path: symbolPath?.value.trim() || "",
    plugins,
    renderer: jsonOutput?.checked ? "json" : "pretty",
  };
};

if (runButton) {
  runButton.addEventListener("click", async () => {
    if (runResults) {
      runResults.hidden = true;
    }
    runButton.disabled = true;
    runButton.textContent = "Running...";
    setRunStatus("Running Volatility...", "neutral");
    try {
      const payload = buildPayload();
      const response = await fetch("/api/volatility/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.error || "Unable to run Volatility.");
      }
      commandPreview.textContent = data.command || commandPreview.textContent;
      if (data.output_path) {
        outputPath.value = data.output_path;
      }
      renderResultsLinks(data.output_path, payload.plugins, payload.renderer);
      currentRunId = data.run_id || "";
      if (currentRunId && window.registerActiveJob) {
        window.registerActiveJob({ id: currentRunId, tool: "Volatility 3" });
      }
      setRunStatus("Running Volatility...", "neutral");
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
            runButton.textContent = "Run Volatility";
            runButton.disabled = false;
          },
          onError: () => {
            setRunStatus("Run failed.", "error");
            runButton.textContent = "Run Volatility";
            runButton.disabled = false;
          },
        });
      } else {
        setRunStatus("Run started. Refresh to see results.", "neutral");
        runButton.textContent = "Run Volatility";
        runButton.disabled = false;
      }
    } catch (error) {
      setRunStatus(error.message || "Run failed.", "error");
      runButton.textContent = "Run Volatility";
      runButton.disabled = false;
    }
  });
}

[imagePath, outputPath, symbolPath, jsonOutput, tableOutput].forEach((input) => {
  if (!input) {
    return;
  }
  input.addEventListener("input", buildCommand);
  input.addEventListener("change", buildCommand);
});

document.querySelectorAll(".chip input").forEach((input) => {
  input.addEventListener("change", buildCommand);
  input.addEventListener("change", filterPlugins);
});

if (tabButtons.length) {
  tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      if (button.dataset.tab) {
        setActiveTab(button.dataset.tab);
      }
    });
  });
  // Restore saved tab or use default
  const savedTab = localStorage.getItem("sifted.volatility.tab");
  const validTabs = tabButtons.map((b) => b.dataset.tab);
  const initialTab = savedTab && validTabs.includes(savedTab)
    ? savedTab
    : tabButtons[0].dataset.tab;
  setActiveTab(initialTab, false);
}

if (bundleButtons.length) {
  const inputsByOs = {};
  document.querySelectorAll(".chip input[data-os]").forEach((input) => {
    const os = input.dataset.os || "linux";
    inputsByOs[os] = inputsByOs[os] || [];
    inputsByOs[os].push(input);
  });

  Object.entries(inputsByOs).forEach(([os, inputs]) => {
    const buttonsForOs = bundleButtons.filter(
      (button) => (button.dataset.bundleOs || "linux") === os,
    );
    inputs.forEach((input) => {
      input.addEventListener("change", () => {
        buttonsForOs.forEach((button) => button.classList.remove("active"));
      });
    });
  });

  bundleButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const rawPlugins = button.dataset.bundlePlugins || "";
      const plugins = rawPlugins
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);
      const pluginSet = new Set(plugins);
      const os = button.dataset.bundleOs || "linux";
      const inputs = inputsByOs[os] || [];
      inputs.forEach((input) => {
        input.checked = pluginSet.has(input.dataset.plugin || "");
      });
      bundleButtons
        .filter((other) => (other.dataset.bundleOs || "linux") === os)
        .forEach((other) => other.classList.remove("active"));
      button.classList.add("active");
      buildCommand();
      filterPlugins();
    });
  });
}

if (pluginSearch) {
  pluginSearch.addEventListener("input", filterPlugins);
}

if (pluginSelectedOnly) {
  pluginSelectedOnly.addEventListener("change", filterPlugins);
}

if (toggleCommandView) {
  toggleCommandView.addEventListener("click", () => {
    showFullCommands = !showFullCommands;
    renderCommandPreview();
  });
}

buildCommand();
filterPlugins();
