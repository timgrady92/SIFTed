const tooling = window.SiftedTooling;

// Get common elements using helper
const common = tooling?.getCommonElements() || {};
const sourcePath = common.sourcePath;
const outputPath = common.outputPath;
const commandPreview = common.commandPreview;
const runStatus = common.runStatus;

// Tool-specific elements
const symbolPath = document.getElementById("symbolPath");
const renderer = document.getElementById("renderer");
const offline = document.getElementById("offline");
const runButton = document.getElementById("runVolatility");
const runResults = document.getElementById("runResults");
const tabButtons = Array.from(document.querySelectorAll("[data-tab]"));
const tabPanels = Array.from(document.querySelectorAll("[data-tab-panel]"));
const bundleButtons = Array.from(document.querySelectorAll("[data-bundle-plugins]"));
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
  tooling?.requestPreview("volatility", buildPayload, (data) => { commandList = data.commands || []; renderCommandPreview(); });
};

// Initialize drawers using helper
if (tooling) {
  tooling.initializeDrawers({
    ...common,
    getRunId: () => currentRunId,
    onSelectPath: (path) => {
      if (sourcePath) {
        sourcePath.value = path;
      }
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
  buildCommand();
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
  const chips = Array.from(panel.querySelectorAll(".plugin-entry"));
  let total = 0;
  let selected = 0;
  let visible = 0;

  chips.forEach((chip) => {
    const input = chip.querySelector("input[data-plugin]");
    if (!input) {
      return;
    }
    total += 1;
    const name = chip.textContent.toLowerCase();
    const options = chip.querySelector("[data-plugin-options]");
    if (options) options.hidden = !input.checked;
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
    document.querySelectorAll(`[data-tab-panel="${getActiveOs()}"] .chip input[data-plugin]:checked`),
  ).map((input) => input.dataset.plugin);
  const pluginOptions = {};
  plugins.forEach((name) => {
    const entry = Array.from(document.querySelectorAll("[data-plugin-entry]")).find(el => el.dataset.pluginEntry === name);
    const values = {};
    entry?.querySelectorAll("[data-option]").forEach((input) => {
      const type = input.dataset.optionType;
      if (type === "boolean") { if (input.checked) values[input.dataset.option] = true; return; }
      const raw = input.value.trim();
      if (!raw) return;
      if (type === "integer") {
        // Send exact text: 64-bit memory addresses exceed JavaScript's integer precision.
        values[input.dataset.option] = raw;
      } else if (type.endsWith("_list")) {
        let parsed;
        try { parsed = JSON.parse(raw); } catch { parsed = raw; }
        if (type === "integer_list" && Array.isArray(parsed) && parsed.some(value => typeof value === "number" && !Number.isSafeInteger(value))) {
          throw new Error("Use quoted decimal or hexadecimal strings for large integers in plugin lists.");
        }
        values[input.dataset.option] = parsed;
      } else { values[input.dataset.option] = raw; }
    });
    pluginOptions[name] = values;
  });
  return {

    case_id: document.getElementById("caseSelect")?.value || "",
    source_path: sourcePath?.value.trim() || "",
    output_path: outputPath?.value.trim() || "",
    symbol_path: symbolPath?.value.trim() || "",
    plugins,
    plugin_options: pluginOptions,
    offline: Boolean(offline?.checked),
    renderer: renderer?.value || "json",
  };
};

if (tooling) {
  tooling.createRunHandler({
    runButton, runStatus, apiEndpoint: "/api/volatility/run", toolName: "Volatility", buildPayload,
    onStart: () => {
      if (!buildPayload().plugins.length) throw new Error("Select at least one plugin.");
      if (runResults) runResults.hidden = true;
    },
    setRunIdRef: id => { currentRunId = id; },
    onSuccess: data => {
      commandList = data.commands;
      renderCommandPreview();
    },
  });
}

// Attach input listeners
if (tooling) {
  tooling.attachInputListeners(
    [sourcePath, outputPath, symbolPath, renderer, offline, ...document.querySelectorAll("[data-option]")],
    buildCommand,
  );
}

document.querySelectorAll(".chip input").forEach((input) => {
  input.addEventListener("change", buildCommand);
  input.addEventListener("change", filterPlugins);
});

// Tab handling
if (tabButtons.length) {
  tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      if (button.dataset.tab) {
        setActiveTab(button.dataset.tab);
      }
    });
  });
  const savedTab = localStorage.getItem("sifted.volatility.tab");
  const validTabs = tabButtons.map((b) => b.dataset.tab);
  const initialTab = savedTab && validTabs.includes(savedTab)
    ? savedTab
    : tabButtons[0].dataset.tab;
  setActiveTab(initialTab, false);
}

// Bundle buttons
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
