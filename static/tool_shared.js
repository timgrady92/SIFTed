(() => {
  "use strict";

  const parsePayload = (event) => {
    if (!event || !event.data) {
      return {};
    }
    try {
      return JSON.parse(event.data);
    } catch (error) {
      return {};
    }
  };

  const toggleDrawer = (drawer, isOpen) => {
    if (!drawer) {
      return;
    }
    drawer.classList.toggle("open", isOpen);
    drawer.setAttribute("aria-hidden", String(!isOpen));
  };

  const setupBrowseDrawer = (options) => {
    if (!options) {
      return null;
    }
    const {
      openButton,
      closeButton,
      drawer,
      drawerList,
      drawerError,
      currentPathLabel,
      pathChips,
      manualPath,
      useManualPath,
      onSelectPath,
      initialPath = "/cases",
    } = options;

    if (!drawerList) {
      return null;
    }

    let currentPath = initialPath;

    const renderDrawer = (data) => {
      drawerList.innerHTML = "";
      if (drawerError) {
        drawerError.hidden = true;
      }
      if (currentPathLabel) {
        currentPathLabel.textContent = data.path;
      }

      if (data.parent) {
        const upButton = document.createElement("button");
        upButton.className = "drawer-item";
        upButton.dataset.type = "dir";
        upButton.dataset.path = data.parent;
        upButton.textContent = "..";
        drawerList.appendChild(upButton);
      }

      data.entries.forEach((entry) => {
        const button = document.createElement("button");
        button.className = "drawer-item";
        button.dataset.type = entry.type;
        button.dataset.path = entry.path;
        button.textContent = entry.name;
        drawerList.appendChild(button);
      });
    };

    const loadDirectory = async (path) => {
      try {
        const response = await fetch(`/api/browse?path=${encodeURIComponent(path)}`);
        if (!response.ok) {
          throw new Error("browse-failed");
        }
        const data = await response.json();
        currentPath = data.path;
        renderDrawer(data);
      } catch (error) {
        if (drawerError) {
          drawerError.hidden = false;
        }
      }
    };

    if (openButton) {
      openButton.addEventListener("click", () => {
        toggleDrawer(drawer, true);
        loadDirectory(currentPath);
      });
    }
    if (closeButton) {
      closeButton.addEventListener("click", () => toggleDrawer(drawer, false));
    }

    drawerList.addEventListener("click", (event) => {
      const target = event.target.closest(".drawer-item");
      if (!target) {
        return;
      }
      const entryPath = target.dataset.path || "";
      const entryType = target.dataset.type || "file";
      if (entryType === "dir") {
        loadDirectory(entryPath);
        return;
      }
      if (onSelectPath) {
        onSelectPath(entryPath);
      }
      toggleDrawer(drawer, false);
    });

    if (Array.isArray(pathChips)) {
      pathChips.forEach((chip) => {
        chip.addEventListener("click", () => {
          const nextPath = chip.dataset.path || "/cases";
          loadDirectory(nextPath);
        });
      });
    }

    if (useManualPath && manualPath) {
      useManualPath.addEventListener("click", () => {
        const nextPath = manualPath.value.trim();
        if (!nextPath) {
          return;
        }
        if (onSelectPath) {
          onSelectPath(nextPath);
        }
        manualPath.value = "";
        toggleDrawer(drawer, false);
      });
    }

    return {
      loadDirectory,
      getCurrentPath: () => currentPath,
      setCurrentPath: (path) => {
        currentPath = path;
      },
    };
  };

  const setupLogDrawer = (options) => {
    if (!options) {
      return null;
    }
    const { openButton, closeButton, drawer, content, status, getRunId } = options;

    if (!openButton || !drawer) {
      return null;
    }

    const loadRecentLog = async () => {
      const runId = getRunId ? getRunId() : "";
      if (!runId || !content) {
        return;
      }
      if (status) {
        status.textContent = "Loading log...";
      }
      try {
        const response = await fetch(`/api/run/${runId}/log`);
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.error || "Unable to load log.");
        }
        content.textContent = data.log || "No log output.";
        if (status) {
          status.textContent = data.truncated ? "Showing the latest 1 MiB. The complete log is saved beside the output folder." : "";
        }
      } catch (error) {
        if (status) {
          status.textContent = error.message;
        }
        if (content) {
          content.textContent = "";
        }
      }
    };

    openButton.addEventListener("click", () => {
      toggleDrawer(drawer, true);
      loadRecentLog();
    });

    if (closeButton) {
      closeButton.addEventListener("click", () => toggleDrawer(drawer, false));
    }

    return { loadRecentLog };
  };

  const attachRunEvents = (runId, handlers = {}) => {
    if (!runId) return null;
    const source = window.EventSource ? new EventSource(`/api/run/${runId}/events`) : null;
    let completed = false;
    let polling = false;
    const finish = (payload) => {
      if (completed) return;
      completed = true;
      clearInterval(timer);
      source?.close();
      const count = document.getElementById("resultCount");
      const mismatches = document.getElementById("resultMismatches");
      if (count && (payload.string_count != null || payload.file_count != null)) count.textContent = payload.string_count ?? payload.file_count;
      if (mismatches && payload.mismatch_count != null) mismatches.textContent = payload.mismatch_count;
      handlers.onDone?.(payload);
    };
    const poll = async () => {
      if (completed || polling) return;
      polling = true;
      try {
        const response = await fetch(`/api/run/${runId}/status`);
        if (!response.ok) throw new Error("Run status unavailable.");
        const run = await response.json();
        if (["success", "error", "cancelled", "interrupted"].includes(run.status)) {
          finish({ ...run, message: String(run.exit_code ?? 1) });
        } else if (run.status === "queued") {
          const health = await fetch("/api/health").then(response => response.json());
          handlers.onStatus?.({ message: health.worker?.status === "online"
            ? "Queued for execution." : "Queued; waiting for the worker to start." });
        }
      } catch (error) {
        handlers.onStatus?.({ message: "Run status unavailable; reconnecting..." });
      } finally {
        polling = false;
      }
    };
    const timer = setInterval(poll, 3000);
    source?.addEventListener("milestone", event => handlers.onMilestone?.(parsePayload(event)));
    source?.addEventListener("status", event => handlers.onStatus?.(parsePayload(event)));
    source?.addEventListener("done", event => finish(parsePayload(event)));
    source?.addEventListener("error", () => {
      handlers.onStatus?.({ message: "Reconnecting to run status..." });
      poll();
    });
    poll();
    return { close: () => { completed = true; clearInterval(timer); source?.close(); } };
  };

  const showRunResults = async (runId) => {
    const panel = document.getElementById("runResults");
    const links = document.getElementById("runResultsLinks");
    if (!panel || !links) return;
    links.replaceChildren();
    panel.hidden = true;
    try {
      const response = await fetch(`/api/run/${runId}/results`);
      if (!response.ok) throw new Error("Unable to load result files.");
      const data = await response.json();
      for (const item of data.files || []) {
        const link = document.createElement("a");
        link.className = "run-result-link";
        link.href = `/view-file?path=${encodeURIComponent(item.path)}`;
        link.textContent = item.name;
        links.append(link);
      }
      if (data.truncated) {
        const note = document.createElement("span");
        note.textContent = "More files are available in the case results.";
        links.append(note);
      }
      panel.hidden = !links.childElementCount;
    } catch (error) {
      links.textContent = error.message;
      panel.hidden = false;
    }
  };

  // --- Status Message Constants ---
  const RUN_MESSAGES = {
    RUNNING: "Running...",
    COMPLETED: "Run completed.",
    COMPLETED_ERRORS: "Run completed with errors.",
    FAILED: "Run failed.",
    STARTED_REFRESH: "Run started. Refresh to see results.",
  };

  // --- Common DOM Element Helpers ---
  const getCommonElements = () => ({
    openBrowser: document.getElementById("openBrowser"),
    closeBrowser: document.getElementById("closeBrowser"),
    browserDrawer: document.getElementById("browserDrawer"),
    manualPath: document.getElementById("manualPath"),
    useManualPath: document.getElementById("useManualPath"),
    drawerList: document.getElementById("drawerList"),
    drawerError: document.getElementById("drawerError"),
    currentPathLabel: document.getElementById("currentPath"),
    pathChips: Array.from(document.querySelectorAll(".path-chip")),
    openLog: document.getElementById("openLog"),
    closeLog: document.getElementById("closeLog"),
    logDrawer: document.getElementById("logDrawer"),
    logDrawerContent: document.getElementById("logDrawerContent"),
    logDrawerStatus: document.getElementById("logDrawerStatus"),
    caseSelect: document.getElementById("caseSelect"),
    sourcePath: document.getElementById("sourcePath"),
    outputPath: document.getElementById("outputPath"),
    commandPreview: document.getElementById("commandPreview"),
    runStatus: document.getElementById("runStatus"),
  });

  // --- Set Run Status Helper ---
  const setRunStatus = (statusElement, message, tone) => {
    if (!statusElement) {
      return;
    }
    statusElement.textContent = message;
    statusElement.dataset.tone = tone || "neutral";
  };

  // --- Completion Status Helper ---
  const getCompletionStatus = (exitCode) => ({
    message: exitCode === 0 ? RUN_MESSAGES.COMPLETED : RUN_MESSAGES.COMPLETED_ERRORS,
    tone: exitCode === 0 ? "success" : "error",
  });

  const previewRequests = new Map();
  const requestPreview = (toolId, buildPayload, onResult) => {
    const previous = previewRequests.get(toolId);
    if (previous) {
      clearTimeout(previous.timer);
      previous.controller.abort();
    }
    const state = { controller: new AbortController(), timer: null };
    previewRequests.set(toolId, state);
    state.timer = setTimeout(async () => {
      const element = document.getElementById("commandPreview");
      try {
        const response = await fetch(`/api/${toolId}/preview`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(buildPayload()),
          signal: state.controller.signal,
        });
        const data = await response.json();
        if (previewRequests.get(toolId) !== state) return;
        if (!response.ok) throw new Error(data.error || "Unable to preview command.");
        if (element) {
          element.textContent = data.command;
          element.title = data.preview_note || "";
          let note = document.getElementById("commandPreviewNote");
          if (!note) {
            note = document.createElement("p");
            note.id = "commandPreviewNote";
            note.className = "helper";
            element.after(note);
          }
          note.textContent = data.preview_note || "";
        }
        if (onResult) onResult(data);
      } catch (error) {
        if (error.name !== "AbortError" && previewRequests.get(toolId) === state && element) {
          element.textContent = error.message;
        }
      }
    }, 150);
  };

  // --- Input Listener Helper ---
  const attachInputListeners = (elements, callback) => {
    elements.forEach((input) => {
      if (!input) {
        return;
      }
      input.addEventListener("input", callback);
      input.addEventListener("change", callback);
    });
  };

  // --- Chip Listener Helper ---
  const attachChipListeners = (selector, callback) => {
    document.querySelectorAll(selector || ".chip input").forEach((input) => {
      input.addEventListener("change", callback);
    });
  };

  // --- Initialize Standard Drawers ---
  const initializeDrawers = (config) => {
    const tooling = window.SiftedTooling;
    if (!tooling) {
      return null;
    }

    const result = {};

    if (config.logDrawer) {
      result.logDrawer = tooling.setupLogDrawer({
        openButton: config.openLog,
        closeButton: config.closeLog,
        drawer: config.logDrawer,
        content: config.logDrawerContent,
        status: config.logDrawerStatus,
        getRunId: config.getRunId,
      });
    }

    if (config.browserDrawer) {
      result.browseDrawer = tooling.setupBrowseDrawer({
        openButton: config.openBrowser,
        closeButton: config.closeBrowser,
        drawer: config.browserDrawer,
        drawerList: config.drawerList,
        drawerError: config.drawerError,
        currentPathLabel: config.currentPathLabel,
        pathChips: config.pathChips,
        manualPath: config.manualPath,
        useManualPath: config.useManualPath,
        onSelectPath: config.onSelectPath,
      });
    }

    return result;
  };

  // --- Run Button Handler Factory ---
  const createRunHandler = (config) => {
    const {
      runButton,
      runStatus,
      apiEndpoint,
      toolName,
      buildPayload,
      onStart,
      onSuccess,
      onRunIdReceived,
      setRunIdRef,
    } = config;

    if (!runButton) {
      return null;
    }

    const defaultLabel =
      runButton.dataset.defaultLabel || runButton.textContent || `Run ${toolName}`;
    runButton.dataset.defaultLabel = defaultLabel;

    const resetRunButton = () => {
      runButton.textContent = runButton.dataset.defaultLabel || defaultLabel;
      runButton.disabled = false;
    };

    const handler = async () => {
      runButton.disabled = true;
      for (const id of ["resultCount", "resultMismatches"]) {
        const metric = document.getElementById(id);
        if (metric) metric.textContent = "—";
      }
      const resultsPanel = document.getElementById("runResults");
      if (resultsPanel) resultsPanel.hidden = true;
      runButton.textContent = "Submitting...";
      setRunStatus(runStatus, `Submitting ${toolName}...`, "neutral");

      try {
        if (onStart) {
          await onStart();
        }
        const response = await fetch(apiEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(buildPayload()),
        });
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.error || `Unable to run ${toolName}.`);
        }

        if (onSuccess) {
          onSuccess(data);
        }

        const runId = data.run_id || "";
        if (setRunIdRef) {
          setRunIdRef(runId);
        }
        if (onRunIdReceived) {
          onRunIdReceived(runId, data);
        }

        if (runId && window.registerActiveJob) {
          window.registerActiveJob({ id: runId, tool: toolName });
        }

        runButton.textContent = "In progress...";
        setRunStatus(runStatus, "Queued for execution.", "neutral");

        if (runId) {
          window.SiftedTooling.attachRunEvents(runId, {
            onMilestone: config.onMilestone,
            onStatus: (payload) => {
              setRunStatus(runStatus, payload.message || RUN_MESSAGES.RUNNING, "neutral");
            },
            onDone: (payload) => {
              const exitCode = Number(payload.message || 0);
              const { message, tone } = getCompletionStatus(exitCode);
              setRunStatus(runStatus, payload.error || message, tone);
              showRunResults(runId);
              config.onDone?.(payload);
              resetRunButton();
            },
          });
        } else {
          setRunStatus(runStatus, RUN_MESSAGES.STARTED_REFRESH, "neutral");
          resetRunButton();
        }
      } catch (error) {
        setRunStatus(runStatus, error.message || RUN_MESSAGES.FAILED, "error");
        resetRunButton();
      }
    };

    runButton.addEventListener("click", handler);
    return handler;
  };

  window.SiftedTooling = {
    setupBrowseDrawer,
    setupLogDrawer,
    attachRunEvents,
    // New helpers
    RUN_MESSAGES,
    getCommonElements,
    setRunStatus,
    getCompletionStatus,
    attachInputListeners,
    attachChipListeners,
    initializeDrawers,
    createRunHandler,
    requestPreview,
    showRunResults,
  };
})();
