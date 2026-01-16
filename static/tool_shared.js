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

    const loadFullLog = async () => {
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
          status.textContent = "";
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
      loadFullLog();
    });

    if (closeButton) {
      closeButton.addEventListener("click", () => toggleDrawer(drawer, false));
    }

    return { loadFullLog };
  };

  const attachRunEvents = (runId, handlers) => {
    if (!runId || !window.EventSource) {
      return null;
    }
    const source = new EventSource(`/api/run/${runId}/events`);
    const safeHandlers = handlers || {};

    if (safeHandlers.onMilestone) {
      source.addEventListener("milestone", (event) => {
        safeHandlers.onMilestone(parsePayload(event));
      });
    }

    if (safeHandlers.onStatus) {
      source.addEventListener("status", (event) => {
        safeHandlers.onStatus(parsePayload(event));
      });
    }

    source.addEventListener("done", (event) => {
      if (safeHandlers.onDone) {
        safeHandlers.onDone(parsePayload(event));
      }
      source.close();
    });

    source.addEventListener("error", () => {
      if (safeHandlers.onError) {
        safeHandlers.onError();
      }
      source.close();
    });

    return source;
  };

  window.SiftedTooling = {
    setupBrowseDrawer,
    setupLogDrawer,
    attachRunEvents,
  };
})();
