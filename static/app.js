const initCaseContext = () => {
  const caseSelect = document.getElementById("caseSelect");
  const imagePath = document.getElementById("imagePath");
  const outputPath = document.getElementById("outputPath");
  const caseChips = Array.from(document.querySelectorAll(".chip[data-case-id]"));

  if (!caseSelect) {
    return;
  }

  let autoImage = "";
  let autoOutput = "";

  const buildDefaultOutput = (caseId) => {
    if (!caseId) {
      return "";
    }
    const selected = caseSelect.selectedOptions[0];
    const slug = selected?.dataset?.slug || caseId;
    const now = new Date();
    const stamp = now
      .toISOString()
      .replace(/[-:]/g, "")
      .slice(0, 15)
      .replace("T", "-");
    return `/cases/${slug}/${caseSelect.dataset.tool || "tool"}/${stamp}`;
  };

  const updateCaseContext = () => {
    const caseId = caseSelect.value;
    if (!caseId) {
      return;
    }
    const tool = caseSelect.dataset.tool || "tool";
    if (outputPath) {
      const nextOutput = buildDefaultOutput(caseId);
      if (!outputPath.value.trim() || outputPath.value.trim() === autoOutput) {
        outputPath.value = nextOutput;
        autoOutput = nextOutput;
      }
    }
    if (imagePath) {
      const selected = caseSelect.selectedOptions[0];
      const caseImage = selected?.dataset?.image || "";
      const current = imagePath.value.trim();
      const looksLikeOutput =
        current.includes(`/${tool}/`) || current.includes(`/outputs/${tool}/`);
      if ((!current || current === autoImage || looksLikeOutput) && caseImage) {
        imagePath.value = caseImage;
        autoImage = caseImage;
      }
    }
    const event = new Event("change", { bubbles: true });
    if (outputPath) {
      outputPath.dispatchEvent(event);
    }
    if (imagePath) {
      imagePath.dispatchEvent(event);
    }
  };

  caseSelect.addEventListener("change", updateCaseContext);

  if (imagePath) {
    imagePath.addEventListener("input", () => {
      if (imagePath.value.trim() !== autoImage) {
        autoImage = "";
      }
    });
  }

  if (outputPath) {
    outputPath.addEventListener("input", () => {
      if (outputPath.value.trim() !== autoOutput) {
        autoOutput = "";
      }
    });
  }

  caseChips.forEach((chip) => {
    chip.addEventListener("click", () => {
      caseSelect.value = chip.dataset.caseId || "";
      updateCaseContext();
    });
  });
};

initCaseContext();

const initCaseCards = () => {
  const cards = Array.from(document.querySelectorAll(".case-card.collapsible"));
  cards.forEach((card) => {
    const toggle = card.querySelector(".case-toggle");
    const label = card.querySelector(".case-toggle-label");
    if (!toggle) {
      return;
    }
    toggle.addEventListener("click", () => {
      const isOpen = card.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(isOpen));
      if (label) {
        const next = isOpen ? label.dataset.openLabel : label.dataset.closedLabel;
        if (next) {
          label.textContent = next;
        }
      }
    });
  });
};

initCaseCards();

const initContextCards = () => {
  const cards = Array.from(document.querySelectorAll(".context-card"));
  cards.forEach((card) => {
    const toggle = card.querySelector(".context-toggle");
    if (!toggle) {
      return;
    }
    toggle.addEventListener("click", () => {
      card.classList.toggle("open");
    });
  });
};

initContextCards();

// Guide cards are now handled by guides.js with modal functionality

const ACTIVE_JOBS_KEY = "sifted.activeJobs";

const loadJobs = () => {
  try {
    return JSON.parse(localStorage.getItem(ACTIVE_JOBS_KEY) || "[]");
  } catch (error) {
    return [];
  }
};

const saveJobs = (jobs) => {
  localStorage.setItem(ACTIVE_JOBS_KEY, JSON.stringify(jobs));
};

const updateJobPill = (jobs) => {
  const pill = document.getElementById("activeJobs");
  if (!pill) {
    return;
  }
  const running = jobs.filter((job) => job.status === "running");
  if (running.length === 0) {
    pill.hidden = true;
    return;
  }
  const last = running[running.length - 1];
  pill.textContent = `Active jobs: ${running.length} (${last.tool})`;
  pill.hidden = false;
};

const refreshJobs = async () => {
  const jobs = loadJobs();
  if (jobs.length === 0) {
    updateJobPill([]);
    return;
  }
  const updated = [];
  for (const job of jobs) {
    try {
      const response = await fetch(`/api/run/${job.id}/status`);
      if (!response.ok) {
        if (response.status !== 404) {
          updated.push(job);
        }
        continue;
      }
      const data = await response.json();
      const status = data.status || job.status;
      const completedAt = status === "running" ? null : Date.now();
      updated.push({
        ...job,
        status,
        completedAt: job.completedAt || completedAt,
      });
    } catch (error) {
      updated.push(job);
    }
  }
  const pruned = updated.filter((job) => {
    // Prune jobs that have been "running" for more than 1 hour (likely stale)
    if (job.status === "running" && job.startedAt) {
      const ageMs = Date.now() - job.startedAt;
      if (ageMs > 60 * 60 * 1000) {
        return false;
      }
      return true;
    }
    if (!job.completedAt) {
      return true;
    }
    return Date.now() - job.completedAt < 5 * 60 * 1000;
  });
  saveJobs(pruned);
  updateJobPill(pruned);
};

const toggleJobsDrawer = (isOpen) => {
  const drawer = document.getElementById("activeJobsDrawer");
  if (!drawer) {
    return;
  }
  drawer.classList.toggle("open", isOpen);
  drawer.setAttribute("aria-hidden", String(!isOpen));
};

const loadActiveJobs = async () => {
  const status = document.getElementById("activeJobsStatus");
  try {
    if (status) {
      status.textContent = "Loading active jobs...";
    }
    const response = await fetch("/api/runs");
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Unable to load jobs.");
    }
    const now = Date.now();
    const runs = (data.runs || []).filter((run) => {
      if (!run.created_at) {
        return false;
      }
      const created = Date.parse(run.created_at);
      if (Number.isNaN(created)) {
        return false;
      }
      // For "running" jobs, only show if less than 1 hour old (otherwise likely stale/abandoned)
      if (run.status === "running") {
        return now - created < 60 * 60 * 1000;
      }
      // For completed jobs, show if less than 5 minutes old
      return now - created < 5 * 60 * 1000;
    });
    renderJobs(runs);
    if (status) {
      status.textContent = "";
    }
  } catch (error) {
    if (status) {
      status.textContent = error.message;
    }
  }
};

const setupJobsDrawer = () => {
  const pill = document.getElementById("activeJobs");
  const closeButton = document.getElementById("closeActiveJobs");
  if (pill) {
    pill.addEventListener("click", (event) => {
      event.preventDefault();
      toggleJobsDrawer(true);
      loadActiveJobs();
    });
  }
  if (closeButton) {
    closeButton.addEventListener("click", () => toggleJobsDrawer(false));
  }
};

const jobState = {
  expanded: new Set(),
};

const fetchTail = async (runId, target) => {
  try {
    const response = await fetch(`/api/run/${runId}/tail?lines=5`);
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Unable to load output.");
    }
    target.textContent = (data.lines || []).join("");
  } catch (error) {
    target.textContent = error.message;
  }
};

const renderJobs = (runs) => {
  const list = document.getElementById("activeJobsList");
  if (!list) {
    return;
  }
  list.innerHTML = "";
  if (!runs.length) {
    list.textContent = "No active jobs.";
    return;
  }
  runs.forEach((run) => {
    const card = document.createElement("div");
    card.className = "job-card";
    card.dataset.runId = run.id;

    const header = document.createElement("div");
    header.className = "job-header";
    header.innerHTML = `<span class="job-title">${run.tool || "job"}</span><span>${run.status}</span>`;

    const caseLine = document.createElement("div");
    caseLine.className = "job-meta";
    caseLine.textContent = run.case_name ? `Case: ${run.case_name}` : "Case: none";

    const imageLine = document.createElement("div");
    imageLine.className = "job-meta";
    imageLine.textContent = run.image_path ? `Image: ${run.image_path}` : "Image: (not set)";

    const outputLine = document.createElement("div");
    outputLine.className = "job-meta";
    outputLine.textContent = run.output_path ? `Output: ${run.output_path}` : "Output: (not set)";

    const command = document.createElement("div");
    command.className = "job-command";
    command.textContent = run.command || "Command: (not set)";

    const toggle = document.createElement("button");
    toggle.className = "ghost wide job-toggle";
    toggle.type = "button";
    toggle.textContent = jobState.expanded.has(run.id)
      ? "Hide output"
      : "Show last 5 lines";

    const output = document.createElement("pre");
    output.className = "job-output";
    output.hidden = !jobState.expanded.has(run.id);

    toggle.addEventListener("click", () => {
      if (jobState.expanded.has(run.id)) {
        jobState.expanded.delete(run.id);
        output.hidden = true;
        toggle.textContent = "Show last 5 lines";
      } else {
        jobState.expanded.add(run.id);
        output.hidden = false;
        toggle.textContent = "Hide output";
        fetchTail(run.id, output);
      }
    });

    card.append(header, caseLine, imageLine, outputLine, command, toggle, output);
    list.appendChild(card);

    if (jobState.expanded.has(run.id)) {
      fetchTail(run.id, output);
    }
  });
};

window.registerActiveJob = (job) => {
  if (!job || !job.id) {
    return;
  }
  const jobs = loadJobs();
  jobs.push({
    id: job.id,
    tool: job.tool || "job",
    status: "running",
    startedAt: Date.now(),
  });
  saveJobs(jobs);
  updateJobPill(jobs);
};

refreshJobs();
setInterval(refreshJobs, 5000);
setupJobsDrawer();

setInterval(() => {
  const drawer = document.getElementById("activeJobsDrawer");
  if (drawer && drawer.classList.contains("open")) {
    loadActiveJobs();
  }
}, 5000);
