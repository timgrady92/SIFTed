(() => {
  "use strict";
  const workspace = document.querySelector("[data-workspace-api]");
  const status = document.getElementById("workspaceUpdates");
  if (!workspace || !status) return;
  const refresh = document.getElementById("refreshWorkspace");
  refresh.addEventListener("click", () => window.location.reload());
  let baseline = null;
  let pending = false;
  const check = async () => {
    if (document.hidden || pending) return;
    pending = true;
    try {
      const response = await fetch(workspace.dataset.workspaceApi);
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Workspace updates unavailable.");
      const current = JSON.stringify(data.runs.map(run => [run.id, run.status]));
      if (baseline !== null && current !== baseline) {
        status.textContent = "Work has changed. Refresh to see updated results and available evidence.";
      }
      baseline = current;
    } catch (error) {
      status.textContent = error.message;
    } finally {
      pending = false;
    }
  };
  check();
  setInterval(check, 10000);
})();
