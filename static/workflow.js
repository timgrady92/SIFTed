(() => {
  "use strict";
  const tooling = window.SiftedTooling;
  const common = tooling.getCommonElements();
  const tool = document.body.dataset.workflow;
  const fields = [...document.querySelectorAll("[data-parameter]")];
  let currentRunId = "";
  const buildPayload = () => {
    const data = {case_id: common.caseSelect?.value || "", source_path: common.sourcePath?.value.trim() || "", output_path: common.outputPath?.value.trim() || ""};
    for (const field of fields) {
      if (field.type === "checkbox") data[field.dataset.parameter] = field.checked;
      else if (field.value !== "") {
        const numeric = field.type === "number" || field.dataset.parameter === "sector_size";
        data[field.dataset.parameter] = numeric ? Number(field.value) : field.value;
      }
    }
    const query = new URLSearchParams(window.location.search);
    const context = query.get("context_run_id");
    if (context && data.source_path === query.get("source_path") && data.case_id === query.get("case_id")) {
      data.context_run_id = context;
      if (query.has("entry_id")) data.entry_id = Number(query.get("entry_id"));
    }
    return data;
  };
  const preview = () => tooling.requestPreview(tool, buildPayload);
  tooling.initializeDrawers({...common, getRunId: () => currentRunId, onSelectPath: path => {common.sourcePath.value = path; preview();}});
  tooling.createRunHandler({runButton: document.getElementById("runWorkflow"), runStatus: common.runStatus,
    apiEndpoint: `/api/${tool}/run`, toolName: tool, buildPayload,
    setRunIdRef: id => {currentRunId = id;},
  });
  const query = new URLSearchParams(window.location.search);
  for (const field of fields) if (query.has(field.dataset.parameter)) {
    if (field.type === "checkbox") field.checked = query.get(field.dataset.parameter) === "true";
    else field.value = query.get(field.dataset.parameter);
  }
  tooling.attachInputListeners([common.sourcePath, common.outputPath, common.caseSelect, ...fields], preview);
  preview();
})();
