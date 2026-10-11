const tooling = window.SiftedTooling;
const common = tooling.getCommonElements();
const tool = document.querySelector('[data-carving-tool]').dataset.carvingTool;
const runButton = document.getElementById(tool === 'foremost' ? 'runForemost' : 'runScalpel');
let currentRunId = '';
const buildPayload = () => ({
  case_id: common.caseSelect?.value || '',
  source_path: common.sourcePath?.value.trim() || '',
  output_path: common.outputPath?.value.trim() || '',
  types: Array.from(document.querySelectorAll('.chip input:checked')).map(input => input.value),
  ...(tool === 'foremost' ? {
    quick: document.getElementById('quickFlag').checked,
    verbose: document.getElementById('verboseFlag').checked,
  } : { organize: document.getElementById('organizeByType').checked }),
});
const buildCommand = () => tooling.requestPreview(tool, buildPayload);
tooling.initializeDrawers({ ...common, getRunId: () => currentRunId, onSelectPath: path => {
  common.sourcePath.value = path;
  buildCommand();
} });
tooling.createRunHandler({ runButton, runStatus: common.runStatus, apiEndpoint: `/api/${tool}/run`,
  toolName: tool === 'foremost' ? 'Foremost' : 'Scalpel', buildPayload,
  setRunIdRef: id => { currentRunId = id; },
});
tooling.attachInputListeners([common.sourcePath, common.outputPath,
  document.getElementById('quickFlag'), document.getElementById('verboseFlag'),
  document.getElementById('organizeByType')], buildCommand);
tooling.attachChipListeners('.chip input', buildCommand);
buildCommand();
