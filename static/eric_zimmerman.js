const tooling = window.SiftedTooling;
const common = tooling.getCommonElements();
const toolData = JSON.parse(document.getElementById('ezToolData').textContent);
const toolsById = Object.fromEntries(toolData.map(tool => [tool.id, tool]));
const buttons = Array.from(document.querySelectorAll('.ez-tool-card'));
const runButton = document.getElementById('runEzTool');
const optionsPane = document.getElementById('ezToolOptions');
let selectedToolId = '';
let currentRunId = '';

const buildPayload = () => {
  const payload = {
    tool_id: selectedToolId,
    case_id: common.caseSelect?.value || '',
    source_path: common.sourcePath.value.trim(),
    output_path: common.outputPath.value.trim(),
  };
  for (const input of optionsPane.querySelectorAll('[data-parser-option]')) {
    payload[input.dataset.parserOption] = input.multiple ? Array.from(input.selectedOptions, option => option.value)
      : input.type === 'checkbox' ? input.checked : input.value;
  }
  return payload;
};
const buildCommand = () => tooling.requestPreview('eric-zimmerman', buildPayload);
const selectTool = id => {
  const tool = toolsById[id];
  selectedToolId = id;
  for (const button of buttons) button.classList.toggle('active', button.dataset.toolId === id);
  document.getElementById('ezToolName').textContent = tool.label;
  document.getElementById('ezToolDescription').textContent = tool.description;
  document.getElementById('ezToolHint').textContent = tool.input_hint;
  document.getElementById('ezToolOutput').textContent = tool.export_summary;
  document.getElementById('ezToolStatus').textContent = tool.installed ? `Available · ${tool.version}` : tool.error;
  runButton.textContent = `Run ${tool.label}`;
  runButton.dataset.defaultLabel = runButton.textContent;
  runButton.disabled = !tool.installed;
  optionsPane.replaceChildren();
  if (Object.keys(tool.rejected_maps).length) {
    const warning = document.createElement('p');
    warning.className = 'helper';
    warning.textContent = 'Unavailable maps: ' + Object.entries(tool.rejected_maps).map(([name, reason]) => `${name}: ${reason}`).join('; ');
    optionsPane.append(warning);
  }
  for (const field of tool.options) {
    const label = document.createElement('label');
    label.className = field.type === 'checkbox' ? 'checkbox' : 'field';
    const input = document.createElement(['select', 'multiselect'].includes(field.type) ? 'select' : 'input');
    input.dataset.parserOption = field.name;
    if (['select', 'multiselect'].includes(field.type)) {
      input.multiple = field.type === 'multiselect';
      for (const choice of field.choices) {
        const option = document.createElement('option');
        option.value = option.textContent = choice;
        input.append(option);
      }
      if (!input.multiple) input.value = field.default;
    } else {
      input.type = 'checkbox';
      input.checked = field.default;
    }
    const title = document.createElement('span');
    title.textContent = field.label;
    label.append(input, title);
    optionsPane.append(label);
    if (field.help) {
      const help = document.createElement('p');
      help.className = 'helper';
      help.textContent = field.help;
      optionsPane.append(help);
    }
    input.addEventListener('change', buildCommand);
  }
  document.getElementById('runResults').hidden = true;
  tooling.setRunStatus(common.runStatus, tool.installed ? 'Ready to run.' : tool.error, tool.installed ? 'neutral' : 'error');
  if (common.caseSelect) {
    common.caseSelect.dataset.tool = `eric-zimmerman/${id}`;
    common.caseSelect.dispatchEvent(new Event('change', { bubbles: true }));
  }
  buildCommand();
};
for (const button of buttons) button.addEventListener('click', () => selectTool(button.dataset.toolId));
tooling.initializeDrawers({ ...common, getRunId: () => currentRunId, onSelectPath: path => {
  common.sourcePath.value = path;
  buildCommand();
} });
tooling.createRunHandler({ runButton, runStatus: common.runStatus, apiEndpoint: '/api/eric-zimmerman/run',
  toolName: 'parser', buildPayload, setRunIdRef: id => { currentRunId = id; },
  onStart: () => { if (!toolsById[selectedToolId]?.installed) throw new Error('Select an available parser.'); },
});
tooling.attachInputListeners([common.sourcePath, common.outputPath, common.caseSelect], buildCommand);
const requestedParser = new URLSearchParams(window.location.search).get('tool_id');
if (toolData.length) selectTool(toolsById[requestedParser] ? requestedParser : (toolData.find(tool => tool.installed) || toolData[0]).id);
