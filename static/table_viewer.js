/**
 * Table Viewer - Interactive table features for file viewer
 * Features: Column sorting, column visibility toggle, virtual scrolling,
 *           global search, column-specific filtering, CSV export
 */

(function () {
  "use strict";

  const viewerPath = document.getElementById("viewerPath");
  const copyViewerPath = document.getElementById("copyViewerPath");
  const tableWrap = document.getElementById("tableWrap");
  const dataTable = document.getElementById("dataTable");
  const tableBody = document.getElementById("tableBody");
  const tableLoading = document.getElementById("tableLoading");
  const columnToggleBtn = document.getElementById("columnToggleBtn");
  const columnDropdown = document.getElementById("columnDropdown");
  const columnDropdownClose = document.getElementById("columnDropdownClose");
  const columnDropdownList = document.getElementById("columnDropdownList");
  const columnSearch = document.getElementById("columnSearch");
  const columnShowAll = document.getElementById("columnShowAll");
  const columnHideAll = document.getElementById("columnHideAll");
  const rowCountSpan = document.getElementById("rowCount");
  const columnCountSpan = document.getElementById("columnCount");

  // New elements for search/filter/export
  const globalSearchInput = document.getElementById("globalSearch");
  const clearSearchBtn = document.getElementById("clearSearch");
  const filterCountSpan = document.getElementById("filterCount");
  const columnFilterBtn = document.getElementById("columnFilterBtn");
  const columnFiltersPanel = document.getElementById("columnFiltersPanel");
  const columnFiltersClose = document.getElementById("columnFiltersClose");
  const columnFiltersList = document.getElementById("columnFiltersList");
  const clearAllFiltersBtn = document.getElementById("clearAllFilters");
  const applyFiltersBtn = document.getElementById("applyFilters");
  const exportCsvBtn = document.getElementById("exportCsvBtn");

  function setupPathCopy() {
    if (!viewerPath || !copyViewerPath) return;
    copyViewerPath.addEventListener("click", async () => {
      const text = viewerPath.textContent || "";
      if (!text) return;
      try {
        if (navigator.clipboard && window.isSecureContext) {
          await navigator.clipboard.writeText(text);
        } else {
          fallbackCopy(text);
        }
        copyViewerPath.textContent = "Copied";
        setTimeout(() => {
          copyViewerPath.textContent = "Copy path";
        }, 1500);
      } catch (err) {
        console.error("Failed to copy path:", err);
      }
    });
  }

  function fallbackCopy(text) {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "absolute";
    textarea.style.left = "-9999px";
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    document.body.removeChild(textarea);
  }

  setupPathCopy();

  if (!tableWrap || !dataTable) return;

  const filePath = tableWrap.dataset.filePath;
  const totalRows = parseInt(tableWrap.dataset.totalRows, 10) || 0;
  const initialRows = parseInt(tableWrap.dataset.initialRows, 10) || 0;

  // Virtual scroll state
  let loadedRows = initialRows;
  let isLoading = false;
  let hasMore = loadedRows < totalRows;
  const BATCH_SIZE = 50;
  const SCROLL_THRESHOLD = 200;

  // Sort state
  let currentSortCol = null;
  let currentSortDir = "none";

  // All rows data (for client-side sorting/filtering after loading)
  let allRowsData = [];
  let filteredRowsData = [];

  // Filter state
  let globalSearchTerm = "";
  let columnFilters = {}; // { colIndex: { operator: 'contains', value: 'search' } }
  let isFiltered = false;

  // Column names for filter labels
  let columnNames = [];

  // Initialize: capture initial rows data and column names
  function initRowsData() {
    const headers = dataTable.querySelectorAll("thead th");
    headers.forEach((th) => {
      const label = th.querySelector(".th-label");
      columnNames.push(label ? label.textContent : "");
    });

    const rows = tableBody.querySelectorAll("tr");
    rows.forEach((row) => {
      const cells = row.querySelectorAll("td");
      const rowData = [];
      cells.forEach((cell) => rowData.push(cell.textContent));
      allRowsData.push(rowData);
    });
    filteredRowsData = [...allRowsData];
  }

  // ==================== COLUMN SORTING ====================

  function setupSorting() {
    const headers = dataTable.querySelectorAll("thead th");
    headers.forEach((th) => {
      th.style.cursor = "pointer";
      th.addEventListener("click", () => handleSort(th));
    });
  }

  function handleSort(th) {
    const colIndex = parseInt(th.dataset.colIndex, 10);
    const currentSort = th.dataset.sort;

    // Reset all other headers
    const allHeaders = dataTable.querySelectorAll("thead th");
    allHeaders.forEach((header) => {
      if (header !== th) {
        header.dataset.sort = "none";
      }
    });

    // Toggle sort direction: none -> asc -> desc -> none
    let newSort;
    if (currentSort === "none") {
      newSort = "asc";
    } else if (currentSort === "asc") {
      newSort = "desc";
    } else {
      newSort = "none";
    }

    th.dataset.sort = newSort;
    currentSortCol = newSort === "none" ? null : colIndex;
    currentSortDir = newSort;

    sortAndRender();
  }

  function sortData(data, colIndex, direction) {
    if (direction === "none" || colIndex === null) {
      return data;
    }

    return [...data].sort((a, b) => {
      const valA = a[colIndex] || "";
      const valB = b[colIndex] || "";

      // Try numeric comparison first
      const numA = parseFloat(valA);
      const numB = parseFloat(valB);

      if (!isNaN(numA) && !isNaN(numB)) {
        return direction === "asc" ? numA - numB : numB - numA;
      }

      // Fall back to string comparison
      const strA = valA.toLowerCase();
      const strB = valB.toLowerCase();

      if (strA < strB) return direction === "asc" ? -1 : 1;
      if (strA > strB) return direction === "asc" ? 1 : -1;
      return 0;
    });
  }

  function sortAndRender() {
    const dataToSort = isFiltered ? filteredRowsData : allRowsData;
    const sortedData = sortData(dataToSort, currentSortCol, currentSortDir);
    renderRows(sortedData);
  }

  function renderRows(rowsData, highlightTerm = "") {
    const hiddenCols = getHiddenColumns();
    tableBody.innerHTML = "";

    rowsData.forEach((row) => {
      const tr = document.createElement("tr");
      row.forEach((cell, idx) => {
        const td = document.createElement("td");
        td.dataset.colIndex = idx;

        // Highlight search matches if there's a search term
        if (highlightTerm && cell) {
          td.innerHTML = highlightMatches(cell, highlightTerm);
        } else {
          td.textContent = cell;
        }

        if (hiddenCols.has(idx)) {
          td.hidden = true;
        }
        tr.appendChild(td);
      });
      tableBody.appendChild(tr);
    });
    updateRowCountDisplay();
    updateColumnCount();
    updateColumnToggleLabel();
  }

  function highlightMatches(text, term) {
    if (!term) return escapeHtml(text);
    const escaped = escapeHtml(text);
    const regex = new RegExp(`(${escapeRegex(term)})`, 'gi');
    return escaped.replace(regex, '<span class="search-match">$1</span>');
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  // ==================== GLOBAL SEARCH ====================

  function setupGlobalSearch() {
    if (!globalSearchInput) return;

    let debounceTimeout;
    globalSearchInput.addEventListener("input", (e) => {
      clearTimeout(debounceTimeout);
      debounceTimeout = setTimeout(() => {
        globalSearchTerm = e.target.value.trim().toLowerCase();
        applyAllFilters();

        // Show/hide clear button
        if (clearSearchBtn) {
          clearSearchBtn.hidden = !globalSearchTerm;
        }
      }, 150);
    });

    if (clearSearchBtn) {
      clearSearchBtn.addEventListener("click", () => {
        globalSearchInput.value = "";
        globalSearchTerm = "";
        clearSearchBtn.hidden = true;
        applyAllFilters();
      });
    }
  }

  // ==================== COLUMN FILTERING ====================

  function setupColumnFilters() {
    if (!columnFilterBtn || !columnFiltersPanel) return;

    columnFilterBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      columnFiltersPanel.hidden = !columnFiltersPanel.hidden;
      if (!columnFiltersPanel.hidden) {
        buildColumnFilterUI();
      }
    });

    if (columnFiltersClose) {
      columnFiltersClose.addEventListener("click", () => {
        columnFiltersPanel.hidden = true;
      });
    }

    if (clearAllFiltersBtn) {
      clearAllFiltersBtn.addEventListener("click", () => {
        columnFilters = {};
        globalSearchTerm = "";
        if (globalSearchInput) globalSearchInput.value = "";
        if (clearSearchBtn) clearSearchBtn.hidden = true;
        buildColumnFilterUI();
        applyAllFilters();
      });
    }

    if (applyFiltersBtn) {
      applyFiltersBtn.addEventListener("click", () => {
        collectColumnFilters();
        applyAllFilters();
        columnFiltersPanel.hidden = true;
      });
    }

    // Close on outside click
    document.addEventListener("click", (e) => {
      if (columnFiltersPanel && !columnFiltersPanel.hidden &&
          !columnFiltersPanel.contains(e.target) &&
          e.target !== columnFilterBtn) {
        columnFiltersPanel.hidden = true;
      }
    });
  }

  function buildColumnFilterUI() {
    if (!columnFiltersList) return;
    columnFiltersList.innerHTML = "";

    columnNames.forEach((name, idx) => {
      if (!name) return;

      const existing = columnFilters[idx] || { operator: "contains", value: "" };
      const isActive = existing.value.trim() !== "";

      const item = document.createElement("div");
      item.className = "column-filter-item" + (isActive ? " active" : "");
      item.innerHTML = `
        <label>${escapeHtml(name)}</label>
        <div style="display: flex; gap: 6px;">
          <select data-col="${idx}" class="filter-operator" style="width: 100px;">
            <option value="contains" ${existing.operator === "contains" ? "selected" : ""}>Contains</option>
            <option value="equals" ${existing.operator === "equals" ? "selected" : ""}>Equals</option>
            <option value="starts" ${existing.operator === "starts" ? "selected" : ""}>Starts with</option>
            <option value="ends" ${existing.operator === "ends" ? "selected" : ""}>Ends with</option>
            <option value="gt" ${existing.operator === "gt" ? "selected" : ""}>&gt; (greater)</option>
            <option value="lt" ${existing.operator === "lt" ? "selected" : ""}>&lt; (less)</option>
            <option value="empty" ${existing.operator === "empty" ? "selected" : ""}>Is empty</option>
            <option value="notempty" ${existing.operator === "notempty" ? "selected" : ""}>Not empty</option>
          </select>
          <input type="text" data-col="${idx}" class="filter-value" value="${escapeHtml(existing.value)}" placeholder="Filter value..." style="flex: 1;" />
        </div>
      `;
      columnFiltersList.appendChild(item);
    });
  }

  function collectColumnFilters() {
    columnFilters = {};
    if (!columnFiltersList) return;

    const operators = columnFiltersList.querySelectorAll(".filter-operator");
    const values = columnFiltersList.querySelectorAll(".filter-value");

    operators.forEach((select) => {
      const colIdx = parseInt(select.dataset.col, 10);
      const operator = select.value;
      const valueInput = columnFiltersList.querySelector(`.filter-value[data-col="${colIdx}"]`);
      const value = valueInput ? valueInput.value.trim() : "";

      // Only add filter if there's a value (unless operator is empty/notempty)
      if (value || operator === "empty" || operator === "notempty") {
        columnFilters[colIdx] = { operator, value };
      }
    });
  }

  function applyAllFilters() {
    // Start with all data
    let result = [...allRowsData];

    // Apply global search
    if (globalSearchTerm) {
      result = result.filter(row => {
        return row.some(cell =>
          (cell || "").toLowerCase().includes(globalSearchTerm)
        );
      });
    }

    // Apply column filters
    Object.entries(columnFilters).forEach(([colIdx, filter]) => {
      const idx = parseInt(colIdx, 10);
      result = result.filter(row => {
        const cellValue = (row[idx] || "").toLowerCase();
        const filterValue = filter.value.toLowerCase();

        switch (filter.operator) {
          case "contains":
            return cellValue.includes(filterValue);
          case "equals":
            return cellValue === filterValue;
          case "starts":
            return cellValue.startsWith(filterValue);
          case "ends":
            return cellValue.endsWith(filterValue);
          case "gt":
            const numA = parseFloat(row[idx]);
            const numFilterA = parseFloat(filter.value);
            return !isNaN(numA) && !isNaN(numFilterA) && numA > numFilterA;
          case "lt":
            const numB = parseFloat(row[idx]);
            const numFilterB = parseFloat(filter.value);
            return !isNaN(numB) && !isNaN(numFilterB) && numB < numFilterB;
          case "empty":
            return !row[idx] || row[idx].trim() === "";
          case "notempty":
            return row[idx] && row[idx].trim() !== "";
          default:
            return true;
        }
      });
    });

    filteredRowsData = result;
    isFiltered = globalSearchTerm || Object.keys(columnFilters).length > 0;

    // Re-apply sorting
    const dataToRender = sortData(filteredRowsData, currentSortCol, currentSortDir);
    renderRows(dataToRender, globalSearchTerm);

    updateFilterCount();
  }

  function updateFilterCount() {
    if (!filterCountSpan) return;

    const activeFilters = Object.keys(columnFilters).length + (globalSearchTerm ? 1 : 0);

    if (isFiltered) {
      filterCountSpan.hidden = false;
      filterCountSpan.textContent = `${filteredRowsData.length} of ${allRowsData.length} rows (${activeFilters} filter${activeFilters !== 1 ? 's' : ''} active)`;
    } else {
      filterCountSpan.hidden = true;
    }
  }

  function updateRowCountDisplay() {
    if (!rowCountSpan) return;

    if (isFiltered) {
      rowCountSpan.textContent = `${filteredRowsData.length} rows (filtered)`;
    } else if (loadedRows >= totalRows) {
      rowCountSpan.textContent = `${totalRows} rows`;
    } else {
      rowCountSpan.textContent = `Showing ${loadedRows} of ${totalRows} rows (scroll for more)`;
    }
  }

  // ==================== CSV EXPORT ====================

  function setupExport() {
    if (!exportCsvBtn) return;

    exportCsvBtn.addEventListener("click", () => {
      exportToCsv();
    });
  }

  function exportToCsv() {
    const visibleCols = [];
    const hiddenCols = getHiddenColumns();

    columnNames.forEach((name, idx) => {
      if (!hiddenCols.has(idx)) {
        visibleCols.push({ name, idx });
      }
    });

    // Use filtered data if filtering is active
    const dataToExport = isFiltered ? filteredRowsData : allRowsData;

    // Build CSV content
    const lines = [];

    // Header row
    lines.push(visibleCols.map(col => csvEscape(col.name)).join(","));

    // Data rows
    dataToExport.forEach(row => {
      const values = visibleCols.map(col => csvEscape(row[col.idx] || ""));
      lines.push(values.join(","));
    });

    const csvContent = lines.join("\n");

    // Download
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const link = document.createElement("a");
    const fileName = filePath ? filePath.split("/").pop().replace(/\.[^.]+$/, "") + "_export.csv" : "export.csv";

    link.href = URL.createObjectURL(blob);
    link.download = fileName;
    link.style.display = "none";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
  }

  function csvEscape(value) {
    if (value === null || value === undefined) return "";
    const str = String(value);
    if (str.includes(",") || str.includes('"') || str.includes("\n") || str.includes("\r")) {
      return '"' + str.replace(/"/g, '""') + '"';
    }
    return str;
  }

  // ==================== COLUMN VISIBILITY ====================

  function setupColumnToggle() {
    if (!columnToggleBtn || !columnDropdown) return;

    columnToggleBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      columnDropdown.hidden = !columnDropdown.hidden;
      if (!columnDropdown.hidden && columnSearch) {
        columnSearch.focus();
        columnSearch.select();
      }
    });

    if (columnDropdownClose) {
      columnDropdownClose.addEventListener("click", () => {
        columnDropdown.hidden = true;
      });
    }

    // Close dropdown when clicking outside
    document.addEventListener("click", (e) => {
      if (!columnDropdown.contains(e.target) && e.target !== columnToggleBtn) {
        columnDropdown.hidden = true;
      }
    });

    // Handle checkbox changes
    if (columnDropdownList) {
      columnDropdownList.addEventListener("change", (e) => {
        if (e.target.type === "checkbox") {
          const colIndex = parseInt(e.target.dataset.colIndex, 10);
          toggleColumn(colIndex, e.target.checked);
          updateColumnCount();
          updateColumnToggleLabel();
        }
      });
    }

    if (columnSearch) {
      columnSearch.addEventListener("input", (e) => {
        filterColumnList(e.target.value);
      });
    }

    if (columnShowAll) {
      columnShowAll.addEventListener("click", () => {
        setAllColumns(true);
      });
    }

    if (columnHideAll) {
      columnHideAll.addEventListener("click", () => {
        setAllColumns(false);
      });
    }
  }

  function toggleColumn(colIndex, visible) {
    // Toggle header
    const th = dataTable.querySelector(`thead th[data-col-index="${colIndex}"]`);
    if (th) th.hidden = !visible;

    // Toggle all cells in that column
    const cells = dataTable.querySelectorAll(`td[data-col-index="${colIndex}"]`);
    cells.forEach((cell) => {
      cell.hidden = !visible;
    });
  }

  function setAllColumns(visible) {
    if (!columnDropdownList) return;
    const checkboxes = columnDropdownList.querySelectorAll('input[type="checkbox"]');
    checkboxes.forEach((cb) => {
      const colIndex = parseInt(cb.dataset.colIndex, 10);
      cb.checked = visible;
      toggleColumn(colIndex, visible);
    });
    updateColumnCount();
    updateColumnToggleLabel();
  }

  function filterColumnList(rawQuery) {
    if (!columnDropdownList) return;
    const query = rawQuery.trim().toLowerCase();
    const items = columnDropdownList.querySelectorAll(".column-toggle-item");
    items.forEach((item) => {
      const label = item.querySelector("span");
      const text = label ? label.textContent.toLowerCase() : "";
      item.hidden = query.length > 0 && !text.includes(query);
    });
  }

  function getHiddenColumns() {
    const hidden = new Set();
    if (columnDropdownList) {
      const checkboxes = columnDropdownList.querySelectorAll('input[type="checkbox"]');
      checkboxes.forEach((cb) => {
        if (!cb.checked) {
          hidden.add(parseInt(cb.dataset.colIndex, 10));
        }
      });
    }
    return hidden;
  }

  function updateColumnCount() {
    if (!columnCountSpan || !dataTable) return;
    const totalCols = dataTable.querySelectorAll("thead th").length;
    const hiddenCols = getHiddenColumns();
    const visibleCols = Math.max(totalCols - hiddenCols.size, 0);
    columnCountSpan.textContent = `${visibleCols} of ${totalCols} columns`;
  }

  function updateColumnToggleLabel() {
    if (!columnToggleBtn || !dataTable) return;
    const totalCols = dataTable.querySelectorAll("thead th").length;
    const hiddenCount = getHiddenColumns().size;
    const suffix = hiddenCount > 0 ? ` (${hiddenCount} hidden)` : "";
    columnToggleBtn.textContent = `Filter Columns${suffix}`;
  }

  // ==================== VIRTUAL SCROLLING ====================

  function setupVirtualScroll() {
    if (!hasMore) return;

    tableWrap.addEventListener("scroll", handleScroll);
  }

  function handleScroll() {
    if (isLoading || !hasMore) return;

    const { scrollTop, scrollHeight, clientHeight } = tableWrap;
    const distanceFromBottom = scrollHeight - scrollTop - clientHeight;

    if (distanceFromBottom < SCROLL_THRESHOLD) {
      loadMoreRows();
    }
  }

  async function loadMoreRows() {
    if (isLoading || !hasMore) return;

    isLoading = true;
    if (tableLoading) tableLoading.hidden = false;

    try {
      const params = new URLSearchParams({
        path: filePath,
        offset: loadedRows,
        limit: BATCH_SIZE,
      });

      const response = await fetch(`/api/table-rows?${params}`);
      if (!response.ok) {
        throw new Error("Failed to load rows");
      }

      const data = await response.json();

      if (data.error) {
        console.error("Error loading rows:", data.error);
        hasMore = false;
        return;
      }

      // Append new rows to allRowsData
      data.rows.forEach((row) => {
        allRowsData.push(row);
      });

      loadedRows += data.rows.length;
      hasMore = data.has_more;

      // Re-apply filters and sorting
      applyAllFilters();

    } catch (err) {
      console.error("Error loading more rows:", err);
    } finally {
      isLoading = false;
      if (tableLoading) tableLoading.hidden = true;
    }
  }

  // ==================== INITIALIZATION ====================

  function init() {
    initRowsData();
    setupSorting();
    setupColumnToggle();
    setupVirtualScroll();
    setupGlobalSearch();
    setupColumnFilters();
    setupExport();
    updateColumnCount();
    updateColumnToggleLabel();
  }

  // Run on DOM ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
