/**
 * Table Viewer - Interactive table features for file viewer
 * Features: Column sorting, column visibility toggle, virtual scrolling
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

  // All rows data (for client-side sorting after loading)
  let allRowsData = [];

  // Initialize: capture initial rows data
  function initRowsData() {
    const rows = tableBody.querySelectorAll("tr");
    rows.forEach((row) => {
      const cells = row.querySelectorAll("td");
      const rowData = [];
      cells.forEach((cell) => rowData.push(cell.textContent));
      allRowsData.push(rowData);
    });
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

    sortTable(colIndex, newSort);
  }

  function sortTable(colIndex, direction) {
    if (direction === "none") {
      // Restore original order
      renderRows(allRowsData);
      return;
    }

    const sortedData = [...allRowsData].sort((a, b) => {
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

    renderRows(sortedData);
  }

  function renderRows(rowsData) {
    const hiddenCols = getHiddenColumns();
    tableBody.innerHTML = "";

    rowsData.forEach((row) => {
      const tr = document.createElement("tr");
      row.forEach((cell, idx) => {
        const td = document.createElement("td");
        td.dataset.colIndex = idx;
        td.textContent = cell;
        if (hiddenCols.has(idx)) {
          td.hidden = true;
        }
        tr.appendChild(td);
      });
      tableBody.appendChild(tr);
    });
    updateColumnCount();
    updateColumnToggleLabel();
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

      // Append new rows
      const hiddenCols = getHiddenColumns();
      data.rows.forEach((row) => {
        allRowsData.push(row);

        const tr = document.createElement("tr");
        row.forEach((cell, idx) => {
          const td = document.createElement("td");
          td.dataset.colIndex = idx;
          td.textContent = cell;
          if (hiddenCols.has(idx)) {
            td.hidden = true;
          }
          tr.appendChild(td);
        });
        tableBody.appendChild(tr);
      });

      loadedRows += data.rows.length;
      hasMore = data.has_more;

      // Update row count display
      updateRowCount();

      // Re-apply sorting if active
      if (currentSortCol !== null && currentSortDir !== "none") {
        sortTable(currentSortCol, currentSortDir);
      }
    } catch (err) {
      console.error("Error loading more rows:", err);
    } finally {
      isLoading = false;
      if (tableLoading) tableLoading.hidden = true;
    }
  }

  function updateRowCount() {
    if (rowCountSpan) {
      if (loadedRows >= totalRows) {
        rowCountSpan.textContent = `${totalRows} rows`;
      } else {
        rowCountSpan.textContent = `Showing ${loadedRows} of ${totalRows} rows (scroll for more)`;
      }
    }
  }

  // ==================== INITIALIZATION ====================

  function init() {
    initRowsData();
    setupSorting();
    setupColumnToggle();
    setupVirtualScroll();
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
