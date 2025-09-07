(function () {
  const html = `
    <div class="phishvault-container" id="draggable-container">
      <div class="phishvault-header" id="drag-handle"> PhishVault</div>

      <label for="urlInput">Enter or paste a URL:</label>
      <input type="text" id="urlInput" placeholder="https://example.com" />

      <div class="scan-mode">
        <label for="scanMode">Scan Mode:</label>
        <select id="scanMode">
          <option value="quick">Quick</option>
          <option value="deep">Deep</option>
        </select>
      </div>

      <div class="ai-toggle">
        <input type="checkbox" id="useAI" />
        <label for="useAI">Explain using AI (ChatGPT)</label>
      </div>

      <div class="darkmode-toggle">
        <input type="checkbox" id="darkModeToggle" />
        <label for="darkModeToggle">Dark Mode</label>
      </div>

      <div class="button-group">
        <button id="scanBtn"> Scan Link</button>
        <button id="scanPageBtn"> Scan This Page</button>
      </div>

      <!-- PAGES: page 0 = main panel, page 1 = results list (paginated) -->
      <div class="pages">

        <!-- PAGE 0: inline single result area (keeps original behavior) -->
        <div class="page" data-page="0">
          <div id="resultBox-inline" class="hidden">
            <h4>Result:</h4>
            <div id="result"></div>
          </div>
        </div>

        <!-- PAGE 1: All results list (paginated) -->
        <div class="page hidden" data-page="1" id="results-page">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
            <strong>All Scan Results</strong>
            <div style="display:flex;align-items:center;gap:6px">
              <button id="results-prev" class="small-btn" aria-label="Previous page">◀</button>
              <span id="results-page-indicator">1/1</span>
              <button id="results-next" class="small-btn" aria-label="Next page">▶</button>
            </div>
          </div>

          <div id="results-list" style="min-height:120px">
            <!-- JS will render .result-item blocks here -->
          </div>

          <div style="margin-top:10px;display:flex;gap:8px;align-items:center;">
            <button id="results-back" class="small-btn">Back</button>
            <div style="font-size:12px;color:var(--subtle-color,#666)">Tip: results are saved for this session</div>
          </div>
        </div>

      </div>

      <hr />

      <label for="leakInput"> Check Data Leak (Email / Phone):</label>
      <input type="text" id="leakInput" placeholder="email@example.com or 9876543210" />
      <button id="checkLeakBtn"> Check</button>

      <div id="leakResultBox" class="hidden">
        <h4>Leak Check Result:</h4>
        <div id="leakResult"></div>
      </div>
    </div>
  `;

  // Style & injection
  const styleLink = document.createElement("link");
  styleLink.rel = "stylesheet";
  styleLink.href = chrome.runtime.getURL("floatingPanel.css");
  document.head.appendChild(styleLink);

  const containerWrapper = document.createElement("div");
  containerWrapper.innerHTML = html;
  document.body.appendChild(containerWrapper);

  const container = containerWrapper.querySelector('#draggable-container');
  const dragHandle = containerWrapper.querySelector('#drag-handle');
  const scanBtn = containerWrapper.querySelector('#scanBtn');
  const scanPageBtn = containerWrapper.querySelector('#scanPageBtn');
  const checkLeakBtn = containerWrapper.querySelector('#checkLeakBtn');
  const urlInput = containerWrapper.querySelector('#urlInput');
  const leakInput = containerWrapper.querySelector('#leakInput');
  const scanMode = containerWrapper.querySelector('#scanMode');
  const useAI = containerWrapper.querySelector('#useAI');
  const resultBox = containerWrapper.querySelector('#resultBox-inline');
  const result = containerWrapper.querySelector('#result');
  const leakResultBox = containerWrapper.querySelector('#leakResultBox');
  const leakResult = containerWrapper.querySelector('#leakResult');
  const darkModeToggle = containerWrapper.querySelector('#darkModeToggle');

  /* === Results paging state & helpers === */
  const results = [];               // store scan results objects { url, mode, ai, score, summary, timestamp }
  let currentResultsPage = 1;       // 1-based page index for results page
  const RESULTS_PER_PAGE = 4;       // items per page (change as needed)

  // DOM refs for the newly inserted results page (use containerWrapper since you injected HTML into it)
  const resultsPage = containerWrapper.querySelector('#results-page');
  const resultsList = containerWrapper.querySelector('#results-list');
  const resultsPrev = containerWrapper.querySelector('#results-prev');
  const resultsNext = containerWrapper.querySelector('#results-next');
  const resultsBack = containerWrapper.querySelector('#results-back');
  const resultsPageIndicator = containerWrapper.querySelector('#results-page-indicator');

  // show a specific page (0 = main / 1 = results)
  function showPage(pageIndex) {
    const pages = containerWrapper.querySelectorAll('.page');
    pages.forEach(p => p.classList.add('hidden'));
    const node = containerWrapper.querySelector(`.page[data-page="${pageIndex}"]`);
    if (node) node.classList.remove('hidden');
  }

  // render current page of results
  function renderResults() {
    const total = Math.max(1, Math.ceil(results.length / RESULTS_PER_PAGE));
    if (currentResultsPage > total) currentResultsPage = total;
    const start = (currentResultsPage - 1) * RESULTS_PER_PAGE;
    const slice = results.slice(start, start + RESULTS_PER_PAGE);

    resultsList.innerHTML = ''; // clear
    if (slice.length === 0) {
      resultsList.innerHTML = '<div style="opacity:0.85;font-size:13px">No results yet.</div>';
    } else {
      slice.forEach(item => {
        const el = document.createElement('div');
        el.className = 'result-item';
        // use textContent to avoid injection; build small DOM
        const head = document.createElement('div');
        head.style.display = 'flex';
        head.style.justifyContent = 'space-between';
        head.style.alignItems = 'center';
        const urlDiv = document.createElement('div');
        urlDiv.style.fontWeight = '700';
        urlDiv.style.fontSize = '13px';
        urlDiv.textContent = item.url;
        const scoreDiv = document.createElement('div');
        scoreDiv.style.fontSize = '13px';
        scoreDiv.style.opacity = '0.9';
        scoreDiv.textContent = item.score + '%';
        head.appendChild(urlDiv);
        head.appendChild(scoreDiv);

        const summaryDiv = document.createElement('div');
        summaryDiv.style.marginTop = '6px';
        summaryDiv.style.fontSize = '12px';
        summaryDiv.style.color = 'var(--subtle,#444)';
        summaryDiv.textContent = item.summary || 'No summary';

        const metaDiv = document.createElement('div');
        metaDiv.style.marginTop = '6px';
        metaDiv.style.fontSize = '11px';
        metaDiv.style.opacity = '0.8';
        metaDiv.textContent = `Mode: ${item.mode} · AI: ${item.ai ? 'Yes' : 'No'} · ${new Date(item.timestamp).toLocaleString()}`;

        el.appendChild(head);
        el.appendChild(summaryDiv);
        el.appendChild(metaDiv);
        resultsList.appendChild(el);
      });
    }

    resultsPageIndicator.textContent = `${currentResultsPage}/${total}`;
    resultsPrev.disabled = currentResultsPage <= 1;
    resultsNext.disabled = currentResultsPage >= total;
  }

  // pagination handlers
  resultsPrev.addEventListener('click', () => {
    if (currentResultsPage > 1) currentResultsPage--;
    renderResults();
  });
  resultsNext.addEventListener('click', () => {
    const total = Math.max(1, Math.ceil(results.length / RESULTS_PER_PAGE));
    if (currentResultsPage < total) currentResultsPage++;
    renderResults();
  });
  resultsBack.addEventListener('click', () => {
    showPage(0); // return to main panel
  });

  const savedX = localStorage.getItem('panelX');
  const savedY = localStorage.getItem('panelY');
  if (savedX && savedY) {
    container.style.left = `${savedX}px`;
    container.style.top = `${savedY}px`;
  }

  const darkModeEnabled = localStorage.getItem('phishvaultDarkMode') === 'true';
  if (darkModeEnabled) {
    container.classList.add('dark-mode');
    darkModeToggle.checked = true;
  }

  darkModeToggle.addEventListener('change', () => {
    if (darkModeToggle.checked) {
      container.classList.add('dark-mode');
      localStorage.setItem('phishvaultDarkMode', 'true');
    } else {
      container.classList.remove('dark-mode');
      localStorage.setItem('phishvaultDarkMode', 'false');
    }
  });

  function isValidURL(str) {
    try {
      new URL(str);
      return true;
    } catch (_) {
      return false;
    }
  }

  function showResult(message, status = "") {
    result.innerHTML = message;
    resultBox.classList.remove('hidden', 'success', 'error', 'warn', 'loading');
    if (status) resultBox.classList.add(status);
  }

  function showLeakResult(message, status = "") {
    leakResult.innerHTML = message;
    leakResultBox.classList.remove('hidden', 'success', 'error', 'warn', 'loading');
    if (status) leakResultBox.classList.add(status);
  }

  // 🔍 Scan Button (URL)
  scanBtn.addEventListener('click', async () => {
    const url = urlInput.value.trim();
    const mode = scanMode.value;
    const aiEnabled = useAI.checked;

    if (!url || !isValidURL(url)) {
      showResult(" <strong>Please enter a valid URL.</strong>", "error");
      return;
    }

    showResult("<em>Scanning the link...</em>", "loading");

    // simulate progress / backend — keep your real call here if you have one
    await new Promise(r => setTimeout(r, 1500));
    // determine score (replace with backend response in real integration)
    const fakeScore = Math.floor(Math.random() * 85) + (mode === 'deep' ? 5 : 0);
    const summaryText = `Placeholder: scanned ${url}. Replace with your model/backend explanation.`;

    // update inline (optional)
    showResult(`<strong>Scan complete!</strong><br>Mode: ${mode}, AI: ${aiEnabled}`, "success");

    // store newest-first
    results.unshift({
      url: url,
      mode: mode,
      ai: aiEnabled,
      score: fakeScore,
      summary: summaryText,
      timestamp: Date.now()
    });

    // render results and switch to results page automatically
    currentResultsPage = 1;
    renderResults();
    showPage(1);
  });

  // 🕸️ Scan This Page
  scanPageBtn.addEventListener('click', async () => {
    const pageURL = window.location.href;
    urlInput.value = pageURL;
    scanBtn.click();
  });

  // 📱 Check Data Leak
  checkLeakBtn.addEventListener('click', async () => {
    const query = leakInput.value.trim();

    if (!query) {
      showLeakResult(" <strong>Please enter email or phone number.</strong>", "error");
      return;
    }

    showLeakResult(" <em>Checking for data leaks...</em>", "loading");

    // Backend placeholder
    await new Promise(r => setTimeout(r, 2000));
    showLeakResult(` <strong>No known leaks found for:</strong> ${query}`, "success");
  });

  // Dragging Logic
  let isDragging = false, offsetX = 0, offsetY = 0;

  dragHandle.addEventListener('mousedown', startDrag);
  document.addEventListener('mousemove', drag);
  document.addEventListener('mouseup', stopDrag);

  dragHandle.addEventListener('touchstart', startDrag);
  document.addEventListener('touchmove', drag);
  document.addEventListener('touchend', stopDrag);

  function startDrag(e) {
    isDragging = true;
    const rect = container.getBoundingClientRect();
    const clientX = e.clientX || e.touches[0].clientX;
    const clientY = e.clientY || e.touches[0].clientY;
    offsetX = clientX - rect.left;
    offsetY = clientY - rect.top;
    container.style.transition = 'none';
  }

  function drag(e) {
    if (!isDragging) return;
    const clientX = e.clientX || e.touches[0].clientX;
    const clientY = e.clientY || e.touches[0].clientY;
    const newX = clientX - offsetX;
    const newY = clientY - offsetY;
    container.style.left = `${newX}px`;
    container.style.top = `${newY}px`;
  }

  function stopDrag() {
    if (!isDragging) return;
    isDragging = false;
    const rect = container.getBoundingClientRect();
    localStorage.setItem('panelX', rect.left);
    localStorage.setItem('panelY', rect.top);
  }

  // Initialize pages and results
  showPage(0); // show main page on load
  renderResults();
})();
