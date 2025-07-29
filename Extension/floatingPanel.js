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

      <div id="resultBox" class="hidden">
        <h4>Result:</h4>
        <div id="result"></div>
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
  const resultBox = containerWrapper.querySelector('#resultBox');
  const result = containerWrapper.querySelector('#result');
  const leakResultBox = containerWrapper.querySelector('#leakResultBox');
  const leakResult = containerWrapper.querySelector('#leakResult');
  const darkModeToggle = containerWrapper.querySelector('#darkModeToggle');

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

    // Backend placeholder
    await new Promise(r => setTimeout(r, 1500));
    showResult(`<strong>Scan complete!</strong><br>Mode: ${mode}, AI: ${aiEnabled}`, "success");
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
})();
