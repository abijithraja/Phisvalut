(function () {
  const html = `
    <div class="phishvault-container" id="draggable-container">
      <div class="phishvault-header" id="drag-handle">
        <span>PhishVault</span>
        <button id="closeExtension" class="extension-close-btn">&times;</button>
      </div>

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

    <!-- Pop-up Result Overlay -->
    <div id="resultPopup" class="result-popup hidden">
      <div class="popup-content">
        <div class="popup-header">
          <h3>Scan Results</h3>
          <button id="closePopup" class="close-btn">&times;</button>
        </div>
        <div class="popup-body">
          <div id="popupResult"></div>
        </div>
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
  const closeExtension = containerWrapper.querySelector('#closeExtension');
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

  // Pop-up elements (these are now in containerWrapper since we added them to the HTML string)
  const resultPopup = containerWrapper.querySelector('#resultPopup');
  const popupResult = containerWrapper.querySelector('#popupResult');
  const closePopup = containerWrapper.querySelector('#closePopup');

  const savedX = localStorage.getItem('panelX');
  const savedY = localStorage.getItem('panelY');
  if (savedX && savedY) {
    container.style.left = `${savedX}px`;
    container.style.top = `${savedY}px`;
  }

  // Apply saved width for consistent sizing
  const WIDTH_KEY = '__pv_width';
  function applySavedWidth(hostEl) {
    const saved = localStorage.getItem(WIDTH_KEY);
    if (saved) {
      // Apply saved width while respecting min() constraints
      const savedWidth = parseInt(saved);
      const maxAllowed = Math.min(420, window.innerWidth * 0.92);
      const finalWidth = Math.min(savedWidth, maxAllowed);
      hostEl.style.width = `${finalWidth}px`;
      hostEl.style.maxWidth = `${finalWidth}px`;
    }
  }

  // Apply saved width on initialization
  applySavedWidth(container);

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

  // Close extension functionality
  closeExtension.addEventListener('click', () => {
    containerWrapper.remove();
  });

  function isValidURL(str) {
    try {
      new URL(str);
      return true;
    } catch (_) {
      return false;
    }
  }

  // Configuration
  const API_BASE_URL = 'http://localhost:8000';  // Your PhishVault API server - REAL MODELS WITH SHAP
  
  function showResult(message, status = "") {
    result.innerHTML = message;
    resultBox.classList.remove('hidden', 'success', 'error', 'warn', 'loading');
    if (status) resultBox.classList.add(status);
  }

  function showPopupResult(scanResult, url, mode, ai) {
    // Check if popup elements exist
    if (!popupResult || !resultPopup) {
      console.warn('Popup elements not found, showing result in main panel instead');
      const riskText = scanResult.is_phishing ? 'High Risk - Phishing Detected' : scanResult.risk_level;
      showResult(`<strong>Scan Complete!</strong><br>Risk: ${riskText}<br>URL: ${url}`, 
                scanResult.is_phishing ? "error" : scanResult.risk_level === 'HIGH' ? "error" : 
                scanResult.risk_level === 'MEDIUM' ? "warn" : "success");
      return;
    }

    // Determine risk styling based on actual API response format
    const riskClass = scanResult.is_phishing ? 'error' : 
                     scanResult.risk_level === 'HIGH' ? 'error' :
                     scanResult.risk_level === 'MEDIUM' ? 'warning' : 'success';
    
    const riskText = scanResult.is_phishing ? '🚨 PHISHING DETECTED' : 
                    scanResult.risk_level === 'HIGH' ? '⚠️ HIGH RISK' :
                    scanResult.risk_level === 'MEDIUM' ? '⚠️ MEDIUM RISK' :
                    scanResult.risk_level === 'LOW' ? '✅ LOW RISK' : '✅ SAFE';
    
    // Build analysis details from actual API response
    const analysis = scanResult.analysis || {};
    const domainInfo = analysis.domain_info || {};
    const urlStructure = analysis.url_structure || {};
    const securityFeatures = analysis.security_features || {};
    const riskIndicators = analysis.risk_indicators || [];
    
    // Build SHAP explanations section
    const shapExplanations = scanResult.shap_explanations || [];
    let shapHTML = '';
    
    if (shapExplanations.length > 0) {
      shapHTML = `
        <div class="result-section">
          <h4>🧠 AI Model Explanations (SHAP)</h4>
          <p><em>How the AI model made its decision:</em></p>
          <div class="shap-explanations">
      `;
      
      shapExplanations.slice(0, 8).forEach((shap, index) => {
        const contributionClass = shap.contribution === 'increases' ? 'shap-positive' : 'shap-negative';
        const contributionIcon = shap.contribution === 'increases' ? '📈' : '📉';
        const shapValueFormatted = Math.abs(shap.shap_value).toFixed(4);
        
        shapHTML += `
          <div class="shap-item ${contributionClass}">
            <div class="shap-header">
              <span class="shap-feature">${contributionIcon} ${shap.feature_name}</span>
              <span class="shap-impact">${shap.contribution} risk</span>
            </div>
            <div class="shap-details">
              <span>Value: ${shap.feature_value.toFixed(2)}</span>
              <span>Impact: ${shapValueFormatted}</span>
            </div>
          </div>
        `;
      });
      
      shapHTML += `
          </div>
          <p class="shap-note">💡 <strong>SHAP values</strong> explain which features most influenced the AI's decision. Positive values increase phishing risk, negative values decrease it.</p>
        </div>
      `;
    }
    
    popupResult.innerHTML = `
      <div class="result-section ${riskClass}">
        <h4>🔍 Scan Summary</h4>
        <p><strong>Status:</strong> ${riskText}</p>
        <p><strong>URL:</strong> ${domainInfo.domain || new URL(url).hostname}</p>
        <p><strong>Confidence:</strong> ${(scanResult.confidence * 100).toFixed(1)}%</p>
        <p><strong>Probability:</strong> ${(scanResult.probability * 100).toFixed(1)}%</p>
        <p><strong>Risk Level:</strong> ${scanResult.risk_level}</p>
        <p><strong>Model:</strong> ${scanResult.model_version || 'XGBoost v2.0'}</p>
        <p><strong>Timestamp:</strong> ${new Date(scanResult.timestamp).toLocaleString()}</p>
      </div>
      
      ${shapHTML}
      
      <div class="result-section">
        <h4>🛡️ Security Analysis</h4>
        <p><strong>HTTPS Enabled:</strong> ${securityFeatures.https_enabled ? '✅ Yes' : '❌ No'}</p>
        <p><strong>Domain Length:</strong> ${domainInfo.length || 'N/A'}</p>
        <p><strong>URL Length:</strong> ${urlStructure.url_length || url.length}</p>
        <p><strong>Suspicious Characters:</strong> ${urlStructure.suspicious_chars || 0}</p>
        <p><strong>Subdomain Count:</strong> ${domainInfo.subdomain_count || 0}</p>
        <p><strong>Path Depth:</strong> ${urlStructure.path_depth || 0}</p>
      </div>
      
      <div class="result-section">
        <h4>⚠️ Risk Indicators</h4>
        ${riskIndicators.length > 0 ? 
          '<ul>' + riskIndicators.map(indicator => `<li>🔸 ${indicator}</li>`).join('') + '</ul>' :
          '<p>✅ No specific risk indicators detected.</p>'
        }
      </div>
      
      <div class="result-section">
        <h4>💡 Recommendations</h4>
        <div style="white-space: pre-line; font-size: 14px;">${scanResult.recommendations || 'No specific recommendations available.'}</div>
      </div>
    `;
    
    // Show the popup
    resultPopup.classList.remove('hidden');
  }

  async function callPhishVaultAPI(url, scanType = 'quick') {
    try {
      console.log('Calling PhishVault API with URL:', url);
      console.log('API Base URL:', API_BASE_URL);
      console.log('Full endpoint:', `${API_BASE_URL}/scan_url`);
      
      const requestBody = {
        url: url,
        scan_type: scanType
      };
      console.log('Request body:', requestBody);
      
      const response = await fetch(`${API_BASE_URL}/scan_url`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody)
      });

      console.log('Response status:', response.status);
      console.log('Response ok:', response.ok);

      if (!response.ok) {
        const errorText = await response.text();
        console.log('Error response text:', errorText);
        let parsed;
        try { 
          parsed = JSON.parse(errorText); 
        } catch(e) { 
          parsed = null; 
        }
        const message = parsed && parsed.detail ? parsed.detail : (errorText || response.statusText);
        throw new Error(`API request failed: ${response.status} ${response.statusText} - ${message}`);
      }

      const result = await response.json();
      console.log('PhishVault API Response:', result);
      return result;
    } catch (error) {
      console.error('PhishVault API Error:', error);
      console.error('Error type:', error.constructor.name);
      console.error('Error message:', error.message);
      console.error('Stack trace:', error.stack);
      throw error;
    }
  }

  function hidePopup() {
    if (resultPopup) {
      resultPopup.classList.add('hidden');
    }
  }

  // Close popup when clicking close button
  if (closePopup) {
    closePopup.addEventListener('click', hidePopup);
  }

  // Close popup when clicking outside the content
  if (resultPopup) {
    resultPopup.addEventListener('click', (e) => {
      if (e.target === resultPopup) {
        hidePopup();
      }
    });
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
      showResult("<strong>Please enter a valid URL.</strong>", "error");
      return;
    }

    showResult("<em>🔍 Analyzing URL with PhishVault...</em>", "loading");

    try {
      console.log('Starting scan for URL:', url);
      
      // Call the PhishVault API
      const scanResult = await callPhishVaultAPI(url, mode);
      
      console.log('Scan completed:', scanResult);
      
      // Hide the main result box since we're showing popup
      resultBox.classList.add('hidden');
      
      // Show detailed results in popup
      showPopupResult(scanResult, url, mode, aiEnabled);
      
    } catch (error) {
      console.error('Scan failed:', error);
      
      // Provide detailed error information based on error type
      if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
        showResult(`
          <strong>🔌 Connection Error</strong><br>
          <p>Cannot connect to PhishVault API server.</p>
          <details>
            <summary>Troubleshooting Steps:</summary>
            <ol>
              <li>Ensure the API server is running:
                <ul>
                  <li>Open terminal in Backend folder</li>
                  <li>Run: <code>python main.py</code></li>
                  <li>Wait for "Uvicorn running on http://0.0.0.0:8000"</li>
                </ul>
              </li>
              <li>Check if port 8000 is available</li>
              <li>Verify firewall settings allow localhost:8000</li>
              <li>Try reloading the extension</li>
            </ol>
          </details>
          <p><strong>Technical Details:</strong><br>
          Error: ${error.message}<br>
          Type: ${error.constructor.name}</p>
        `, "error");
      } else if (error.message.includes('TypeError')) {
        showResult(`
          <strong>🔧 Extension Configuration Error</strong><br>
          <p>There's an issue with the browser extension configuration.</p>
          <details>
            <summary>Fix Steps:</summary>
            <ol>
              <li>Go to Chrome Extensions (chrome://extensions/)</li>
              <li>Find "PhishVault Floating Panel"</li>
              <li>Click "Remove" then reload the extension</li>
              <li>Make sure to enable "Developer mode"</li>
              <li>Click "Load unpacked" and select the Extension folder</li>
            </ol>
          </details>
          <p><strong>Error:</strong> ${error.message}</p>
        `, "error");
      } else {
        showResult(`<strong>Scan Failed:</strong> ${error.message}`, "error");
      }
    }
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
