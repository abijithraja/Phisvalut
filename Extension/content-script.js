const container = document.createElement("div");
container.id = "phishvault-root";
container.style.position = "fixed";
container.style.top = "0";
container.style.left = "0";
container.style.zIndex = "999999";

const shadow = container.attachShadow({ mode: "open" });

shadow.innerHTML = `
  <style>
    /* Paste the full CSS here (from above) */
  </style>
  <div class="phishvault-container" id="draggable-container">
    <div class="phishvault-header" id="drag-handle">PhishVault</div>
    <label for="linkInput">Enter URL to Scan:</label>
    <input type="text" id="linkInput" placeholder="https://example.com" />

    <div class="ai-toggle">
      <input type="checkbox" id="useAI" />
      <label for="useAI">Use AI-Powered Scan</label>
    </div>

    <button id="scanBtn">Scan</button>
    <div id="resultBox" class="hidden">Result will appear here</div>
  </div>
`;

document.body.appendChild(container);
