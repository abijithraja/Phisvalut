document.addEventListener('DOMContentLoaded', function () {
  const scanBtn = document.getElementById('scanBtn');
  const urlInput = document.getElementById('urlInput');
  const scanMode = document.getElementById('scanMode');
  const useAI = document.getElementById('useAI');
  const resultBox = document.getElementById('resultBox');
  const result = document.getElementById('result');
  const container = document.getElementById('draggable-container');
  const dragHandle = document.getElementById('drag-handle');

  // Load saved position
  const savedX = localStorage.getItem('panelX');
  const savedY = localStorage.getItem('panelY');
  if (savedX && savedY) {
    container.style.left = `${savedX}px`;
    container.style.top = `${savedY}px`;
  }

  // Scan button click
  scanBtn.addEventListener('click', async () => {
    const url = urlInput.value.trim();
    const mode = scanMode.valuse;
    const aiEnabled = useAI.checked;

    if (!url || !isValidURL(url)) {
      showResult("<strong>Please enter a valid URL.</strong>", "error");
      return;
    }

    showResult("<em>Scanning the link...</em>", "loading");

    try {
      const response = await fetch('http://localhost:5000/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, mode, ai: aiEnabled })
      });

      const data = await response.json();

      if (response.ok) {
        showResult(`<strong>${data.message}</strong>`, "success");
      } else {
        showResult(`<strong>Scan failed:</strong> ${data.message || "Unknown error."}`, "warn");
      }
    } catch (error) {
      console.error(error);
      showResult("<strong>Unable to connect to the scanning server.</strong>", "error");
    }
  });

  // Utility: Result display
  function showResult(message, status = "") {
    result.innerHTML = message;
    resultBox.classList.remove('hidden', 'success', 'error', 'warn', 'loading');
    if (status) resultBox.classList.add(status);
  }

  // URL validation
  function isValidURL(str) {
    try {
      new URL(str);
      return true;
    } catch (_) {
      return false;
    }
  }

  // Smooth Draggable Panel
  let isDragging = false, offsetX = 0, offsetY = 0;

  dragHandle.addEventListener('mousedown', startDrag);
  document.addEventListener('mousemove', drag);
  document.addEventListener('mouseup', stopDrag);

  // Mobile support
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

    // Save position to localStorage
    const rect = container.getBoundingClientRect();
    localStorage.setItem('panelX', rect.left);
    localStorage.setItem('panelY', rect.top);
  }
});
