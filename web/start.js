// Loads the WebAssembly app. Kept as its own file, not inline, so the page can run under a
// Content-Security-Policy that allows scripts only from its own origin.
import init from './app.js';

try {
  await init();
} catch (error) {
  const status = document.getElementById('status');
  status.textContent = 'Could not load the app: ' + error;
}
