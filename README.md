# VirusTotal-URL-checker

Chrome extension that automatically checks URLs against the VirusTotal API when a page finishes loading. It alerts users if a URL is flagged as potentially risky, Safe, or if it hasn't been analyzed by VirusTotal before.

**Instructions:**

1.  Download both `manifest.json` and `background.js` into the same folder.
2.  Open Chrome and navigate to `chrome://extensions/`.
3.  Enable "Developer mode" by toggling the switch in the top right corner.
4.  Click the "Load unpacked" button in the top left corner.
5.  In the file dialog, navigate to and select the folder where you saved `manifest.json` and `background.js`. Click "Select Folder".

The extension will now be installed and active. When you browse to new websites, it will automatically check the URL in the background and alert you if any potential risks are detected by VirusTotal or if the URL is new to their analysis.
