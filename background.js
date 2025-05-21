//replace with API key from VirusTotal
const VT_API_KEY = 'VT_API_KEY';
const VT_API_URL_BASE = 'https://www.virustotal.com/api/v3/urls';

// Helper function to show alerts on the active tab ---
function showAlert(tabId, message) {
  chrome.scripting.executeScript({
    target: { tabId: tabId },
    func: (msg) => { // This function runs in the content script context
      alert(msg);
    },
    args: [message] // Pass the message to the injected function
  }).catch(err => console.error("Failed to inject script:", err)); // Basic error handling for injection
}

// Function to check URL with VirusTotal ---
async function checkUrlWithVirusTotal(tabId, url) {
  if (!VT_API_KEY) {
    console.error("VirusTotal API Key not set in background.js");
    showAlert(tabId, "Error: VirusTotal API Key is not configured in the extension.");
    return;
  }

  // encode URL to base64 representation
  const urlId = btoa(url).replace(/=/g, '');
  const requestUrl = `${VT_API_URL_BASE}/${urlId}`;

  console.log(`Checking URL: ${url}`);
  console.log(`Requesting VT report: ${requestUrl}`);

  try {
    const response = await fetch(requestUrl, {
      method: 'GET',
      headers: {
        'x-apikey': VT_API_KEY,
        'Accept': 'application/json'
      }
    });

    if (response.status === 404) {
        // URL not found in VT database
        console.log(`URL not found in VirusTotal: ${url}`);
        showAlert(tabId, `VirusTotal Info: URL not analyzed before.`);
        
        return; // No report, nothing to alert about based on past scans
    }

    if (!response.ok) {
        // Handle other errors
        console.error(`VirusTotal API Error: ${response.status} ${response.statusText}`);
        // Don't alert the user for every API error, just log it. Could alert for specific errors like 401 if needed.
        showAlert(tabId, `VirusTotal API Error: ${response.status}`);
        return;
    }

    const data = await response.json();
    console.log("VirusTotal Response:", data);

    // Check the analysis results
    if (data && data.data && data.data.attributes && data.data.attributes.last_analysis_stats) {
      const stats = data.data.attributes.last_analysis_stats;
      const maliciousCount = stats.malicious || 0;
      const suspiciousCount = stats.suspicious || 0;
      const harmlessCount = stats.harmless || 0; // Optional: For more detailed info

      console.log(`VT Stats for ${url}: Malicious=${maliciousCount}, Suspicious=${suspiciousCount}, Harmless=${harmlessCount}`);

      if (maliciousCount > 0 || suspiciousCount > 0) {
        showAlert(tabId, `⚠️ VirusTotal Warning! ⚠️\n\nURL: ${url}\n\nDetected as potentially RISKY:\n- Malicious: ${maliciousCount}\n- Suspicious: ${suspiciousCount}`);
      } else {
        // Alert for safe sites (can be annoying)
        showAlert(tabId, `✅ VirusTotal Check:\n\nURL: ${url}\n\nAppears SAFE (M:${maliciousCount}, S:${suspiciousCount}, H:${harmlessCount})`);
        console.log(`URL appears safe according to VirusTotal: ${url}`);
      }
    } else {
       console.log(`No analysis stats found in VT response for ${url}`);
       // This might happen if the URL was submitted but never analyzed
    }

  } catch (error) {
    console.error('Error fetching VirusTotal data:', error);
  }
}

// --- Event Listener for Tab Updates ---
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // Wait for the page to finish loading and ensure it has a valid http/https URL
  if (changeInfo.status === 'complete' && tab.url && (tab.url.startsWith('http:') || tab.url.startsWith('https:'))) {
     // Don't check internal chrome URLs or invalid URLs
     if (tab.url.startsWith('chrome://') || !tab.url.includes('.')) {
         console.log("Skipping internal or invalid URL:", tab.url);
         return;
     }
    checkUrlWithVirusTotal(tabId, tab.url);
  }
});
