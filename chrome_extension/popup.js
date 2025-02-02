document.addEventListener('DOMContentLoaded', function() {
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    const currentUrl = tabs[0].url;
    checkPhishing(currentUrl);
  });
});

async function checkPhishing(url) {
  const resultDiv = document.getElementById('result');
  
  try {
    // Replace with your Flask API endpoint
    const response = await fetch('http://127.0.0.1:5000/check-phishing', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: url })
    });

    const data = await response.json();
    
    if (data.is_phishing) {
      resultDiv.className = 'status-card danger fade-in';
      resultDiv.innerHTML = `
        <div class="status-icon">
          <i class="fas fa-exclamation-triangle"></i>
        </div>
        <div class="status-text">
          <div class="status-title">Potential Phishing Site</div>
          <div class="status-description">This website shows signs of being a phishing attempt</div>
        </div>
      `;
    } else {
      resultDiv.className = 'status-card safe fade-in';
      resultDiv.innerHTML = `
        <div class="status-icon">
          <i class="fas fa-shield-alt"></i>
        </div>
        <div class="status-text">
          <div class="status-title">Website Appears Safe</div>
          <div class="status-description">No phishing indicators detected</div>
        </div>
      `;
    }
  } catch (error) {
    resultDiv.className = 'status-card danger fade-in';
    resultDiv.innerHTML = `
      <div class="status-icon">
        <i class="fas fa-exclamation-circle"></i>
      </div>
      <div class="status-text">
        <div class="status-title">Error Checking Website</div>
        <div class="status-description">Unable to analyze this website</div>
      </div>
    `;
    console.error('Error:', error);
  }
}