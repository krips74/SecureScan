// API Configuration (same-origin)
const API_BASE_URL = '/api';

// Global variables
let currentScanData = null;
let selectedPayloadsFile = null;

// Initialize page
document.addEventListener('DOMContentLoaded', function() {
    const scanForm = document.getElementById('scanForm');
    if (scanForm) {
        scanForm.addEventListener('submit', handleScanSubmit);
    }
    
    // Check API health
    checkApiHealth();
});

// Check if API is available
async function checkApiHealth() {
    try {
        // Best-effort: use the generic API info route
        await fetch(`${API_BASE_URL}/info`);
    } catch (error) {
        console.error('API health check failed:', error);
        showWarningBanner('Cannot connect to the backend API. Ensure the server is running.');
    }
}

function bearerAuthHeader() {
    const token = localStorage.getItem('ss_token');
    return token ? { 'Authorization': 'Bearer ' + token } : {};
}

function showWarningBanner(message) {
    const banner = document.createElement('div');
    banner.className = 'warning-banner';
    const content = document.createElement('div');
    content.className = 'warning-content';

    const text = document.createElement('span');
    text.textContent = message;

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.textContent = 'Close';
    closeBtn.addEventListener('click', () => banner.remove());

    content.appendChild(text);
    content.appendChild(closeBtn);
    banner.appendChild(content);
    document.body.insertBefore(banner, document.body.firstChild);
}

// Handle scan form submission
async function handleScanSubmit(event) {
    event.preventDefault();
    console.log("Form submitted");
    
    const targetUrl = document.getElementById('targetUrl').value.trim();
    
    // Validate URL
    if (!targetUrl) {
        showError('Please enter a target URL');
        return;
    }
    
    if (!isValidUrl(targetUrl)) {
        showError('Please enter a valid URL starting with http:// or https://');
        return;
    }
    
    // Start single URL scan
    await startScan(targetUrl);
}

// Handle payload file selection
function handlePayloadFileSelect(event) {
    const file = event.target.files[0];
    if (file) {
        if (!file.name.toLowerCase().endsWith('.txt')) {
            showError('Only .txt files are allowed');
            clearPayloadFile();
            return;
        }
        selectedPayloadsFile = file;
        document.getElementById('payloadFileName').textContent = `${file.name} (${formatFileSize(file.size)})`;
        document.getElementById('payloadFileInfo').style.display = 'block';
        // Clear textarea when file is selected
        document.getElementById('customPayloads').value = '';
    }
}

// Clear payload file
function clearPayloadFile() {
    selectedPayloadsFile = null;
    document.getElementById('payloadsFile').value = '';
    document.getElementById('payloadFileInfo').style.display = 'none';
}

// Format file size
function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

// Start file-based XSS scan
async function startFileScan(file) {
    // Hide previous results
    hideResults();
    hideError();
    
    // Show loading
    showLoading('Uploading payload file and preparing XSS scan…');
    const progress = startScanProgress('Running XSS scan', [
        'Uploading payload file',
        'Submitting scan request',
        'Testing payload reflections',
        'Collecting vulnerabilities'
    ]);
    
    try {
        const formData = new FormData();
        formData.append('file', file);
        
        const response = await fetch(`${API_BASE_URL}/xss/scan/file`, {
            method: 'POST',
            headers: bearerAuthHeader(),
            body: formData,
            signal: progress ? progress.signal : undefined
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentScanData = data.data;
            saveReportToStorage(data.data);
            displayResults(data.data);
            if (progress) progress.complete('XSS file scan completed');
        } else {
            showError(data.error || 'Scan failed. Please try again.');
        }
    } catch (error) {
        console.error('Scan error:', error);
        if (error.name === 'AbortError') {
            showError('Scan cancelled by user.');
        } else {
            showError('Failed to connect to the scanning service. Please ensure the backend is running.');
        }
    } finally {
        hideLoading();
    }
}

// Validate URL format
function isValidUrl(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
    } catch (e) {
        return false;
    }
}

// Start XSS scan
async function startScan(url) {
    // Hide previous results
    hideResults();
    hideError();
    
    // Show loading
    showLoading('Preparing XSS scanner…');
    const progress = startScanProgress('Running XSS scan', [
        'Preparing payload set',
        'Submitting XSS scan',
        'Testing parameters and payloads',
        'Finalizing report'
    ]);
    
    try {
        const requestBody = {
            url: url
        };
        
        // Check if payloads file is uploaded
        const payloadsFile = document.getElementById('payloadsFile').files[0];
        if (payloadsFile) {
            const fileContent = await payloadsFile.text();
            const payloads = fileContent.split('\n').map(p => p.trim()).filter(p => p);
            requestBody.custom_payloads = payloads;
        } else {
            // Check if custom payloads textarea has content
            const customPayloadsText = document.getElementById('customPayloads').value.trim();
            if (customPayloadsText) {
                const payloads = customPayloadsText.split('\n').map(p => p.trim()).filter(p => p);
                requestBody.custom_payloads = payloads;
            }
        }
        
        const response = await fetch(`${API_BASE_URL}/xss/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...bearerAuthHeader(),
            },
            body: JSON.stringify(requestBody),
            signal: progress ? progress.signal : undefined
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentScanData = data.data;
            saveReportToStorage(data.data);
            displayResults(data.data);
            if (progress) progress.complete('XSS scan completed');
        } else {
            showError(data.error || 'Scan failed. Please try again.');
        }
    } catch (error) {
        console.error('Scan error:', error);
        if (error.name === 'AbortError') {
            showError('Scan cancelled by user.');
        } else {
            showError('Failed to connect to the scanning service. Please ensure the backend is running.');
        }
    } finally {
        hideLoading();
    }
}

// Save report to localStorage
function saveReportToStorage(data) {
    const reports = JSON.parse(localStorage.getItem('securescan_reports') || '[]');
    
    const report = {
        id: Date.now(),
        target: data.target,
        timestamp: data.timestamp || new Date().toISOString(),
        type: 'xss',
        totalVulns: data.total_found || 0,
        vulnerabilities: data.vulnerabilities || [],
        mockMode: data.mock_mode || false
    };
    
    reports.unshift(report);
    
    // Keep only last 50 reports
    if (reports.length > 50) {
        reports.pop();
    }
    
    localStorage.setItem('securescan_reports', JSON.stringify(reports));
    console.log('Report saved to localStorage');
}

// Display scan results
function displayResults(data) {
    const resultsSection = document.getElementById('resultsSection');
    const summaryDiv = document.getElementById('resultsSummary');
    const vulnerabilitiesDiv = document.getElementById('vulnerabilitiesList');

    const clearChildren = (node) => {
        while (node.firstChild) node.removeChild(node.firstChild);
    };

    const appendLabelValue = (container, label, value) => {
        const p = document.createElement('p');
        const strong = document.createElement('strong');
        strong.textContent = label;
        p.appendChild(strong);
        p.appendChild(document.createTextNode(' ' + value));
        container.appendChild(p);
    };
    
    // Build summary
    const totalVulns = data.total_found || 0;
    const severityCounts = countSeverities(data.vulnerabilities);

    clearChildren(summaryDiv);
    if (data.mock_mode || data.note) {
        const notice = document.createElement('div');
        notice.className = 'mock-mode-notice';
        const strong = document.createElement('strong');
        strong.textContent = 'Demo mode:';
        notice.appendChild(strong);
        notice.appendChild(document.createTextNode(' These are simulated results. '));
        const link = document.createElement('a');
        link.href = 'https://github.com/hahwul/dalfox';
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.textContent = 'Install Dalfox';
        notice.appendChild(link);
        notice.appendChild(document.createTextNode(' for real vulnerability scanning.'));
        summaryDiv.appendChild(notice);
    }

    const summaryCard = document.createElement('div');
    summaryCard.className = 'summary-card';
    const h3 = document.createElement('h3');
    h3.textContent = 'Scan Summary';
    summaryCard.appendChild(h3);
    appendLabelValue(summaryCard, 'Target:', String(data.target ?? ''));
    appendLabelValue(summaryCard, 'Timestamp:', String(formatTimestamp(data.timestamp)));

    const totalP = document.createElement('p');
    const totalStrong = document.createElement('strong');
    totalStrong.textContent = 'Total Vulnerabilities:';
    totalP.appendChild(totalStrong);
    totalP.appendChild(document.createTextNode(' '));
    const badge = document.createElement('span');
    badge.className = `badge ${totalVulns > 0 ? 'badge-danger' : 'badge-success'}`;
    badge.textContent = String(totalVulns);
    totalP.appendChild(badge);
    summaryCard.appendChild(totalP);

    if (totalVulns > 0) {
        const breakdown = document.createElement('div');
        breakdown.className = 'severity-breakdown';
        const high = document.createElement('span');
        high.className = 'severity-high';
        high.textContent = `High: ${severityCounts.high}`;
        const med = document.createElement('span');
        med.className = 'severity-medium';
        med.textContent = `Medium: ${severityCounts.medium}`;
        const low = document.createElement('span');
        low.className = 'severity-low';
        low.textContent = `Low: ${severityCounts.low}`;
        breakdown.appendChild(high);
        breakdown.appendChild(med);
        breakdown.appendChild(low);
        summaryCard.appendChild(breakdown);
    }

    summaryDiv.appendChild(summaryCard);
    
    // Build vulnerabilities list
    clearChildren(vulnerabilitiesDiv);
    if (totalVulns > 0) {
        const title = document.createElement('h3');
        title.textContent = 'Findings';
        vulnerabilitiesDiv.appendChild(title);

        (data.vulnerabilities || []).forEach((vuln, index) => {
            const sev = String(vuln.severity || 'low').toLowerCase();
            const card = document.createElement('div');
            card.className = `vulnerability-card severity-${sev}`;

            const header = document.createElement('div');
            header.className = 'vuln-header';
            const num = document.createElement('span');
            num.className = 'vuln-number';
            num.textContent = `#${index + 1}`;
            const type = document.createElement('span');
            type.className = 'vuln-type';
            type.textContent = String(vuln.type ?? '');
            const sevBadge = document.createElement('span');
            sevBadge.className = `vuln-severity badge badge-${sev}`;
            sevBadge.textContent = String(vuln.severity ?? '').toString();
            header.appendChild(num);
            header.appendChild(type);
            header.appendChild(sevBadge);

            const body = document.createElement('div');
            body.className = 'vuln-body';

            const rowWithCode = (label, value) => {
                const p = document.createElement('p');
                const strong = document.createElement('strong');
                strong.textContent = label;
                p.appendChild(strong);
                p.appendChild(document.createTextNode(' '));
                const code = document.createElement('code');
                code.textContent = String(value ?? '');
                p.appendChild(code);
                return p;
            };

            body.appendChild(rowWithCode('Parameter:', vuln.parameter));
            body.appendChild(rowWithCode('Payload:', vuln.payload));
            if (vuln.evidence) body.appendChild(rowWithCode('Evidence:', vuln.evidence));
            if (vuln.cwe) {
                const p = document.createElement('p');
                const strong = document.createElement('strong');
                strong.textContent = 'CWE:';
                p.appendChild(strong);
                p.appendChild(document.createTextNode(' ' + String(vuln.cwe)));
                body.appendChild(p);
            }

            card.appendChild(header);
            card.appendChild(body);
            vulnerabilitiesDiv.appendChild(card);
        });
    } else {
        const wrap = document.createElement('div');
        wrap.className = 'no-vulnerabilities';
        const title = document.createElement('h3');
        title.textContent = 'No Vulnerabilities Found';
        const p = document.createElement('p');
        p.textContent = 'The scan did not detect any XSS vulnerabilities in the target URL.';
        wrap.appendChild(title);
        wrap.appendChild(p);
        vulnerabilitiesDiv.appendChild(wrap);
    }
    
    resultsSection.style.display = 'block';
    
    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Count vulnerabilities by severity
function countSeverities(vulnerabilities) {
    const counts = { high: 0, medium: 0, low: 0 };
    
    vulnerabilities.forEach(vuln => {
        const severity = vuln.severity.toLowerCase();
        if (counts.hasOwnProperty(severity)) {
            counts[severity]++;
        }
    });
    
    return counts;
}

// Download report as JSON
function downloadReport() {
    if (!currentScanData) return;
    
    const dataStr = JSON.stringify(currentScanData, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `xss-scan-report-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Reset scan and show form again
function resetScan() {
    document.getElementById('scanForm').reset();
    clearPayloadFile();
    hideResults();
    hideError();
    currentScanData = null;
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// UI Helper Functions
function showLoading() {
    document.getElementById('loadingIndicator').style.display = 'block';
    const scanBtn = document.querySelector('.scan-btn');
    if (scanBtn) {
        scanBtn.disabled = true;
        scanBtn.textContent = 'Scanning...';
    }
    
    // Hide results if visible
    document.getElementById('resultsSection').style.display = 'none';
    
    // Scroll to loading indicator
    document.getElementById('loadingIndicator').scrollIntoView({ behavior: 'smooth', block: 'center' });
}

function hideLoading() {
    document.getElementById('loadingIndicator').style.display = 'none';
    const scanBtn = document.querySelector('.scan-btn');
    if (scanBtn) {
        scanBtn.disabled = false;
        scanBtn.textContent = 'Scan Now';
    }
}

function showResults() {
    document.getElementById('resultsSection').style.display = 'block';
}

function hideResults() {
    document.getElementById('resultsSection').style.display = 'none';
}

function showError(message) {
    document.getElementById('errorMessage').textContent = message;
    document.getElementById('errorSection').style.display = 'block';
}

function hideError() {
    document.getElementById('errorSection').style.display = 'none';
}

function showWarning(message) {
    console.warn(message);
}

// Utility Functions
function formatTimestamp(timestamp) {
    try {
        const date = new Date(timestamp);
        return date.toLocaleString();
    } catch (e) {
        return timestamp;
    }
}
