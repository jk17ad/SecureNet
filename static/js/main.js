// SecureNet Client side Logic Controller

document.addEventListener("DOMContentLoaded", () => {
    initClock();
    initTheme();
    initNotificationsPoll();
    initCharts();
    initUploadDropzone();
    initForms();
});

// --- LIVE CLOCK ---
function initClock() {
    const clockSpan = document.getElementById("clock-time");
    if (!clockSpan) return;
    
    function updateClock() {
        const now = new Date();
        const timeStr = now.toTimeString().split(' ')[0];
        clockSpan.textContent = timeStr;
    }
    
    updateClock();
    setInterval(updateClock, 1000);
}

// --- LIGHT / DARK MODE ---
function initTheme() {
    const toggleBtn = document.getElementById("theme-toggle");
    if (!toggleBtn) return;
    
    // Check saved theme or default to dark
    const savedTheme = localStorage.getItem("securenet-theme") || "dark";
    document.documentElement.setAttribute("data-theme", savedTheme);
    
    toggleBtn.addEventListener("click", () => {
        const currentTheme = document.documentElement.getAttribute("data-theme");
        const newTheme = currentTheme === "dark" ? "light" : "dark";
        
        document.documentElement.setAttribute("data-theme", newTheme);
        localStorage.setItem("securenet-theme", newTheme);
        
        // Re-color charts for readability in light mode
        updateChartsTheme(newTheme);
    });
}

// --- TOAST NOTIFICATIONS ---
function showToast(title, message, type = "info") {
    const container = document.getElementById("toast-container");
    if (!container) return;
    
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    
    let iconClass = "bi-info-circle-fill";
    if (type === "warning") iconClass = "bi-exclamation-triangle-fill";
    if (type === "error") iconClass = "bi-shield-fill-x";
    
    toast.innerHTML = `
        <div class="toast-icon">
            <i class="bi ${iconClass}"></i>
        </div>
        <div class="toast-body">
            <span class="toast-title">${title}</span>
            <span class="toast-msg">${message}</span>
        </div>
    `;
    
    container.appendChild(toast);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        toast.style.animation = "slideIn 0.3s cubic-bezier(0.16, 1, 0.3, 1) reverse forwards";
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

// Poll backend alerts every 4 seconds to push as Toast notifications
function initNotificationsPoll() {
    // Only poll if logged in
    if (!document.querySelector(".navbar .user-control")) return;
    
    function poll() {
        fetch("/api/notifications")
            .then(res => res.json())
            .then(data => {
                if (data && data.length > 0) {
                    data.forEach(notif => {
                        showToast(notif.title, notif.message, notif.type);
                        
                        // Dynamically prepend alert in Sidebar log list if on Dashboard
                        prependAlertToSidebar(notif);
                    });
                }
            })
            .catch(err => console.error("Notification poll error:", err));
    }
    
    // Run immediately and then periodically
    poll();
    setInterval(poll, 4000);
}

function prependAlertToSidebar(notif) {
    const list = document.getElementById("latest-alerts-list");
    if (!list) return;
    
    // Remove empty alerts message if present
    const emptyMsg = list.querySelector(".empty-alerts");
    if (emptyMsg) emptyMsg.remove();
    
    const alertItem = document.createElement("div");
    alertItem.className = "alert-item";
    
    const category = notif.title.includes("URL") ? "URL Scan" : "Network Scan";
    const iconClass = category === "URL Scan" ? "bi-link" : "bi-hdd-network";
    
    // Determine confidence message
    let conf = "100.0%";
    if (notif.message.includes("Confidence:")) {
        const matches = notif.message.match(/Confidence:\s*([0-9.]+%)/);
        if (matches) conf = matches[1];
    }
    
    // Clean message detail
    let detail = notif.message.split("\n").slice(1).join(" ").replace("URL:", "URL:").replace("Intrusion Type:", "Intrusion:");
    
    alertItem.innerHTML = `
        <div class="alert-icon bg-red-dim text-red">
            <i class="bi ${iconClass}"></i>
        </div>
        <div class="alert-content">
            <p class="alert-desc">${detail}</p>
            <div class="alert-meta">
                <span class="alert-time">${notif.timestamp}</span>
                <span class="alert-conf">Conf: ${conf}</span>
            </div>
        </div>
    `;
    
    list.insertBefore(alertItem, list.firstChild);
    
    // Limit log height list to 6 items
    const items = list.querySelectorAll(".alert-item");
    if (items.length > 6) {
        items[items.length - 1].remove();
    }
}

// --- SCAN TABS ---
function switchScanTab(tabName) {
    document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));
    document.querySelectorAll(".scan-tab-content").forEach(content => content.classList.remove("active"));
    
    // Activate clicked tab
    const clickedBtn = event.currentTarget;
    clickedBtn.classList.add("active");
    
    document.getElementById(`scan-tab-${tabName}`).classList.add("active");
}

// --- ADMIN TABS ---
function switchAdminTab(tabName) {
    document.querySelectorAll(".admin-tab-btn").forEach(btn => btn.classList.remove("active"));
    document.querySelectorAll(".admin-tab-content").forEach(content => content.classList.remove("active"));
    
    const clickedBtn = event.currentTarget;
    clickedBtn.classList.add("active");
    
    document.getElementById(`admin-tab-${tabName}`).classList.add("active");
}

// --- DRAG & DROP ---
function initUploadDropzone() {
    const dropzone = document.getElementById("upload-label");
    const fileInput = document.getElementById("network-file");
    if (!dropzone || !fileInput) return;
    
    fileInput.addEventListener("change", () => {
        if (fileInput.files.length > 0) {
            dropzone.querySelector(".upload-title").textContent = `Selected: ${fileInput.files[0].name}`;
            dropzone.querySelector(".upload-subtitle").textContent = `${(fileInput.files[0].size / 1024).toFixed(1)} KB`;
        }
    });
    
    ["dragenter", "dragover"].forEach(evtName => {
        dropzone.addEventListener(evtName, (e) => {
            e.preventDefault();
            dropzone.style.borderColor = "var(--accent-cyan)";
            dropzone.style.background = "rgba(6, 182, 212, 0.05)";
        }, false);
    });
    
    ["dragleave", "drop"].forEach(evtName => {
        dropzone.addEventListener(evtName, (e) => {
            e.preventDefault();
            dropzone.style.borderColor = "var(--border-color)";
            dropzone.style.background = "none";
        }, false);
    });
    
    dropzone.addEventListener("drop", (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0 && files[0].name.endsWith(".csv")) {
            fileInput.files = files;
            dropzone.querySelector(".upload-title").textContent = `Selected: ${files[0].name}`;
            dropzone.querySelector(".upload-subtitle").textContent = `${(files[0].size / 1024).toFixed(1)} KB`;
        } else {
            showToast("Invalid File Type", "Please drop a valid .csv network log file.", "warning");
        }
    });
}

// --- AJAX FORMS SUBMISSIONS ---
function initForms() {
    const progressBar = document.getElementById("top-bar-progress");
    
    function animateProgress(percent) {
        if (progressBar) progressBar.style.width = `${percent}%`;
    }
    
    // A. URL Scan Form
    const urlForm = document.getElementById("url-scan-form");
    const urlInput = document.getElementById("url-input");
    
    if (urlForm && urlInput) {
        // Function to perform URL scan
        function performUrlScan() {
            const urlValue = urlInput.value.trim();
            if (!urlValue) return;
            
            const btn = document.getElementById("url-scan-btn");
            const spinner = document.getElementById("url-spinner");
            const resultPanel = document.getElementById("url-result-panel");
            
            btn.disabled = true;
            spinner.style.display = "block";
            animateProgress(30);
            
            const formData = new FormData();
            formData.append("url", urlValue);
            
            fetch("/api/scan/url", {
                method: "POST",
                body: formData
            })
            .then(res => res.json())
            .then(data => {
                animateProgress(100);
                setTimeout(() => animateProgress(0), 1000);
                btn.disabled = false;
                spinner.style.display = "none";
                
                if (data.success) {
                    resultPanel.classList.remove("hidden");
                    
                    // Render details
                    document.getElementById("url-result-target").textContent = data.url;
                    document.getElementById("url-result-confidence").textContent = data.confidence;
                    document.getElementById("url-result-time").textContent = data.time;
                    
                    const badge = document.getElementById("url-result-badge");
                    const badgeIcon = document.getElementById("url-result-icon");
                    const badgeText = document.getElementById("url-result-text");
                    
                    if (data.prediction === "Safe") {
                        badge.className = "result-badge bg-green";
                        badgeIcon.className = "bi bi-shield-check";
                        badgeText.textContent = "SAFE VERDICT";
                        
                        // Update metrics locally
                        incrementCounter("stat-safe-urls");
                        window.THREATS_CHART_DATA.safe_urls += 1;
                    } else {
                        badge.className = "result-badge bg-red";
                        badgeIcon.className = "bi bi-shield-slash";
                        badgeText.textContent = "MALICIOUS DETECTED";
                        
                        // Update metrics locally
                        incrementCounter("stat-malicious-urls");
                        incrementCounter("stat-total-threats");
                        window.THREATS_CHART_DATA.malicious_urls += 1;
                    }
                    
                    incrementCounter("stat-total-scans");
                    updateChartsData();
                    showToast("Scan Completed", `Lexical assessment: ${data.prediction}`, data.prediction === "Safe" ? "info" : "error");
                } else {
                    showToast("Scan Error", data.error || "Failed to scan URL.", "error");
                }
            })
            .catch(err => {
                animateProgress(0);
                btn.disabled = false;
                spinner.style.display = "none";
                showToast("System Connection Error", "Could not reach scan server.", "error");
            });
        }
        
        // Auto-scan on paste
        urlInput.addEventListener("paste", (e) => {
            // Wait for paste to complete, then auto-scan
            setTimeout(() => {
                if (urlInput.value.trim()) {
                    performUrlScan();
                }
            }, 100);
        });
        
        // Form submit handler
        urlForm.addEventListener("submit", (e) => {
            e.preventDefault();
            performUrlScan();
        });
    }
    
    // B. Network Threat Scan Form
    const netForm = document.getElementById("network-scan-form");
    if (netForm) {
        netForm.addEventListener("submit", (e) => {
            e.preventDefault();
            const fileInput = document.getElementById("network-file");
            if (fileInput.files.length === 0) {
                showToast("Missing File", "Please select a CSV dataset to scan.", "warning");
                return;
            }
            
            const btn = document.getElementById("network-scan-btn");
            const spinner = document.getElementById("network-spinner");
            const resultPanel = document.getElementById("network-result-panel");
            
            btn.disabled = true;
            spinner.style.display = "block";
            animateProgress(40);
            
            const formData = new FormData();
            formData.append("file", fileInput.files[0]);
            
            fetch("/api/scan/network", {
                method: "POST",
                body: formData
            })
            .then(res => res.json())
            .then(data => {
                animateProgress(100);
                setTimeout(() => animateProgress(0), 1000);
                btn.disabled = false;
                spinner.style.display = "none";
                
                if (data.success) {
                    resultPanel.classList.remove("hidden");
                    
                    // Render details
                    document.getElementById("net-threat-rate").textContent = `${data.threat_rate} Threat Rate`;
                    document.getElementById("net-total-scanned").textContent = data.total_records;
                    document.getElementById("net-threats-count").textContent = data.threats_detected;
                    
                    // Render Breakdown details
                    const breakdown = data.breakdown;
                    const total = data.total_records;
                    
                    renderBreakdownItem("normal", breakdown.Normal, total);
                    renderBreakdownItem("dos", breakdown.DoS, total);
                    renderBreakdownItem("malware", breakdown.Malware, total);
                    renderBreakdownItem("bruteforce", breakdown["Brute-Force"], total);
                    
                    // Update global chart variables
                    window.THREATS_CHART_DATA.normal += breakdown.Normal;
                    window.THREATS_CHART_DATA.dos += breakdown.DoS;
                    window.THREATS_CHART_DATA.malware += breakdown.Malware;
                    window.THREATS_CHART_DATA.bruteforce += breakdown["Brute-Force"];
                    
                    // Update counters at top
                    updateCounterVal("stat-total-threats", parseInt(document.getElementById("stat-total-threats").textContent) + data.threats_detected);
                    
                    updateChartsData();
                    showToast("Intrusion Scan Complete", `Scanned ${data.total_records} rows. Detected ${data.threats_detected} threats.`, data.threats_detected > 0 ? "error" : "info");
                } else {
                    showToast("Scan Error", data.error || "Failed to parse network CSV.", "error");
                }
            })
            .catch(err => {
                animateProgress(0);
                btn.disabled = false;
                spinner.style.display = "none";
                showToast("System Connection Error", "Could not upload dataset.", "error");
            });
        });
    }
}

// Helpers for DOM counter increments
function incrementCounter(elementId) {
    const el = document.getElementById(elementId);
    if (el) {
        el.textContent = parseInt(el.textContent) + 1;
    }
}
function updateCounterVal(elementId, val) {
    const el = document.getElementById(elementId);
    if (el) {
        el.textContent = val;
    }
}

function renderBreakdownItem(typeId, count, total) {
    const percent = total > 0 ? ((count / total) * 100).toFixed(0) : 0;
    document.getElementById(`breakdown-val-${typeId}`).textContent = `${count} (${percent}%)`;
    document.getElementById(`breakdown-fill-${typeId}`).style.width = `${percent}%`;
}

// --- REPORTS EXPORT ---
function downloadReport(format) {
    const range = document.getElementById("report-range").value;
    const progressBar = document.getElementById("top-bar-progress");
    
    if (progressBar) progressBar.style.width = "40%";
    showToast("Generating Report", `Processing ${range} database logs...`, "info");
    
    // Redirect to download trigger
    window.location.href = `/api/reports/generate?format=${format}&range=${range}`;
    
    setTimeout(() => {
        if (progressBar) progressBar.style.width = "100%";
        setTimeout(() => { if (progressBar) progressBar.style.width = "0%"; }, 1000);
    }, 1500);
}

// --- CHART.JS CONFIG ---
let threatTypesChartInstance = null;
let ratioChartInstance = null;

// Copy initial data rendered in templates
window.THREATS_CHART_DATA = window.INITIAL_THREATS_DATA || {
    normal: 0,
    dos: 0,
    malware: 0,
    bruteforce: 0,
    safe_urls: 0,
    malicious_urls: 0
};

function initCharts() {
    const threatCtx = document.getElementById("threatTypesChart");
    const ratioCtx = document.getElementById("ratioChart");
    if (!threatCtx || !ratioCtx) return;
    
    const isDark = document.documentElement.getAttribute("data-theme") === "dark";
    const textThemeColor = isDark ? "#94a3b8" : "#475569";
    const gridThemeColor = isDark ? "rgba(255, 255, 255, 0.05)" : "rgba(0, 0, 0, 0.05)";
    
    // 1. Bar Chart: Threat Types distribution
    threatTypesChartInstance = new Chart(threatCtx, {
        type: 'bar',
        data: {
            labels: ['Normal', 'DoS Attack', 'Malware Download', 'Brute-Force'],
            datasets: [{
                label: 'Log Count',
                data: [
                    window.THREATS_CHART_DATA.normal,
                    window.THREATS_CHART_DATA.dos,
                    window.THREATS_CHART_DATA.malware,
                    window.THREATS_CHART_DATA.bruteforce
                ],
                backgroundColor: [
                    'rgba(16, 185, 129, 0.7)',  // Green
                    'rgba(239, 68, 68, 0.7)',   // Red
                    'rgba(139, 92, 246, 0.7)',  // Purple
                    'rgba(245, 158, 11, 0.7)'   // Amber
                ],
                borderColor: [
                    '#10b981',
                    '#ef4444',
                    '#8b5cf6',
                    '#f59e0b'
                ],
                borderWidth: 1.5,
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: textThemeColor }
                },
                y: {
                    grid: { color: gridThemeColor },
                    ticks: { color: textThemeColor, stepSize: 1 }
                }
            }
        }
    });
    
    // 2. Doughnut Chart: Ratio of Safe vs Malicious Scans
    ratioChartInstance = new Chart(ratioCtx, {
        type: 'doughnut',
        data: {
            labels: ['Safe Verdicts', 'Malicious Verdicts'],
            datasets: [{
                data: [
                    window.THREATS_CHART_DATA.safe_urls + window.THREATS_CHART_DATA.normal,
                    window.THREATS_CHART_DATA.malicious_urls + window.THREATS_CHART_DATA.dos + window.THREATS_CHART_DATA.malware + window.THREATS_CHART_DATA.bruteforce
                ],
                backgroundColor: [
                    '#10b981', // Green
                    '#ef4444'  // Red
                ],
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: textThemeColor, padding: 15 }
                }
            },
            cutout: '65%'
        }
    });
}

function updateChartsData() {
    if (!threatTypesChartInstance || !ratioChartInstance) return;
    
    // Update threat type breakdown bar
    threatTypesChartInstance.data.datasets[0].data = [
        window.THREATS_CHART_DATA.normal,
        window.THREATS_CHART_DATA.dos,
        window.THREATS_CHART_DATA.malware,
        window.THREATS_CHART_DATA.bruteforce
    ];
    threatTypesChartInstance.update();
    
    // Update ratio doughnut
    const totalSafe = window.THREATS_CHART_DATA.safe_urls + window.THREATS_CHART_DATA.normal;
    const totalMalicious = window.THREATS_CHART_DATA.malicious_urls + window.THREATS_CHART_DATA.dos + window.THREATS_CHART_DATA.malware + window.THREATS_CHART_DATA.bruteforce;
    
    ratioChartInstance.data.datasets[0].data = [totalSafe, totalMalicious];
    ratioChartInstance.update();
}

function updateChartsTheme(themeName) {
    if (!threatTypesChartInstance || !ratioChartInstance) return;
    
    const isDark = themeName === "dark";
    const textThemeColor = isDark ? "#94a3b8" : "#475569";
    const gridThemeColor = isDark ? "rgba(255, 255, 255, 0.05)" : "rgba(0, 0, 0, 0.05)";
    
    // Update bar chart colors
    threatTypesChartInstance.options.scales.x.ticks.color = textThemeColor;
    threatTypesChartInstance.options.scales.y.ticks.color = textThemeColor;
    threatTypesChartInstance.options.scales.y.grid.color = gridThemeColor;
    threatTypesChartInstance.update();
    
    // Update ratio chart colors
    ratioChartInstance.options.plugins.legend.labels.color = textThemeColor;
    ratioChartInstance.update();
}
