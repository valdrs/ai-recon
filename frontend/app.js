// AI-Augmented Recon & Attack Surface Analyser - Frontend Controller

document.addEventListener("DOMContentLoaded", () => {
    // Check initial system health and provider status
    fetchHealthStatus();
    // Run an initial RAG search to populate the knowledge base explorer tab
    searchRAG("OpenSSH");

    // Event Listeners
    document.getElementById("scanForm").addEventListener("submit", handleScanSubmit);
    document.getElementById("ragSearchBtn").addEventListener("click", () => {
        const query = document.getElementById("ragSearchInput").value;
        if (query) searchRAG(query);
    });
    document.getElementById("ragSearchInput").addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            e.preventDefault();
            searchRAG(e.target.value);
        }
    });

    // Tab Navigation
    document.querySelectorAll(".tab-btn").addEventListener ? null : document.querySelectorAll(".tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
            btn.classList.add("active");
            document.getElementById(btn.dataset.tab).classList.add("active");
        });
    });
});

async function fetchHealthStatus() {
    try {
        const response = await fetch("/api/v1/health");
        const data = await response.json();
        const providerBadge = document.getElementById("providerBadge");
        providerBadge.innerHTML = `LLM Engine: <span style="text-transform: uppercase;">${data.active_llm_provider}</span>`;
    } catch (error) {
        console.error("Health check error:", error);
    }
}

async function handleScanSubmit(e) {
    e.preventDefault();
    
    const target = document.getElementById("targetInput").value.trim();
    const scanType = document.getElementById("scanType").value;
    const modules = Array.from(document.querySelectorAll('input[name="module"]:checked')).map(cb => cb.value);

    if (!modules.length) {
        alert("Please select at least one reconnaissance module.");
        return;
    }

    // Show loading
    document.getElementById("loadingIndicator").classList.remove("hidden");
    document.getElementById("resultsSection").classList.add("hidden");
    const scanBtn = document.getElementById("scanBtn");
    scanBtn.disabled = true;

    // Simulate progress bar
    let progress = 10;
    const progressBar = document.getElementById("progressBar");
    const loaderMsg = document.getElementById("loaderMessage");
    progressBar.style.width = `${progress}%`;

    const progressInterval = setInterval(() => {
        if (progress < 85) {
            progress += 15;
            progressBar.style.width = `${progress}%`;
            if (progress === 40) loaderMsg.textContent = "Applying prompt injection guardrails to raw banner outputs...";
            if (progress === 70) loaderMsg.textContent = "Querying FAISS vector store for CVE and MITRE ATT&CK citations...";
        }
    }, 450);

    try {
        const response = await fetch("/api/v1/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                target: target,
                scan_type: scanType,
                modules: modules,
                enable_ai_synthesis: true
            })
        });

        const report = await response.json();
        clearInterval(progressInterval);
        progressBar.style.width = "100%";

        setTimeout(() => {
            document.getElementById("loadingIndicator").classList.add("hidden");
            renderScanReport(report);
            document.getElementById("resultsSection").classList.remove("hidden");
            scanBtn.disabled = false;
        }, 500);

    } catch (error) {
        clearInterval(progressInterval);
        document.getElementById("loadingIndicator").classList.add("hidden");
        scanBtn.disabled = false;
        alert("Scan execution failed: " + error.message);
    }
}

function renderScanReport(report) {
    // Stats
    document.getElementById("statFindingsCount").textContent = report.raw_findings_count;
    document.getElementById("statInjectionsCount").textContent = report.sanitization_summary?.prompt_injections_neutralized || 0;
    
    // Count total RAG citations across findings
    let totalCitations = 0;
    report.vulnerabilities.forEach(v => { totalCitations += (v.rag_citations?.length || 0); });
    document.getElementById("statCitationsCount").textContent = totalCitations;

    const duration = (new Date(report.scan_completed_at) - new Date(report.scan_started_at)) / 1000;
    document.getElementById("statDuration").textContent = `${duration.toFixed(2)}s`;

    // Executive Summary Gauge
    const exec = report.executive_summary;
    const score = exec.overall_risk_score;
    document.getElementById("gaugeScore").textContent = score;
    const circle = document.getElementById("gaugeCircle");
    const badge = document.getElementById("gaugeTierBadge");
    badge.textContent = exec.risk_tier.toUpperCase();

    // Set gauge colors by severity
    if (exec.risk_tier === "Critical") {
        circle.style.borderColor = "var(--severity-critical)";
        circle.style.boxShadow = "0 0 25px rgba(239, 68, 68, 0.4)";
        badge.className = "gauge-tier badge sev-critical";
    } else if (exec.risk_tier === "High") {
        circle.style.borderColor = "var(--severity-high)";
        circle.style.boxShadow = "0 0 25px rgba(249, 115, 22, 0.4)";
        badge.className = "gauge-tier badge sev-high";
    } else {
        circle.style.borderColor = "var(--severity-medium)";
        circle.style.boxShadow = "0 0 25px rgba(234, 179, 8, 0.4)";
        badge.className = "gauge-tier badge sev-medium";
    }

    document.getElementById("execSummaryText").textContent = exec.summary_text;

    // Vectors and Recommendations
    const vecList = document.getElementById("execAttackVectors");
    vecList.innerHTML = exec.key_attack_vectors.map(v => `<li>${v}</li>`).join("");

    const recList = document.getElementById("execRecommendations");
    recList.innerHTML = exec.critical_recommendations.map(r => `<li>${r}</li>`).join("");

    // Tab Counts
    document.getElementById("tabCountVulns").textContent = report.vulnerabilities.length;

    // Render Vulnerability Cards
    const vulnsContainer = document.getElementById("vulnsListContainer");
    vulnsContainer.innerHTML = report.vulnerabilities.map(v => {
        const sevClass = `sev-${v.severity.toLowerCase()}`;
        
        const citsHtml = (v.rag_citations || []).map(c => 
            `<span class="citation-tag" title="${c.content.replace(/"/g, '&quot;')}">📚 ${c.doc_id} (${c.category})</span>`
        ).join("");

        const stepsHtml = (v.remediation_steps || []).map(step => {
            // Highlight backticked code items
            const formatted = step.replace(/`([^`]+)`/g, '<code>$1</code>');
            return `<li>${formatted}</li>`;
        }).join("");

        return `
            <div class="vuln-card">
                <div class="vuln-header">
                    <div class="vuln-title-row">
                        <span class="severity-pill ${sevClass}">${v.severity}</span>
                        <h3>${v.title}</h3>
                    </div>
                    <span class="cvss-score">CVSS ${v.cvss_estimate.toFixed(1)}</span>
                </div>
                <p class="vuln-meta">Affected Service: <strong style="color: var(--accent-cyan);">${v.affected_service}</strong></p>
                <p class="vuln-desc">${v.description}</p>
                <div class="vuln-impact">
                    <strong>Technical Impact:</strong> ${v.technical_impact}
                </div>
                <div class="remediation-box">
                    <h4>Actionable Remediation & Hardening Steps:</h4>
                    <ol>${stepsHtml}</ol>
                </div>
                ${citsHtml ? `<div class="citation-tags"><strong>RAG Citations:</strong> ${citsHtml}</div>` : ''}
            </div>
        `;
    }).join("");

    // Collect all unique MITRE techniques across findings
    const mitreMap = new Map();
    report.vulnerabilities.forEach(v => {
        (v.mitre_mappings || []).forEach(m => {
            if (!mitreMap.has(m.technique_id)) {
                mitreMap.set(m.technique_id, m);
            }
        });
    });

    const mitreArray = Array.from(mitreMap.values());
    document.getElementById("tabCountMitre").textContent = mitreArray.length;

    const mitreContainer = document.getElementById("mitreGridContainer");
    mitreContainer.innerHTML = mitreArray.map(m => `
        <div class="mitre-card">
            <span class="mitre-tactic">Tactic: ${m.tactic}</span>
            <h3><span class="mitre-id">${m.technique_id}</span> ${m.technique_name}</h3>
            <p style="font-size: 0.88rem; line-height: 1.5; color: var(--text-muted);">${m.description}</p>
        </div>
    `).join("");
}

async function searchRAG(query) {
    try {
        const response = await fetch(`/api/v1/rag/search?query=${encodeURIComponent(query)}&top_k=6`);
        const data = await response.json();
        
        const container = document.getElementById("ragResultsContainer");
        container.innerHTML = (data.citations || []).map(c => `
            <div class="rag-card">
                <div class="rag-card-header">
                    <span class="citation-tag">${c.category}</span>
                    <span class="rag-score">Similarity: ${(c.similarity_score * 100).toFixed(0)}%</span>
                </div>
                <h3 style="font-size: 1.05rem; color: var(--accent-cyan);">${c.title}</h3>
                <p style="font-size: 0.88rem; line-height: 1.5; color: var(--text-muted);">${c.content}</p>
            </div>
        `).join("");
    } catch (error) {
        console.error("RAG search error:", error);
    }
}
