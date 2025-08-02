/**
 * This script manages the functionality of the individual report viewing page.
 * It fetches report details from the server, renders the content dynamically,
 * and handles staff actions like claiming and closing reports.
 */
document.addEventListener('DOMContentLoaded', () => {
    // --- GLOBAL VARIABLES ---
    const reportId = window.location.pathname.split('/').pop();
    const container = document.getElementById('report-details-container');
    let currentAdminUsername = ''; // To store the logged-in staff's name

    /**
     * Main function to initialize the page.
     * Fetches the current user's session status and the specific report details.
     */
    const loadReportDetails = async () => {
        try {
            // First, get the current admin's username for permission checks
            const authRes = await fetch('/api/auth/status');
            const authData = await authRes.json();
            if (authData.loggedIn) {
                currentAdminUsername = authData.user.username;
            }

            // Then, fetch the report data
            const response = await fetch(`/api/report/${reportId}`);
            if (!response.ok) throw new Error('Report not found or you do not have permission to view it.');
            
            const report = await response.json();
            renderReport(report);

        } catch (error) {
            container.innerHTML = `<h1 class="loading-text">${error.message}</h1>`;
        }
    };

    /**
     * Renders the entire report page based on the data fetched from the server.
     * @param {object} report - The report data object.
     */
    const renderReport = (report) => {
        const defaultColor = 'color: #AAAAAA;';
        const reporterStyle = report.reporterStyle || defaultColor;
        const reportedStyle = report.reportedStyle || defaultColor;

        const evidenceUrl = parseEvidenceUrl(report.evidence_link);

        // Determine the status and action buttons to display
        let statusHtml = '';
        let actionsHtml = '';
        if (report.status === 'claimed') {
            statusHtml = `<span class="status-badge status-claimed">Claimed</span>`;
            if (report.claimed_by === currentAdminUsername) {
                actionsHtml = `<button id="close-report-btn" class="action-btn close-btn">Close Report</button>`;
            } else {
                actionsHtml = `<p class="claimed-by-text">Claimed by: ${report.claimed_by}</p>`;
            }
        } else {
            statusHtml = `<span class="status-badge status-pending">Pending</span>`;
            actionsHtml = `<button id="claim-report-btn" class="action-btn claim-btn">Claim Report</button>`;
        }
        
        // Construct the final HTML for the page
        container.innerHTML = `
            <header class="report-header">
                <h1>Report #${report.id} Details</h1>
                ${statusHtml}
            </header>
            <div class="report-grid">
                <div class="video-card">
                    <iframe class="video-player" src="${evidenceUrl}" frameborder="0" allowfullscreen></iframe>
                </div>
                <div class="details-card">
                    <div class="details-card-content">
                        <h2>Information</h2>
                        <div class="info-item">
                            <span class="label">Reported Player</span>
                            <span class="value"><a href="/profile/${report.reported_username}" style="${reportedStyle}">${report.reported_username}</a></span>
                        </div>
                        <div class="info-item">
                            <span class="label">Reported By</span>
                            <span class="value"><a href="/profile/${report.reporter_username}" style="${reporterStyle}">${report.reporter_username}</a></span>
                        </div>
                        <div class="info-item">
                            <span class="label">Report Type</span>
                            <span class="value">${report.report_type}</span>
                        </div>
                        <div class="info-item extra-notes">
                            <span class="label">Extra Notes</span>
                            <p class="value">${report.extra_notes || 'None provided.'}</p>
                        </div>
                    </div>
                    <div class="details-actions">
                        ${actionsHtml}
                    </div>
                </div>
            </div>
        `;
        
        // Add event listeners to the newly created buttons
        const claimBtn = document.getElementById('claim-report-btn');
        if (claimBtn) claimBtn.addEventListener('click', handleClaim);
        
        const closeBtn = document.getElementById('close-report-btn');
        if (closeBtn) closeBtn.addEventListener('click', () => openCloseModal(report.id));
    };

    /**
     * Handles the logic for claiming a report.
     */
    const handleClaim = async () => {
        if (!confirm('Are you sure you want to claim this report?')) return;
        try {
            const response = await fetch(`/api/reports/claim/${reportId}`, { method: 'POST' });
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: 'Server returned a non-JSON error.' }));
                throw new Error(errorData.message || `Server responded with status: ${response.status}`);
            }
            loadReportDetails(); // Refresh the page content to show updated status
        } catch (error) {
            console.error('Error during report claim:', error);
            alert(`An error occurred while claiming the report: ${error.message}`);
        }
    };

    // --- Close Report Modal Logic ---
    const closeReportModal = document.getElementById('close-report-modal');
    const closeForm = document.getElementById('close-form');
    
    const openCloseModal = (id) => {
        document.getElementById('close-modal-report-id').textContent = id;
        closeForm.reset();
        closeReportModal.style.display = 'flex';
    };

    document.getElementById('close-modal-cancel').addEventListener('click', () => {
        closeReportModal.style.display = 'none';
    });

    closeForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const outcome = document.getElementById('close-outcome').value;
        try {
            const response = await fetch(`/api/reports/close/${reportId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ outcome })
            });
            
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: 'Server returned a non-JSON error.' }));
                throw new Error(errorData.message || `Server responded with status: ${response.status}`);
            }

            const result = await response.json();
            if (result.success) {
                alert('Report closed successfully!');
                window.location.href = '/staff/admin-reports'; // Redirect back to the list
            } else {
                alert(result.message || 'Failed to close report.');
            }
        } catch (error) {
            console.error('Error during report closure:', error);
            alert(`An error occurred while closing the report: ${error.message}`);
        }
    });

    /**
     * Parses various video links into a universal embeddable URL.
     * @param {string} url - The original evidence link.
     * @returns {string} The embeddable URL.
     */
    function parseEvidenceUrl(url) {
        let videoId = null;
        if (url.includes('streamable.com')) {
            return `https://streamable.com/e/${url.split('/').pop()}`;
        } else if (url.includes('youtube.com/watch?v=')) {
            videoId = new URL(url).searchParams.get('v');
        } else if (url.includes('youtu.be/')) {
            videoId = url.split('youtu.be/')[1].split('?')[0];
        }
        
        if (videoId) {
            return `https://www.youtube-nocookie.com/embed/${videoId}`;
        }
        return url; // Return original URL if it's not a recognized format
    }

    // --- INITIALIZE THE PAGE ---
    loadReportDetails();
});
