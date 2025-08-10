document.addEventListener('DOMContentLoaded', function() {
    const applicationId = getApplicationIdFromUrl();
    if (applicationId) {
        loadApplicationData(applicationId);
    } else {
        showError('Invalid application ID');
    }
});

function getApplicationIdFromUrl() {
    const pathParts = window.location.pathname.split('/');
    return pathParts[pathParts.length - 1];
}

async function loadApplicationData(applicationId) {
    try {
        const response = await fetch(`/api/staff/applications/${applicationId}/submissions`);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to load application data');
        }
        
        // Update page elements
        document.getElementById('breadcrumb-app-id').textContent = `Application #${applicationId}`;
        document.getElementById('page-title').textContent = `Applications #${applicationId}`;
        document.getElementById('applications-count').textContent = `(${data.applications.length} Applications)`;
        
        // Render the applications table
        renderApplicationsTable(data.applications);
        
    } catch (error) {
        console.error('Error loading application data:', error);
        showError('Failed to load application data. Please try again later.');
    }
}

function renderApplicationsTable(applications) {
    const container = document.getElementById('table-container');
    
    if (applications.length === 0) {
        container.innerHTML = `
            <div class="no-applications-notice">
                <i class="fas fa-inbox"></i>
                <h3>No Applications Yet</h3>
                <p>No applications have been submitted for this category yet.</p>
            </div>
        `;
        return;
    }
    
    // Create the table HTML
    let tableHTML = `
        <table id="applications-table" class="display" style="width:100%">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>IGN</th>
                    <th>Hours</th>
                    <th>Discord ID</th>
                    <th>At</th>
                    <th>Last Modified By</th>
                    <th>Last Modified At</th>
                    <th>State</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    applications.forEach(app => {
        const statusClass = getStatusClass(app.status);
        const statusText = getStatusText(app.status);
        
        tableHTML += `
            <tr>
                <td>${app.id}</td>
                <td>
                    <div class="player-cell">
                        <img src="https://crafatar.com/avatars/${app.uuid || '00000000-0000-0000-0000-000000000000'}?size=64&overlay" 
                             alt="${app.username}" class="player-skin">
                        <div class="player-info">
                            <div class="player-name" style="${app.colorStyle || ''}">${app.username}</div>
                            <div class="player-hours">${formatPlaytime(app.playtime)}</div>
                        </div>
                    </div>
                </td>
                <td>${formatPlaytime(app.playtime)}</td>
                <td>${app.discord || 'N/A'}</td>
                <td>${formatDate(app.created_at)}</td>
                <td>
                    ${app.handled_by ? `
                        <div class="player-cell">
                            <img src="https://crafatar.com/avatars/${app.handled_by_uuid || '00000000-0000-0000-0000-000000000000'}?size=64&overlay" 
                                 alt="${app.handled_by}" class="player-skin">
                            <span style="${app.handled_by_color || ''}">${app.handled_by}</span>
                        </div>
                    ` : 'N/A'}
                </td>
                <td>${app.handled_at ? formatDate(app.handled_at) : 'N/A'}</td>
                <td>
                    <span class="status-badge ${statusClass}">${statusText}</span>
                </td>
                <td>
                    <a href="/staff/applications/view/${app.id}" class="action-btn view-btn">
                        <i class="fas fa-eye"></i> View
                    </a>
                </td>
            </tr>
        `;
    });
    
    tableHTML += `
            </tbody>
        </table>
    `;
    
    container.innerHTML = tableHTML;
    
    // Initialize DataTable
    $('#applications-table').DataTable({
        pageLength: 10,
        order: [[0, 'desc']], // Order by ID descending
        columnDefs: [
            { orderable: false, targets: [8] } // Disable sorting on Actions column
        ],
        language: {
            search: "Search:",
            lengthMenu: "Show _MENU_ entries",
            info: "Showing _START_ to _END_ of _TOTAL_ applications",
            paginate: {
                first: "First",
                last: "Last",
                next: "Next",
                previous: "Previous"
            }
        }
    });
}

function getStatusClass(status) {
    switch (status) {
        case 'pending':
        case 'reviewing':
            return 'status-pending';
        case 'approved':
            return 'status-accepted';
        case 'denied':
            return 'status-rejected';
        default:
            return 'status-pending';
    }
}

function getStatusText(status) {
    switch (status) {
        case 'pending':
            return 'Pending';
        case 'reviewing':
            return 'Reviewing';
        case 'approved':
            return 'Accepted';
        case 'denied':
            return 'Rejected';
        default:
            return 'Pending';
    }
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function formatPlaytime(milliseconds) {
    if (!milliseconds) return '0h';
    const hours = Math.floor(milliseconds / 3600000);
    return `${hours}h`;
}

function showError(message) {
    const container = document.getElementById('table-container');
    container.innerHTML = `
        <div class="no-applications-notice">
            <i class="fas fa-exclamation-triangle" style="color: #dc3545;"></i>
            <h3>Error</h3>
            <p>${message}</p>
        </div>
    `;
}