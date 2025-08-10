document.addEventListener('DOMContentLoaded', function() {
    loadApplications();
    setupEventListeners();
});

let applicationsData = [];

function setupEventListeners() {
    // Create application button
    document.getElementById('create-app-btn').addEventListener('click', openCreateModal);
    
    // Toggle applications button
    document.getElementById('toggle-apps-btn').addEventListener('click', toggleApplications);
    
    // Modal events
    document.getElementById('cancel-create-btn').addEventListener('click', closeCreateModal);
    document.getElementById('create-app-form').addEventListener('submit', handleCreateApplication);
    
    // Close modal on overlay click
    document.getElementById('create-app-modal').addEventListener('click', function(e) {
        if (e.target === this) {
            closeCreateModal();
        }
    });
}

async function loadApplications() {
    try {
        const response = await fetch('/api/staff/application-categories');
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to load applications');
        }
        
        applicationsData = data.applications || [];
        const applicationsOpen = data.applicationsOpen || false;
        
        updateToggleButton(applicationsOpen);
        renderApplications();
        
    } catch (error) {
        console.error('Error loading applications:', error);
        showError('Failed to load applications. Please try again later.');
    }
}

function updateToggleButton(isOpen) {
    const toggleBtn = document.getElementById('toggle-apps-btn');
    const toggleText = document.getElementById('toggle-text');
    
    if (isOpen) {
        toggleBtn.className = 'toggle-btn open';
        toggleText.textContent = 'Close Applications';
    } else {
        toggleBtn.className = 'toggle-btn closed';
        toggleText.textContent = 'Open Applications';
    }
}

function renderApplications() {
    const container = document.getElementById('applications-container');
    
    if (applicationsData.length === 0) {
        container.innerHTML = `
            <div class="applications-closed-notice">
                <h2><i class="fas fa-info-circle"></i> No Applications Created</h2>
                <p>No application periods have been created yet. Click "Create Application" to start accepting applications.</p>
            </div>
        `;
        return;
    }
    
    let html = '<div class="applications-grid">';
    
    applicationsData.forEach(app => {
        const statusClass = app.status === 'open' ? 'status-open' : 'status-closed';
        const statusText = app.status === 'open' ? 'Applications Open' : 'Applications Closed';
        
        html += `
            <div class="application-card" onclick="viewApplication(${app.id})">
                <div class="app-header">
                    <h3 class="app-title">Application #${app.id}</h3>
                    <span class="app-status ${statusClass}">${statusText}</span>
                </div>
                <div class="app-info">
                    <div class="info-row">
                        <span class="info-label">State:</span>
                        <span class="info-value">${statusText}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Created By:</span>
                        <span class="info-value">
                            <img src="https://crafatar.com/avatars/${app.created_by_uuid || '00000000-0000-0000-0000-000000000000'}?size=64&overlay" alt="${app.created_by}">
                            <span style="${app.created_by_color || ''}">${app.created_by}</span>
                        </span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Created At:</span>
                        <span class="info-value">${formatDate(app.created_at)}</span>
                    </div>
                    ${app.last_modified_by ? `
                    <div class="info-row">
                        <span class="info-label">Last ${app.status === 'open' ? 'Opened' : 'Closed'} By:</span>
                        <span class="info-value">
                            <img src="https://crafatar.com/avatars/${app.last_modified_by_uuid || '00000000-0000-0000-0000-000000000000'}?size=64&overlay" alt="${app.last_modified_by}">
                            <span style="${app.last_modified_by_color || ''}">${app.last_modified_by}</span>
                        </span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Last ${app.status === 'open' ? 'Opened' : 'Closed'} At:</span>
                        <span class="info-value">${formatDate(app.last_modified_at)}</span>
                    </div>
                    ` : ''}
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    container.innerHTML = html;
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

function viewApplication(applicationId) {
    window.location.href = `/staff/applications/${applicationId}`;
}

function openCreateModal() {
    document.getElementById('create-app-modal').style.display = 'flex';
}

function closeCreateModal() {
    document.getElementById('create-app-modal').style.display = 'none';
    document.getElementById('create-app-form').reset();
}

async function handleCreateApplication(event) {
    event.preventDefault();
    
    const form = event.target;
    const formData = new FormData(form);
    const submitBtn = form.querySelector('button[type="submit"]');
    
    submitBtn.disabled = true;
    submitBtn.textContent = 'Creating...';
    
    try {
        const response = await fetch('/api/staff/application-categories/create', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(Object.fromEntries(formData))
        });
        
        const result = await response.json();
        
        if (response.ok) {
            closeCreateModal();
            showSuccess('Application created successfully!');
            loadApplications(); // Reload the applications
        } else {
            throw new Error(result.message || 'Failed to create application');
        }
        
    } catch (error) {
        console.error('Error creating application:', error);
        showError(error.message || 'Failed to create application. Please try again.');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Create Application';
    }
}

async function toggleApplications() {
    const toggleBtn = document.getElementById('toggle-apps-btn');
    const originalText = toggleBtn.innerHTML;
    
    toggleBtn.disabled = true;
    toggleBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Updating...';
    
    try {
        const response = await fetch('/api/staff/applications/toggle', {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showSuccess(result.message);
            loadApplications(); // Reload to get updated status
        } else {
            throw new Error(result.message || 'Failed to toggle applications');
        }
        
    } catch (error) {
        console.error('Error toggling applications:', error);
        showError(error.message || 'Failed to update application status. Please try again.');
    } finally {
        toggleBtn.disabled = false;
        toggleBtn.innerHTML = originalText;
    }
}

function showSuccess(message) {
    // Create a temporary success notification
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #28a745;
        color: white;
        padding: 15px 20px;
        border-radius: 5px;
        z-index: 10000;
        font-weight: bold;
    `;
    notification.innerHTML = `<i class="fas fa-check-circle"></i> ${message}`;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 3000);
}

function showError(message) {
    // Create a temporary error notification
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #dc3545;
        color: white;
        padding: 15px 20px;
        border-radius: 5px;
        z-index: 10000;
        font-weight: bold;
    `;
    notification.innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${message}`;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 5000);
}