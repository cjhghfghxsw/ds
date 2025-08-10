document.addEventListener('DOMContentLoaded', function() {
    const applicationId = getApplicationIdFromUrl();
    if (applicationId) {
        loadApplicationDetails(applicationId);
    } else {
        showError('Invalid application ID');
    }
    
    setupEventListeners();
});

function getApplicationIdFromUrl() {
    const pathParts = window.location.pathname.split('/');
    return pathParts[pathParts.length - 1];
}

function setupEventListeners() {
    // Modal events
    document.getElementById('cancel-response-btn').addEventListener('click', closeResponseModal);
    document.getElementById('response-form').addEventListener('submit', handleResponseSubmission);
    
    // Close modal on overlay click
    document.getElementById('response-modal').addEventListener('click', function(e) {
        if (e.target === this) {
            closeResponseModal();
        }
    });
}

async function loadApplicationDetails(applicationId) {
    try {
        const response = await fetch(`/api/staff/applications/view/${applicationId}`);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to load application details');
        }
        
        renderApplicationDetails(data);
        
    } catch (error) {
        console.error('Error loading application details:', error);
        showError('Failed to load application details. Please try again later.');
    }
}

function renderApplicationDetails(application) {
    // Update breadcrumb
    document.getElementById('breadcrumb-category-link').href = `/staff/applications/${application.category_id || '1'}`;
    document.getElementById('breadcrumb-category-link').textContent = `Application #${application.category_id || '1'}`;
    document.getElementById('breadcrumb-app-id').textContent = `Application #${application.id}`;
    
    const container = document.getElementById('application-content');
    
    const statusClass = getStatusClass(application.status);
    const statusText = getStatusText(application.status);
    
    container.innerHTML = `
        <div class="application-grid">
            <div class="application-details-card">
                <div class="card-header">
                    <i class="fas fa-file-alt"></i>
                    Application #${application.id}
                </div>
                <div class="card-content">
                    <!-- Player Info -->
                    <div class="player-info-section">
                        <img src="https://crafatar.com/avatars/${application.uuid || '00000000-0000-0000-0000-000000000000'}?size=128&overlay" 
                             alt="${application.username}" class="player-avatar">
                        <div class="player-details">
                            <h2 style="${application.colorStyle || ''}">${application.username}</h2>
                            <div class="player-meta">Playtime: ${formatPlaytime(application.playtime)}</div>
                            <div class="player-meta">Submitted: ${formatDate(application.created_at)}</div>
                        </div>
                    </div>
                    
                    <!-- Basic Information -->
                    <div class="info-section">
                        <h3>Basic Information</h3>
                        <div class="info-grid">
                            <div class="info-item">
                                <span class="info-label">Real Name:</span>
                                <span class="info-value">${application.real_name}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Age:</span>
                                <span class="info-value">${application.age}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Timezone:</span>
                                <span class="info-value">${application.timezone}</span>
                            </div>
                            <div class="info-item">
                                <span class="info-label">Discord:</span>
                                <span class="info-value">${application.discord}</span>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Experience & Motivation -->
                    <div class="info-section">
                        <h3>Experience & Motivation</h3>
                        
                        <div class="question-section">
                            <h4>Previous Moderation Experience:</h4>
                            <div class="question-answer">${application.experience}</div>
                        </div>
                        
                        <div class="question-section">
                            <h4>Why do you want to become a moderator?</h4>
                            <div class="question-answer">${application.motivation}</div>
                        </div>
                        
                        <div class="question-section">
                            <h4>When are you usually online?</h4>
                            <div class="question-answer">${application.availability}</div>
                        </div>
                    </div>
                    
                    <!-- Scenario Questions -->
                    <div class="info-section">
                        <h3>Scenario Questions</h3>
                        
                        <div class="question-section">
                            <h4>A player is repeatedly using inappropriate language in chat despite warnings. How would you handle this?</h4>
                            <div class="question-answer">${application.scenario1}</div>
                        </div>
                        
                        <div class="question-section">
                            <h4>Two players are arguing and the situation is escalating. What steps would you take?</h4>
                            <div class="question-answer">${application.scenario2}</div>
                        </div>
                    </div>
                    
                    ${application.response ? `
                    <div class="response-section">
                        <h4>Staff Response:</h4>
                        <p class="response-text">${application.response}</p>
                    </div>
                    ` : ''}
                </div>
            </div>
            
            <div class="actions-card">
                <div class="card-header">
                    <i class="fas fa-cog"></i>
                    Actions
                </div>
                <div class="actions-content">
                    <div class="status-section">
                        <span class="status-badge ${statusClass}">${statusText}</span>
                        
                        ${application.status === 'reviewing' && application.handled_by ? `
                        <div class="claimed-info">
                            <h4>Claimed by:</h4>
                            <p style="${application.handled_by_color || ''}">${application.handled_by}</p>
                        </div>
                        ` : ''}
                    </div>
                    
                    ${renderActionButtons(application)}
                </div>
            </div>
        </div>
    `;
}

function renderActionButtons(application) {
    if (application.status === 'pending') {
        return `
            <button onclick="claimApplication(${application.id})" class="action-btn claim-btn">
                <i class="fas fa-hand-paper"></i> Claim Application
            </button>
            <button onclick="openResponseModal('approve', ${application.id})" class="action-btn approve-btn">
                <i class="fas fa-check"></i> Approve
            </button>
            <button onclick="openResponseModal('deny', ${application.id})" class="action-btn deny-btn">
                <i class="fas fa-times"></i> Deny
            </button>
        `;
    } else if (application.status === 'reviewing') {
        return `
            <button onclick="openResponseModal('approve', ${application.id})" class="action-btn approve-btn">
                <i class="fas fa-check"></i> Approve
            </button>
            <button onclick="openResponseModal('deny', ${application.id})" class="action-btn deny-btn">
                <i class="fas fa-times"></i> Deny
            </button>
        `;
    } else {
        return `
            <div style="text-align: center; color: #a0aec0; padding: 20px;">
                <i class="fas fa-check-circle" style="font-size: 2em; margin-bottom: 10px;"></i>
                <p>This application has been ${application.status}.</p>
            </div>
        `;
    }
}

async function claimApplication(applicationId) {
    try {
        const response = await fetch(`/api/staff/applications/${applicationId}/claim`, {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            showSuccess(result.message);
            loadApplicationDetails(applicationId); // Reload to show updated status
        } else {
            throw new Error(result.message || 'Failed to claim application');
        }
        
    } catch (error) {
        console.error('Error claiming application:', error);
        showError(error.message || 'Failed to claim application. Please try again.');
    }
}

function openResponseModal(action, applicationId) {
    const modal = document.getElementById('response-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalAction = document.getElementById('modal-action');
    const submitBtn = document.getElementById('submit-response-btn');
    
    modalAction.value = action;
    
    if (action === 'approve') {
        modalTitle.textContent = 'Approve Application';
        submitBtn.textContent = 'Approve';
        submitBtn.className = 'modal-btn approve-btn';
    } else {
        modalTitle.textContent = 'Deny Application';
        submitBtn.textContent = 'Deny';
        submitBtn.className = 'modal-btn deny-btn';
    }
    
    modal.style.display = 'flex';
}

function closeResponseModal() {
    document.getElementById('response-modal').style.display = 'none';
    document.getElementById('response-form').reset();
}

async function handleResponseSubmission(event) {
    event.preventDefault();
    
    const form = event.target;
    const formData = new FormData(form);
    const applicationId = getApplicationIdFromUrl();
    const submitBtn = document.getElementById('submit-response-btn');
    
    submitBtn.disabled = true;
    submitBtn.textContent = 'Processing...';
    
    try {
        const response = await fetch(`/api/staff/applications/${applicationId}/handle`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(Object.fromEntries(formData))
        });
        
        const result = await response.json();
        
        if (response.ok) {
            closeResponseModal();
            showSuccess(result.message);
            loadApplicationDetails(applicationId); // Reload to show updated status
        } else {
            throw new Error(result.message || 'Failed to handle application');
        }
        
    } catch (error) {
        console.error('Error handling application:', error);
        showError(error.message || 'Failed to handle application. Please try again.');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = form.action.value === 'approve' ? 'Approve' : 'Deny';
    }
}

function getStatusClass(status) {
    switch (status) {
        case 'pending':
            return 'status-pending';
        case 'reviewing':
            return 'status-reviewing';
        case 'approved':
            return 'status-approved';
        case 'denied':
            return 'status-denied';
        default:
            return 'status-pending';
    }
}

function getStatusText(status) {
    switch (status) {
        case 'pending':
            return 'Pending';
        case 'reviewing':
            return 'Under Review';
        case 'approved':
            return 'Approved';
        case 'denied':
            return 'Denied';
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

function showSuccess(message) {
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
    const container = document.getElementById('application-content');
    container.innerHTML = `
        <div style="text-align: center; padding: 40px; color: #dc3545;">
            <i class="fas fa-exclamation-triangle" style="font-size: 3em; margin-bottom: 15px;"></i>
            <h3>Error</h3>
            <p>${message}</p>
        </div>
    `;
}