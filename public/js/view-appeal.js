document.addEventListener('DOMContentLoaded', () => {
    const appealId = window.location.pathname.split('/').pop();
    const container = document.getElementById('appeal-details-container');

    const loadAppealDetails = async () => {
        try {
            const response = await fetch(`/api/appeal/${appealId}`);
            if (!response.ok) throw new Error('Appeal not found.');
            const appeal = await response.json();
            renderAppeal(appeal);
        } catch (error) {
            container.innerHTML = `<h1>Error: ${error.message}</h1>`;
        }
    };

    const renderAppeal = (appeal) => {
        const punishmentReason = appeal.punishment_type === 'ban' ? appeal.banReason : appeal.muteReason;
        const punisher = appeal.punishment_type === 'ban' ? appeal.banBy : appeal.muteBy;

        // ✅ NEW: Conditionally render the response form or a read-only box
        let responseHtml = '';
        if (appeal.response) {
            // If a response exists, display it as plain text
            responseHtml = `
                <label for="response-text">Staff Response</label>
                <div class="response-text-display">${appeal.response}</div>
            `;
        } else {
            // If no response, show the editable form
            responseHtml = `
                <form id="response-form">
                    <label for="response-text">Staff Response</label>
                    <textarea id="response-text" placeholder="Enter your response..."></textarea>
                    <button type="submit" class="action-btn update-btn">Update Response</button>
                </form>
            `;
        }

        container.innerHTML = `
            <div class="appeal-grid">
                <div class="card">
                    <h2>Appeal Details</h2>
                    <div class="info-item">
                        <span class="label">Appealing Player</span>
                        <p class="value"><a href="/profile/${appeal.username}" style="${appeal.colorStyle}">${appeal.username}</a></p>
                    </div>
                    <div class="info-item">
                        <span class="label">Appeal Reason</span>
                        <div class="appeal-reason">${appeal.reason}</div>
                    </div>
                </div>
                <div class="card">
                    <h2>Original Punishment</h2>
                    <div class="info-item">
                        <span class="label">Type</span>
                        <p class="value">${appeal.punishment_type.toUpperCase()}</p>
                    </div>
                    <div class="info-item">
                        <span class="label">Punished By</span>
                        <p class="value">${punisher || 'N/A'}</p>
                    </div>
                    <div class="info-item">
                        <span class="label">Reason</span>
                        <p class="value">${punishmentReason || 'N/A'}</p>
                    </div>
                    <div class="actions-card">
                        ${responseHtml}
                        <div style="margin-top: 20px; display: flex; gap: 10px;">
                            <button class="action-btn accept-btn" data-outcome="Accepted">Accept Appeal</button>
                            <button class="action-btn deny-btn" data-outcome="Denied">Deny Appeal</button>
                        </div>
                    </div>
                </div>
            </div>
        `;

        // Only add the event listener if the form exists on the page
        const responseForm = document.getElementById('response-form');
        if (responseForm) {
            responseForm.addEventListener('submit', handleResponseUpdate);
        }
        
        document.querySelectorAll('.accept-btn, .deny-btn').forEach(button => {
            button.addEventListener('click', () => handleAppeal(button.dataset.outcome, appeal.punishment_id, appeal.punishment_type));
        });
    };

    const handleResponseUpdate = async (e) => {
        e.preventDefault();
        const responseText = document.getElementById('response-text').value;
        try {
            const response = await fetch(`/api/appeal/update-response/${appealId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ response: responseText })
            });
            const result = await response.json();
            alert(result.message);
            if (result.success) {
                loadAppealDetails(); // Refresh the page to show the read-only response
            }
        } catch (error) {
            alert('An error occurred.');
        }
    };

    const handleAppeal = async (outcome, punishment_id, punishment_type) => {
        if (!confirm(`Are you sure you want to ${outcome.toLowerCase()} this appeal?`)) return;
        try {
            const response = await fetch(`/api/appeal/handle/${appealId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ outcome, punishment_id, punishment_type })
            });
            const result = await response.json();
            alert(result.message);
            if (result.success) {
                window.location.href = '/staff/appeals';
            }
        } catch (error) {
            alert('An error occurred.');
        }
    };

    loadAppealDetails();
});
