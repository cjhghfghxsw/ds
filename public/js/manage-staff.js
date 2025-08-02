document.addEventListener('DOMContentLoaded', async () => {
    const username = window.location.pathname.split('/').pop();
    const container = document.getElementById('manage-area');
    const confirmationModal = document.getElementById('confirmation-modal');
    const alertModal = document.getElementById('alert-modal');

    // Fetch player data to get their rank color
    const playerResponse = await fetch(`/api/player/${username}`);
    const playerData = await playerResponse.json();
    const playerNameStyle = playerData.colorStyle || '';

    // Data for forms
    const warnReasons = ["Breaking staff rules┃مخالفة قوانين الادارة", "Breaking server rules┃مخالة قوانين السيرفر", "Muting without evidence┃كتم بدون دليل", "Banning without evidence┃حظر بدون دليل", "Muting with a weak evidence ┃كتم بـ دليل ضعيف", "Banning with a weak evidence┃حظر بـ دليل ضعيف", "Rank demote┃سحب رتبة"];
    const promoteRanks = { "srmod": "Senior Moderator", "admin": "Admin", "headadmin": "Head-Admin", "manager": "Manager" };
    const demoteRanks = { "mod": "Mod", "default": "Member" };

    // Build Page HTML
    container.innerHTML = `
        <header class="manage-header">
            <h1 style="${playerNameStyle}">${username}</h1>
            <p>Select an action to manage this staff member.</p>
        </header>
        <div class="actions-grid">
            <div class="action-card full-width">
                <h2><i class="fas fa-exclamation-triangle"></i> Issue Warning</h2>
                <form id="warn-form" class="action-form">
                    <select class="form-select">${warnReasons.map(r => `<option value="${r}">${r}</option>`).join('')}</select>
                    <button type="submit" class="action-btn warn-btn">Warn Player</button>
                </form>
            </div>
            <div class="action-card">
                <h2><i class="fas fa-arrow-up"></i> Promote</h2>
                <form id="promote-form" class="action-form">
                    <select class="form-select">${Object.entries(promoteRanks).map(([val, name]) => `<option value="${val}">${name}</option>`).join('')}</select>
                    <button type="submit" class="action-btn promote-btn">Promote</button>
                </form>
            </div>
            <div class="action-card">
                <h2><i class="fas fa-arrow-down"></i> Demote</h2>
                <form id="demote-form" class="action-form">
                    <select class="form-select">${Object.entries(demoteRanks).map(([val, name]) => `<option value="${val}">${name}</option>`).join('')}</select>
                    <button type="submit" class="action-btn demote-btn">Demote</button>
                </form>
            </div>
        </div>
    `;

    // --- Custom Modal & Alert Logic ---
    let confirmCallback = null;
    document.getElementById('modal-confirm').addEventListener('click', () => {
        if (confirmCallback) confirmCallback();
        confirmationModal.style.display = 'none';
    });
    document.getElementById('modal-cancel').addEventListener('click', () => {
        confirmationModal.style.display = 'none';
    });
    document.getElementById('alert-ok-btn').addEventListener('click', () => {
        alertModal.style.display = 'none';
    });

    const showConfirmationModal = (onConfirm) => {
        confirmationModal.style.display = 'flex';
        confirmCallback = onConfirm;
    };
    
    const showAlertModal = (message) => {
        document.getElementById('alert-text').textContent = message;
        alertModal.style.display = 'flex';
    };

    // --- Event Listeners ---
    document.getElementById('warn-form').addEventListener('submit', e => handleAction(e, '/api/staff/warn', { username, reason: e.target.querySelector('select').value }));
    document.getElementById('promote-form').addEventListener('submit', e => handleAction(e, '/api/staff/promote', { username, newRank: e.target.querySelector('select').value }));
    document.getElementById('demote-form').addEventListener('submit', e => handleAction(e, '/api/staff/demote', { username, newRank: e.target.querySelector('select').value }));

    // Helper function to handle form submissions
    function handleAction(event, url, body) {
        event.preventDefault();
        
        showConfirmationModal(async () => {
            try {
                const response = await fetch(url, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                const result = await response.json();
                showAlertModal(result.message);
            } catch (error) {
                showAlertModal('An error occurred.');
            }
        });
    }
});