document.addEventListener('DOMContentLoaded', () => {
    const banTabContent = document.getElementById('ban-appeal');
    const muteTabContent = document.getElementById('mute-appeal');
    let punishmentData = {};

    const loadPunishmentStatus = async () => {
        try {
            const response = await fetch('/api/my-punishment');
            const data = await response.json();
            punishmentData = data;
            renderTabs();
        } catch (error) {
            banTabContent.innerHTML = `<div class="notice-box error">Could not check your punishment status.</div>`;
            muteTabContent.innerHTML = `<div class="notice-box error">Could not check your punishment status.</div>`;
        }
    };

    const renderTabs = () => {
        // Render Ban Tab
        if (punishmentData.hasBan) {
            if (punishmentData.appeal) {
                banTabContent.innerHTML = createStatusBox(punishmentData.appeal);
            } else {
                banTabContent.innerHTML = createAppealForm('ban', punishmentData.banDetails);
                document.getElementById('appeal-form-ban').addEventListener('submit', handleAppealSubmit);
            }
        } else {
            banTabContent.innerHTML = `<div class="notice-box info">You are not banned right now!</div>`;
        }

        // Render Mute Tab
        if (punishmentData.hasMute) {
            if (punishmentData.appeal) {
                muteTabContent.innerHTML = createStatusBox(punishmentData.appeal);
            } else {
                muteTabContent.innerHTML = createAppealForm('mute', punishmentData.muteDetails);
                document.getElementById('appeal-form-mute').addEventListener('submit', handleAppealSubmit);
            }
        } else {
            muteTabContent.innerHTML = `<div class="notice-box info">You are not muted right now!</div>`;
        }
    };

    const createStatusBox = (appeal) => {
        if (appeal.response) {
            return `<div class="notice-box response"><h4>Staff Response:</h4><p>${appeal.response}</p></div>`;
        }
        return `<div class="notice-box pending">Your appeal is under review!</div>`;
    };

    const createAppealForm = (type, details) => {
        const reason = type === 'ban' ? details.banReason : details.muteReason;
        const duration = type === 'ban' ? details.banDuration : details.muteDuration;
        const expiresAt = type === 'ban' ? details.banExpiresAt : details.muteExpiresAt;

        return `
            <div class="appeal-form-container">
                <h4>Punishment Details</h4>
                <ul class="punishment-details-list">
                    <li><span>Type:</span> <strong>${type.charAt(0).toUpperCase() + type.slice(1)}</strong></li>
                    <li><span>Reason:</span> <em>"${reason}"</em></li>
                    <li><span>Duration:</span> <strong>${formatDuration(duration)}</strong></li>
                    <li><span>Expires:</span> <strong>${expiresAt === 0 || expiresAt < 0 ? 'Never' : new Date(expiresAt).toLocaleString()}</strong></li>
                </ul>
            </div>
            <form id="appeal-form-${type}" class="appeal-input-form">
                <label for="appeal-reason-${type}">Appeal Reason</label>
                <textarea id="appeal-reason-${type}" placeholder="Explain why you believe this punishment should be removed..." required></textarea>
                <button type="submit">Submit Appeal</button>
            </form>
        `;
    };

    const handleAppealSubmit = async (e) => {
        e.preventDefault();
        const type = e.target.id.includes('ban') ? 'ban' : 'mute';
        const reason = document.getElementById(`appeal-reason-${type}`).value;
        const punishment_id = type === 'ban' ? punishmentData.banDetails.banid : punishmentData.muteDetails.muteid;
        const contentContainer = type === 'ban' ? banTabContent : muteTabContent;

        try {
            const response = await fetch('/api/submit-appeal', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ punishment_id, punishment_type: type, reason })
            });
            const result = await response.json();
            
            if (result.success) {
                contentContainer.innerHTML = `<div class="notice-box success">${result.message}</div>`;
            } else {
                alert(result.message);
            }
        } catch (error) {
            alert('An error occurred while submitting your appeal.');
        }
    };

    // Tab switching logic
    const tabs = document.querySelectorAll('.tab-link');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.getElementById(tab.dataset.tab).classList.add('active');
        });
    });

    loadPunishmentStatus();
});

/**
 * Formats a duration in milliseconds into a human-readable string (e.g., "7d 12h").
 * @param {number} ms - The duration in milliseconds.
 * @returns {string} The formatted duration string.
 */
function formatDuration(ms) {
    if (ms === 0 || ms < 0) return 'Permanent';
    
    let seconds = Math.floor(ms / 1000);
    let minutes = Math.floor(seconds / 60);
    let hours = Math.floor(minutes / 60);
    let days = Math.floor(hours / 24);

    hours = hours % 24;
    minutes = minutes % 60;
    seconds = seconds % 60;

    let result = '';
    if (days > 0) result += `${days}d `;
    if (hours > 0) result += `${hours}h `;
    if (minutes > 0) result += `${minutes}m `;
    if (seconds > 0 && days === 0 && hours === 0 && minutes === 0) result += `${seconds}s`;
    
    return result.trim();
}