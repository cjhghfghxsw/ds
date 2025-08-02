document.addEventListener('DOMContentLoaded', () => {
    // --- Event Listener for the Word Checker Form ---
    document.getElementById('word-check-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const wordInput = document.getElementById('word-input');
        const resultBox = document.getElementById('word-result-box');
        const word = wordInput.value.trim();
        
        resultBox.style.display = 'none';
        wordInput.value = ''; // Clear the input field

        if (!word) return;

        try {
            const response = await fetch('/api/check-word', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ word })
            });
            const data = await response.json();

            if (data.found === false) {
                resultBox.className = 'result-box success';
                resultBox.textContent = data.message;
            } else if (data.allowed === true) {
                resultBox.className = 'result-box success';
                resultBox.textContent = data.message;
            } else {
                resultBox.className = 'result-box error';
                resultBox.textContent = `Word '${word}' is not allowed: ${data.reason}`;
            }
            resultBox.style.display = 'block';

        } catch (error) {
            console.error('Error checking word:', error);
            resultBox.className = 'result-box error';
            resultBox.textContent = 'An error occurred. Please try again.';
            resultBox.style.display = 'block';
        }
    });

    // --- Load All Page Content ---
    loadStaffRules();
    loadMyWarnings();
    loadMyStats(); // Load the new stats card
});

// Function to display the static staff rules
function loadStaffRules() {
    const container = document.getElementById('staff-rules-card');
    if (!container) return; // Failsafe if the element doesn't exist
    const rules = [
        "You are not allowed to mention a member's name before/after banning/muting the member.",
        "Be friendly when chatting in the discord/minecraft chat.",
        "You are not allowed to leak anything staff related (e.g. these rules, your moderation commands, etc.)",
        "Breaking member rules can lead to a warn or even a permanent ban.",
        "Not punishing your friends for breaking rules just because it's your friend is prohibited and can lead into punishment.",
        "Banning/Muting for no reason is forbidden and can lead into getting a warning from the administration.",
        "Sharing your account is prohibited and can lead into a permanent ban."
    ];

    const rulesHtml = rules.map(rule => `<li>${rule}</li>`).join('');

    container.innerHTML = `
        <h2>Staff Rules</h2>
        <ul class="rules-list">
            ${rulesHtml}
        </ul>
    `;
}

// Function to fetch and display the user's warnings
async function loadMyWarnings() {
    const container = document.getElementById('your-warnings-card');
    if (!container) return;
    let contentHtml = '';

    try {
        const response = await fetch('/api/my-warnings');
        const warnings = await response.json();

        let warningsRows = '';
        if (warnings.length > 0) {
            warningsRows = warnings.map(warn => `
                <tr>
                    <td>${warn.reason}</td>
                    <td>${new Date(warn.created_at).toLocaleString()}</td>
                </tr>
            `).join('');
        } else {
            warningsRows = '<tr><td colspan="2" class="no-warnings">You have no warnings, well done!</td></tr>';
        }

        contentHtml = `
            <h2>Your Warnings</h2>
            <table class="warnings-table">
                <thead>
                    <tr>
                        <th>Reason</th>
                        <th>At</th>
                    </tr>
                </thead>
                <tbody>
                    ${warningsRows}
                </tbody>
            </table>
        `;

    } catch (error) {
        console.error('Failed to load warnings:', error);
        contentHtml = '<h2>Your Warnings</h2><p class="no-warnings">Could not load your warnings.</p>';
    }

    container.innerHTML = contentHtml;
}

// Function to fetch and display General and Moderation stats
async function loadMyStats() {
    const mainContentContainer = document.querySelector('.main-content');
    if (!mainContentContainer) return;

    try {
        const response = await fetch('/api/my-stats');
        if (!response.ok) throw new Error('Could not load your stats.');
        
        const stats = await response.json();

        const rankDisplay = {
            'owner': 'Owner', 'manager': 'Manager', 'headadmin': 'Head-Admin',
            'admin': 'Admin', 'srmod': 'Senior Moderator', 'mod': 'Mod'
        };

        // Create Moderation Stats Card
        const moderationCard = `
            <div class="content-card">
                <h2><i class="fas fa-gavel"></i> Moderation Stats</h2>
                <div class="stat-item">
                    <i class="fas fa-ban stat-icon"></i>
                    <div class="stat-details">
                        <span class="stat-label">Total Bans</span>
                        <span class="stat-value">${stats.banCounts || 0}</span>
                    </div>
                </div>
                <div class="stat-item">
                    <i class="fas fa-comment-slash stat-icon"></i>
                    <div class="stat-details">
                        <span class="stat-label">Total Mutes</span>
                        <span class="stat-value">${stats.muteCounts || 0}</span>
                    </div>
                </div>
            </div>
        `;

        // Append the new card to the main content area
        mainContentContainer.insertAdjacentHTML('beforeend', moderationCard);

    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

// Helper function to format playtime
function formatPlaytime(totalSeconds) {
    if (!totalSeconds) return 'N/A';
    if (totalSeconds < 60) return `${totalSeconds}s`;
    
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    
    return `${hours}h ${minutes}m`;
}
