document.addEventListener('DOMContentLoaded', () => {
    loadStaff();
});

async function loadStaff() {
    const container = document.getElementById('staff-list-container');
    try {
        const response = await fetch('/api/staff');
        const players = await response.json();

        // DEBUG: Log the full array of players received by the browser
        console.log('[Browser] Received staff data from server:', players);

        if (players.length === 0) {
            container.innerHTML = '<p>No staff members found.</p>';
            return;
        }

        const staffGroups = {
            Owner: players.filter(p => p.primary_group === 'owner'),
            "High Staff": players.filter(p => ['manager', 'headadmin', 'admin'].includes(p.primary_group)),
            Moderators: players.filter(p => ['srmod', 'mod'].includes(p.primary_group)),
        };

        let html = '';
        for (const groupName in staffGroups) {
            const groupPlayers = staffGroups[groupName];
            if (groupPlayers.length > 0) {
                html += `
                    <section class="staff-group">
                        <h2>${groupName}</h2>
                        <div class="player-cards-container">
                            ${groupPlayers.map(player => createPlayerCard(player)).join('')}
                        </div>
                    </section>
                `;
            }
        }
        container.innerHTML = html;

    } catch (error) {
        console.error('Failed to load staff list:', error);
        container.innerHTML = '<p>Could not load the staff list.</p>';
    }
}

function createPlayerCard(player) {
    const playerUUID = player.uuid ? player.uuid.replace(/-/g, '') : '';
    const playerNameStyle = player.colorStyle || '';

    // Use the new rankColor for the border, with a default fallback
    const borderColor = player.rankColor || '#00AAAA';

    return `
        <div class="player-card">
            <img class="player-skin-head" src="https://cravatar.eu/helmavatar/${playerUUID}/36.png" alt="${player.username}'s skin">
            <div class="player-info">
                <a href="/profile/${player.username}" style="${playerNameStyle}" class="player-profile-link">${player.username}</a>
            </div>
        </div>
    `;
}