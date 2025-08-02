document.addEventListener('DOMContentLoaded', () => {
    loadProfile();
});

// Fetches and displays the profile data for the user in the URL
// Replace the existing loadProfile function with this one
async function loadProfile() {
    const container = document.getElementById('profile-area');
    const username = window.location.pathname.split('/').pop();

    if (!username) {
        container.innerHTML = '<h1 class="loading-text">No player specified.</h1>';
        return;
    }

    try {
        const response = await fetch(`/api/player/${username}`);
        if (!response.ok) throw new Error('Player not found');
        
        const player = await response.json();

        const playerUUID = player.uuid ? player.uuid.replace(/-/g, '') : 'steve';
        const rankDisplay = {
            'owner': 'Owner', 'manager': 'Manager', 'headadmin': 'Head-Admin',
            'admin': 'Admin', 'seniormod': 'Senior Moderator', 'mod': 'Moderator'
        };

        // Function to create the guild tag link if the player is in a guild
        const createGuildTag = () => {
            if (player.guild_name && player.guild_tag) {
                return `
                    <a href="/guild/${encodeURIComponent(player.guild_name)}" class="profile-guild-tag" style="${player.guildTagStyle}">
                        [${player.guild_tag}]
                    </a>
                `;
            }
            return ''; // Return empty string if not in a guild
        };

        const createPvpCard = () => {
            if (player.points === null && player.kills === null) return '';
            return `
                <div class="stats-card">
                    <h2><i class="fas fa-swords stat-icon"></i> PvP Stats</h2>
                    <div class="stat-item">
                        <i class="fas fa-star stat-icon"></i>
                        <div class="stat-details">
                            <span class="stat-label">Points</span>
                            <span class="stat-value">${player.points || 0}</span>
                        </div>
                    </div>
                    <div class="stat-item">
                        <i class="fas fa-skull stat-icon"></i>
                        <div class="stat-details">
                            <span class="stat-label">Kills</span>
                            <span class="stat-value">${player.kills || 0}</span>
                        </div>
                    </div>
                    <div class="stat-item">
                        <i class="fas fa-crosshairs stat-icon"></i>
                        <div class="stat-details">
                            <span class="stat-label">Deaths</span>
                            <span class="stat-value">${player.deaths || 0}</span>
                        </div>
                    </div>
                </div>
            `;
        };

        const html = `
            <div class="profile-banner"></div>
            <div class="profile-content-wrapper">
                <div class="profile-header">
                    <img class="profile-avatar" src="https://cravatar.eu/helmavatar/${playerUUID}/160.png?default=steve" alt="${player.username}'s skin">
                    <div class="profile-identity">
                        <h1>
                            <span style="${player.colorStyle}">${player.username}</span>
                            ${createGuildTag()}
                        </h1>
                    </div>
                </div>
                <div class="profile-info-bar">
                    <div class="info-item">
                        <span class="info-label">Status</span>
                        <span class="info-value ${player.is_logged_in ? 'online' : 'offline'}">
                            ${player.is_logged_in ? 'Online' : 'Offline'}
                        </span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Rank</span>
                        <span class="info-value" style="${player.colorStyle}">
                            ${rankDisplay[player.primary_group] || player.primary_group}
                        </span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Playtime</span>
                        <span class="info-value">${formatPlaytime(player.playtime)}</span>
                    </div>
                </div>
                ${createPvpCard()}
            </div>
        `;
        container.innerHTML = html;

    } catch (error) {
        container.innerHTML = `<h1 class="loading-text">Error: ${error.message}</h1>`;
    }
}

// Make sure this helper function is still in the file
function formatPlaytime(totalSeconds) {
    if (!totalSeconds) return 'N/A';
    if (totalSeconds < 60) return `${totalSeconds}s`;
    
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    
    return `${hours}h ${minutes}m`;
}

// Make sure this helper function is still in the file
function formatPlaytime(totalSeconds) {
    if (!totalSeconds) return 'N/A';
    if (totalSeconds < 60) return `${totalSeconds}s`;
    
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    
    return `${hours}h ${minutes}m`;
}

// Helper function to format playtime from seconds into a human-readable string
function formatPlaytime(totalSeconds) {
    if (!totalSeconds) return 'N/A';
    if (totalSeconds < 60) return `${totalSeconds}s`;
    
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    
    return `${hours}h ${minutes}m`;
}
// Make sure this helper function is still in the file
function formatPlaytime(totalSeconds) {
    if (!totalSeconds) return 'N/A';
    if (totalSeconds < 60) return `${totalSeconds}s`;
    
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    
    return `${hours}h ${minutes}m`;
}


// Make sure this helper function is still in the file
function formatPlaytime(totalSeconds) {
    if (!totalSeconds) return 'N/A';
    if (totalSeconds < 60) return `${totalSeconds}s`;
    
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    
    return `${hours}h ${minutes}m`;
}

// Formats playtime from seconds into a human-readable string
function formatPlaytime(totalSeconds) {
    if (!totalSeconds) return 'N/A';
    if (totalSeconds < 60) return `${totalSeconds}s`;
    
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    
    return `${hours}h ${minutes}m`;
}