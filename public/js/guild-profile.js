document.addEventListener('DOMContentLoaded', () => {
    loadGuildProfile();
});

async function loadGuildProfile() {
    const container = document.getElementById('guild-profile-container');
    const guildName = decodeURIComponent(window.location.pathname.split('/').pop());

    try {
        const response = await fetch(`/api/guild/${guildName}`);
        if (!response.ok) throw new Error('Guild not found');
        
        const { guildInfo, members } = await response.json();

        // Sort members by their rank priority (highest rank first)
        members.sort((a, b) => (b.priority || 0) - (a.priority || 0));

        // --- Build Info Card ---
        const infoCardHtml = `
            <div class="info-card">
                <div class="card-header">Guild Information</div>
                <ul class="info-list">
                    <li><span>Name</span> <span>${guildInfo.name}</span></li>
                    <li><span>Tag</span> <span>${guildInfo.tag || 'N/A'}</span></li>
                    <li><span>Created</span> <span>${new Date(guildInfo.created_at).toLocaleDateString()}</span></li>
                    <li><span>Members</span> <span>${guildInfo.member_count}</span></li>
                </ul>
            </div>
        `;

        // --- Build Members Table ---
        const membersTableHtml = `
            <div class="members-card">
                <table class="members-table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Guild Role</th>
                            <th>Joined</th>
                            <th>Last Login</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${members.map(member => `
                            <tr>
                                <td><a href="/profile/${member.username}" class="player-profile-link" style="${member.colorStyle}">${member.username}</a></td>
                                <td>${member.guild_rank_name || 'Unknown'}</td>
                                <td>${new Date(member.joined_at).toLocaleString()}</td>
                                <td>${member.last_login ? new Date(member.last_login).toLocaleString() : 'Never'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;

        container.innerHTML = infoCardHtml + membersTableHtml;

    } catch (error) {
        container.innerHTML = `<h1>Error: ${error.message}</h1>`;
    }
}
