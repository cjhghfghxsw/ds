document.addEventListener('DOMContentLoaded', () => {
    loadGuilds();
});

async function loadGuilds() {
    const tableBody = document.getElementById('guilds-table-body');
    try {
        const response = await fetch('/api/guilds');
        const guilds = await response.json();

        if (guilds.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="4" style="text-align: center;">No guilds found.</td></tr>';
            return;
        }

        tableBody.innerHTML = guilds.map(guild => {
            const ownerName = guild.owner_name || 'Unknown';
            const guildTag = guild.tag ? `[${guild.tag}]` : '';

            return `
                <tr>
                    <td>
                        <a href="/guild/${encodeURIComponent(guild.name)}" class="guild-name-link">
                            <span class="guild-name" style="${guild.tagColorStyle}">${guild.name}</span>
                            <span class="guild-tag" style="${guild.tagColorStyle}">${guildTag}</span>
                        </a>
                    </td>
                    <td>
                        <a href="/profile/${ownerName}" class="player-profile-link" style="${guild.ownerColorStyle}">
                            ${ownerName}
                        </a>
                    </td>
                    <td>${guild.member_count}</td>
                    <td>${new Date(guild.created_at).toLocaleString()}</td>
                </tr>
            `;
        }).join('');

    } catch (error) {
        console.error('Failed to load guilds:', error);
        tableBody.innerHTML = '<tr><td colspan="4" style="text-align: center;">Error loading guilds.</td></tr>';
    }
}