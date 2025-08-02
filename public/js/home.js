document.addEventListener('DOMContentLoaded', () => {
    loadNews();
    loadTopPlaytime();
});

// Function to fetch and display news articles
async function loadNews() {
    const newsContainer = document.getElementById('news-container');
    try {
        const response = await fetch('/api/news');
        const articles = await response.json();

        if (articles.length === 0) {
            newsContainer.innerHTML = '<p>No news to display right now.</p>';
            return;
        }

        let newsHtml = '';
        articles.forEach(article => {
            newsHtml += `
                <article class="news-article">
                    <h3>${article.title}</h3>
                    <p>${article.content}</p>
                    <div class="news-meta">
                        <span>By ${article.author} on ${article.date}</span>
                    </div>
                </article>
            `;
        });
        newsContainer.innerHTML = newsHtml;

    } catch (error) {
        console.error('Failed to load news:', error);
        newsContainer.innerHTML = '<p>Could not load news articles.</p>';
    }
}

// Function to fetch and display top players
async function loadTopPlaytime() {
    const container = document.getElementById('playtime-list-container');
    try {
        const response = await fetch('/api/top-playtime');
        const players = await response.json();

        if (players.length === 0) {
            container.innerHTML = '<p>No player data available.</p>';
            return;
        }

        let rank = 1;
        // Start building an unordered list
        let playersHtml = '<ul id="playtime-list">'; 

        players.forEach(player => {
            const playerNameStyle = player.colorStyle || '';
            const playerUUID = player.uuid ? player.uuid.replace(/-/g, '') : 'steve';

            playersHtml += `
                <li class="player-playtime-item">
                    <span class="playtime-rank">#${rank}</span>
                    <div class="playtime-player-info">
                        <img class="playtime-skin-head" src="https://cravatar.eu/helmavatar/${playerUUID}/36.png" alt="${player.username}'s skin">
                        <a href="/profile/${player.username}" style="${playerNameStyle}" class="player-profile-link">${player.username}</a>
                    </div>
                    <span class="playtime-duration">${formatPlaytime(player.playtime)}</span>
                </li>
            `;
            rank++;
        });

        playersHtml += '</ul>'; // Close the list
        container.innerHTML = playersHtml;

    } catch (error) {
        console.error('Failed to load top playtime:', error);
        container.innerHTML = '<p>Could not load top playtime.</p>';
    }
}

/**
 * Formats playtime from seconds into a human-readable string (e.g., "12h 34m").
 * @param {number} totalSeconds - The total playtime in seconds.
 * @returns {string} The formatted playtime string.
 */
function formatPlaytime(totalSeconds) {
    if (!totalSeconds) return '0h 0m';
    if (totalSeconds < 60) {
        return `${totalSeconds}s`;
    }
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    
    let result = '';
    if (hours > 0) {
        result += `${hours}h `;
    }
    if (minutes > 0 || hours === 0) { // Show minutes if hours are 0
        result += `${minutes}m`;
    }
    return result.trim();
}