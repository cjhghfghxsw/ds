$(document).ready(function() {
    $('#active-mutes-table').DataTable({
        ajax: {
            url: '/api/active-mutes',
            dataSrc: ''
        },
        columns: [
            { data: 'muteid' },
            { data: 'ign', render: (data) => `<a href="/profile/${data}" class="player-profile-link">${data}</a>` },
            { data: 'muteBy', render: (data) => (data.toLowerCase() === 'console') ? `<span>Console</span>` : `<a href="/profile/${data}" class="player-profile-link">${data}</a>` },
            { data: 'muteReason' },
            { data: 'muteDuration', render: (data) => (data === 0 || data < 0) ? `<span style="color: #e74c3c;">Permanent</span>` : formatDuration(data) },
            { data: 'muteExpiresAt', render: (data) => (data === 0 || data < 0) ? 'Never' : new Date(data).toLocaleString() }
        ],
        "language": { "search": "Search:", "lengthMenu": "Show _MENU_ entries" },
        "pageLength": 10,
        "order": [[0, "desc"]]
    });
});

function formatDuration(ms) {
    if (ms < 1000) return `${ms}ms`;
    const s = Math.floor(ms / 1000);
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h`;
    const d = Math.floor(h / 24);
    return `${d}d`;
}