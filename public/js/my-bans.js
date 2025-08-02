$(document).ready(function() {
    $('#my-bans-table').DataTable({
        ajax: {
            url: '/api/my-bans',
            dataSrc: ''
        },
        columns: [
            { data: 'banid' },
            { 
                data: 'ign',
                render: function(data, type, row) {
                    const style = row.colorStyle || 'color: #AAAAAA;';
                    return `<a href="/profile/${data}" class="player-profile-link" style="${style}">${data}</a>`;
                }
            },
            { data: 'banReason' },
            { 
                data: 'banDuration',
                render: function(data) {
                    if (data === 0 || data < 0) return '<span style="color: #e74c3c;">Permanent</span>';
                    return formatDuration(data);
                }
            },
            { 
                data: 'banExpiresAt',
                render: function(data) {
                    if (data === 0 || data < 0) return 'Never';
                    return new Date(data).toLocaleString();
                }
            }
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
