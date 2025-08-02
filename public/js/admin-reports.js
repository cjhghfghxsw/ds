$(document).ready(function() {
    $('#admin-reports-table').DataTable({
        ajax: {
            url: '/api/admin-reports',
            dataSrc: ''
        },
        columns: [
            { data: 'id' },
            { 
                data: 'reported_username',
                render: function(data, type, row) {
                    const style = row.reportedStyle || 'color: #AAAAAA;';
                    return `<a href="/profile/${data}" class="player-profile-link" style="${style}">${data}</a>`;
                }
            },
            { 
                data: 'reporter_username',
                render: function(data, type, row) {
                    const style = row.reporterStyle || 'color: #AAAAAA;';
                    return `<a href="/profile/${data}" class="player-profile-link" style="${style}">${data}</a>`;
                }
            },
            { data: 'report_type' },
            { 
                data: 'status',
                render: function(data, type, row) {
                    if (data === 'claimed') {
                        return `<span class="status-badge status-claimed">Claimed by ${row.claimed_by}</span>`;
                    }
                    return `<span class="status-badge status-pending">Pending</span>`;
                }
            },
            {
                data: 'id',
                render: function(data, type, row) {
                    return `<a href="/staff/admin-reports/${data}" class="action-btn view-btn">View</a>`;
                },
                orderable: false
            }
        ],
        "language": {
            "search": "Search:",
            "lengthMenu": "Show _MENU_ entries"
        },
        "pageLength": 10,
        "order": [[0, "desc"]] // Default sort by ID descending
    });
});
