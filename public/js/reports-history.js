$(document).ready(function() {
    $('#reports-history-table').DataTable({
        ajax: {
            url: '/api/reports-history',
            dataSrc: ''
        },
        columns: [
            { data: 'report_id' },
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
            { 
                data: 'handled_by',
                render: function(data, type, row) {
                    const style = row.handlerStyle || 'color: #AAAAAA;';
                    return `<a href="/profile/${data}" class="player-profile-link" style="${style}">${data}</a>`;
                }
            },
            { 
                data: 'handled_at',
                render: function(data) {
                    return new Date(data).toLocaleString();
                }
            }
        ],
        "language": { "search": "Search:", "lengthMenu": "Show _MENU_ entries" },
        "pageLength": 10,
        "order": [[0, "desc"]]
    });
});
