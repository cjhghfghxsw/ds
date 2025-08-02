$(document).ready(function() {
    $('#appeals-table').DataTable({
        ajax: {
            url: '/api/appeals',
            dataSrc: ''
        },
        columns: [
            { data: 'id' },
            { 
                data: 'username',
                render: function(data, type, row) {
                    const style = row.colorStyle || 'color: #AAAAAA;';
                    return `<a href="/profile/${data}" class="player-profile-link" style="${style}">${data}</a>`;
                }
            },
            { data: 'punishment_type' },
            { 
                data: 'reason',
                render: function(data) {
                    return data.length > 50 ? data.substring(0, 50) + '...' : data;
                }
            },
            { 
                data: 'created_at',
                render: function(data) {
                    return new Date(data).toLocaleString();
                }
            },
            {
                data: 'id',
                // ✅ FIX: Changed the button to a proper <a> link
                render: function(data) {
                    return `<a href="/staff/appeals/${data}" class="action-btn view-btn">View</a>`;
                },
                orderable: false
            }
        ],
        "language": { "search": "Search:", "lengthMenu": "Show _MENU_ entries" },
        "pageLength": 10,
        "order": [[0, "desc"]]
    });
});