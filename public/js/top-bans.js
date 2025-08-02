$(document).ready(function() {
    $('#top-bans-table').DataTable({
        ajax: {
            url: '/api/top-bans',
            dataSrc: ''
        },
        columns: [
            { 
                data: null, // No data from API for this column
                render: function (data, type, row, meta) {
                    // meta.row is the row index, so we add 1 for the rank
                    return `#${meta.row + 1}`;
                },
                orderable: false,
                searchable: false
            },
            { 
                data: 'ign',
                render: function(data, type, row) {
                    const style = row.colorStyle || 'color: #AAAAAA;';
                    const uuid = row.uuid ? row.uuid.replace(/-/g, '') : 'steve';
                    return `
                        <div class="player-cell">
                            <img src="https://cravatar.eu/helmavatar/${uuid}/32.png" class="skin-tiny">
                            <a href="/profile/${data}" class="player-profile-link" style="${style}">${data}</a>
                        </div>
                    `;
                }
            },
            { data: 'banCounts' }
        ],
        "language": { "search": "Search:", "lengthMenu": "Show _MENU_ entries" },
        "pageLength": 10,
        "order": [[2, "desc"]] // Sort by the ban count column (index 2)
    });
});
