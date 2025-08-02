$(document).ready(function() {
    // --- Configuration ---
    const validReasons = ["Swearing", "Disrespecting", "Advertising", "Racism", "Allowed"];
    const reasonsWithNote = ["Swearing", "Disrespecting", "Advertising", "Racism"];

    // --- Initialize DataTable ---
    const dataTable = $('#all-words-datatable').DataTable({
        ajax: {
            url: '/api/all-words',
            dataSrc: '' // The data source is the top-level array
        },
        columns: [
            { data: 'id' },
            { 
                data: 'added_by',
                render: function(data, type, row) {
                    // Fetch uuid and color style for the admin who added the word
                    const uuid = row.added_by_uuid ? row.added_by_uuid.replace(/-/g, '') : 'steve';
                    const colorStyle = row.added_by_color_style || '';
                    
                    return `
                        <div class="added-by-cell">
                            <img src="https://cravatar.eu/helmavatar/${uuid}/24.png" class="skin-tiny">
                            <a href="/profile/${data}" class="player-profile-link" style="${colorStyle}">${data}</a>
                        </div>
                    `;
                }
            },
            { data: 'word' },
            { 
                data: 'last_edited',
                render: function(data, type, row) {
                    return new Date(data).toLocaleString();
                }
            },
            { data: 'reason' },
            {
                data: null,
                defaultContent: `<button class="action-btn update-btn">Update</button><button class="action-btn delete-btn">Delete</button>`,
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

    // --- Modal Elements ---
    const modal = $('#update-modal');
    const modalWord = $('#modal-word');
    const modalWordId = $('#modal-word-id');
    const modalReason = $('#modal-reason');
    const modalNote = $('#modal-note');

    // Populate reason dropdown in the modal
    validReasons.forEach(r => modalReason.append(`<option value="${r}">${r}</option>`));

    // --- Event Listeners ---

    // Handle clicks on Update and Delete buttons
    $('#all-words-datatable tbody').on('click', 'button', async function() {
        const data = dataTable.row($(this).parents('tr')).data();

        if ($(this).hasClass('delete-btn')) {
            // DELETE action
            if (confirm(`Are you sure you want to delete the word "${data.word}"?`)) {
                try {
                    const response = await fetch(`/api/word/${data.id}`, { method: 'DELETE' });
                    if (!response.ok) throw new Error('Server error');
                    dataTable.ajax.reload(); // Refresh table
                } catch (error) {
                    alert('Failed to delete word.');
                }
            }
        } else if ($(this).hasClass('update-btn')) {
            // UPDATE action: open and populate the modal
            const [reason, note] = data.reason.split(' | ');
            modalWord.text(data.word);
            modalWordId.val(data.id);
            modalReason.val(reason || '');
            modalNote.val(note || '');
            modalNote.toggle(reasonsWithNote.includes(reason));
            modal.show();
        }
    });

    // Handle reason change inside the modal
    modalReason.on('change', function() {
        modalNote.toggle(reasonsWithNote.includes($(this).val()));
    });

    // Handle modal form submission
    $('#update-form').on('submit', async function(e) {
        e.preventDefault();
        const id = modalWordId.val();
        const reason = modalReason.val();
        const note = modalNote.val();

        try {
            const response = await fetch(`/api/word/${id}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ reason, note })
            });
            if (!response.ok) throw new Error('Server error');
            modal.hide();
            dataTable.ajax.reload();
        } catch (error) {
            alert('Failed to update word.');
        }
    });

    // Handle modal cancellation
    $('#modal-cancel-btn').on('click', () => modal.hide());
});