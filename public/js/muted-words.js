document.addEventListener('DOMContentLoaded', () => {
    const tableBody = document.getElementById('words-table-body');
    const saveBtn = document.getElementById('save-all-btn');
    let pendingWords = [];

    const validReasons = ["Swearing", "Disrespecting", "Advertising", "Racism", "Allowed"];
    const reasonsWithNote = ["Swearing", "Disrespecting", "Advertising", "Racism"];

    const renderTable = () => {
        tableBody.innerHTML = pendingWords.map(word => `
            <tr data-id="${word.id}">
                <td>${word.id}</td>
                <td>${word.word}</td>
                <td class="reason-cell">
                    <select class="reason-select">
                        <option value="">Select Reason</option>
                        ${validReasons.map(r => `<option value="${r}">${r}</option>`).join('')}
                        <option value="DEL">DELETE</option>
                    </select>
                    <input type="text" class="reason-note" placeholder="Optional note..." style="display: none;">
                </td>
                <td>${new Date(word.created_at).toLocaleString()}</td>
            </tr>
        `).join('');
    };

    const loadPendingWords = async () => {
        try {
            const response = await fetch('/api/pending-words');
            pendingWords = await response.json();
            renderTable();
        } catch (error) {
            console.error("Failed to load words:", error);
        }
    };

    tableBody.addEventListener('change', (e) => {
        if (e.target.classList.contains('reason-select')) {
            const row = e.target.closest('tr');
            const noteInput = row.querySelector('.reason-note');
            const selectedReason = e.target.value;
            noteInput.style.display = reasonsWithNote.includes(selectedReason) ? 'block' : 'none';
        }
    });

    saveBtn.addEventListener('click', async () => {
        const wordsToSave = [];
        const wordsToDelete = [];

        tableBody.querySelectorAll('tr').forEach(row => {
            const id = parseInt(row.dataset.id);
            const word = pendingWords.find(w => w.id === id).word;
            const reasonSelect = row.querySelector('.reason-select');
            const noteInput = row.querySelector('.reason-note');

            if (reasonSelect.value && reasonSelect.value !== "DEL") {
                wordsToSave.push({
                    id,
                    word,
                    reason: reasonSelect.value,
                    note: noteInput.style.display === 'block' ? noteInput.value : null
                });
            } else if (reasonSelect.value === "DEL") {
                wordsToDelete.push(id);
            }
        });

        try {
            const response = await fetch('/api/save-words', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ wordsToSave, wordsToDelete })
            });
            const result = await response.json();
            alert(result.message);
            if (result.success) loadPendingWords();
        } catch (error) {
            alert('Failed to save words.');
        }
    });

    loadPendingWords();
});