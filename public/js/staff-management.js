document.addEventListener('DOMContentLoaded', () => {
    loadAllStaff();
    setupSetRankForm();
});

async function loadAllStaff() {
    const tableBody = document.getElementById('staff-table-body');
    try {
        const response = await fetch('/api/all-staff');
        const staffList = await response.json();

        if (staffList.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="3">No staff found.</td></tr>';
            return;
        }

        const rankDisplay = { 'srmod': 'Senior Moderator', 'mod': 'Mod' };

        tableBody.innerHTML = staffList.map(staff => {
            const uuid = staff.uuid ? staff.uuid.replace(/-/g, '') : 'steve';
            const nameStyle = staff.colorStyle || '';
            return `
                <tr>
                    <td>
                        <div class="player-cell">
                            <img src="https://cravatar.eu/helmavatar/${uuid}/32.png">
                            <a href="/profile/${staff.username}" style="${nameStyle}">${staff.username}</a>
                        </div>
                    </td>
                    <td>${rankDisplay[staff.primary_group] || staff.primary_group}</td>
                    <td><a href="/staff/management/${staff.username}" class="action-btn manage-btn">Manage</a></td>
                </tr>
            `;
        }).join('');
    } catch (error) {
        console.error('Failed to load staff list:', error);
        tableBody.innerHTML = '<tr><td colspan="3">Error loading staff list.</td></tr>';
    }
}

// NEW function to set up the Set Rank form
function setupSetRankForm() {
    const form = document.getElementById('set-rank-form');
    const usernameInput = document.getElementById('set-rank-username');
    const rankSelect = document.getElementById('set-rank-select');

    // Ranks that can be assigned
    const assignableRanks = { "mod": "Mod", "srmod": "Sr. Mod", "admin": "Admin" };
    rankSelect.innerHTML = Object.entries(assignableRanks)
        .map(([val, name]) => `<option value="${val}">${name}</option>`).join('');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = usernameInput.value.trim();
        const newRank = rankSelect.value;
        if (!username) return;

        if (!confirm(`Are you sure you want to set ${username}'s rank to ${assignableRanks[newRank]}?`)) return;

        try {
            const response = await fetch('/api/staff/setrank', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, newRank })
            });
            const result = await response.json();
            alert(result.message);
            if (result.success) {
                usernameInput.value = ''; // Clear input on success
                loadAllStaff(); // Refresh the staff list
            }
        } catch (error) {
            alert('An error occurred.');
        }
    });
}