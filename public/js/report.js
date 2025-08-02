document.addEventListener('DOMContentLoaded', () => {
    // --- Tab Switching Logic ---
    const tabs = document.querySelectorAll('.tab-link');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.getElementById(tab.dataset.tab).classList.add('active');
        });
    });

    // --- Form Submission Logic ---
    document.querySelectorAll('.report-form').forEach(form => {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const type = form.dataset.type;
            const reported_username = document.getElementById(`${type}-username`).value;
            const evidence_link = document.getElementById(`${type}-link`).value;
            const extra_notes = document.getElementById(`${type}-notes`).value;

            try {
                const response = await fetch('/api/submit-report', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        report_type: type,
                        reported_username,
                        evidence_link,
                        extra_notes
                    })
                });
                const result = await response.json();
                
                if (result.success) {
                    alert(result.message);
                    form.reset(); // Clear the form
                } else {
                    alert(result.message || 'An error occurred.');
                }
            } catch (error) {
                alert('Failed to connect to the server.');
            }
        });
    });
});