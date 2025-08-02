document.addEventListener("DOMContentLoaded", async () => {
    // Helper function to load HTML partials
    const loadHTML = async (url, elementId) => {
        try {
            const response = await fetch(url);
            if (!response.ok) throw new Error(`Failed to fetch ${url}`);
            const text = await response.text();
            const element = document.getElementById(elementId);
            if (element) {
                element.innerHTML = text;
            }
        } catch (error) {
            console.error(`Error loading partial:`, error);
        }
    };

    // Handles showing/hiding elements based on login status
    const handleAuthStatus = (authStatus) => {
        const navLoggedIn = document.getElementById('nav-logged-in');
        const navLoginButton = document.getElementById('nav-login-button');
        const staffNav = document.getElementById('staff-nav-links');
        const staffManagementLink = document.getElementById('staff-management-link');
        const activeBansLink = document.getElementById('active-bans-link');
        const activeMutesLink = document.getElementById('active-mutes-link'); // Get the new link
        const adminReportsLink = document.getElementById('admin-reports-link'); // Get the new link
        const appealsLink = document.getElementById('appeals-link');


        if (authStatus.loggedIn) {
            // User is logged in: show user info, hide login button
            navLoginButton.style.display = 'none';
            navLoggedIn.style.display = 'flex';
            document.getElementById('nav-username').textContent = authStatus.user.username;
            
            const userSkinImg = document.getElementById('nav-user-skin');
            if (authStatus.user && authStatus.user.uuid) {
                const playerUUID = authStatus.user.uuid.replace(/-/g, '');
                userSkinImg.src = `https://cravatar.eu/helmavatar/${playerUUID}/32.png`;
            }

            document.getElementById('profile-link').href = `/profile/${authStatus.user.username}`;
            
            document.getElementById('logout-button').addEventListener('click', async (e) => {
                e.preventDefault();
                await fetch('/logout', { method: 'POST' });
                window.location.href = '/';
            });

            // --- Permission Checks for Control Panel Links ---
            const userGroup = authStatus.user.primary_group;

            const staffRanks = ['mod', 'srmod', 'admin', 'headadmin', 'manager', 'owner'];
            if (staffRanks.includes(userGroup)) {
                staffNav.style.display = 'flex';
            }
            
            const adminRanks = ['admin', 'headadmin', 'manager', 'owner'];
            if (adminRanks.includes(userGroup)) {
                staffManagementLink.style.display = 'block';
            }

            const seniorStaffRanks = ['srmod', 'admin', 'headadmin', 'manager', 'owner'];
            if (seniorStaffRanks.includes(userGroup)) {
                activeBansLink.style.display = 'block';
                activeMutesLink.style.display = 'block';
                adminReportsLink.style.display = 'block'; // Show the reports link
                appealsLink.style.display = 'block'; // Show the appeals link


            }

        } else {
            // User is not logged in: hide everything
            navLoggedIn.style.display = 'none';
            navLoginButton.style.display = 'block';
            if (staffNav) {
                staffNav.style.display = 'none';
            }
        }
    };

    // Main function to set up the page
    const setupPage = async () => {
        await Promise.all([
            loadHTML('/html/partials/navbar.html', 'navbar-placeholder'),
            loadHTML('/html/partials/footer.html', 'footer-placeholder')
        ]);

        // Initialize search bar functionality
        const searchForm = document.getElementById('player-search-form');
        const searchInput = document.getElementById('player-search-input');
        if (searchForm) {
            searchForm.addEventListener('submit', (e) => {
                e.preventDefault();
                const username = searchInput.value.trim();
                if (username) {
                    window.location.href = `/profile/${username}`;
                }
            });
        }

        // Logic for auth status check
        try {
            const response = await fetch('/api/auth/status');
            const authStatus = await response.json();
            handleAuthStatus(authStatus);
        } catch (error) {
            console.error('Failed to get auth status:', error);
        }
    };

    setupPage();
});
