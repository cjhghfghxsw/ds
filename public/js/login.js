document.addEventListener('DOMContentLoaded', () => {
    const loginForm = document.getElementById('login-form');
    const messageBox = document.getElementById('message-box');

    loginForm.addEventListener('submit', async (event) => {
        event.preventDefault();

        const username = loginForm.username.value;
        const password = loginForm.password.value;

        messageBox.textContent = '';
        messageBox.className = '';
        
        console.log('Attempting to log in...'); // <-- DEBUG

        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password }),
            });

            const data = await response.json();
            console.log('Server responded:', data); // <-- DEBUG

            if (data.success) {
                console.log('Login success. Redirecting to /home...'); // <-- DEBUG
                messageBox.classList.add('success');
                messageBox.textContent = data.message;
                
                setTimeout(() => {
                    window.location.href = '/';
                }, 1000);

            } else {
                console.log('Login failed. Displaying error message.'); // <-- DEBUG
                messageBox.classList.add('error');
                messageBox.textContent = data.message;
            }

        } catch (error) {
            console.error('An error occurred during fetch:', error); // <-- DEBUG
        }
    });
});