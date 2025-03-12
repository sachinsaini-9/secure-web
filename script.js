document.addEventListener("DOMContentLoaded", function() {
    const passwordInput = document.getElementById("password");
    const strengthMeter = document.getElementById("password-strength");
    
    passwordInput.addEventListener("input", function() {
        const password = passwordInput.value;
        let strength = getPasswordStrength(password);
        strengthMeter.innerText = strength.text;
        strengthMeter.style.color = strength.color;
    });

    function getPasswordStrength(password) {
        let score = 0;

        if (password.length >= 8) score++;
        if (/[A-Z]/.test(password)) score++; // Uppercase Letter
        if (/[a-z]/.test(password)) score++; // Lowercase Letter
        if (/\d/.test(password)) score++; // Number
        if (/[\W_]/.test(password)) score++; // Special Character

        if (score === 5) return { text: "Strong", color: "green" };
        if (score >= 3) return { text: "Medium", color: "orange" };
        return { text: "Weak", color: "red" };
    }
});

