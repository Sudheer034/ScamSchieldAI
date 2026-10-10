// ==========================================
// ScamShield AI — Login, Registration and 2FA
// Connected to the Flask authentication API
// ==========================================


// 1. HTML elements

const showLoginButton = document.getElementById("showLogin");
const showRegisterButton = document.getElementById("showRegister");

const authTabs = document.querySelector(".auth-tabs");

const loginPanel = document.getElementById("loginPanel");
const registerPanel = document.getElementById("registerPanel");
const otpPanel = document.getElementById("otpPanel");

const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");
const otpForm = document.getElementById("otpForm");

const loginMessage = document.getElementById("loginMessage");
const registerMessage = document.getElementById("registerMessage");
const otpMessage = document.getElementById("otpMessage");

const loginToRegister = document.getElementById("loginToRegister");
const registerToLogin = document.getElementById("registerToLogin");

const otpHeading = document.getElementById("otpHeading");
const otpDescription = document.getElementById("otpDescription");
const otpBackButton = document.getElementById("otpBackButton");

const otpCodeInput = document.getElementById("otpCode");


// 2. Authentication state

let csrfToken = null;
let pendingEmail = "";
let otpPurpose = "";
let previousPanel = "login";


// 3. Display status messages

function displayMessage(element, message, type = "error") {

    if (!element) {
        return;
    }

    element.textContent = message;
    element.className = "form-message " + type;
}


// 4. Clear messages

function clearMessages() {

    [loginMessage, registerMessage, otpMessage].forEach(element => {

        if (element) {
            element.textContent = "";
            element.className = "form-message";
        }

    });

}


// 5. Switch between Login, Register and OTP

function showAuthenticationPanel(panelName) {

    loginPanel.hidden = panelName !== "login";
    registerPanel.hidden = panelName !== "register";
    otpPanel.hidden = panelName !== "otp";

    if (authTabs) {
        authTabs.hidden = panelName === "otp";
    }

    showLoginButton.classList.toggle(
        "active",
        panelName === "login"
    );

    showRegisterButton.classList.toggle(
        "active",
        panelName === "register"
    );

    showLoginButton.setAttribute(
        "aria-pressed",
        String(panelName === "login")
    );

    showRegisterButton.setAttribute(
        "aria-pressed",
        String(panelName === "register")
    );

    clearMessages();

}


// Connect navigation buttons

showLoginButton.addEventListener("click", () => {
    showAuthenticationPanel("login");
});

showRegisterButton.addEventListener("click", () => {
    showAuthenticationPanel("register");
});

loginToRegister.addEventListener("click", () => {
    showAuthenticationPanel("register");
});

registerToLogin.addEventListener("click", () => {
    showAuthenticationPanel("login");
});


// 6. Show or hide passwords

function connectPasswordToggle(buttonId, inputId) {

    const button = document.getElementById(buttonId);
    const input = document.getElementById(inputId);

    if (!button || !input) {
        return;
    }

    button.addEventListener("click", function () {

        const showPassword = input.type === "password";

        input.type = showPassword ? "text" : "password";

        button.textContent = showPassword ? "Hide" : "Show";

        button.setAttribute(
            "aria-label",
            showPassword ? "Hide password" : "Show password"
        );

    });
}


connectPasswordToggle(
    "toggleLoginPassword",
    "loginPassword"
);

connectPasswordToggle(
    "toggleRegisterPassword",
    "registerPassword"
);

connectPasswordToggle(
    "toggleConfirmPassword",
    "confirmPassword"
);


// 7. Get a CSRF security token from Flask

async function refreshCsrfToken() {

    const response = await fetch("/api/csrf", {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store"
    });

    const data = await response.json();

    if (!response.ok || !data.csrfToken) {
        throw new Error("Could not initialize the security token. Refresh the page and try again.");
    }

    csrfToken = data.csrfToken;
}


// 8. Send a JSON request to the backend

async function apiPost(endpoint, payload) {

    if (!csrfToken) {
        await refreshCsrfToken();
    }

    const response = await fetch(endpoint, {
        method: "POST",
        credentials: "same-origin",

        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": csrfToken
        },

        body: JSON.stringify(payload)
    });

    const data = await response.json().catch(() => ({}));

    // Refresh the token if Flask reports that it has expired.

    if (
        response.status === 400 &&
        typeof data.message === "string" &&
        data.message.toLowerCase().includes("security token")
    ) {
        csrfToken = null;
    }

    if (!response.ok) {

        throw new Error(
            data.message || "The request could not be completed."
        );

    }

    return data;
}


// 9. Set up a submit button while a request is running

function setButtonBusy(button, busy, originalText) {

    if (!button) {
        return;
    }

    button.disabled = busy;

    button.textContent = busy
        ? "Please wait..."
        : originalText;

}


// 10. Display the OTP verification panel

function openOtpPanel(email, purpose, message) {

    pendingEmail = email;
    otpPurpose = purpose;

    previousPanel = purpose === "verify_registration"
        ? "register"
        : "login";

    if (otpHeading) {
        otpHeading.textContent = purpose === "verify_registration"
            ? "Verify Your Email"
            : "Two-Step Verification";
    }

    if (otpDescription) {
        otpDescription.textContent =
            "A six-digit verification code has been sent to " +
            email +
            ". The code expires in five minutes.";
    }

    if (otpBackButton) {

        otpBackButton.textContent = previousPanel === "register"
            ? "← Back to Register"
            : "← Back to Login";

    }

    showAuthenticationPanel("otp");

    displayMessage(otpMessage, message, "success");

    if (otpCodeInput) {
        otpCodeInput.value = "";
        otpCodeInput.focus();
    }

}


// 11. Registration

registerForm.addEventListener("submit", async function (event) {

    event.preventDefault();

    const name = document
        .getElementById("registerName")
        .value
        .trim();

    const email = document
        .getElementById("registerEmail")
        .value
        .trim()
        .toLowerCase();

    const password = document
        .getElementById("registerPassword")
        .value;

    const confirmPassword = document
        .getElementById("confirmPassword")
        .value;

    const submitButton = registerForm.querySelector(
        'button[type="submit"]'
    );

    const originalText = "Create Account →";

    if (password.length < 8 || password.length > 128) {

        displayMessage(
            registerMessage,
            "Password must contain between 8 and 128 characters."
        );

        return;
    }

    if (password !== confirmPassword) {

        displayMessage(
            registerMessage,
            "Passwords do not match."
        );

        return;
    }

    setButtonBusy(submitButton, true, originalText);

    try {

        const data = await apiPost("/api/register", {
            name: name,
            email: email,
            password: password
        });

        if (data.nextStep !== "verify_registration") {
            throw new Error("Unexpected response from the registration server.");
        }

        openOtpPanel(
            email,
            data.nextStep,
            data.message
        );

    } catch (error) {

        displayMessage(
            registerMessage,
            error.message || "Registration failed."
        );

    } finally {

        setButtonBusy(
            submitButton,
            false,
            originalText
        );

    }

});


// 12. Login — verify password first

loginForm.addEventListener("submit", async function (event) {

    event.preventDefault();

    const email = document
        .getElementById("loginEmail")
        .value
        .trim()
        .toLowerCase();

    const password = document
        .getElementById("loginPassword")
        .value;

    const submitButton = loginForm.querySelector(
        'button[type="submit"]'
    );

    const originalText = "Login to Your Account →";

    setButtonBusy(submitButton, true, originalText);

    try {

        const data = await apiPost("/api/login", {
            email: email,
            password: password
        });

        if (data.nextStep !== "verify_login") {
            throw new Error("Unexpected response from the login server.");
        }

        openOtpPanel(
            email,
            data.nextStep,
            data.message
        );

    } catch (error) {

        displayMessage(
            loginMessage,
            error.message || "Login failed."
        );

    } finally {

        setButtonBusy(
            submitButton,
            false,
            originalText
        );

    }

});


// 13. Verify the six-digit OTP

otpForm.addEventListener("submit", async function (event) {

    event.preventDefault();

    const code = otpCodeInput.value.trim();

    const submitButton = document.getElementById(
        "verifyOtpButton"
    );

    const originalText = "Verify and Continue →";

    if (!/^\d{6}$/.test(code)) {

        displayMessage(
            otpMessage,
            "Enter the six-digit verification code."
        );

        return;
    }

    if (!pendingEmail || !otpPurpose) {

        displayMessage(
            otpMessage,
            "Your verification session is missing. Please return to Login or Register."
        );

        return;
    }

    const endpoint = otpPurpose === "verify_registration"
        ? "/api/verify-registration"
        : "/api/verify-login";

    setButtonBusy(submitButton, true, originalText);

    try {

        const data = await apiPost(endpoint, {
            email: pendingEmail,
            code: code
        });

        displayMessage(
            otpMessage,
            data.message || "Verification successful.",
            "success"
        );

        // Redirect only after Flask confirms OTP verification.

        setTimeout(function () {

            window.location.assign(data.redirect || "/");

        }, 600);

    } catch (error) {

        displayMessage(
            otpMessage,
            error.message || "Verification failed."
        );

    } finally {

        setButtonBusy(
            submitButton,
            false,
            originalText
        );

    }

});


// 14. Return to the previous form

otpBackButton.addEventListener("click", function () {

    showAuthenticationPanel(previousPanel);

});


// 15. Keep OTP input numeric

otpCodeInput.addEventListener("input", function () {

    otpCodeInput.value = otpCodeInput.value
        .replace(/\D/g, "")
        .slice(0, 6);

});


// 16. Initialize the interface

showAuthenticationPanel("login");

console.log("ScamShield AI login interface initialized.");