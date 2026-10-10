# ScamShield AI

**Employment safety and career-readiness prototype**  
Theme: *Automation, AI, and the Future of Jobs*

ScamShield AI is a web application concept designed to help job seekers review suspicious recruitment messages, compare their resume with a job description, and plan learning activities for a target career.

> **Project status:** Hackathon prototype. The current scam checks are rule-based, and resume matching currently works through keyword matching. The optional OpenAI integration is present in the backend code but was not working during the latest test because the configured API key was rejected. Do not describe the current results as AI-generated unless the API connection is repaired and verified.

## Features

### 1. Job offer scanner
- Accepts pasted job advertisements or recruitment emails.
- Supports document text extraction for PDF, DOCX, TXT, EML, and HTML/HTM in the existing frontend flow.
- Looks for predefined warning signals such as upfront fees, requests for sensitive information, urgency, certain high-pay claims, and guaranteed-selection language.
- Displays an illustrative warning score, findings, and a safety recommendation.
- Downloads a text scan report.

The scanner flags indicators for further review. It does not prove that an opportunity is fraudulent or legitimate, and its score is not a validated probability of fraud.

### 2. Resume & Job Match
- Accepts a PDF, DOCX, or TXT resume.
- Compares extracted resume text with a pasted job description or recruitment email.
- Shows recognized matching skills, skills not found in the resume text, an estimated keyword-coverage score, and recommendations.
- Requires an authenticated, email-verified session for the backend comparison endpoint.

The current reliable mode is **keyword-based matching**. A skill omitted from a resume may still be known by the candidate; the system cannot reliably assess proficiency from keyword presence alone.

### 3. Skillup career roadmap
- Provides career cards and learning-resource links.
- Includes a Full Stack Java Developer roadmap.
- Lets users check off learning stages and displays progress.
- Saves progress in the browser's `localStorage`, so it is local to that browser/device rather than an account-level sync.

### 4. Registration and two-step login
- Flask routes handle registration and login.
- Passwords are stored as hashes using Werkzeug security helpers.
- Email verification and login OTP are sent through configured SMTP credentials.
- OTPs expire after five minutes and have a limited number of verification attempts.
- Flask session cookies and CSRF protection are configured.
- The homepage checks the session; logout clears the session.

### 5. Supporting sections
- Verify and Scam Reports interface sections are included in the prototype. Their underlying verification sources or reporting workflows should be reviewed before claiming any third-party verification or real-world reporting integration.

## Technology stack

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Python, Flask
- **Database:** SQLite
- **Authentication:** Werkzeug password hashing, Flask sessions, Flask-WTF CSRF protection, Flask-Limiter request limits
- **Document extraction:** `pypdf`, `python-docx`, plus browser-side libraries for PDF and DOCX extraction in the existing UI
- **Email:** SMTP (Gmail SMTP is the current configuration example)
- **Optional AI integration:** OpenAI Python SDK; currently needs a valid API key and a successfully tested request

## Project structure

```text
TS-072_ScamShieldAI/
├── app.py
├── scamshield.db          # created by the application; do not publish
├── .env                   # local secrets; do not publish
├── .gitignore
├── index.html
├── style.css
├── script.js
├── login.html
├── login.css
└── login.js
```

Additional files may be present in your local project. Keep the existing names and paths consistent with the routes in `app.py`.

## Local setup

### 1. Install Python packages

Open a terminal in the project directory and run:

```powershell
py -m pip install Flask Flask-WTF Flask-Limiter python-dotenv pypdf python-docx openai
```

If a package is already installed, pip will report that it is satisfied.

### 2. Configure `.env`

Create a `.env` file beside `app.py`. Never commit this file to a public repository.

```dotenv
SECRET_KEY=replace_with_a_long_random_secret
COOKIE_SECURE=0
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_gmail_app_password
MAIL_FROM=your_email@gmail.com
OPENAI_API_KEY=your_openai_api_key_if_used
OPENAI_MODEL=gpt-5-mini
```

Generate a secret key locally with:

```powershell
py -c "import secrets; print(secrets.token_hex(32))"
```

Use a Gmail App Password when using Gmail SMTP, not the normal Gmail password. If the OpenAI API integration is not enabled, keep the key unset and use the keyword-based resume matcher. API access and charges are separate from a ChatGPT subscription; check current API pricing before making requests.

`COOKIE_SECURE=0` is intended only for local HTTP development. For a properly configured HTTPS deployment, set secure cookies and review all production settings.

### 3. Start the application

Run from the directory containing `app.py`:

```powershell
py app.py
```

Open the site through Flask, not VS Code Live Server:

- Login: `http://127.0.0.1:5000/login`
- Dashboard: `http://127.0.0.1:5000/`

Keep the terminal open while testing. The SQLite database is initialized by the application if needed.

## Important API routes

| Route | Purpose |
|---|---|
| `GET /api/csrf` | Provides a CSRF token for frontend requests |
| `POST /api/register` | Starts account registration and sends email verification |
| `POST /api/verify-registration` | Verifies registration OTP |
| `POST /api/login` | Checks credentials and sends a login OTP |
| `POST /api/verify-login` | Verifies login OTP and creates the session |
| `GET /api/me` | Returns the authenticated user's basic profile, if signed in |
| `POST /api/logout` | Clears the session |
| `POST /api/resume-match` | Compares an uploaded resume with a job description |

## Privacy and security notes

- Use fictional or redacted resume and job-ad data for demos.
- Resume text may be processed by the Flask server. If the OpenAI integration is enabled, the submitted resume text and job description are sent to the configured AI provider; disclose this to users and avoid sending sensitive data unnecessarily.
- Never place API keys, SMTP passwords, session secrets, or database files in frontend JavaScript or a public repository.
- Keep `.env`, `scamshield.db`, Python cache files, and virtual environments out of Git. A `.gitignore` should include at least:

```gitignore
.env
scamshield.db
__pycache__/
.venv/
*.pyc
```

- Rotating a secret that was exposed in a repository or screenshot is safer than merely deleting the visible copy.
- Flask's built-in server is for local development, not public production hosting.
- Before public deployment, review HTTPS, secure cookie settings, secret management, database backup and migration, persistent rate-limit storage, OTP resend controls, account enumeration, logging, file limits, monitoring, and authentication/session behavior.
- A local URL such as `127.0.0.1:5000` is not a public deployment link.

## Known limitations

1. Scam detection uses predefined text rules. It can miss new scam tactics and can flag legitimate messages that contain similar phrases.
2. The scam score is an illustrative signal score, not a statistically calibrated fraud probability.
3. Resume matching is based on known skill keywords in the documents; it does not reliably judge context, experience depth, transferable skills, or true competence.
4. The attempted OpenAI branch did not work in the latest test because the API returned `401 invalid_api_key`; the application fell back to keyword matching. AI mode must be retested with a valid API key before being demonstrated as operational.
5. Scanned PDFs made of images may not yield text unless OCR is implemented.
6. Skillup progress is stored locally in the browser and does not sync between devices or accounts.
7. Verify and Scam Reports sections should not be described as connected to authoritative external databases unless such integrations have been implemented and tested.

## Suggested demo flow

1. Log in and complete email OTP verification.
2. Upload a fictional job advertisement in Job Scanner; show the warnings and download a scan report.
3. Upload a sample resume and paste a fictional job description in Resume & Job Match; explain the keyword-based score accurately.
4. Open Skillup, mark roadmap steps complete, and refresh to demonstrate local progress persistence.
5. Log out, open the dashboard URL, and demonstrate the redirect to Login.

## Project metadata to complete

- Team name: `[Add team name]`
- Team members: `[Add names]`
- Institution: `[Add institution]`
- Hackathon name: `[Add hackathon name]`
- Public deployment URL: `[Add only after a public deployment is tested]`
- Repository URL: `[Add repository URL, after checking no secrets or database have been committed]`
