// ==========================================
// ScamShield AI — Job Scam Detection
// Rule-based prototype for a hackathon MVP
// ==========================================


// 1. Connect JavaScript to the HTML elements

const jobText = document.getElementById("jobText");
const jobFile = document.getElementById("jobFile");
const fileName = document.getElementById("fileName");
const analyzeButton = document.getElementById("analyzeButton");

const riskScore = document.getElementById("riskScore");
const riskLabel = document.getElementById("riskLabel");
const riskDescription = document.getElementById("riskDescription");

const warningList = document.getElementById("warningList");
const recommendationText = document.getElementById("recommendationText");


// 2. Check that the required HTML elements exist

if (
    !jobText ||
    !analyzeButton ||
    !riskScore ||
    !riskLabel ||
    !riskDescription ||
    !warningList ||
    !recommendationText
) {
    console.error(
        "ScamShield AI: A required HTML element is missing. Check the element IDs in index.html."
    );
} else {

    // 3. Define the warning signs to investigate

    function detectWarningSigns(text) {

        const findings = [];
        const normalizedText = text.toLowerCase();

        // Warning sign 1: Requests for upfront payments

        const feePattern =
            /\b(registration fee|refundable fee|processing fee|joining fee|security deposit|application fee|training fee|placement fee|pay to apply|pay to get the job|advance payment|pay an upfront fee)\b/i;

        if (feePattern.test(normalizedText)) {
            findings.push({
                title: "Upfront payment requested",
                description:
                    "The message mentions a registration, processing, training, or similar fee.",
                points: 30
            });
        }


        // Warning sign 2: Requests for passwords, OTPs, or PINs

        const credentialPattern =
            /\b(share|send|provide|tell|submit|enter|reveal|verify)\b.{0,45}\b(otp|one[- ]time password|password|upi pin|atm pin|cvv)\b|\b(otp|one[- ]time password|upi pin|atm pin|cvv)\b.{0,45}\b(share|send|provide|tell|submit|reveal)\b/i;

        if (credentialPattern.test(normalizedText)) {
            findings.push({
                title: "Sensitive credentials requested",
                description:
                    "The message may be asking for an OTP, password, PIN, or other security credential.",
                points: 35
            });
        }


        // Warning sign 3: Sensitive personal or financial information

        const personalDataPattern =
            /\b(aadhaar|aadhar|pan card|bank account details|bank account number|debit card details|credit card details|identity document|identity proof)\b/i;

        if (personalDataPattern.test(normalizedText)) {
            findings.push({
                title: "Sensitive personal or financial information",
                description:
                    "The message mentions identity documents or financial information. Verify why the information is needed before sharing it.",
                points: 20
            });
        }


        // Warning sign 4: Pressure to act immediately

        const urgencyPattern =
            /\b(act now|urgent|immediately|limited time|offer expires|last chance|apply immediately|within 24 hours|limited vacancies|hurry up)\b/i;

        if (urgencyPattern.test(normalizedText)) {
            findings.push({
                title: "Pressure to act quickly",
                description:
                    "The message uses urgency or scarcity language that could pressure applicants into making rushed decisions.",
                points: 10
            });
        }


        // Warning sign 5: Potentially unrealistic salary claims

        const salaryPattern =
            /(?:₹|rs\.?\s*|inr\s*)?(\d{1,3}(?:,\d{3})+|\d{5,})\s*(?:\/\s*|per\s+)(week|weekly|day|daily)\b/i;

        const salaryMatch = normalizedText.match(salaryPattern);

        if (salaryMatch) {

            const salaryAmount = Number(
                salaryMatch[1].replace(/,/g, "")
            );

            const salaryPeriod = salaryMatch[2];

            const unusuallyHigh =
                (salaryPeriod.startsWith("week") && salaryAmount >= 25000) ||
                (salaryPeriod.startsWith("day") && salaryAmount >= 5000);

            if (unusuallyHigh) {
                findings.push({
                    title: "Salary claim worth verifying",
                    description:
                        "The advertised pay is unusually high for a weekly or daily amount. Compare it with reliable listings for the same role.",
                    points: 20
                });
            }
        }


        // Warning sign 6: Guaranteed job without an interview

        const noInterviewPattern =
            /\b(no interview|without interview|guaranteed job|job guaranteed|direct selection guaranteed)\b/i;

        if (noInterviewPattern.test(normalizedText)) {
            findings.push({
                title: "Guaranteed selection claim",
                description:
                    "The message promises selection without a normal assessment or interview. Check the employer's official recruitment process.",
                points: 10
            });
        }


        // Warning sign 7: High pay combined with no experience required

        const noExperiencePattern =
            /\b(no experience required|no experience needed|no prior experience|zero experience)\b/i;

        const highPayClaimPattern =
            /\b(high salary|huge salary|earn thousands|easy money|earn lakhs|very high salary)\b/i;

        if (
            noExperiencePattern.test(normalizedText) &&
            highPayClaimPattern.test(normalizedText)
        ) {
            findings.push({
                title: "High earnings with no experience",
                description:
                    "The message combines promises of high earnings with no experience requirements. Verify the duties, employer, and compensation.",
                points: 15
            });
        }


        // Return the findings and the total illustrative score

        const totalPoints = findings.reduce(
            (total, finding) => total + finding.points,
            0
        );

        const score = Math.min(totalPoints, 100);

        return {
            score: score,
            findings: findings
        };
    }


    // 4. Display a finding safely on the webpage

    function addWarning(title, description) {

        const item = document.createElement("li");

        const heading = document.createElement("strong");
        heading.textContent = title;

        const details = document.createElement("p");
        details.textContent = description;

        item.appendChild(heading);
        item.appendChild(details);

        warningList.appendChild(item);
    }


    // 5. Analyze the job description

    function analyzeJob() {

        const text = jobText.value.trim();

        if (!text) {
            alert("Please paste a job description or load a supported text file first.");
            jobText.focus();
            return;
        }

        const result = detectWarningSigns(text);

        // Display the illustrative score

        riskScore.textContent = result.score + "/100";


        // Display the risk category

        let category;
        let explanation;
        let recommendation;

        if (result.score >= 70) {

            category = "Very High Warning";

            explanation =
                "Several significant warning signs were found. Do not pay or share sensitive information until you independently verify the opportunity.";

            recommendation =
                "Pause the application. Verify the employer through its official website and contact details obtained independently. Never share an OTP, password, or UPI PIN.";

        } else if (result.score >= 40) {

            category = "High Warning";

            explanation =
                "Multiple warning signs were found. Investigate the employer, recruiter, and job details carefully before proceeding.";

            recommendation =
                "Do not make payments or share sensitive information. Check the company's official careers page and verify the recruiter's identity independently.";

        } else if (result.score >= 20) {

            category = "Use Caution";

            explanation =
                "Some warning signs were found. These signals are not proof of fraud, but they deserve further investigation.";

            recommendation =
                "Verify the employer and job listing through independent sources before sharing personal details or accepting an offer.";

        } else {

            category = "Few Warning Signs Found";

            explanation =
                "This prototype found few of the warning phrases it checks for. That does not establish that the job is legitimate.";

            recommendation =
                "Verify the employer, official job listing, recruiter identity, and employment terms independently before proceeding.";
        }

        riskLabel.textContent = category;
        riskDescription.textContent = explanation;
        recommendationText.textContent = recommendation;


        // Clear the results from the previous scan

        warningList.replaceChildren();


        // Display the identified warning signs

        if (result.findings.length === 0) {

            addWarning(
                "No matching warning phrases found",
                "The scanner did not detect any of its predefined warning patterns. Scams can still use other tactics."
            );

        } else {

            result.findings.forEach(function (finding) {

                addWarning(
                    finding.title,
                    finding.description
                );

            });
        }

        console.log("ScamShield AI scan completed:", result);
    }


    // 6. Connect the Analyze button

    analyzeButton.addEventListener("click", analyzeJob);


    // 7. Display the selected filename

    if (jobFile) {

        jobFile.addEventListener("change", function () {

            const file = jobFile.files[0];

            if (!file) {
                return;
            }

            if (fileName) {
                fileName.textContent = "Selected file: " + file.name;
            }

        });

    }


// 8. Read TXT, EML, HTML, PDF and DOCX files

if (jobFile) {

    jobFile.addEventListener("change", async function () {

        const file = jobFile.files[0];

        if (!file) {
            return;
        }

        const extension = file.name
            .split(".")
            .pop()
            .toLowerCase();

        const supportedTypes = [
            "txt",
            "eml",
            "html",
            "htm",
            "pdf",
            "docx"
        ];

        // Check the file type

        if (!supportedTypes.includes(extension)) {

            if (fileName) {
                fileName.textContent =
                    "Unsupported file type. Use TXT, EML, HTML, PDF or DOCX.";
            }

            alert("Please upload a supported file type.");
            return;
        }

        // Limit the file size for the prototype

        if (file.size > 15 * 1024 * 1024) {

            alert("Please upload a file smaller than 15 MB.");
            return;
        }

        try {

            let extractedText = "";

            // --------------------------------
            // PDF FILE EXTRACTION
            // --------------------------------

            if (extension === "pdf") {

                if (fileName) {
                    fileName.textContent = "Reading PDF...";
                }

                const pdfjsLib = await import(
                    "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/6.4.299/pdf.min.mjs"
                );

                pdfjsLib.GlobalWorkerOptions.workerSrc =
                    "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/6.4.299/pdf.worker.min.mjs";

                const fileData = await file.arrayBuffer();

                const pdfDocument = await pdfjsLib
                    .getDocument({ data: fileData })
                    .promise;

                if (pdfDocument.numPages > 80) {
                    throw new Error(
                        "For this prototype, PDF files can contain up to 80 pages."
                    );
                }

                const pageTexts = [];

                for (
                    let pageNumber = 1;
                    pageNumber <= pdfDocument.numPages;
                    pageNumber++
                ) {

                    const page = await pdfDocument.getPage(pageNumber);

                    const content = await page.getTextContent();

                    const pageText = content.items
                        .map(item => item.str || "")
                        .join(" ");

                    pageTexts.push(pageText);
                }

                extractedText = pageTexts.join("\n").trim();

                if (!extractedText) {
                    throw new Error(
                        "No readable text was found. This may be a scanned PDF; OCR is not supported yet."
                    );
                }
            }

            // --------------------------------
            // WORD DOCUMENT EXTRACTION
            // --------------------------------

            else if (extension === "docx") {

                if (fileName) {
                    fileName.textContent = "Reading Word document...";
                }

                if (!window.mammoth) {
                    throw new Error(
                        "The Word document library did not load. Check your internet connection and refresh the page."
                    );
                }

                const fileData = await file.arrayBuffer();

                const result = await window.mammoth.extractRawText({
                    arrayBuffer: fileData
                });

                extractedText = result.value.trim();
            }

            // --------------------------------
            // TXT, EML AND HTML EXTRACTION
            // --------------------------------

            else {

                const contents = await file.text();

                if (extension === "html" || extension === "htm") {

                    const parser = new DOMParser();

                    const parsedDocument = parser.parseFromString(
                        contents,
                        "text/html"
                    );

                    // Remove active and non-visible elements before
                    // extracting text. Never execute uploaded HTML.

                    parsedDocument
                        .querySelectorAll(
                            "script, style, iframe, object, embed, noscript"
                        )
                        .forEach(element => element.remove());

                    extractedText = parsedDocument.body
                        ? parsedDocument.body.textContent.trim()
                        : "";

                } else {

                    // TXT and EML are processed as plain text

                    extractedText = contents.trim();
                }
            }

            // --------------------------------
            // PUT EXTRACTED TEXT INTO THE SCANNER
            // --------------------------------

            if (!extractedText) {

                throw new Error(
                    "No readable text was found in this file."
                );
            }

            jobText.value = extractedText;

            if (fileName) {
                fileName.textContent = "Loaded successfully: " + file.name;
            }

        } catch (error) {

            console.error("File extraction error:", error);

            if (fileName) {
                fileName.textContent =
                    "Could not read the file: " + file.name;
            }

            alert(
                error.message ||
                "Unable to read this file. Please try another file."
            );
        }

    });

}
// ==========================================
// 9. Skillup Learning Progress Tracker
// ==========================================

const roadmapCheckboxes = Array.from(
    document.querySelectorAll(".roadmap-step-check")
);

const progressText = document.getElementById(
    "roadmap-progress-text"
);

const progressPercent = document.getElementById(
    "roadmap-progress-percent"
);

const progressBar = document.getElementById(
    "roadmap-progress-bar"
);

const progressFill = document.getElementById(
    "roadmap-progress-fill"
);

const storageKey = "scamshield-java-roadmap-progress";


// Style the progress bar

if (progressBar) {
    progressBar.style.height = "10px";
    progressBar.style.backgroundColor = "rgba(255,255,255,0.12)";
    progressBar.style.borderRadius = "20px";
    progressBar.style.overflow = "hidden";
}

if (progressFill) {
    progressFill.style.height = "100%";
    progressFill.style.width = "0%";
    progressFill.style.background =
        "linear-gradient(90deg, #66e5df, #b49aff)";
    progressFill.style.borderRadius = "20px";
    progressFill.style.transition = "width 0.3s ease";
}


// Update the progress display

function updateRoadmapProgress(saveProgress = true) {

    const totalSteps = roadmapCheckboxes.length;

    const completedSteps = roadmapCheckboxes.filter(
        checkbox => checkbox.checked
    ).length;

    const percentage = totalSteps > 0
        ? Math.round((completedSteps / totalSteps) * 100)
        : 0;


    // Update the progress text

    if (progressText) {
        progressText.textContent =
            `${completedSteps} of ${totalSteps} steps completed`;
    }

    if (progressPercent) {
        progressPercent.textContent = `${percentage}%`;
    }


    // Update the visual progress bar

    if (progressFill) {
        progressFill.style.width = `${percentage}%`;
    }

    if (progressBar) {
        progressBar.setAttribute(
            "aria-valuenow",
            String(percentage)
        );
    }


    // Remember completed stages

    if (saveProgress) {

        try {

            const completedStepNumbers = roadmapCheckboxes
                .filter(checkbox => checkbox.checked)
                .map(checkbox => checkbox.dataset.step);

            localStorage.setItem(
                storageKey,
                JSON.stringify(completedStepNumbers)
            );

        } catch (error) {

            console.warn(
                "Progress could not be saved in this browser.",
                error
            );

        }
    }
}


// Restore previously completed stages

try {

    const savedProgress = JSON.parse(
        localStorage.getItem(storageKey) || "[]"
    );

    if (Array.isArray(savedProgress)) {

        roadmapCheckboxes.forEach(checkbox => {

            checkbox.checked = savedProgress.includes(
                checkbox.dataset.step
            );

        });

    }

} catch (error) {

    console.warn("Could not restore learning progress.", error);

}


// Update progress whenever a checkbox changes

roadmapCheckboxes.forEach(checkbox => {

    checkbox.addEventListener("change", function () {
        updateRoadmapProgress();
    });

});


// Display the initial progress

updateRoadmapProgress(false);
// ==========================================
// 10. Download ScamShield AI Scan Report
// ==========================================

const downloadReportButton = document.getElementById(
    "downloadReportButton"
);

if (downloadReportButton) {

    downloadReportButton.addEventListener("click", function () {

        // Ensure the user has performed a scan first

        if (
            warningList.textContent.includes(
                "No analysis performed yet."
            )
        ) {
            alert("Please analyze a job offer before downloading a report.");
            return;
        }

        // Collect the displayed scan results

        const score = riskScore.textContent.trim();
        const category = riskLabel.textContent.trim();
        const explanation = riskDescription.textContent.trim();
        const recommendation = recommendationText.textContent.trim();

        const warnings = Array.from(
            warningList.querySelectorAll("li")
        ).map(function (item) {
            return "- " + item.innerText.trim();
        });

        const scanDate = new Date().toLocaleString();

        // Build the report

        const report = `
========================================
          SCAMSHIELD AI
       JOB SAFETY SCAN REPORT
========================================

Scan Date: ${scanDate}

RISK ASSESSMENT
----------------------------------------
Risk Indicator: ${score}
Category: ${category}

SUMMARY
----------------------------------------
${explanation}

DETECTED WARNING SIGNS
----------------------------------------
${warnings.join("\n\n")}

SAFETY RECOMMENDATION
----------------------------------------
${recommendation}

IMPORTANT DISCLAIMER
----------------------------------------
This report is generated by a rule-based
prototype. Its score is an illustrative
indicator, not a validated probability
of fraud.

Detected warning signs do not prove that
a job is fraudulent. The absence of
warning signs does not prove that a job
is genuine.

Always verify the employer and job
opportunity independently.

========================================
          END OF REPORT
========================================
`;

        // Create a downloadable text file

        const blob = new Blob(
            [report],
            { type: "text/plain;charset=utf-8" }
        );

        const downloadURL = URL.createObjectURL(blob);

        const downloadLink = document.createElement("a");

        downloadLink.href = downloadURL;
        downloadLink.download = "ScamShield_Scan_Report.txt";

        document.body.appendChild(downloadLink);

        downloadLink.click();

        downloadLink.remove();

        URL.revokeObjectURL(downloadURL);

    });

}
}
// ==========================================
// 11. Secure Logout
// ==========================================

const logoutButton = document.getElementById("logoutButton");

if (logoutButton) {

    logoutButton.addEventListener("click", async function () {

        const originalText = logoutButton.textContent;

        logoutButton.disabled = true;
        logoutButton.textContent = "Logging out...";

        try {

            // Obtain a CSRF token from Flask

            const tokenResponse = await fetch("/api/csrf", {
                credentials: "same-origin",
                cache: "no-store"
            });

            if (!tokenResponse.ok) {
                throw new Error("Could not initialize the security token.");
            }

            const tokenData = await tokenResponse.json();

            // Request logout from the Flask backend

            const response = await fetch("/api/logout", {

                method: "POST",

                credentials: "same-origin",

                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": tokenData.csrfToken
                },

                body: JSON.stringify({})

            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(
                    data.message || "Logout failed."
                );
            }

            // Return to Login after the server clears the session

            window.location.replace("/login");

        } catch (error) {

            console.error("Logout error:", error);

            alert(
                "Unable to log out. Please try refreshing the page."
            );

            logoutButton.disabled = false;
            logoutButton.textContent = originalText;

        }

    });
// ==========================================
// 12. Display the Logged-In User's Name
// ==========================================

const userGreeting = document.getElementById("userGreeting"); 
const currentUserName = document.getElementById("currentUserName");
const signInButton = document.getElementById("signInButton");

async function loadLoggedInUserGreeting() {

    // Stop if the greeting elements are not present.

    if (!userGreeting || !currentUserName) {
        return;
    }

    try {

        // Ask Flask for the current user's information.

        const response = await fetch("/api/me", {
            method: "GET",
            credentials: "same-origin",
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error("Could not retrieve the user profile.");
        }

        const data = await response.json();

        // Display the greeting only for an authenticated user.

     if (
    data.authenticated &&
    data.user &&
    typeof data.user.name === "string"
) {

    // Display the logged-in user's name.
    currentUserName.textContent = data.user.name;
    userGreeting.hidden = false;

    // Hide Sign In when the user is authenticated.
    if (signInButton) {
        signInButton.hidden = true;
    }

} else {

    // Hide the personalized greeting.
    userGreeting.hidden = true;

    // Show Sign In when the user is not authenticated.
    if (signInButton) {
        signInButton.hidden = false;
    }

}

    } catch (error) {

        console.error("User greeting error:", error);

        userGreeting.hidden = true;

    }
}


// Load the user's name when the page opens.

loadLoggedInUserGreeting();
}
// ==========================================
// 13. Resume & Job Match Feature
// ==========================================

const resumeMatchFileInput = document.getElementById("resumeFile");
const resumeMatchFileName = document.getElementById("resumeFileName");
const resumeMatchJobText = document.getElementById("jobEmailText");

const resumeMatchButton = document.getElementById(
    "analyzeResumeMatchButton"
);

const resumeMatchStatus = document.getElementById(
    "resumeMatchStatus"
);

const resumeMatchScore = document.getElementById(
    "resumeMatchScore"
);

const matchedSkillsList = document.getElementById(
    "matchedSkillsList"
);

const missingSkillsList = document.getElementById(
    "missingSkillsList"
);

const resumeRecommendations = document.getElementById(
    "resumeRecommendations"
);


// Display the selected resume filename.

if (resumeMatchFileInput) {

    resumeMatchFileInput.addEventListener("change", function () {

        const file = resumeMatchFileInput.files[0];

        if (resumeMatchFileName) {
            resumeMatchFileName.textContent = file
                ? "Selected: " + file.name
                : "No resume selected";
        }

    });

}


// Helper: Display lists safely without inserting HTML from the server.

function displayResumeSkillList(listElement, items, emptyMessage) {

    if (!listElement) {
        return;
    }

    listElement.replaceChildren();

    if (!Array.isArray(items) || items.length === 0) {

        const item = document.createElement("li");

        item.textContent = emptyMessage;

        listElement.appendChild(item);

        return;
    }

    items.forEach(function (skill) {

        const item = document.createElement("li");

        item.textContent = skill;

        listElement.appendChild(item);

    });

}


// Run the resume comparison.

if (resumeMatchButton) {

    resumeMatchButton.addEventListener("click", async function () {

        const resumeFile = resumeMatchFileInput
            ? resumeMatchFileInput.files[0]
            : null;

        const jobDescription =
    (resumeMatchJobText?.value.trim() ||
    document.getElementById("jobText")?.value.trim() ||
    "");

        // Validate the inputs.

        if (!resumeFile) {

            alert("Please upload your resume first.");

            return;
        }

        if (!jobDescription) {

            alert("Please paste a job description or recruitment email.");

            resumeMatchJobText.focus();

            return;
        }

        // Validate file extension.

        const extension = resumeFile.name
            .split(".")
            .pop()
            .toLowerCase();

        const allowedExtensions = ["pdf", "docx", "txt"];

        if (!allowedExtensions.includes(extension)) {

            alert("Please upload a PDF, DOCX, or TXT resume.");

            return;
        }

        // Validate file size. The backend has its own checks too.

        if (resumeFile.size > 5 * 1024 * 1024) {

            alert("Please upload a resume smaller than 5 MB.");

            return;
        }

        const originalButtonText = "Compare Resume & Job →";

        resumeMatchButton.disabled = true;

        resumeMatchButton.textContent = "Analyzing Resume...";

        if (resumeMatchStatus) {
            resumeMatchStatus.textContent =
                "Extracting resume text and comparing recognized skills...";
        }

        if (resumeMatchScore) {
            resumeMatchScore.textContent = "--%";
        }

        try {

            // Step 1: Obtain a CSRF security token from Flask.

            const tokenResponse = await fetch("/api/csrf", {
                method: "GET",
                credentials: "same-origin",
                cache: "no-store"
            });

            const tokenContentType =
                tokenResponse.headers.get("content-type") || "";

            if (
                !tokenResponse.ok ||
                !tokenContentType.includes("application/json")
            ) {
                throw new Error(
                    "Could not initialize security. Open ScamShield AI through http://127.0.0.1:5000/."
                );
            }

            const tokenData = await tokenResponse.json();

            if (!tokenData.csrfToken) {

                throw new Error(
                    "The security token is missing. Refresh the page and try again."
                );

            }

            // Step 2: Prepare the uploaded file and job description.

            const formData = new FormData();

            formData.append("resumeFile", resumeFile);

            formData.append("jobDescription", jobDescription);


            // Step 3: Send the comparison request to Flask.

            const response = await fetch("/api/resume-match", {

                method: "POST",

                credentials: "same-origin",

                headers: {
                    "X-CSRFToken": tokenData.csrfToken
                },

                body: formData

            });

            const responseContentType =
                response.headers.get("content-type") || "";

            if (!responseContentType.includes("application/json")) {

                throw new Error(
                    "The server returned an unexpected response. Make sure Flask is running and you are not using Live Server."
                );

            }

            const data = await response.json();

            if (!response.ok) {

                throw new Error(
                    data.message || "The resume comparison failed."
                );

            }


            // Step 4: Display the match score.

            if (resumeMatchScore) {
                resumeMatchScore.textContent =
                    data.matchScore + "%";
            }


            // Step 5: Display matching skills.

            displayResumeSkillList(
                matchedSkillsList,
                data.matchedSkills,
                "No matching skills were identified."
            );


            // Step 6: Display skills not found in the resume.

            displayResumeSkillList(
                missingSkillsList,
                data.missingSkills,
                "No skill gaps were identified by the keyword matcher."
            );


            // Step 7: Display recommendations.

            if (resumeRecommendations) {

                resumeRecommendations.textContent =
                    Array.isArray(data.recommendations)
                        ? data.recommendations.join("\n\n")
                        : "No recommendations were returned.";

                resumeRecommendations.style.whiteSpace = "pre-line";

            }


            // Step 8: Explain what the score means.

          if (resumeMatchStatus) {

    if (data.method === "openai_ai") {

        const summary = typeof data.summary === "string"
            ? data.summary
            : "";

        resumeMatchStatus.textContent =
            "✅ AI-powered analysis completed. " + summary;

        resumeMatchStatus.style.whiteSpace = "pre-line";

    } else {

        resumeMatchStatus.textContent =
            "ℹ️ Keyword-based comparison completed. AI analysis was unavailable, so these results use predefined skill-matching rules.";

    }

}   

        } catch (error) {

            console.error("Resume comparison error:", error);

            if (resumeMatchStatus) {

                resumeMatchStatus.textContent =
                    error.message || "Unable to compare the resume.";

            }

            if (resumeMatchScore) {
                resumeMatchScore.textContent = "--%";
            }

        } finally {

            // Restore the button whether the request succeeds or fails.

            resumeMatchButton.disabled = false;

            resumeMatchButton.textContent = originalButtonText;

        }

    });

}