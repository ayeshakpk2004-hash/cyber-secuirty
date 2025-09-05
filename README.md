# Task for Cybersecurity Interns: Strengthening Security Measures for a Web Application

## Overview
Analyze a simple User Management System for vulnerabilities and apply security measures. Learn the basics of web app security by identifying and fixing common issues.

## Week 1: Security Assessment
1. **Understand the Application**
   - Use the sample app in `server/`.
   - Start it with:
     ```bash
     cd server
     npm install
     cp .env.example .env
     # edit .env and change JWT_SECRET
     npm start
     ```
     Visit `http://localhost:3000`. Try **signup**, **login**, and **/profile** (with Bearer token).

2. **Perform Basic Vulnerability Assessment**
   - **OWASP ZAP**: Automated scanning against `http://localhost:3000`.
   - **Browser DevTools**: Try `<script>alert('XSS');</script>` in input fields.
   - **SQL Injection**: Try classic payloads like `admin' OR '1'='1` conceptually; document how this app resists and what would change if SQL were used.
   - **Focus Areas**: XSS, weak password storage, misconfigurations.

3. **Document Findings**
   - Use `REPORT_TEMPLATE.md` to list vulnerabilities and improvements.

## Week 2: Implementing Security Measures
1. **Fix Vulnerabilities**
   - Input validation/sanitization with `validator` (already included). Extend rules as needed.
   - Password hashing with `bcrypt` (already included).
2. **Enhance Authentication**
   - Token-based auth using `jsonwebtoken` (already included). Consider refresh tokens and rotation.
3. **Secure Data Transmission**
   - Helmet is enabled. Note: for production, use HTTPS/TLS termination (document in report).

## Week 3: Advanced Security and Final Reporting
1. **Basic Pen Testing**
   - Use `nmap` or browser-based testing to simulate common attacks.
2. **Logging**
   - `winston` writes to console and `security.log`. Extend with levels and error tracking.
3. **Checklist**
   - Complete `CHECKLIST.md` to confirm best practices.
4. **Final Submission**
   - Recorded video, GitHub repo, and report.

## Submission Details
- **Deadline:** 5th Sep, 2025
- **Submit:** Video explanation, GitHub repository link, and report document.
