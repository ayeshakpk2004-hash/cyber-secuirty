# Security Best Practices Checklist

- [ ] Validate and sanitize **all** inputs (client + server).
- [ ] Enforce strong passwords (min length, complexity, breach check if possible).
- [ ] Hash and salt passwords with bcrypt/argon2.
- [ ] Use HTTPS/TLS in production; HSTS enabled.
- [ ] Store secrets in environment variables; do **not** commit `.env`.
- [ ] Use secure HTTP headers (Helmet).
- [ ] Implement rate limiting on auth endpoints.
- [ ] Implement brute-force protection / account lockouts.
- [ ] Use JWT with short expiry; consider refresh tokens and rotation.
- [ ] Log security-relevant events; protect logs from tampering.
- [ ] Principle of least privilege for services and DB accounts.
- [ ] Regular dependency updates and vulnerability scans (e.g., `npm audit`).
- [ ] Backup and recovery procedures documented.
- [ ] Security review before releases.
