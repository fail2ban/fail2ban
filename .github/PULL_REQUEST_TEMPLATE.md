Before submitting your PR, please review the following checklist:

- [ ] **CHOOSE CORRECT BRANCH**: if filing a bugfix/enhancement
      against certain release version, choose `0.9`, `0.10` or `0.11` branch,
      for dev-edition use `master` branch
- [ ] **CONSIDER adding a unit test** if your PR resolves an issue
- [ ] **LIST ISSUES** this PR resolves
- [ ] **MAKE SURE** this PR doesn't break existing tests
- [ ] **KEEP PR small** so it could be easily reviewed.
- [ ] **AVOID** making unnecessary stylistic changes in unrelated code
- [ ] **ACCOMPANY** each new `failregex` for filter `X` with sample log lines
      within `fail2ban/tests/files/logs/X` file
