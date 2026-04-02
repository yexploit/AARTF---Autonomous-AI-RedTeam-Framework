# AARTF v1.0.0 Release Checklist

Use this checklist before creating your first GitHub release.

## 1) Repository metadata

- [ ] Rename placeholders in `README.md` CI badge:
  - Replace `<OWNER>` with your GitHub username/org
  - Replace `<REPO>` with your repository name
- [ ] Confirm project description, topics, and homepage in GitHub repo settings
- [ ] Add social preview image (optional, recommended)

## 2) Local validation

- [ ] Create clean virtual environment
- [ ] Install dependencies:
  - `pip install -r requirements.txt`
- [ ] CLI smoke test:
  - `python aartf.py --help`
  - `python aartf.py -t 127.0.0.1 --report`
- [ ] GUI smoke test:
  - `python aartf.py --gui`
- [ ] Confirm reports are generated in `reports/`

## 3) Safety and policy

- [ ] Ensure `.env` is not committed
- [ ] Ensure no secrets/API keys in code or commit history
- [ ] Confirm authorized-use policy and disclaimer are present in `README.md`

## 4) CI and quality

- [ ] Ensure GitHub Actions `CI` workflow passes on default branch
- [ ] Fix any failing checks before tagging release

## 5) Versioning

- [ ] Create changelog notes for v1.0.0
- [ ] Tag release:
  - `git tag v1.0.0`
  - `git push origin v1.0.0`
- [ ] Create GitHub release from tag `v1.0.0`

## 6) Suggested first release notes (copy template)

```md
## AARTF v1.0.0

### Highlights
- CLI + GUI workflow support
- Modular phase-based engine
- Report generation (TXT, PDF, graph, timeline animation)
- Runtime hardening for missing external dependencies
- GitHub CI automation

### Notes
- Intended for authorized lab environments and educational usage.
```
