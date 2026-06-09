# How to Upload ReconX to GitHub (Step by Step)

This guide walks you through creating a professional GitHub repo for ReconX from scratch.

---

## Step 1 — Create a GitHub account (if you don't have one)

1. Go to [https://github.com](https://github.com) and click **Sign up**
2. Choose a username — this appears in your repo URL (e.g. `github.com/yourname/reconx`)
3. Verify your email

---

## Step 2 — Create a new repository on GitHub

1. Click the **+** icon (top right) → **New repository**
2. Fill in:
   - **Repository name:** `reconx`
   - **Description:** `Automated Passive + Active Reconnaissance CLI Tool`
   - **Visibility:** Public ✅
   - ❌ Do NOT check "Add a README file" (you already have one)
   - ❌ Do NOT check "Add .gitignore" (you already have one)
3. Click **Create repository**
4. GitHub will show you a page with a URL like:
   ```
   https://github.com/yourname/reconx.git
   ```
   Copy that URL — you'll need it in Step 4.

---

## Step 3 — Install Git on your machine (if not already installed)

```bash
# Check if git is installed
git --version

# If not installed:
# Ubuntu/Debian
sudo apt install git

# macOS
brew install git

# Windows — download from https://git-scm.com/download/win
```

Then set your identity (one time only):

```bash
git config --global user.name "Your Name"
git config --global user.email "you@example.com"
```

---

## Step 4 — Push ReconX to GitHub

Open a terminal, go to the reconx folder, and run these commands one by one:

```bash
# 1. Go into the project folder
cd reconx

# 2. Initialize git
git init

# 3. Add all files (gitignore will automatically exclude config.ini, logs/, reports/output/)
git add .

# 4. Check what's being added — make sure config.ini is NOT in the list
git status

# 5. Make your first commit
git commit -m "Initial commit — ReconX v1.0.0"

# 6. Rename branch to main (GitHub standard)
git branch -M main

# 7. Link to your GitHub repo (replace URL with yours from Step 2)
git remote add origin https://github.com/yourname/reconx.git

# 8. Push to GitHub
git push -u origin main
```

GitHub will ask for your username and password.
> If it asks for a password, use a **Personal Access Token** (not your account password) — see Step 5.

---

## Step 5 — Create a Personal Access Token (if needed)

GitHub no longer accepts account passwords over HTTPS. Use a token instead:

1. Go to [https://github.com/settings/tokens](https://github.com/settings/tokens)
2. Click **Generate new token (classic)**
3. Give it a name like `reconx-push`
4. Check the **repo** scope (full control of private repositories)
5. Click **Generate token**
6. Copy the token — use it as your password when Git asks

---

## Step 6 — Make the repo look professional

### Add a short description and tags on GitHub

1. On your repo page, click the ⚙️ gear icon next to **About** (top right of the repo)
2. Add:
   - **Description:** `Automated Passive + Active Reconnaissance CLI Tool`
   - **Website:** (leave blank or add your site)
   - **Topics:** `python`, `recon`, `osint`, `subdomain-enumeration`, `cybersecurity`, `penetration-testing`, `shodan`, `cli-tool`, `bug-bounty`
3. Click **Save changes**

### Pin the repo to your profile

1. Go to your GitHub profile page (`github.com/yourname`)
2. Click **Customize your pins**
3. Check `reconx` → **Save pins**

---

## Step 7 — Future updates (how to push changes)

Every time you make changes to the code:

```bash
# See what changed
git status

# Stage all changes
git add .

# Commit with a message describing what you changed
git commit -m "Add VirusTotal module"

# Push to GitHub
git push
```

---

## What your repo will look like

```
github.com/yourname/reconx
│
├── 📄 README.md          ← shown on the homepage automatically
├── 📄 LICENSE
├── 📄 requirements.txt
├── 📄 config.example.ini ← users copy this to set their keys
├── 📄 .gitignore
├── 📁 modules/
├── 📁 reports/
└── 📁 utils/
```

The README.md is automatically rendered on the GitHub homepage — that's what visitors see first. Since yours has the ASCII banner, feature table, install steps, and API key guide, it will look very professional right away.

---

## Quick checklist before pushing

- [ ] `config.ini` is NOT in the folder (or is gitignored)
- [ ] No real API keys anywhere in the code
- [ ] `config.example.ini` has placeholder text only
- [ ] `README.md` has your actual GitHub username (replace `yourusername`)
- [ ] `reconx.py` has your GitHub URL updated (line with `github.com/yourusername`)
