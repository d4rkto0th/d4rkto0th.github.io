# Security Labs

CTF and security lab write-ups hosted on GitHub Pages.

## Setup

1. Create a new repo on GitHub (e.g., `labs` or `security-writeups`)

2. Push this directory:
   ```bash
   cd labs-site
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin git@github.com:YOUR_USERNAME/YOUR_REPO.git
   git push -u origin main
   ```

3. Enable GitHub Pages:
   - Go to repo **Settings** → **Pages**
   - Source: **Deploy from a branch**
   - Branch: **main** / **root**
   - Save

4. Your site will be live at `https://YOUR_USERNAME.github.io/YOUR_REPO/`

## Adding Write-ups

Drop markdown files into the appropriate category folder:

```
labs/
  webapp/     # XSS, SQLi, etc.
  cloud/      # AWS, Azure, GCP
  onprem/     # Network, AD, etc.
```

Each file needs front matter at the top:

```yaml
---
layout: default
title: Your Lab Title
---
```

## Customization

- Edit `_config.yml` for site title/description
- Edit `_layouts/default.html` for styling
- Update `baseurl` in `_config.yml` if using a project site (e.g., `/labs`)

