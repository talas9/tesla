# Deployment Guide

This research is ready for deployment to free documentation hosting services.

## Quick Deploy Options

### 1. GitHub Pages + MkDocs (RECOMMENDED)

**Best for:** Professional documentation, search, navigation

```bash
# Install MkDocs
pip install mkdocs mkdocs-material

# Initialize
cd ~/tesla
mkdocs new .
# Edit mkdocs.yml (see template below)

# Preview locally
mkdocs serve

# Deploy to GitHub Pages
mkdocs gh-deploy
```

**mkdocs.yml template:**
```yaml
site_name: Tesla MCU2 Security Research
theme:
  name: material
  palette:
    scheme: slate
  features:
    - navigation.tabs
    - navigation.sections
    - toc.integrate
    - search.suggest

nav:
  - Home: README.md
  - Index: INDEX.md
  - Core Research: core/
  - Gateway: gateway/
  - MCU: mcu/
  - APE: ape/
  - Evidence: evidence/

plugins:
  - search
  - awesome-pages
```

### 2. Docsify (NO BUILD STEP)

**Best for:** Quick deployment, no build process

```bash
# Install docsify
npm i docsify-cli -g

# Initialize
cd ~/tesla
docsify init ./docs

# Serve
docsify serve docs
```

**index.html template:**
```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Tesla MCU2 Security Research</title>
  <link rel="stylesheet" href="//cdn.jsdelivr.net/npm/docsify/themes/vue.css">
</head>
<body>
  <div id="app"></div>
  <script>
    window.$docsify = {
      name: 'Tesla MCU2 Security',
      repo: 'https://github.com/YOUR_USERNAME/tesla-research',
      loadSidebar: true,
      subMaxLevel: 3,
      search: 'auto'
    }
  </script>
  <script src="//cdn.jsdelivr.net/npm/docsify/lib/docsify.min.js"></script>
  <script src="//cdn.jsdelivr.net/npm/docsify/lib/plugins/search.min.js"></script>
</body>
</html>
```

### 3. VitePress (MODERN)

**Best for:** Fast, modern UI, Vue-based

```bash
# Install
npm install -D vitepress

# Initialize
npx vitepress init

# Serve
npm run docs:dev

# Build
npm run docs:build
```

### 4. GitBook (EASIEST)

**Best for:** Non-technical users, beautiful UI

1. Go to https://www.gitbook.com
2. Sign up (free tier)
3. Import GitHub repo
4. Auto-deployed!

---

## Free Hosting Providers

### GitHub Pages (FREE)
- **Pros:** Unlimited bandwidth, custom domain, integrated with Git
- **Cons:** Public repos only (or pay for private)
- **Setup:** Push to GitHub, enable Pages in repo settings
- **URL:** `https://username.github.io/tesla-research`

### ReadTheDocs (FREE)
- **Pros:** Built for technical docs, auto-builds on commit
- **Cons:** Requires Sphinx/MkDocs setup
- **Setup:** Connect GitHub repo at https://readthedocs.org
- **URL:** `https://tesla-research.readthedocs.io`

### Netlify (FREE TIER)
- **Pros:** Fast CDN, preview deployments, custom domain
- **Cons:** 100GB bandwidth limit (plenty for docs)
- **Setup:** Connect GitHub, set build command
- **URL:** `https://tesla-research.netlify.app`

### Vercel (FREE TIER)
- **Pros:** Zero-config, excellent performance
- **Cons:** Commercial use requires paid plan
- **Setup:** Import from GitHub
- **URL:** `https://tesla-research.vercel.app`

### Cloudflare Pages (FREE)
- **Pros:** Unlimited bandwidth, fast CDN, custom domain
- **Cons:** Requires Cloudflare account
- **Setup:** Connect GitHub repo
- **URL:** `https://tesla-research.pages.dev`

---

## Git Setup

### Initialize Repo

```bash
cd ~/tesla

# Create .gitignore
cat > .gitignore << 'GITIGNORE'
# Large binaries
*.bin
data/binaries/*.bin

# Large text files (use Git LFS or exclude)
data/disassembly/gateway_full_disassembly.txt

# Python
*.pyc
__pycache__/
.venv/

# IDE
.vscode/
.idea/

# OS
.DS_Store
Thumbs.db
GITIGNORE

# Initialize repo
git init
git add .
git commit -m "Initial commit: Tesla MCU2 security research"

# Add remote (replace with your repo URL)
git remote add origin https://github.com/YOUR_USERNAME/tesla-research.git
git branch -M main
git push -u origin main
```

### Git LFS for Large Files

```bash
# Install Git LFS
git lfs install

# Track large files
git lfs track "*.bin"
git lfs track "data/disassembly/*.txt"

# Add .gitattributes
git add .gitattributes
git commit -m "Add Git LFS tracking"
git push
```

---

## Recommended Deployment: MkDocs + GitHub Pages

### Step-by-Step

```bash
# 1. Install MkDocs
pip install mkdocs mkdocs-material mkdocs-awesome-pages-plugin

# 2. Create mkdocs.yml
cd ~/tesla
cat > mkdocs.yml << 'YAML'
site_name: Tesla MCU2 Security Research
site_description: Comprehensive security analysis of Tesla Model S/X/3/Y MCU2
site_author: Security Researcher

theme:
  name: material
  palette:
    scheme: slate
    primary: red
    accent: red
  font:
    text: Roboto
    code: Roboto Mono
  features:
    - navigation.tabs
    - navigation.sections
    - navigation.expand
    - toc.integrate
    - search.suggest
    - search.highlight
    - content.code.copy

plugins:
  - search
  - awesome-pages

markdown_extensions:
  - pymdownx.highlight
  - pymdownx.superfences
  - pymdownx.tabbed
  - pymdownx.details
  - admonition
  - tables
  - attr_list

extra:
  social:
    - icon: fontawesome/brands/github
      link: https://github.com/YOUR_USERNAME/tesla-research
YAML

# 3. Preview locally
mkdocs serve
# Open http://localhost:8000

# 4. Deploy to GitHub Pages
mkdocs gh-deploy --clean
```

### GitHub Pages URL
After deployment: `https://YOUR_USERNAME.github.io/tesla-research/`

---

## Custom Domain (Optional)

### GitHub Pages

1. Add `CNAME` file to repo root:
   ```
   tesla-research.yourdomain.com
   ```

2. Add DNS record:
   ```
   Type: CNAME
   Name: tesla-research
   Value: YOUR_USERNAME.github.io
   ```

3. Enable HTTPS in repo settings → Pages

### Cloudflare Pages

1. Deploy to Cloudflare Pages
2. Add custom domain in dashboard
3. DNS automatically configured

---

## Maintenance

### Update Docs

```bash
# Edit markdown files
vim docs/gateway/NEW_DOC.md

# Preview changes
mkdocs serve

# Deploy
git add .
git commit -m "Add new documentation"
git push

# Deploy to GitHub Pages
mkdocs gh-deploy
```

### Add New Sections

1. Create folder: `docs/new-section/`
2. Add documents
3. Update `docs/INDEX.md`
4. Update `mkdocs.yml` nav (if using MkDocs)
5. Commit and push

---

## Security Considerations

### Public vs Private

**Public Repo:**
- ✅ Free hosting
- ✅ Community contributions
- ❌ Security research visible to everyone

**Private Repo:**
- ✅ Controlled access
- ❌ GitHub Pages requires paid plan
- ❌ ReadTheDocs doesn't support private repos

**Recommendation:** Public repo is fine for security research (responsible disclosure already done).

### Sensitive Data

**Remove before publishing:**
- VINs, license plates
- Personal information
- Live credentials (if any)
- Internal Tesla documentation (if copyrighted)

**Already safe:**
- Firmware binaries (Tesla's property, but reverse engineering is legal for research)
- Config values (non-confidential)
- Network diagrams (security research)

---

## Search Optimization

### Add metadata to docs

```yaml
---
title: Gateway Config Security
description: Analysis of Tesla Gateway configuration security model
keywords: tesla, gateway, config, security, mcu2
---
```

### Generate sitemap

MkDocs automatically generates `sitemap.xml` for SEO.

---

## Analytics (Optional)

### Google Analytics

Add to `mkdocs.yml`:
```yaml
extra:
  analytics:
    provider: google
    property: G-XXXXXXXXXX
```

### Privacy-friendly alternatives:
- **Plausible** (privacy-focused)
- **Fathom** (simple, GDPR-compliant)
- **GoatCounter** (free, open-source)

---

## Questions?

- **MkDocs Docs:** https://www.mkdocs.org
- **Material Theme:** https://squidfunk.github.io/mkdocs-material
- **GitHub Pages:** https://pages.github.com
- **Docsify:** https://docsify.js.org

---

*Ready to deploy? Run `mkdocs serve` to preview, then `mkdocs gh-deploy` to publish!*
