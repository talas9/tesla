# Quick Start - Deploy to GitHub Pages

**One-command deployment to GitHub Pages! 🚀**

---

## Option 1: Automatic Deployment (Recommended)

### Step 1: Push to GitHub

```bash
cd ~/tesla

# Replace YOUR_USERNAME with your GitHub username
export GITHUB_USER="YOUR_USERNAME"

# Initialize repo (if not done)
git remote add origin "https://github.com/$GITHUB_USER/tesla.git"

# Push to GitHub
git push -u origin master
```

### Step 2: Enable GitHub Actions

1. Go to: `https://github.com/YOUR_USERNAME/tesla/settings/pages`
2. Under "Source", select: **GitHub Actions**
3. Done! Every push auto-deploys.

**Your site:** `https://YOUR_USERNAME.github.io/tesla/`

---

## Option 2: Manual Deployment

### One-Command Deploy

```bash
cd ~/tesla
./deploy.sh YOUR_USERNAME
```

That's it! Script will:
- ✅ Install MkDocs if needed
- ✅ Update config with your username
- ✅ Build documentation
- ✅ Deploy to GitHub Pages
- ✅ Show you the live URL

---

## What Gets Deployed

### Documentation (111 files)
- ✅ All research documents organized
- ✅ Complete navigation and search
- ✅ Dark/light mode toggle
- ✅ Mobile-friendly

### Tools & Scripts
- ✅ `gateway_crc_validator.py` - Download from site
- ✅ `gateway_database_query.py` - Download from site
- ✅ `match_odin_to_configs.py` - Download from site

### Data Files
- ✅ Config databases (662 configs)
- ✅ String extractions (37,702 strings)
- ✅ CAN message database
- ✅ Odin database (unhashed)

---

## Update Deployed Site

Every time you push to GitHub:

```bash
cd ~/tesla
git add -A
git commit -m "Update documentation"
git push
```

**With GitHub Actions:** Auto-deploys in ~2 minutes  
**Manual:** Run `./deploy.sh YOUR_USERNAME`

---

## Local Preview

Test before deploying:

```bash
cd ~/tesla
mkdocs serve
```

Open: http://localhost:8000

---

## Features

- 🔍 **Full-text search** - Find any config, command, or offset
- 📱 **Mobile-friendly** - Responsive design
- 🌙 **Dark/light mode** - Toggle with one click
- 📊 **Navigation tabs** - Easy category browsing
- 🔗 **Direct links** - Share specific sections
- 📥 **Download scripts** - All tools available

---

## Troubleshooting

### "Permission denied" error

```bash
chmod +x deploy.sh
./deploy.sh YOUR_USERNAME
```

### MkDocs not found

```bash
pip install -r requirements.txt
```

### Git remote already exists

```bash
git remote set-url origin https://github.com/YOUR_USERNAME/tesla.git
```

---

## Next Steps

1. ✅ Push to GitHub
2. ✅ Run `./deploy.sh YOUR_USERNAME`
3. ✅ Visit `https://YOUR_USERNAME.github.io/tesla/`
4. 🎉 Share your research!

---

**Questions?** See `docs/DEPLOYMENT.md` for detailed guides.
