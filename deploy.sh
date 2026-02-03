#!/bin/bash
# Tesla Research - One-Command Deployment to GitHub Pages
# Usage: ./deploy.sh [github_username]

set -e

GITHUB_USERNAME="${1:-YOUR_USERNAME}"
REPO_NAME="tesla-research"

echo "======================================"
echo "Tesla Research - GitHub Pages Deploy"
echo "======================================"
echo ""

# Update mkdocs.yml with actual username
echo "📝 Updating configuration with GitHub username: $GITHUB_USERNAME"
sed -i "s/YOUR_USERNAME/$GITHUB_USERNAME/g" mkdocs.yml
sed -i "s/YOUR_USERNAME/$GITHUB_USERNAME/g" docs/SCRIPTS.md
sed -i "s/YOUR_USERNAME/$GITHUB_USERNAME/g" docs/DEPLOYMENT.md

# Check if MkDocs is installed
if ! command -v mkdocs &> /dev/null; then
    echo "📦 Installing MkDocs and dependencies..."
    pip install mkdocs mkdocs-material mkdocs-minify-plugin
else
    echo "✅ MkDocs already installed"
fi

# Check if git remote exists
if ! git remote | grep -q origin; then
    echo "🔗 Adding GitHub remote..."
    git remote add origin "https://github.com/$GITHUB_USERNAME/$REPO_NAME.git"
else
    echo "✅ Git remote already configured"
fi

# Commit any changes
if [ -n "$(git status --porcelain)" ]; then
    echo "💾 Committing changes..."
    git add -A
    git commit -m "Deploy configuration update"
fi

# Build and deploy to GitHub Pages
echo "🚀 Building and deploying to GitHub Pages..."
mkdocs gh-deploy --clean --force

echo ""
echo "✅ Deployment complete!"
echo ""
echo "📍 Your site will be live at:"
echo "   https://$GITHUB_USERNAME.github.io/$REPO_NAME/"
echo ""
echo "⚙️  Configure GitHub Pages:"
echo "   1. Go to https://github.com/$GITHUB_USERNAME/$REPO_NAME/settings/pages"
echo "   2. Source should be set to: gh-pages branch"
echo "   3. Wait 1-2 minutes for deployment"
echo ""
echo "🔄 To update the site, run: ./deploy.sh $GITHUB_USERNAME"
echo ""
