# Publishing to PyPI - Step-by-Step Instructions

## ✅ Pre-Publishing Checklist Complete
- ✅ Tests passing (154 passed, 90.38% coverage)
- ✅ Package built successfully
- ✅ Package contents verified (only source code included)

## 📦 Package Ready to Publish
- **Name**: `traylinx-auth-client`
- **Version**: `1.0.0`
- **Files**: `dist/traylinx_auth_client-1.0.0.tar.gz` and `.whl`

---

## 🔐 Step 1: PyPI Authentication Setup

### Option A: Using PyPI API Token (Recommended)

1. **Create PyPI Account** (if you don't have one):
   - Go to: https://pypi.org/account/register/
   - Complete registration and verify email

2. **Create API Token**:
   - Go to: https://pypi.org/manage/account/token/
   - Click "Add API token"
   - Token name: `traylinx-auth-client` (or any name you prefer)
   - Scope: "Entire account" (for first publish) or "Project: traylinx-auth-client" (after first publish)
   - Click "Create token"
   - **IMPORTANT**: Copy the token immediately (it won't be shown again)

3. **Configure Poetry with Token**:
   ```bash
   poetry config pypi-token.pypi pypi-YOUR_TOKEN_HERE
   ```
   Replace `pypi-YOUR_TOKEN_HERE` with your actual token.

### Option B: Using Username/Password

```bash
# Poetry will prompt for credentials when you publish
poetry publish
# Enter username and password when prompted
```

---

## 🚀 Step 2: Test Publish (Optional but Recommended)

Test on TestPyPI first to ensure everything works:

```bash
# Configure TestPyPI repository
poetry config repositories.testpypi https://test.pypi.org/legacy/

# Get TestPyPI account and token from https://test.pypi.org
poetry config pypi-token.testpypi pypi-YOUR_TEST_TOKEN_HERE

# Publish to TestPyPI
poetry publish -r testpypi

# Test installation from TestPyPI
pip install --index-url https://test.pypi.org/simple/ traylinx-auth-client
```

---

## 🎯 Step 3: Publish to PyPI

Once you're ready to publish to the official PyPI:

```bash
cd /Users/sebastian/Projects/makakoo/agents/traylinx/traylinx_auth_client_py

# Publish to PyPI
poetry publish
```

If you configured the API token, it will publish automatically. Otherwise, it will prompt for credentials.

---

## ✅ Step 4: Verify Publication

After publishing:

1. **Check PyPI page**: https://pypi.org/project/traylinx-auth-client/
2. **Test installation**:
   ```bash
   pip install traylinx-auth-client
   ```
3. **Verify it works**:
   ```bash
   python3 -c "from traylinx_auth_client import TraylinxAuthClient; print('Success!')"
   ```

---

## 🔄 Publishing Updates (Future Versions)

For future releases:

1. Update version in `pyproject.toml`:
   ```toml
   version = "1.0.1"  # or "1.1.0", "2.0.0" etc.
   ```

2. Update `CHANGELOG.md` with changes

3. Rebuild and publish:
   ```bash
   rm -rf dist/
   poetry build
   poetry publish
   ```

---

## 🆘 Troubleshooting

### Error: "File already exists"
- Package version already published
- Update version number in `pyproject.toml`

### Error: "Invalid authentication"
- Check your API token is correct
- Reconfigure: `poetry config pypi-token.pypi pypi-YOUR_TOKEN_HERE`

### Error: "Package name already taken"
- Choose a different package name in `pyproject.toml`
- Or request ownership transfer from PyPI support

### Error: "403 Forbidden"
- For project-scoped tokens, ensure the project already exists
- Use "Entire account" scope for first publish

---

## 📝 Next Steps After Publishing

1. **Create GitHub Release**:
   - Tag: `v1.0.0`
   - Title: `Release 1.0.0`
   - Description: Copy from CHANGELOG.md

2. **Announce Release** (optional):
   - Company blog
   - Social media
   - Documentation site

3. **Update Documentation**:
   - Verify installation instructions work
   - Update any links or references

---

## 🎉 Ready to Publish!

Run this command when you're ready:

```bash
cd /Users/sebastian/Projects/makakoo/agents/traylinx/traylinx_auth_client_py
poetry publish
```

**Note**: If you haven't configured PyPI credentials, the command will prompt you for them.

