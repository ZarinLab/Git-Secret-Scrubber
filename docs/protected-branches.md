# Solution for Protected Branch Force Push Issue

Your branch (typically `main` or `master`) is protected, which prevents force pushes. Here are your options:

## Option 1: Temporarily Unprotect Branch (If you have Admin/Maintainer access)

1. **Go to Repository Settings:**
   - **GitLab**: Navigate to `Repository` → `Settings` → `Protected Branches`
   - **GitHub**: Navigate to `Settings` → `Branches` → `Branch protection rules`
   - **Bitbucket**: Navigate to `Repository settings` → `Branch permissions`

2. **Unprotect the branch:**
   - Find your branch (e.g., `main`, `master`) in the protected branches list
   - Click `Unprotect` or `Remove protection`
   - Confirm the action

3. **Force push:**
   ```powershell
   git push origin --force --all
   git push origin --force --tags
   ```

4. **Re-protect the branch:**
   - Go back to Protected Branches settings
   - Re-protect your branch with the same rules as before

## Option 2: Use a New Branch (Recommended - Safer)

This approach doesn't require unprotecting the branch:

1. **Create a new branch from your cleaned history:**
   ```powershell
   git checkout -b cleanup-secrets-history
   ```

2. **Push the new branch:**
   ```powershell
   git push origin cleanup-secrets-history
   ```

3. **Create a Merge/Pull Request:**
   - **GitLab**: Go to `Merge Requests` → `New Merge Request`
   - **GitHub**: Go to `Pull Requests` → `New Pull Request`
   - **Bitbucket**: Go to `Pull requests` → `Create pull request`
   - Source: `cleanup-secrets-history`
   - Target: `main` (or your default branch)
   - Title: "Clean git history: Remove secrets from historical commits"
   - Description: Explain that this replaces the entire history and team must re-clone

4. **After MR is approved and merged:**
   - The cleaned history will be in `main`
   - Delete the old `main` branch (if GitLab allows)
   - Or keep both and deprecate the old one

## Option 3: Contact Repository Admin

If you don't have admin/maintainer access:
- Contact someone with `Maintainer`, `Owner`, or `Admin` role
- Ask them to temporarily unprotect your branch for the force push
- Or ask them to perform the force push themselves

## Important Notes

⚠️ **After force push (whichever method you use):**
- All team members must **re-clone** the repository (their local copies will be incompatible)
- All commit SHAs have changed, so any references to old SHAs will break
- CI/CD pipelines may need to be updated if they reference specific commits
- Any open Merge Requests will need to be rebased or recreated

## Verification

After pushing, verify the cleanup worked:
```bash
# Check that secrets are gone from git history
gitleaks detect --source . --log-opts="--all"

# Check current files only
gitleaks detect --source . --no-git

# Verify remote history
git log --oneline -10
```

## GitLab Repository Cleanup (Remove Orphaned Commits)

Even after force-pushing, GitLab may retain old commits in its object store. To fully purge them:

1. **Run housekeeping**: Settings → General → Advanced → Run housekeeping
2. **Repository cleanup**: Settings → Repository → Repository cleanup
   - Upload a file with commit SHAs to remove
   - GitLab will purge those objects from its storage

## Related Documentation

- [Main README](../README.md) - Full usage guide
- [Command Line Options](README.md#command-line-options) - All available options

