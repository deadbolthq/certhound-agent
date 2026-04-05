package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ghRelease is the subset of the GitHub Releases API response we need.
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// Result describes the outcome of an update check.
type Result struct {
	Updated        bool
	CurrentVersion string
	NewVersion     string
	Error          error
}

// CheckAndUpdate checks for a new release, downloads it with checksum
// verification, backs up the current binary (for rollback), and replaces it.
//
// It is the caller's responsibility to restart the process after a
// successful update.
func CheckAndUpdate(ctx context.Context, currentVersion, checkURL string) Result {
	res := Result{CurrentVersion: currentVersion}

	if !isPrivileged() {
		res.Error = fmt.Errorf("update requires administrator/root privileges")
		return res
	}

	release, err := fetchLatestRelease(ctx, checkURL)
	if err != nil {
		res.Error = fmt.Errorf("checking for updates: %w", err)
		return res
	}

	res.NewVersion = release.TagName
	if !isNewer(currentVersion, release.TagName) {
		return res // already up to date
	}

	binaryAsset, checksumAsset := findAssets(release)
	if binaryAsset == nil {
		res.Error = fmt.Errorf("no matching binary for %s/%s in release %s", runtime.GOOS, runtime.GOARCH, release.TagName)
		return res
	}

	// Download the new binary to a temp file
	tmpPath, err := downloadToTemp(ctx, binaryAsset.BrowserDownloadURL)
	if err != nil {
		res.Error = fmt.Errorf("downloading update: %w", err)
		return res
	}
	defer os.Remove(tmpPath) // clean up if we fail before rename

	// Checksum verification
	if checksumAsset != nil {
		if err := verifyChecksum(ctx, tmpPath, binaryAsset.Name, checksumAsset.BrowserDownloadURL); err != nil {
			res.Error = fmt.Errorf("checksum verification failed: %w", err)
			return res
		}
	} else {
		res.Error = fmt.Errorf("no checksum file found in release %s — refusing to update without verification", release.TagName)
		return res
	}

	// Replace the current binary with rollback backup
	currentBinary, err := os.Executable()
	if err != nil {
		res.Error = fmt.Errorf("finding current binary path: %w", err)
		return res
	}
	currentBinary, err = filepath.EvalSymlinks(currentBinary)
	if err != nil {
		res.Error = fmt.Errorf("resolving binary symlinks: %w", err)
		return res
	}

	if err := replaceBinary(currentBinary, tmpPath); err != nil {
		res.Error = fmt.Errorf("replacing binary: %w", err)
		return res
	}

	res.Updated = true
	return res
}

// Rollback restores the backup binary created during the last update.
// Returns an error if no backup exists.
func Rollback() error {
	currentBinary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("finding current binary: %w", err)
	}
	currentBinary, err = filepath.EvalSymlinks(currentBinary)
	if err != nil {
		return fmt.Errorf("resolving binary symlinks: %w", err)
	}

	backupPath := currentBinary + ".bak"
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("no backup found at %s", backupPath)
	}

	// On Windows, rename the running binary out of the way first
	if runtime.GOOS == "windows" {
		oldPath := currentBinary + ".old"
		os.Remove(oldPath)
		if err := os.Rename(currentBinary, oldPath); err != nil {
			return fmt.Errorf("moving current binary: %w", err)
		}
	}

	if err := os.Rename(backupPath, currentBinary); err != nil {
		return fmt.Errorf("restoring backup: %w", err)
	}
	return nil
}

func fetchLatestRelease(ctx context.Context, url string) (*ghRelease, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("parsing release JSON: %w", err)
	}
	return &release, nil
}

// isNewer returns true if remoteTag is a higher version than current.
// Both are expected to have a "v" prefix (e.g. "v1.2.3").
// Falls back to string comparison if parsing fails.
func isNewer(current, remote string) bool {
	if current == "dev" {
		return false // never auto-update dev builds
	}
	// Strip "v" prefix for comparison
	c := strings.TrimPrefix(current, "v")
	r := strings.TrimPrefix(remote, "v")
	return r > c
}

// findAssets returns the binary asset and checksum asset for the current OS/arch.
func findAssets(release *ghRelease) (binary *ghAsset, checksum *ghAsset) {
	suffix := binarySuffix()
	for i := range release.Assets {
		a := &release.Assets[i]
		if strings.HasSuffix(a.Name, suffix) {
			binary = a
		}
		if a.Name == "checksums.txt" || strings.HasSuffix(a.Name, "_checksums.txt") || strings.HasSuffix(a.Name, "SHA256SUMS") {
			checksum = a
		}
	}
	return binary, checksum
}

func binarySuffix() string {
	switch {
	case runtime.GOOS == "windows" && runtime.GOARCH == "amd64":
		return "windows-amd64.exe"
	case runtime.GOOS == "linux" && runtime.GOARCH == "amd64":
		return "linux-amd64"
	case runtime.GOOS == "linux" && runtime.GOARCH == "arm64":
		return "linux-arm64"
	case runtime.GOOS == "darwin" && runtime.GOARCH == "amd64":
		return "darwin-amd64"
	case runtime.GOOS == "darwin" && runtime.GOARCH == "arm64":
		return "darwin-arm64"
	default:
		return fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
	}
}

func downloadToTemp(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "certhound-update-*")
	if err != nil {
		return "", err
	}

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	tmp.Close()
	return tmp.Name(), nil
}

// verifyChecksum downloads the checksum file, computes the SHA-256 of the
// downloaded binary, and compares them. Returns nil on match.
func verifyChecksum(ctx context.Context, filePath, expectedName, checksumURL string) error {
	// Compute actual hash
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("hashing file: %w", err)
	}
	actualHash := hex.EncodeToString(h.Sum(nil))

	// Download checksum file
	req, err := http.NewRequestWithContext(ctx, "GET", checksumURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("downloading checksums: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading checksums: %w", err)
	}

	// Parse checksum file — each line is "hash  filename"
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[1] == expectedName {
			if parts[0] == actualHash {
				return nil
			}
			return fmt.Errorf("hash mismatch: expected %s, got %s", parts[0], actualHash)
		}
	}

	return fmt.Errorf("no checksum entry found for %s", expectedName)
}

// replaceBinary backs up the current binary and moves the new one into place.
func replaceBinary(currentPath, newPath string) error {
	backupPath := currentPath + ".bak"

	// Remove old backup if it exists
	os.Remove(backupPath)

	if runtime.GOOS == "windows" {
		// Windows can't overwrite a running binary directly.
		// Rename the running binary out of the way, then move the new one in.
		oldPath := currentPath + ".old"
		os.Remove(oldPath)
		if err := os.Rename(currentPath, oldPath); err != nil {
			return fmt.Errorf("moving running binary: %w", err)
		}
		// Copy old to .bak for rollback
		copyFile(oldPath, backupPath)

		if err := os.Rename(newPath, currentPath); err != nil {
			// Try to restore the original
			os.Rename(oldPath, currentPath)
			return fmt.Errorf("placing new binary: %w", err)
		}
		os.Remove(oldPath)
	} else {
		// Unix: copy current to .bak, then overwrite
		if err := copyFile(currentPath, backupPath); err != nil {
			return fmt.Errorf("creating backup: %w", err)
		}

		if err := os.Rename(newPath, currentPath); err != nil {
			return fmt.Errorf("placing new binary: %w", err)
		}

		// Preserve executable permissions
		os.Chmod(currentPath, 0755)
	}

	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	// Preserve source permissions
	info, err := os.Stat(src)
	if err == nil {
		os.Chmod(dst, info.Mode())
	}
	return nil
}
