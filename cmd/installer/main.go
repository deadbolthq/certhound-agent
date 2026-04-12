package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

const (
	releasesURL = "https://github.com/deadbolthq/certhound-agent/releases/latest/download"
	installDir  = `C:\Program Files\CertHound`
	binaryName  = "certhound-agent.exe"
	serviceName = "CertHoundAgent"
)

func main() {
	var mw *walk.MainWindow
	var keyEdit, endpointEdit *walk.LineEdit
	var statusLabel *walk.TextLabel
	var installBtn *walk.PushButton
	var progressBar *walk.ProgressBar

	MainWindow{
		AssignTo: &mw,
		Title:    "CertHound Agent Installer",
		MinSize:  Size{Width: 480, Height: 320},
		Size:     Size{Width: 480, Height: 320},
		Layout:   VBox{MarginsZero: false},
		Children: []Widget{
			Label{Text: "Install the CertHound certificate monitoring agent on this server."},
			VSpacer{Size: 4},

			Label{Text: "API Key:"},
			LineEdit{
				AssignTo:    &keyEdit,
				CueBanner:   "ch_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			},
			VSpacer{Size: 4},

			Label{Text: "Endpoint:"},
			LineEdit{
				AssignTo:    &endpointEdit,
				CueBanner:   "https://api.certhound.dev/ingest",
			},
			VSpacer{Size: 8},

			PushButton{
				AssignTo: &installBtn,
				Text:     "Install",
				OnClicked: func() {
					key := strings.TrimSpace(keyEdit.Text())
					endpoint := strings.TrimSpace(endpointEdit.Text())

					if key == "" {
						statusLabel.SetText("Please enter your API key.")
						return
					}
					if endpoint == "" {
						statusLabel.SetText("Please enter the endpoint URL.")
						return
					}

					installBtn.SetEnabled(false)
					keyEdit.SetEnabled(false)
					endpointEdit.SetEnabled(false)
					progressBar.SetVisible(true)

					go func() {
						err := runInstall(key, endpoint, func(msg string) {
							mw.Synchronize(func() {
								statusLabel.SetText(msg)
							})
						})

						mw.Synchronize(func() {
							progressBar.SetVisible(false)
							if err != nil {
								statusLabel.SetText(fmt.Sprintf("Installation failed: %v", err))
								installBtn.SetEnabled(true)
								keyEdit.SetEnabled(true)
								endpointEdit.SetEnabled(true)
							} else {
								statusLabel.SetText("CertHound agent installed and running! You can close this window.")
							}
						})
					}()
				},
			},

			ProgressBar{
				AssignTo: &progressBar,
				Visible:  false,
				MarqueeMode: true,
			},

			VSpacer{Size: 4},
			TextLabel{
				AssignTo: &statusLabel,
				Text:     "",
			},
		},
	}.Run()
}

func runInstall(key, endpoint string, log func(string)) error {
	binaryPath := filepath.Join(installDir, binaryName)

	// 1. Create install directory
	log("Creating install directory…")
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	// 2. Download binary
	arch := runtime.GOARCH
	url := fmt.Sprintf("%s/certhound-agent-windows-%s.exe", releasesURL, arch)
	log(fmt.Sprintf("Downloading agent from GitHub (%s)…", arch))
	if err := downloadFile(binaryPath, url); err != nil {
		return fmt.Errorf("download: %w", err)
	}

	// 3. Provision (writes key + config)
	log("Provisioning agent…")
	out, err := exec.Command(binaryPath, "--provision", "--key", key, "--endpoint", endpoint).CombinedOutput()
	if err != nil {
		return fmt.Errorf("provision: %s (%w)", strings.TrimSpace(string(out)), err)
	}

	// 4. Remove existing service if present
	log("Configuring Windows service…")
	exec.Command("sc.exe", "stop", serviceName).Run()
	exec.Command("sc.exe", "delete", serviceName).Run()

	// 5. Create and start service
	binPathArg := fmt.Sprintf(`"%s" --watch`, binaryPath)
	if out, err := exec.Command("sc.exe", "create", serviceName,
		"binPath=", binPathArg,
		"DisplayName=", "CertHound Agent",
		"start=", "auto",
	).CombinedOutput(); err != nil {
		return fmt.Errorf("create service: %s (%w)", strings.TrimSpace(string(out)), err)
	}

	log("Starting service…")
	if out, err := exec.Command("sc.exe", "start", serviceName).CombinedOutput(); err != nil {
		return fmt.Errorf("start service: %s (%w)", strings.TrimSpace(string(out)), err)
	}

	// 6. Add to PATH
	addToPath(installDir)

	log("Installation complete!")
	return nil
}

func downloadFile(dest, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	tmp := dest + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}

	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()

	os.Remove(dest)
	return os.Rename(tmp, dest)
}

func addToPath(dir string) {
	exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`$p = [Environment]::GetEnvironmentVariable('Path','Machine'); if ($p -notlike '*%s*') { [Environment]::SetEnvironmentVariable('Path', "$p;%s", 'Machine') }`, dir, dir),
	).Run()
}
