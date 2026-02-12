package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unsafe"
)

func main() {
	ensureElevated()

	reader := bufio.NewReader(os.Stdin)
	clearScreen()
	fmt.Println("======================================")
	fmt.Println("     Welcome to ToolsKit (Go CLI)     ")
	fmt.Println("  A friendly orchestrator for Windows ")
	fmt.Println("======================================")
	fmt.Println("Press Enter to continue...")
	_ = waitEnter(reader)

	for {
		clearScreen()
		fmt.Println("Choose required operation:")
		fmt.Println("  1) Windows files")
		fmt.Println("  2) Repair system files (DISM + SFC)")
		fmt.Println("  3) Repair boot records (UEFI/BIOS-aware)")
		fmt.Println("  4) Check disk errors (chkdsk /f /r)")
		fmt.Println("  5) Stop/restore auto-restart after crash (bcdedit)")
		fmt.Println("  6) Wi-Fi configuration")
		fmt.Println("  7) Clear cache")
		fmt.Println("  0) Exit")
		fmt.Print("> ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			handleWindowsFiles(reader)
		case "2":
			handleRepairSystemFiles(reader)
		case "3":
			handleRepairBootRecords(reader)
		case "4":
			handleCheckDisk(reader)
		case "5":
			handleCrashPolicy(reader)
		case "6":
			handleWiFi(reader)
		case "7":
			handleClearCache(reader)
		case "0":
			fmt.Println("Goodbye!")
			return
		default:
			fmt.Println("Invalid choice.")
			promptReturn(reader)
		}
	}
}

// Utilities

func runShell(command string) error {
	// Runs via cmd.exe so we can use built-ins like 'start' and piping.
	cmd := exec.Command("cmd", "/C", command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runShellOut(command string) (string, error) {
	cmd := exec.Command("cmd", "/C", command)
	var out, errB bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errB
	err := cmd.Run()
	return out.String() + errB.String(), err
}

func clearScreen() {
	_ = runShell("cls")
}

func promptReturn(reader *bufio.Reader) {
	fmt.Println("\nPress Enter to return to the main menu...")
	_ = waitEnter(reader)
}

func waitEnter(reader *bufio.Reader) error {
	_, err := reader.ReadString('\n')
	return err
}

func readYN(reader *bufio.Reader, prompt string) bool {
	for {
		fmt.Print(prompt)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))
		if input == "y" || input == "yes" || input == "Y" {
			return true
		}
		if input == "n" || input == "no" || input == "N" {
			return false
		}
		fmt.Println("Please type 'y' or 'n'.")
	}
}

func ensureDir(d string) {
	_ = os.MkdirAll(d, 0755)
}

func timestamped(base string) string {
	return fmt.Sprintf("%s_%s", base, time.Now().Format("20060102_150405"))
}

// Admin elevation

func ensureElevated() {
	if isElevated() {
		return
	}

	fmt.Println("This tool needs administrative privileges.")
	if err := relaunchElevated(); err != nil {
		fmt.Println("Failed to re-launch elevated:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// NotAType resolvation
type tokenElevation struct {
	TokenIsElevated uint32
}

func isElevated() bool {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_QUERY,
		&token,
	); err != nil {
		return false
	}
	defer token.Close()

	var elevation tokenElevation
	var outLen uint32

	err := windows.GetTokenInformation(
		token,
		windows.TokenElevation,
		(*byte)(unsafe.Pointer(&elevation)),
		uint32(unsafe.Sizeof(elevation)),
		&outLen,
	)
	if err != nil {
		return false
	}

	return elevation.TokenIsElevated != 0
}

// relaunchElevated uses ShellExecuteW with verb "runas".
func relaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb := windows.StringToUTF16Ptr("runas")
	lpFile := windows.StringToUTF16Ptr(exe)
	args := windows.StringToUTF16Ptr(strings.Join(os.Args[1:], " "))
	dir := windows.StringToUTF16Ptr(filepath.Dir(exe))

	shell32 := windows.NewLazySystemDLL("shell32.dll")
	proc := shell32.NewProc("ShellExecuteW")

	ret, _, callErr := proc.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(lpFile)),
		uintptr(unsafe.Pointer(args)),
		uintptr(unsafe.Pointer(dir)),
		uintptr(1),
	)
	if ret <= 32 {
		if callErr != windows.ERROR_SUCCESS {
			return callErr
		}
		return errors.New("ShellExecuteW returned error")
	}
	return nil
}

// -----------------------
// 1) Windows files (Explorer visibility)
//
// do it by switch
// -----------------------

func handleWindowsFiles(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("[Windows files] Toggle common Explorer visibility settings.")

	if readYN(reader, "Show hidden files? (y/n): ") {
		_ = runShell(`reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f`)
	} else {
		_ = runShell(`reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 2 /f`)
	}

	if readYN(reader, "Show file extensions? (y/n): ") {
		_ = runShell(`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f`)
	} else {
		_ = runShell(`reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /t REG_DWORD /d 1 /f`)
	}

	if readYN(reader, "Show protected operating system files? (y/n): ") {
		_ = runShell(`reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f`)
	} else {
		_ = runShell(`reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 0 /f`)
	}

	fmt.Println("Please wait until your explorer restart to apply the changes!!")

	_ = runShell(`taskkill /f /im explorer.exe`)
	_ = runShell(`cmd /c start explorer.exe`)

	promptReturn(reader)
}

// -----------------------
// 2) Repair system files (DISM + SFC + CBS summary)
// -----------------------

func handleRepairSystemFiles(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("[Repair system files] (Requires Administrator)")
	logDir := "logs"
	ensureDir(logDir)

	if readYN(reader, "Run DISM to restore Windows image health? (y/n): ") {
		_ = runShell(`DISM /Online /Cleanup-Image /RestoreHealth`)
	}
	if readYN(reader, "Run SFC (System File Checker)? (y/n): ") {
		_ = runShell(`sfc /scannow`)

		// Extract [SR] lines from CBS.log as a summary
		cbs := `C:\Windows\Logs\CBS\CBS.log`
		data, err := os.ReadFile(cbs)
		if err == nil {
			lines := strings.Split(string(data), "\n")
			var out []string
			sr := regexp.MustCompile(`\b\[SR\]\b`)
			for _, line := range lines {
				if sr.MatchString(line) {
					out = append(out, line)
				}
			}
			summaryFile := filepath.Join(logDir, timestamped("sfc_summary.txt"))
			_ = os.WriteFile(summaryFile, []byte(strings.Join(out, "")), 0644)
			fmt.Println("SFC summary saved to:", summaryFile)
		} else {
			fmt.Println("Could not read CBS.log:", err)
		}
	}

	promptReturn(reader)
}

// -----------------------
// 3) Repair boot records (UEFI/BIOS-aware)
// -----------------------

func handleRepairBootRecords(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("[Repair boot records] (Recommended from WinRE for locked system drives)")

	// Offer BCD backup
	if readYN(reader, "Backup current BCD store before changes? (y/n): ") {
		out := filepath.Join("logs", timestamped("bcd_backup.bak"))
		ensureDir("logs")
		if err := runShell(`bcdedit /export "` + out + `"`); err == nil {
			fmt.Println("BCD backup exported to:", out)
		} else {
			fmt.Println("BCD export failed (try from WinRE).")
		}
	}

	fw := detectFirmware()
	fmt.Println("Detected firmware:", fw)

	switch fw {
	case "UEFI":
		fmt.Println("\nUEFI path will use: mountvol S: /S  +  bcdboot C:\\Windows /s S: /f UEFI")
		if readYN(reader, "Proceed with UEFI rebuild? (y/n): ") {
			_ = runShell(`mountvol S: /S`)
			_ = runShell(`bcdboot C:\Windows /s S: /f UEFI`)
		}
		// Helpful extras from WinRE:
		if readYN(reader, "Also attempt bootrec /scanos and /rebuildbcd? (y/n) [WinRE preferred]: ") {
			_ = runShell(`bootrec /scanos`)
			_ = runShell(`bootrec /rebuildbcd`)
		}
	case "BIOS":
		fmt.Println("\nBIOS/MBR path will use: bootrec /fixmbr  /fixboot  /scanos  /rebuildbcd")
		if readYN(reader, "Proceed with BIOS/MBR repair? (y/n): ") {
			_ = runShell(`bootrec /fixmbr`)
			_ = runShell(`bootrec /fixboot`)
			_ = runShell(`bootrec /scanos`)
			_ = runShell(`bootrec /rebuildbcd`)
		}
	default:
		fmt.Println("\nFirmware type unknown. You can try generic steps or run from WinRE.")
		if readYN(reader, "Run bootrec generic sequence? (y/n): ") {
			_ = runShell(`bootrec /fixmbr`)
			_ = runShell(`bootrec /fixboot`)
			_ = runShell(`bootrec /scanos`)
			_ = runShell(`bootrec /rebuildbcd`)
		}
	}

	// Offer reboot to Advanced Startup (WinRE)
	if readYN(reader, "Reboot into Advanced Startup (WinRE) now? (y/n): ") {
		_ = runShell(`shutdown /r /o /f /t 0`)
	}

	promptReturn(reader)
}

func detectFirmware() string {
	// Open: HKLM\SYSTEM\CurrentControlSet\Control
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control`, registry.QUERY_VALUE)
	if err != nil {
		return "Unknown"
	}
	defer k.Close()

	// Read DWORD: PEFirmwareType (1=BIOS, 2=UEFI)
	val, _, err := k.GetIntegerValue("PEFirmwareType")
	if err != nil {
		return "Unknown"
	}

	switch val {
	case 2:
		return "UEFI"
	case 1:
		return "BIOS"
	default:
		return "Unknown"
	}
}

// -----------------------
// 4) Check disk errors (chkdsk /f /r)
// -----------------------

func handleCheckDisk(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("[Check disk errors]")
	fmt.Print("Enter drive letter (e.g., C or D): ")
	drive, _ := reader.ReadString('\n')
	drive = strings.ToUpper(strings.TrimSpace(drive))
	if drive == "" {
		drive = "C"
	}
	if !strings.HasSuffix(drive, ":") {
		drive += ":"
	}

	fmt.Println("\nWARNING: /r does a surface scan and is time-consuming. On SSDs it's rarely useful unless read errors are suspected.")
	if !readYN(reader, fmt.Sprintf("Run 'chkdsk %s /f /r' (may require reboot)? (y/n): ", drive)) {
		promptReturn(reader)
		return
	}

	// If volume is in use, echo Y to schedule at next boot
	_ = runShell(`cmd /C "echo Y|chkdsk ` + drive + ` /f /r"`)

	// Try to export the latest Wininit (boot-time chkdsk) report
	if readYN(reader, "Collect last CHKDSK/Wininit report to a file now? (y/n): ") {
		ps := `Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Microsoft-Windows-Wininit'} | Select-Object -First 1 | Format-List -Property *`
		out, _ := runShellOut(`powershell -NoProfile -Command "` + ps + `"`)
		ensureDir("logs")
		file := filepath.Join("logs", timestamped("chkdsk_report.txt"))
		_ = os.WriteFile(file, []byte(out), 0644)
		fmt.Println("Saved:", file)
	}
	promptReturn(reader)
}

// -----------------------
// 5) Crash policy (bcdedit + registry fallback)
// -----------------------

func handleCrashPolicy(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("[Stop/restore auto-restart after crash]")

	fmt.Println("1) Disable auto-restart and ignore boot status failures (bcdedit)")
	fmt.Println("2) Re-enable defaults")
	fmt.Println("3) Registry fallback only (CrashControl AutoReboot)")
	fmt.Println("0) Back")
	fmt.Print("> ")
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		_ = runShell(`bcdedit /set {default} recoveryenabled No`)
		_ = runShell(`bcdedit /set {default} bootstatuspolicy ignoreallfailures`)
	case "2":
		_ = runShell(`bcdedit /set {default} recoveryenabled Yes`)
		_ = runShell(`bcdedit /set {default} bootstatuspolicy DisplayAllFailures`)
	case "3":
		if readYN(reader, "Disable auto-restart via registry? (y/n): ") {
			_ = runShell(`reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v AutoReboot /t REG_DWORD /d 0 /f`)
		}
		if readYN(reader, "Re-enable auto-restart via registry? (y/n): ") {
			_ = runShell(`reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v AutoReboot /t REG_DWORD /d 1 /f`)
		}
	default:
	}
	promptReturn(reader)
}

// -----------------------
// 6) Wi‑Fi configuration (netsh wlan)
// -----------------------

func handleWiFi(reader *bufio.Reader) {
	for {
		clearScreen()
		fmt.Println("[Wi‑Fi configuration]")
		fmt.Println("1) Show available networks (with BSSIDs)")
		fmt.Println("2) Show saved profiles")
		fmt.Println("3) Connect to a saved profile (SSID)")
		fmt.Println("4) Disconnect")
		fmt.Println("5) Export profiles to current folder (key=clear)")
		fmt.Println("6) Import profile from XML")
		fmt.Println("0) Back")
		fmt.Print("> ")

		ch, _ := reader.ReadString('\n')
		ch = strings.TrimSpace(ch)

		switch ch {
		case "1":
			_ = runShell(`netsh wlan show networks mode=Bssid`)
			promptReturn(reader)
		case "2":
			_ = runShell(`netsh wlan show profiles`)
			promptReturn(reader)
		case "3":
			fmt.Print("Enter SSID/profile name: ")
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)
			if name != "" {
				_ = runShell(`netsh wlan connect name="` + name + `"`)
			}
			promptReturn(reader)
		case "4":
			_ = runShell(`netsh wlan disconnect`)
			promptReturn(reader)
		case "5":
			_ = runShell(`netsh wlan export profile key=clear`)
			promptReturn(reader)
		case "6":
			fmt.Print("Enter XML path: ")
			xml, _ := reader.ReadString('\n')
			xml = strings.TrimSpace(xml)
			if xml != "" {
				_ = runShell(`netsh wlan add profile filename="` + xml + `"`)
			}
			promptReturn(reader)
		case "0":
			return
		default:
			fmt.Println("Invalid choice.")
			promptReturn(reader)
		}
	}
}

// -----------------------
// 7) Clear cache
// -----------------------

func handleClearCache(reader *bufio.Reader) {
	clearScreen()
	fmt.Println("[Clear cache]")
	if readYN(reader, "Flush DNS cache? (y/n): ") {
		_ = runShell(`ipconfig /flushdns`)
	}
	if readYN(reader, "Clear user TEMP files? (y/n): ") {
		_ = runShell(`del /q /f /s "%TEMP%\*"`)
	}
	if readYN(reader, "Reset Microsoft Store cache (wsreset)? (y/n): ") {
		_ = runShell(`wsreset`)
	}
	promptReturn(reader)
}
