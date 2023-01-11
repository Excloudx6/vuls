package scanner

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

// inherit OsTypeInterface
type windows struct {
	base
}

func newWindows(c config.ServerInfo) *windows {
	d := &windows{
		base: base{
			osPackages: osPackages{
				Packages:  models.Packages{},
				VulnInfos: models.VulnInfos{},
			},
			windowsKB: &models.WindowsKB{},
		},
	}
	d.log = logging.NewNormalLogger()
	d.setServerInfo(c)
	return d
}

func detectWindows(c config.ServerInfo) (bool, osTypeInterface) {
	w := newWindows(c)
	w.setDistro(constant.Windows, "")
	if r := w.exec("systeminfo.exe", noSudo); r.isSuccess() {
		release, _, err := parseSystemInfo(r.Stdout)
		if err != nil {
			w.setErrs([]error{xerrors.Errorf("Failed to parse systeminfo.exe. err: %w", err)})
			return true, w
		}
		w.setDistro(constant.Windows, release)
	}

	if r := w.exec("Get-ComputerInfo | Select WindowsProductName, OsVersion, WindowsEditionId, OsCSDVersion, CsSystemType, WindowsInstallationType | Format-List", noSudo); r.isSuccess() {
		release, err := parseGetComputerInfo(r.Stdout)
		if err != nil {
			w.setErrs([]error{xerrors.Errorf("Failed to parse Get-ComputerInfo. err: %w", err)})
			return true, w
		}
		w.setDistro(constant.Windows, release)
	}

	if w.getServerInfo().Distro.Release != "" {
		return true, w
	}
	return false, nil
}

func parseSystemInfo(stdout string) (string, []string, error) {
	var (
		o   osInfo
		kbs []string
	)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "OS Name:"):
			o.productName = strings.TrimSpace(strings.TrimPrefix(line, "OS Name:"))
		case strings.HasPrefix(line, "OS Version:"):
			s := strings.TrimSpace(strings.TrimPrefix(line, "OS Version:"))
			lhs, build, _ := strings.Cut(s, " Build ")
			vb, sp, _ := strings.Cut(lhs, " ")
			o.version = strings.TrimSuffix(vb, fmt.Sprintf(".%s", build))
			o.build = build
			if sp != "N/A" {
				o.servicePack = sp
			}
		case strings.HasPrefix(line, "System Type:"):
			o.arch = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "System Type:"), "PC"))
		case strings.HasPrefix(line, "OS Configuration:"):
			switch {
			case strings.Contains(line, "Server"):
				o.installationType = "Server"
			case strings.Contains(line, "Workstation"):
				o.installationType = "Client"
			default:
				return "", nil, xerrors.Errorf("Failed to detect installation type. line: %s", line)
			}
		case strings.HasPrefix(line, "Hotfix(s):"):
			nKB, err := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "Hotfix(s):"), "Hotfix(s) Installed.")))
			if err != nil {
				return "", nil, xerrors.Errorf("Failed to detect number of installed hotfix from %s", line)
			}
			for i := 0; i < nKB; i++ {
				scanner.Scan()
				line := scanner.Text()
				_, rhs, found := strings.Cut(line, ":")
				if !found {
					continue
				}
				s := strings.TrimSpace(rhs)
				if strings.HasPrefix(s, "KB") {
					kbs = append(kbs, strings.TrimPrefix(s, "KB"))
				}
			}
		default:
		}
	}
	release, err := detectOSName(o)
	if err != nil {
		return "", nil, xerrors.Errorf("Failed to detect os name. err: %w", err)
	}
	return release, kbs, nil
}

func parseGetComputerInfo(stdout string) (string, error) {
	var o osInfo
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "WindowsProductName"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return "", xerrors.Errorf(`Failed to detect ProductName. expected: "WindowsProductName : <ProductName>", line: "%s"`, line)
			}
			o.productName = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "OsVersion"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return "", xerrors.Errorf(`Failed to detect OsVersion. expected: "OsVersion : <Version>", line: "%s"`, line)
			}
			ss := strings.Split(strings.TrimSpace(rhs), ".")
			o.version = strings.Join(ss[0:len(ss)-1], ".")
			o.build = ss[len(ss)-1]
		case strings.HasPrefix(line, "WindowsEditionId"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return "", xerrors.Errorf(`Failed to detect WindowsEditionId. expected: "WindowsEditionId : <EditionId>", line: "%s"`, line)
			}
			o.edition = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "OsCSDVersion"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return "", xerrors.Errorf(`Failed to detect OsCSDVersion. expected: "OsCSDVersion : <CSDVersion>", line: "%s"`, line)
			}
			o.servicePack = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "CsSystemType"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return "", xerrors.Errorf(`Failed to detect CsSystemType. expected: "CsSystemType : <SystemType>", line: "%s"`, line)
			}
			o.arch = strings.TrimSpace(strings.TrimSuffix(rhs, "PC"))
		case strings.HasPrefix(line, "WindowsInstallationType"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return "", xerrors.Errorf(`Failed to detect WindowsInstallationType. expected: "WindowsInstallationType : <InstallationType>", line: "%s"`, line)
			}
			o.installationType = strings.TrimSpace(rhs)
		default:
		}
	}
	release, err := detectOSName(o)
	if err != nil {
		return "", xerrors.Errorf("Failed to detect os name. err: %w", err)
	}
	return release, nil
}

type osInfo struct {
	productName      string
	version          string
	build            string
	edition          string
	servicePack      string
	arch             string
	installationType string
}

func detectOSName(osInfo osInfo) (string, error) {
	osName, err := detectOSNameFromOSInfo(osInfo)
	if err != nil {
		return "", xerrors.Errorf("Failed to detect OS Name from OSInfo: %+v, err: %w", osInfo, err)
	}
	return osName, nil
}

func detectOSNameFromOSInfo(osInfo osInfo) (string, error) {
	switch osInfo.version {
	case "5.0":
		switch osInfo.installationType {
		case "Client":
			if osInfo.servicePack != "" {
				return fmt.Sprintf("Microsoft Windows 2000 %s", osInfo.servicePack), nil
			}
			return "Microsoft Windows 2000", nil
		case "Server":
			if osInfo.servicePack != "" {
				return fmt.Sprintf("Microsoft Windows 2000 Server %s", osInfo.servicePack), nil
			}
			return "Microsoft Windows 2000 Server", nil
		}
	case "5.1":
		switch osInfo.installationType {
		case "Client":
			var n string
			switch osInfo.edition {
			case "Professional":
				n = "Microsoft Windows XP Professional"
			case "Media Center":
				n = "Microsoft Windows XP Media Center Edition 2005"
			case "Tablet PC":
				n = "Microsoft Windows XP Tablet PC Edition 2005"
			default:
				n = "Microsoft Windows XP"
			}
			switch osInfo.arch {
			case "x64":
				n = fmt.Sprintf("%s x64 Edition", n)
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("%s %s", n, osInfo.servicePack), nil
			}
			return n, nil
		}
	case "5.2":
		switch osInfo.installationType {
		case "Client":
			var n string
			switch osInfo.edition {
			case "Professional":
				n = "Microsoft Windows XP Professional"
			case "Media Center":
				n = "Microsoft Windows XP Media Center Edition 2005"
			case "Tablet PC":
				n = "Microsoft Windows XP Tablet PC Edition 2005"
			default:
				n = "Microsoft Windows XP"
			}
			switch osInfo.arch {
			case "x64":
				n = fmt.Sprintf("%s x64 Edition", n)
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("%s %s", n, osInfo.servicePack), nil
			}
			return n, nil
		case "Server":
			n := "Microsoft Windows Server 2003"
			if strings.Contains(osInfo.productName, "R2") {
				n = "Microsoft Windows Server 2003 R2"
			}
			switch osInfo.arch {
			case "x64":
				n = fmt.Sprintf("%s x64 Edition", n)
			case "IA64":
				if osInfo.edition == "Enterprise" {
					n = fmt.Sprintf("%s, Enterprise Edition for Itanium-based Systems", n)
				} else {
					n = fmt.Sprintf("%s for Itanium-based Systems", n)
				}
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("%s %s", n, osInfo.servicePack), nil
			}
			return n, nil
		}
	case "6.0":
		switch osInfo.installationType {
		case "Client":
			var n string
			switch osInfo.arch {
			case "x64":
				n = "Windows Vista x64 Editions"
			default:
				n = "Windows Vista"
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("%s %s", n, osInfo.servicePack), nil
			}
			return n, nil
		case "Server":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", err
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("Windows Server 2008 for %s Systems %s", arch, osInfo.servicePack), nil
			}
			return fmt.Sprintf("Windows Server 2008 for %s Systems", arch), nil
		case "Server Core":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", err
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("Windows Server 2008 for %s Systems %s (Server Core installation)", arch, osInfo.servicePack), nil
			}
			return fmt.Sprintf("Windows Server 2008 for %s Systems (Server Core installation)", arch), nil
		}
	case "6.1":
		switch osInfo.installationType {
		case "Client":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", err
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("Windows 7 for %s Systems %s", arch, osInfo.servicePack), nil
			}
			return fmt.Sprintf("Windows 7 for %s Systems", arch), nil
		case "Server":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", err
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("Windows Server 2008 R2 for %s Systems %s", arch, osInfo.servicePack), nil
			}
			return fmt.Sprintf("Windows Server 2008 R2 for %s Systems", arch), nil
		case "Server Core":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", err
			}
			if osInfo.servicePack != "" {
				return fmt.Sprintf("Windows Server 2008 R2 for %s Systems %s (Server Core installation)", arch, osInfo.servicePack), nil
			}
			return fmt.Sprintf("Windows Server 2008 R2 for %s Systems (Server Core installation)", arch), nil
		}
	case "6.2":
		switch osInfo.installationType {
		case "Client":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("Windows 8 for %s Systems", arch), nil
		case "Server":
			return "Windows Server 2012", nil
		case "Server Core":
			return "Windows Server 2012 (Server Core installation)", nil
		}
	case "6.3":
		switch osInfo.installationType {
		case "Client":
			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("Windows 8.1 for %s Systems", arch), nil
		case "Server":
			return "Windows Server 2012 R2", nil
		case "Server Core":
			return "Windows Server 2012 R2 (Server Core installation)", nil
		}
	case "10.0":
		switch osInfo.installationType {
		case "Client":
			if strings.Contains(osInfo.productName, "Windows 11") {
				arch, err := formatArch(osInfo.arch)
				if err != nil {
					return "", err
				}
				name, err := formatNamebyBuild("11", osInfo.build)
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("%s for %s Systems", name, arch), nil
			}

			arch, err := formatArch(osInfo.arch)
			if err != nil {
				return "", err
			}
			name, err := formatNamebyBuild("10", osInfo.build)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%s for %s Systems", name, arch), nil
		case "Server":
			return formatNamebyBuild("Server", osInfo.build)
		case "Server Core":
			name, err := formatNamebyBuild("Server", osInfo.build)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("%s (Server Core installation)", name), nil
		}
	}
	return "", xerrors.New("OS Name not found")
}

func formatArch(arch string) (string, error) {
	switch arch {
	case "x64-based":
		return "x64-based", nil
	case "ARM64-based":
		return "ARM64-based", nil
	case "Itanium-based":
		return "Itanium-based", nil
	case "X86-based":
		return "32-bit", nil
	default:
		return "", xerrors.New("CPU Architecture not found")
	}
}

type buildNumber struct {
	build string
	name  string
}

var (
	winBuilds = map[string][]buildNumber{
		"10": {
			{
				build: "10240",
				name:  "Windows 10", // not "Windows 10 Version 1507"
			},
			{
				build: "10586",
				name:  "Windows 10 Version 1511",
			},
			{
				build: "14393",
				name:  "Windows 10 Version 1607",
			},
			{
				build: "15063",
				name:  "Windows 10 Version 1703",
			},
			{
				build: "16299",
				name:  "Windows 10 Version 1709",
			},
			{
				build: "17134",
				name:  "Windows 10 Version 1803",
			},
			{
				build: "17763",
				name:  "Windows 10 Version 1809",
			},
			{
				build: "18362",
				name:  "Windows 10 Version 1903",
			},
			{
				build: "18363",
				name:  "Windows 10 Version 1909",
			},
			{
				build: "19041",
				name:  "Windows 10 Version 2004",
			},
			{
				build: "19042",
				name:  "Windows 10 Version 20H2",
			},
			{
				build: "19043",
				name:  "Windows 10 Version 21H1",
			},
			{
				build: "19044",
				name:  "Windows 10 Version 21H2",
			},
			{
				build: "19045",
				name:  "Windows 10 Version 22H2",
			},
			// It seems that there are cases where the Product Name is Windows 10 even though it is Windows 11
			// ref: https://docs.microsoft.com/en-us/answers/questions/586548/in-the-official-version-of-windows-11-why-the-key.html
			{
				build: "22000",
				name:  "Windows 11 Version 21H2",
			},
			{
				build: "22621",
				name:  "Windows 11 Version 22H2",
			},
		},
		"11": {
			{
				build: "22000",
				name:  "Windows 11 Version 21H2",
			},
			{
				build: "22621",
				name:  "Windows 11 Version 22H2",
			},
		},
		"Server": {
			{
				build: "14393",
				name:  "Windows Server 2016",
			},
			{
				build: "16299",
				name:  "Windows Server, Version 1709",
			},
			{
				build: "17134",
				name:  "Windows Server, Version 1809",
			},
			{
				build: "17763",
				name:  "Windows Server 2019",
			},
			{
				build: "18362",
				name:  "Windows Server, Version 1903",
			},
			{
				build: "18363",
				name:  "Windows Server, Version 1909",
			},
			{
				build: "19041",
				name:  "Windows Server, Version 2004",
			},
			{
				build: "19042",
				name:  "Windows Server, Version 20H2",
			},
			{
				build: "20348",
				name:  "Windows Server 2022",
			},
		},
	}
)

func formatNamebyBuild(osType string, mybuild string) (string, error) {
	builds, ok := winBuilds[osType]
	if !ok {
		return "", xerrors.New("OS Type not found")
	}

	v := builds[0].name
	for _, b := range builds {
		if mybuild == b.build {
			return b.name, nil
		}
		if mybuild < b.build {
			break
		}
		v = b.name
	}
	return v, nil
}

func (o *windows) checkScanMode() error {
	return nil
}

func (o *windows) checkIfSudoNoPasswd() error {
	return nil
}

func (o *windows) checkDeps() error {
	return nil
}

func (o *windows) preCure() error {
	return nil
}

func (o *windows) postScan() error {
	return nil
}

func (o *windows) scanPackages() error {
	if r := o.exec("Get-Package | Select Name, Version, ProviderName | Format-List", noSudo); r.isSuccess() {
		installed, _, err := o.parseInstalledPackages(r.Stdout)
		if err != nil {
			return xerrors.Errorf("Failed to parse installed packages. err: %w", err)
		}
		o.Packages = installed
	}

	applied, unapplied, err := o.scanKBs()
	if err != nil {
		return xerrors.Errorf("Failed to scan KB. err: %w", err)
	}
	o.windowsKB.Applied = applied
	o.windowsKB.Unapplied = unapplied

	return nil
}

func (o *windows) parseInstalledPackages(stdout string) (models.Packages, models.SrcPackages, error) {
	installed := models.Packages{}

	var name, version string
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			name, version = "", ""
		case strings.HasPrefix(line, "Name"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, nil, xerrors.Errorf(`Failed to detect PackageName. expected: "Name : <PackageName>", line: "%s"`, line)
			}
			name = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "Version"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, nil, xerrors.Errorf(`Failed to detect Version. expected: "Version : <Version>", line: "%s"`, line)
			}
			version = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "ProviderName"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, nil, xerrors.Errorf(`Failed to detect ProviderName. expected: "ProviderName : <ProviderName>", line: "%s"`, line)
			}

			switch strings.TrimSpace(rhs) {
			case "msu":
			default:
				if name != "" {
					installed[name] = models.Package{Name: name, Version: version}
				}
			}
		default:
		}
	}

	return installed, nil, nil
}

func (o *windows) scanKBs() ([]string, []string, error) {
	applied, unapplied := map[string]struct{}{}, map[string]struct{}{}
	if r := o.exec("Get-Hotfix | Select HotFixID | Format-List", noSudo); r.isSuccess() {
		kbs, err := o.parseGetHotfix(r.Stdout)
		if err != nil {
			return nil, nil, xerrors.Errorf("Failed to parse Get-Hotifx. err: %w", err)
		}
		for _, kb := range kbs {
			applied[kb] = struct{}{}
		}
	}

	if r := o.exec("Get-Package -ProviderName msu | Select Name | Format-List", noSudo); r.isSuccess() {
		kbs, err := o.parseGetPackageMSU(r.Stdout)
		if err != nil {
			return nil, nil, xerrors.Errorf("Failed to parse Get-Package. err: %w", err)
		}
		for _, kb := range kbs {
			applied[kb] = struct{}{}
		}
	}

	var searcher string
	switch c := o.getServerInfo().Windows; c.ServerSelection {
	case 3: // https://learn.microsoft.com/en-us/windows/win32/wua_sdk/using-wua-to-scan-for-updates-offline
		searcher = fmt.Sprintf(`$UpdateSession = New-Object -ComObject Microsoft.Update.Session
$UpdateServiceManager = New-Object -ComObject Microsoft.Update.ServiceManager
$UpdateService = $UpdateServiceManager.AddScanPackageService("Offline Sync Service", "%s", 1)
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
$UpdateSearcher.ServerSelection = %d
$UpdateSearcher.ServiceID = $UpdateService.ServiceID`, c.CabPath, c.ServerSelection)
	default:
		searcher = fmt.Sprintf(`$UpdateSession = New-Object -ComObject Microsoft.Update.Session
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
$UpdateSearcher.ServerSelection = %d`, c.ServerSelection)
	}

	if r := o.exec(fmt.Sprintf(`%s
$UpdateSearcher.search("IsInstalled = 1 and RebootRequired = 0 and Type='Software'").Updates | %% {$_.KBArticleIDs}`, searcher), noSudo); r.isSuccess() {
		kbs, err := o.parseWindowsUpdaterSearch(r.Stdout)
		if err != nil {
			return nil, nil, xerrors.Errorf("Failed to parse Windows Update Search. err: %w", err)
		}
		for _, kb := range kbs {
			applied[kb] = struct{}{}
		}
	}
	if r := o.exec(fmt.Sprintf(`%s
$UpdateSearcher.search("IsInstalled = 0 and Type='Software'").Updates | %% {$_.KBArticleIDs}`, searcher), noSudo); r.isSuccess() {
		kbs, err := o.parseWindowsUpdaterSearch(r.Stdout)
		if err != nil {
			return nil, nil, xerrors.Errorf("Failed to parse Windows Update Search. err: %w", err)
		}
		for _, kb := range kbs {
			unapplied[kb] = struct{}{}
		}
	}
	if r := o.exec(fmt.Sprintf(`%s
$UpdateSearcher.search("IsInstalled = 1 and RebootRequired = 1 and Type='Software'").Updates | %% {$_.KBArticleIDs}`, searcher), noSudo); r.isSuccess() {
		kbs, err := o.parseWindowsUpdaterSearch(r.Stdout)
		if err != nil {
			return nil, nil, xerrors.Errorf("Failed to parse Windows Update Search. err: %w", err)
		}
		for _, kb := range kbs {
			unapplied[kb] = struct{}{}
		}
	}

	if r := o.exec(`$UpdateSearcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
$HistoryCount = $UpdateSearcher.GetTotalHistoryCount()
$UpdateSearcher.QueryHistory(0,$HistoryCount) | Sort-Object -Property Date | Select Title, Operation, ResultCode | Format-List`, noSudo); r.isSuccess() {
		kbs, err := o.parseWindowsUpdateHistory(r.Stdout)
		if err != nil {
			return nil, nil, xerrors.Errorf("Failed to parse Windows Update History. err: %w", err)
		}
		for _, kb := range kbs {
			applied[kb] = struct{}{}
		}
	}

	return maps.Keys(applied), maps.Keys(unapplied), nil
}

func (o *windows) parseGetHotfix(stdout string) ([]string, error) {
	var kbs []string

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "HotFixID"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, xerrors.Errorf(`Failed to detect HotFixID. expected: "HotFixID : <KBID>", line: "%s"`, line)
			}
			kbs = append(kbs, strings.TrimPrefix(strings.TrimSpace(rhs), "KB"))
		default:
		}
	}

	return kbs, nil
}

func (o *windows) parseGetPackageMSU(stdout string) ([]string, error) {
	var kbs []string

	kbIDPattern := regexp.MustCompile(`KB(\d{6,7})`)
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Name"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, xerrors.Errorf(`Failed to detect PackageName. expected: "Name : <PackageName>", line: "%s"`, line)
			}

			for _, m := range kbIDPattern.FindAllStringSubmatch(strings.TrimSpace(rhs), -1) {
				kbs = append(kbs, m[1])
			}
		default:
		}
	}

	return kbs, nil
}

func (o *windows) parseWindowsUpdaterSearch(stdout string) ([]string, error) {
	var kbs []string

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			kbs = append(kbs, line)
		}
	}

	return kbs, nil
}

func (o *windows) parseWindowsUpdateHistory(stdout string) ([]string, error) {
	kbs := map[string]struct{}{}

	kbIDPattern := regexp.MustCompile(`KB(\d{6,7})`)
	var title, operation string
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case line == "":
			title, operation = "", ""
		case strings.HasPrefix(line, "Title"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, xerrors.Errorf(`Failed to detect Title. expected: "Title : <Title>", line: "%s"`, line)
			}
			title = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "Operation"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, xerrors.Errorf(`Failed to detect Operation. expected: "Operation : <Operation>", line: "%s"`, line)
			}
			operation = strings.TrimSpace(rhs)
		case strings.HasPrefix(line, "ResultCode"):
			_, rhs, found := strings.Cut(line, ":")
			if !found {
				return nil, xerrors.Errorf(`Failed to detect ResultCode. expected: "ResultCode : <ResultCode>", line: "%s"`, line)
			}

			// https://learn.microsoft.com/en-us/windows/win32/api/wuapi/ne-wuapi-operationresultcode
			if strings.TrimSpace(rhs) == "2" {
				for _, m := range kbIDPattern.FindAllStringSubmatch(title, -1) {
					// https://learn.microsoft.com/en-us/windows/win32/api/wuapi/ne-wuapi-updateoperation
					switch operation {
					case "1":
						kbs[m[1]] = struct{}{}
					case "2":
						delete(kbs, m[1])
					default:
					}
				}
			}
		default:
		}
	}

	return maps.Keys(kbs), nil
}

func (o *windows) detectPlatform() {
	o.setPlatform(models.Platform{Name: "other"})
}
