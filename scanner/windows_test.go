package scanner

import (
	"reflect"
	"testing"

	"golang.org/x/exp/slices"

	"github.com/future-architect/vuls/models"
)

func Test_parseSystemInfo(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name    string
		args    args
		release string
		kbs     []string
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				stdout: `
Host Name:                 DESKTOP
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19044 N/A Build 19044
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Member Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00000-00000-00000-AA000
Original Install Date:     2022/04/13, 12:25:41
System Boot Time:          2022/06/06, 16:43:45
System Manufacturer:       HP
System Model:              HP EliteBook 830 G7 Notebook PC
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
						   [01]: Intel64 Family 6 Model 142 Stepping 12 GenuineIntel ~1803 Mhz
BIOS Version:              HP S70 Ver. 01.05.00, 2021/04/26
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     15,709 MB
Available Physical Memory: 12,347 MB
Virtual Memory: Max Size:  18,141 MB
Virtual Memory: Available: 14,375 MB
Virtual Memory: In Use:    3,766 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\DESKTOP
Hotfix(s):                 7 Hotfix(s) Installed.
						   [01]: KB5012117
						   [02]: KB4562830
						   [03]: KB5003791
						   [04]: KB5007401
						   [05]: KB5012599
						   [06]: KB5011651
						   [07]: KB5005699
Network Card(s):           1 NIC(s) Installed.
						   [01]: Intel(R) Wi-Fi 6 AX201 160MHz
								 Connection Name: Wi-Fi
								 DHCP Enabled:    Yes
								 DHCP Server:     192.168.0.1
								 IP address(es)
								 [01]: 192.168.0.205
Hyper-V Requirements:      VM Monitor Mode Extensions: Yes
						   Virtualization Enabled In Firmware: Yes
						   Second Level Address Translation: Yes
						   Data Execution Prevention Available: Yes
`,
			},
			release: "Windows 10 Version 21H2 for x64-based Systems",
			kbs:     []string{"5012117", "4562830", "5003791", "5007401", "5012599", "5011651", "5005699"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			release, kbs, err := parseSystemInfo(tt.args.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSystemInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if release != tt.release {
				t.Errorf("parseSystemInfo() got = %v, want %v", release, tt.release)
			}
			if !reflect.DeepEqual(kbs, tt.kbs) {
				t.Errorf("parseSystemInfo() got = %v, want %v", kbs, tt.kbs)
			}
		})
	}
}

func Test_parseGetComputerInfo(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				stdout: `
WindowsProductName         : Windows 10 Pro
OsVersion                  : 10.0.19044
WindowsEditionId           : Professional
OsCSDVersion               :
CsSystemType               : x64-based PC
WindowsInstallationType    : Client
`,
			},
			want:    "Windows 10 Version 21H2 for x64-based Systems",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseGetComputerInfo(tt.args.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseGetComputerInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseGetComputerInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseInstalledPackages(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name    string
		args    args
		want    models.Packages
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				stdout: `
Name         : Git
Version      : 2.35.1.2
ProviderName : Programs

Name         : Oracle Database 11g Express Edition
Version      : 11.2.0
ProviderName : msi

Name         : 2022-12 x64 ベース システム用 Windows 10 Version 21H2 の累積更新プログラム (KB5021233)
Version      :
ProviderName : msu
`,
			},
			want: models.Packages{
				"Git": {
					Name:    "Git",
					Version: "2.35.1.2",
				},
				"Oracle Database 11g Express Edition": {
					Name:    "Oracle Database 11g Express Edition",
					Version: "11.2.0",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &windows{}
			got, _, err := o.parseInstalledPackages(tt.args.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("windows.parseInstalledPackages() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("windows.parseInstalledPackages() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseGetHotfix(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				stdout: `
HotFixID : KB5020872

HotFixID : KB4562830
`,
			},
			want:    []string{"5020872", "4562830"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &windows{}
			got, err := o.parseGetHotfix(tt.args.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("windows.parseGetHotfix() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("windows.parseGetHotfix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseGetPackageMSU(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				stdout: `
Name         : Git
Version      : 2.35.1.2
ProviderName : Programs

Name         : Oracle Database 11g Express Edition
Version      : 11.2.0
ProviderName : msi

Name         : 2022-12 x64 ベース システム用 Windows 10 Version 21H2 の累積更新プログラム (KB5021233)
Version      :
ProviderName : msu
`,
			},
			want:    []string{"5021233"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &windows{}
			got, err := o.parseGetPackageMSU(tt.args.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("windows.parseGetPackageMSU() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("windows.parseGetPackageMSU() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseWindowsUpdaterSearch(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				stdout: `5012170
5021233
5021088
`,
			},
			want:    []string{"5012170", "5021233", "5021088"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &windows{}
			got, err := o.parseWindowsUpdaterSearch(tt.args.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("windows.parseWindowsUpdaterSearch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("windows.parseWindowsUpdaterSearch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseWindowsUpdateHistory(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				stdout: `
Title      : 2022-10 x64 ベース システム用 Windows 10 Version 21H2 の累積更新プログラム (KB5020435)
Operation  : 1
ResultCode : 2

Title      : 2022-10 x64 ベース システム用 Windows 10 Version 21H2 の累積更新プログラム (KB5020435)
Operation  : 2
ResultCode : 2

Title      : 2022-12 x64 (KB5021088) 向け Windows 10 Version 21H2 用 .NET Framework 3.5、4.8 および 4.8.1 の累積的な更新プログラム
Operation  : 1
ResultCode : 2

Title      : 2022-12 x64 ベース システム用 Windows 10 Version 21H2 の累積更新プログラム (KB5021233)
Operation  : 1
ResultCode : 2
`,
			},
			want:    []string{"5021088", "5021233"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &windows{}
			got, err := o.parseWindowsUpdateHistory(tt.args.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("windows.parseWindowsUpdateHistory() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			slices.Sort(got)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("windows.parseWindowsUpdateHistory() = %v, want %v", got, tt.want)
			}
		})
	}
}
