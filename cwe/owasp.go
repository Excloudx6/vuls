package cwe

// OwaspTopTens has CWE-ID in OWASP Top 10
var OwaspTopTens = map[string]map[string]string{
	"2017": owaspTopTen2017,
	"2021": owaspTopTen2021,
}

var owaspTopTen2017 = map[string]string{
	"77":  "1",
	"89":  "1",
	"564": "1",
	"917": "1",

	"287": "2",
	"384": "2",

	"220": "3",
	"310": "3",
	"312": "3",
	"319": "3",
	"326": "3",
	"359": "3",

	"611": "4",

	"22":  "5",
	"284": "5",
	"285": "5",
	"639": "5",

	"2":   "6",
	"16":  "6",
	"388": "6",

	"79": "7",

	"502": "8",

	"223": "10",
	"778": "10",
}

var owaspTopTen2021 = map[string]string{
	"22":   "1",
	"23":   "1",
	"35":   "1",
	"59":   "1",
	"200":  "1",
	"201":  "1",
	"219":  "1",
	"264":  "1",
	"275":  "1",
	"276":  "1",
	"284":  "1",
	"285":  "1",
	"352":  "1",
	"359":  "1",
	"377":  "1",
	"402":  "1",
	"425":  "1",
	"441":  "1",
	"497":  "1",
	"538":  "1",
	"540":  "1",
	"552":  "1",
	"566":  "1",
	"601":  "1",
	"639":  "1",
	"651":  "1",
	"668":  "1",
	"706":  "1",
	"862":  "1",
	"863":  "1",
	"913":  "1",
	"922":  "1",
	"1275": "1",

	"261": "2",
	"296": "2",
	"310": "2",
	"319": "2",
	"321": "2",
	"322": "2",
	"323": "2",
	"324": "2",
	"325": "2",
	"326": "2",
	"327": "2",
	"328": "2",
	"329": "2",
	"330": "2",
	"331": "2",
	"335": "2",
	"336": "2",
	"337": "2",
	"338": "2",
	"340": "2",
	"347": "2",
	"523": "2",
	"720": "2",
	"757": "2",
	"759": "2",
	"760": "2",
	"780": "2",
	"818": "2",
	"916": "2",

	"20":  "3",
	"74":  "3",
	"75":  "3",
	"77":  "3",
	"78":  "3",
	"79":  "3",
	"80":  "3",
	"83":  "3",
	"87":  "3",
	"88":  "3",
	"89":  "3",
	"90":  "3",
	"91":  "3",
	"93":  "3",
	"94":  "3",
	"95":  "3",
	"96":  "3",
	"97":  "3",
	"98":  "3",
	"99":  "3",
	"100": "3",
	"113": "3",
	"116": "3",
	"138": "3",
	"184": "3",
	"470": "3",
	"471": "3",
	"564": "3",
	"610": "3",
	"643": "3",
	"644": "3",
	"652": "3",
	"917": "3",

	"73":   "4",
	"183":  "4",
	"209":  "4",
	"213":  "4",
	"235":  "4",
	"256":  "4",
	"257":  "4",
	"266":  "4",
	"269":  "4",
	"280":  "4",
	"311":  "4",
	"312":  "4",
	"313":  "4",
	"316":  "4",
	"419":  "4",
	"430":  "4",
	"434":  "4",
	"444":  "4",
	"451":  "4",
	"472":  "4",
	"501":  "4",
	"522":  "4",
	"525":  "4",
	"539":  "4",
	"579":  "4",
	"598":  "4",
	"602":  "4",
	"642":  "4",
	"646":  "4",
	"650":  "4",
	"653":  "4",
	"656":  "4",
	"657":  "4",
	"799":  "4",
	"807":  "4",
	"840":  "4",
	"841":  "4",
	"927":  "4",
	"1021": "4",
	"1173": "4",

	"2":    "5",
	"11":   "5",
	"13":   "5",
	"15":   "5",
	"16":   "5",
	"260":  "5",
	"315":  "5",
	"520":  "5",
	"526":  "5",
	"537":  "5",
	"541":  "5",
	"547":  "5",
	"611":  "5",
	"614":  "5",
	"756":  "5",
	"776":  "5",
	"942":  "5",
	"1004": "5",
	"1032": "5",
	"1174": "5",

	"937":  "6",
	"1035": "6",
	"1104": "6",

	"255":  "7",
	"259":  "7",
	"287":  "7",
	"288":  "7",
	"290":  "7",
	"294":  "7",
	"295":  "7",
	"297":  "7",
	"300":  "7",
	"302":  "7",
	"304":  "7",
	"306":  "7",
	"307":  "7",
	"346":  "7",
	"384":  "7",
	"521":  "7",
	"613":  "7",
	"620":  "7",
	"640":  "7",
	"798":  "7",
	"940":  "7",
	"1216": "7",

	"345": "8",
	"353": "8",
	"426": "8",
	"494": "8",
	"502": "8",
	"565": "8",
	"784": "8",
	"829": "8",
	"830": "8",
	"915": "8",

	"117": "9",
	"223": "9",
	"532": "9",
	"778": "9",

	"918": "10",
}

// OwaspTopTenURLsEn has GitHub links
var OwaspTopTenURLsEn = map[string]map[string]string{
	"2017": {
		"1":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa1-injection.md",
		"2":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa2-broken-authentication.md",
		"3":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa3-sensitive-data-disclosure.md",
		"4":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa4-xxe.md",
		"5":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa5-broken-access-control.md",
		"6":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa6-security-misconfiguration.md",
		"7":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa7-xss.md",
		"8":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa8-insecure-deserialization.md",
		"9":  "https://github.com/OWASP/Top10/blob/master/2017/en/0xa9-known-vulns.md",
		"10": "https://github.com/OWASP/Top10/blob/master/2017/en/0xaa-logging-detection-response.md",
	},
	"2021": {
		"1":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A01_2021-Broken_Access_Control.md",
		"2":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A02_2021-Cryptographic_Failures.md",
		"3":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A03_2021-Injection.md",
		"4":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A04_2021-Insecure_Design.md",
		"5":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A05_2021-Security_Misconfiguration.md",
		"6":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A06_2021-Vulnerable_and_Outdated_Components.md",
		"7":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A07_2021-Identification_and_Authentication_Failures.md",
		"8":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A08_2021-Software_and_Data_Integrity_Failures.md",
		"9":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A09_2021-Security_Logging_and_Monitoring_Failures.md",
		"10": "https://github.com/OWASP/Top10/blob/master/2021/docs/A10_2021-Server-Side_Request_Forgery_(SSRF).md",
	},
}

// OwaspTopTenURLsJa has GitHub links
var OwaspTopTenURLsJa = map[string]map[string]string{
	"2017": {
		"1":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa1-injection.md",
		"2":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa2-broken-authentication.md",
		"3":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa3-sensitive-data-disclosure.md",
		"4":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa4-xxe.md",
		"5":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa5-broken-access-control.md",
		"6":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa6-security-misconfiguration.md",
		"7":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa7-xss.md",
		"8":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa8-insecure-deserialization.md",
		"9":  "https://github.com/OWASP/Top10/blob/master/2017/ja/0xa9-known-vulns.md",
		"10": "https://github.com/OWASP/Top10/blob/master/2017/ja/0xaa-logging-detection-response.md",
	},
	"2021": {
		"1":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A01_2021-Broken_Access_Control.ja.md",
		"2":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A02_2021-Cryptographic_Failures.ja.md",
		"3":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A03_2021-Injection.ja.md",
		"4":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A04_2021-Insecure_Design.ja.md",
		"5":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A05_2021-Security_Misconfiguration.ja.md",
		"6":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A06_2021-Vulnerable_and_Outdated_Components.ja.md",
		"7":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A07_2021-Identification_and_Authentication_Failures.ja.md",
		"8":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A08_2021-Software_and_Data_Integrity_Failures.ja.md",
		"9":  "https://github.com/OWASP/Top10/blob/master/2021/docs/A09_2021-Security_Logging_and_Monitoring_Failures.ja.md",
		"10": "https://github.com/OWASP/Top10/blob/master/2021/docs/A10_2021-Server-Side_Request_Forgery_(SSRF).ja.md",
	},
}
