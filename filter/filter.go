package filter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

func IsVulnerableClass(buf []byte, filename string, v Vulnerabilities) *FileInfo {
	hasher := sha256.New()
	io.Copy(hasher, bytes.NewBuffer(buf))
	sum := hex.EncodeToString(hasher.Sum(nil))

	if info, ok := vulnVersions[sum]; ok {
		if info.Vulnerabilities&v != 0 {
			return &info
		}
	}

	// cf. https://sources.debian.org/src/apache-log4j1.2/1.2.17-10/debian/patches/CVE-2019-17571.patch
	if v&CVE_2019_17571 != 0 &&
		strings.Contains(strings.ToLower(filepath.Base(filename)), "socketnode.") &&
		bytes.Equal(buf[:4], []byte{0xca, 0xfe, 0xba, 0xbe}) &&
		bytes.Contains(buf, []byte("org/apache/log4j")) &&
		!bytes.Contains(buf, []byte("FilteredObjectInputStream")) {
		return &FileInfo{
			"SocketNode class missing FilteredObjectInputStream patch",
			filepath.Base(filename), CVE_2019_17571,
		}
	}

	if v&CVE_2021_44228 != 0 &&
		strings.Contains(strings.ToLower(filepath.Base(filename)), "jndimanager.") &&
		bytes.Equal(buf[:4], []byte{0xca, 0xfe, 0xba, 0xbe}) &&
		// 2.15+
		!bytes.Contains(buf, []byte("Invalid JNDI URI - {}")) &&
		// 2.12.2. Note the extra space for extra security.
		!bytes.Contains(buf, []byte("Invalid  JNDI URI - {}")) {
		return &FileInfo{
			"JndiManager class missing new error message string literal",
			filepath.Base(filename), CVE_2021_44228,
		}
	}

	if v&CVE_2022_23307 != 0  &&
		strings.Contains(strings.ToLower(filepath.Base(filename)), "chainsaw/main.") {
		return &FileInfo{
			"Chainsaw Main.class found",
			filepath.Base(filename), CVE_2022_23307,
		}
	}

	return nil
}

type Vulnerabilities uint8

func (v Vulnerabilities) String() string {
	var tags []string
	if v&CVE_2019_17571 != 0 {
		tags = append(tags, "CVE-2019-17571")
	}
	if v&CVE_2021_44228 != 0 {
		tags = append(tags, "CVE-2021-44228")
	}
	if v&CVE_2022_23307 != 0 {
		tags = append(tags, "CVE_2022_23307")
	}
	if v&CVE_2021_45105 != 0 {
		tags = append(tags, "CVE-2021-45105")
	}
	if v&CVE_2021_45046 != 0 {
		tags = append(tags, "CVE-2021-45046")
	}
	if v&CVE_2021_44832 != 0 {
		tags = append(tags, "CVE-2021-44832")
	}
	return strings.Join(tags, ", ")
}

func (v *Vulnerabilities) Set(s string) error {
	*v = 0
	for _, tag := range strings.Split(s, ",") {
		switch strings.Trim(tag, " ") {
		case "CVE-2019-17571":
			*v |= CVE_2019_17571
		case "CVE_2022_23307":
			*v |= CVE_2022_23307
		case "CVE-2021-44228":
			*v |= CVE_2021_44228
		case "CVE-2021-45105":
			*v |= CVE_2021_45105
		case "CVE-2021-45046":
			*v |= CVE_2021_45046
		case "CVE-2021-44832":
			*v |= CVE_2021_44832
		case "":
		default:
			return fmt.Errorf("invalid vulnerability '%s'", tag)
		}
	}
	return nil
}

const (
	CheckDefaultVulnerabilities Vulnerabilities = CVE_2019_17571 | CVE_2021_44228 | CVE_2021_45046 | CVE_2022_23307
	CheckAllVulnerabilities     Vulnerabilities = 0xff
)

const (
	// v1.x
	CVE_2019_17571 Vulnerabilities = 1 << iota
	CVE_2022_23307
	// v2.x
	CVE_2021_44228
	CVE_2021_45105
	CVE_2021_45046
	CVE_2021_44832
)

type FileInfo struct {
	Version  string
	Filename string
	Vulnerabilities
}

var vulnVersions = map[string]FileInfo{
	"39a495034d37c7934b64a9aa686ea06b61df21aa222044cc50a47d6903ba1ca8": FileInfo{
		"log4j 2.0-rc1", "JndiLookup.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"a03e538ed25eff6c4fe48aabc5514e5ee687542f29f2206256840e74ed59bcd2": FileInfo{
		"log4j 2.0-rc2", "JndiLookup.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"964fa0bf8c045097247fa0c973e0c167df08720409fd9e44546e0ceda3925f3e": FileInfo{
		"log4j 2.0.1", "JndiLookup.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"9626798cce6abd0f2ffef89f1a3d0092a60d34a837a02bbe571dbe00236a2c8c": FileInfo{
		"log4j 2.0.2", "JndiLookup.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"fd6c63c11f7a6b52eff04be1de3477c9ddbbc925022f7216320e6db93f1b7d29": FileInfo{
		"log4j 2.0", "JndiLookup.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"a768e5383990b512f9d4f97217eda94031c2fa4aea122585f5a475ab99dc7307": FileInfo{
		"2.1-2.3", "JndiLookup.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"a534961bbfce93966496f86c9314f46939fd082bb89986b48b7430c3bea903f7": FileInfo{
		"2.4-2.5", "JndiLookup.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"e8ffed196e04f81b015f847d4ec61f22f6731c11b5a21b1cfc45ccbc58b8ea45": FileInfo{
		"2.6-2.6.2", "JndiLookup.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"cee2305065bb61d434cdb45cfdaa46e7da148e5c6a7678d56f3e3dc8d7073eae": FileInfo{
		"2.7", "JndiLookup.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"66c89e2d5ae674641138858b571e65824df6873abb1677f7b2ef5c0dd4dbc442": FileInfo{
		"2.8-2.8.1", "JndiLookup.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"d4ec57440cd6db6eaf6bcb6b197f1cbaf5a3e26253d59578d51db307357cbf15": FileInfo{
		"2.8.2", "JndiLookup.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"0f038a1e0aa0aff76d66d1440c88a2b35a3d023ad8b2e3bac8e25a3208499f7e": FileInfo{
		"2.9.0-2.11.2", "JndiLookup.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"5c104d16ff9831b456e4d7eaf66bcf531f086767782d08eece3fb37e40467279": FileInfo{
		"2.12.0-2.12.1", "JndiLookup.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"2b32bfc0556ea59307b9b2fde75b6dfbb5bf4f1d008d1402bc9a2357d8a8c61f": FileInfo{
		"2.13.0-2.13.3", "JndiLookup.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"ad5acfcbcb02f849ab695276285b6a5aef5f187b4d36b2159439084f4c732a4b": FileInfo{
		"2.13.3 (debian)", "JndiLookup.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f": FileInfo{
		"2.14.0-2.15.0", "JndiLookup.class",
		CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"3ce98fd29cd9467cb97bd9819677ee3cdbb35205c4d15f0e3cf6182bb196ef7c": FileInfo{
		"2.16.0", "JndiLookup.class", CVE_2021_45105 | CVE_2021_44832},
	"e732b989d3ffcb718ca5476781f2941bbc36f41ed929fed915a24801b40f8052": FileInfo{
		"2.17.0-2.17.1", "JndiLookup.class", 0},

	"1584b839cfceb33a372bb9e6f704dcea9701fa810a9ba1ad3961615a5b998c32": FileInfo{
		"log4j 2.7-2.8.1", "JndiManager.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"1fa92c00fa0b305b6bbe6e2ee4b012b588a906a20a05e135cbe64c9d77d676de": FileInfo{
		"log4j 2.12.0-2.12.1", "JndiManager.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6": FileInfo{
		"log4j 2.9.0-2.11.2", "JndiManager.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"3bff6b3011112c0b5139a5c3aa5e698ab1531a2f130e86f9e4262dd6018916d7": FileInfo{
		"log4j 2.4-2.5", "JndiManager.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"6540d5695ddac8b0a343c2e91d58316cfdbfdc5b99c6f3f91bc381bc6f748246": FileInfo{
		"log4j 2.6-2.6.2", "JndiManager.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"764b06686dbe06e3d5f6d15891250ab04073a0d1c357d114b7365c70fa8a7407": FileInfo{
		"log4j 2.8.2", "JndiManager.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"77323460255818f4cbfe180141d6001bfb575b429e00a07cbceabd59adf334d6": FileInfo{
		"log4j 2.14.0-2.14.1", "JndiManager.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"ae950f9435c0ef3373d4030e7eff175ee11044e584b7f205b7a9804bbe795f9c": FileInfo{
		"log4j 2.1-2.3", "JndiManager.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"c3e95da6542945c1a096b308bf65bbd7fcb96e3d201e5a2257d85d4dedc6a078": FileInfo{
		"log4j 2.13.0-2.13.3", "JndiManager.class",
		CVE_2021_44228 | CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"db07ef1ea174e000b379732681bd835cfede648a7971bf4e9a0d31981582d69e": FileInfo{
		"log4j 2.15.0", "JndiManager.class",
		CVE_2021_45046 | CVE_2021_45105 | CVE_2021_44832},
	"5210e6aae7dd8a61cd16c56937c5f2ed43941487830f46e99d0d3f45bfa6f953": FileInfo{
		"log4j 2.16.0", "JndiManager.class",
		CVE_2021_45105 | CVE_2021_44832},
	"838ed75ea7747fa2c7068f64c76c3f623e7fe4305cdadc2ce5d7b49c7c805221": FileInfo{
		"log4j 2.16.0 (debian)", "JndiManager.class",
		CVE_2021_45105 | CVE_2021_44832},
	"9c2a6ea36c79fa23da59cc0f6c52c07ce54ca145ddd654790a3116d2b24de51b": FileInfo{
		"log4j 2.17.0", "JndiManager.class", CVE_2021_44832},
	"3588a6aaf84fa79215a1cc5d12dee69413b8772656c73bdf26ef35df713b1091": FileInfo{
		"log4j 2.17.1", "JndiManager.class", 0},
	"6adb3617902180bdf9cbcfc08b5a11f3fac2b44ef1828131296ac41397435e3d": FileInfo{
		"log4j 1.2.4", "SocketNode.class", CVE_2019_17571},
	"3ef93e9cb937295175b75182e42ba9a0aa94f9f8e295236c9eef914348efeef0": FileInfo{
		"log4j 1.2.6-1.2.9", "SocketNode.class", CVE_2019_17571},
	"bee4a5a70843a981e47207b476f1e705c21fc90cb70e95c3b40d04a2191f33e9": FileInfo{
		"log4j 1.2.8", "SocketNode.class", CVE_2019_17571},
	"7b996623c05f1a25a57fb5b43c519c2ec02ec2e647c2b97b3407965af928c9a4": FileInfo{
		"log4j 1.2.15", "SocketNode.class", CVE_2019_17571},
	"688a3dadfb1c0a08fb2a2885a356200eb74e7f0f26a197d358d74f2faf6e8f46": FileInfo{
		"log4j 1.2.16", "SocketNode.class", CVE_2019_17571},
	"8ef0ebdfbf28ec14b2267e6004a8eea947b4411d3c30d228a7b48fae36431d74": FileInfo{
		"log4j 1.2.17", "SocketNode.class", CVE_2019_17571},
	"d778227b779f8f3a2850987e3cfe6020ca26c299037fdfa7e0ac8f81385963e6": FileInfo{
		"log4j 1.2.11", "SocketNode.class", CVE_2019_17571},
	"ed5d53deb29f737808521dd6284c2d7a873a59140e702295a80bd0f26988f53a": FileInfo{
		"log4j 1.2.5", "SocketNode.class", CVE_2019_17571},
	"f3b815a2b3c74851ff1b94e414c36f576fbcdf52b82b805b2e18322b3f5fc27c": FileInfo{
		"log4j 1.2.12", "SocketNode.class", CVE_2019_17571},
	"fbda3cfc5853ab4744b853398f2b3580505f5a7d67bfb200716ef6ae5be3c8b7": FileInfo{
		"log4j 1.2.13-1.2.14", "SocketNode.class", CVE_2019_17571},
	"287c1d40f2a4bc0055b32b45f12f01bdc2a27379ec33fe13a084bf69a1f4c6e1": FileInfo{
		"log4j 1.2.15.v201012070815", "SocketNode.class", CVE_2019_17571},

	"1ac1e0ce33feca95834596faceb3a5b042b2a0c4d612c0e6f5045068bab89cd2": FileInfo{
		"log4j 2.17.0", "DataSourceConnectionSource.class", CVE_2021_44832},

	"fb288e8015a971b16af5ab8d655b22f261276291aec8b1b40fdc2f2cddabd5fa": FileInfo{
		"log4j 1.2.4-1.2.7", "Main.class", CVE_2022_23307},
	"2624d58c0bee501cf37b29cf9b12482b9fdc01f6bfdffba51da4f2bfb864b656": FileInfo{
		"log4j 1.2.8", "Main.class", CVE_2022_23307},
	"b945ca6f5e31a88d78cc33302e4cfbdbf458560a5413c8918675765f22b4a1e3": FileInfo{
		"log4j 1.2.9", "Main.class", CVE_2022_23307},
	"9cb67446ecf998f8d3cc5b883b76f6f415ce2b1a76c05f83e2812317ff874185": FileInfo{
		"log4j 1.2.11", "Main.class", CVE_2022_23307},
	"acccc50431f2f155a57d777d4863cb3ca7c7882ac5842d1d2238d703159390d4": FileInfo{
		"log4j 1.2.12", "Main.class", CVE_2022_23307},
	"19cd72c17a6063af790198b434ff8cc1837d4537703742834b6c228a03bd2797": FileInfo{
		"log4j 1.2.13-1.2.14", "Main.class", CVE_2022_23307},
	"93f4770b0196b28b4a95960bf9057381a394486ddbb998639bccf8c79f7e3bd2": FileInfo{
		"log4j 1.2.15", "Main.class", CVE_2022_23307},
	"c224d01478e0a06878395e40ad9c93f8e30dc93c5cffd7c8b2b3909d8e7fef82": FileInfo{
		"log4j 1.2.16", "Main.class", CVE_2022_23307},
	"c0c544876e7083f76341ceb2bbb4d5004b10946c1ba8a3aec4b1aebb5e902312": FileInfo{
		"log4j 1.2.17", "Main.class", CVE_2022_23307},
}
