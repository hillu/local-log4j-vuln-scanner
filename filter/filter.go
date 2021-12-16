package filter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"path/filepath"
	"strings"
)

func IsVulnerableClass(buf []byte, filename string, examineV1 bool) string {
	hasher := sha256.New()
	io.Copy(hasher, bytes.NewBuffer(buf))
	sum := hex.EncodeToString(hasher.Sum(nil))

	if desc, ok := vulnVersions[sum]; ok {
		return desc
	}

	if examineV1 {
		if desc, ok := vulnVersionsV1[sum]; ok {
			return desc
		}
		// cf. https://sources.debian.org/src/apache-log4j1.2/1.2.17-10/debian/patches/CVE-2019-17571.patch
		if strings.Contains(strings.ToLower(filepath.Base(filename)), "socketnode.") &&
			bytes.Equal(buf[:4], []byte{0xca, 0xfe, 0xba, 0xbe}) &&
			bytes.Contains(buf, []byte("org/apache/log4j")) &&
			!bytes.Contains(buf, []byte("FilteredObjectInputStream")) {
			return "SocketNode class missing FilteredObjectInputStream patch"
		}
	}

	if strings.Contains(strings.ToLower(filepath.Base(filename)), "jndimanager.") &&
		bytes.Equal(buf[:4], []byte{0xca, 0xfe, 0xba, 0xbe}) &&
		!bytes.Contains(buf, []byte("Invalid JNDI URI - {}")) {
		return "JndiManager class missing new error message string literal"
	}

	return ""
}

var vulnVersions = map[string]string{
	"39a495034d37c7934b64a9aa686ea06b61df21aa222044cc50a47d6903ba1ca8": "log4j 2.0-rc1",       // JndiLookup.class
	"a03e538ed25eff6c4fe48aabc5514e5ee687542f29f2206256840e74ed59bcd2": "log4j 2.0-rc2",       // JndiLookup.class
	"964fa0bf8c045097247fa0c973e0c167df08720409fd9e44546e0ceda3925f3e": "log4j 2.0.1",         // JndiLookup.class
	"9626798cce6abd0f2ffef89f1a3d0092a60d34a837a02bbe571dbe00236a2c8c": "log4j 2.0.2",         // JndiLookup.class
	"fd6c63c11f7a6b52eff04be1de3477c9ddbbc925022f7216320e6db93f1b7d29": "log4j 2.0",           // JndiLookup.class
	"1584b839cfceb33a372bb9e6f704dcea9701fa810a9ba1ad3961615a5b998c32": "log4j 2.7-2.8.1",     // JndiManager.class
	"1fa92c00fa0b305b6bbe6e2ee4b012b588a906a20a05e135cbe64c9d77d676de": "log4j 2.12.0-2.12.1", // JndiManager.class
	"293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6": "log4j 2.9.0-2.11.2",  // JndiManager.class
	"3bff6b3011112c0b5139a5c3aa5e698ab1531a2f130e86f9e4262dd6018916d7": "log4j 2.4-2.5",       // JndiManager.class
	"6540d5695ddac8b0a343c2e91d58316cfdbfdc5b99c6f3f91bc381bc6f748246": "log4j 2.6-2.6.2",     // JndiManager.class
	"764b06686dbe06e3d5f6d15891250ab04073a0d1c357d114b7365c70fa8a7407": "log4j 2.8.2",         // JndiManager.class
	"77323460255818f4cbfe180141d6001bfb575b429e00a07cbceabd59adf334d6": "log4j 2.14.0-2.14.1", // JndiManager.class
	"ae950f9435c0ef3373d4030e7eff175ee11044e584b7f205b7a9804bbe795f9c": "log4j 2.1-2.3",       // JndiManager.class
	"c3e95da6542945c1a096b308bf65bbd7fcb96e3d201e5a2257d85d4dedc6a078": "log4j 2.13.0-2.13.3", // JndiManager.class
}

var vulnVersionsV1 = map[string]string{
	"6adb3617902180bdf9cbcfc08b5a11f3fac2b44ef1828131296ac41397435e3d": "log4j 1.2.4",                // SocketNode.class
	"3ef93e9cb937295175b75182e42ba9a0aa94f9f8e295236c9eef914348efeef0": "log4j 1.2.6-1.2.9",          // SocketNode.class
	"bee4a5a70843a981e47207b476f1e705c21fc90cb70e95c3b40d04a2191f33e9": "log4j 1.2.8",                // SocketNode.class
	"7b996623c05f1a25a57fb5b43c519c2ec02ec2e647c2b97b3407965af928c9a4": "log4j 1.2.15",               // SocketNode.class
	"688a3dadfb1c0a08fb2a2885a356200eb74e7f0f26a197d358d74f2faf6e8f46": "log4j 1.2.16",               // SocketNode.class
	"8ef0ebdfbf28ec14b2267e6004a8eea947b4411d3c30d228a7b48fae36431d74": "log4j 1.2.17",               // SocketNode.class
	"d778227b779f8f3a2850987e3cfe6020ca26c299037fdfa7e0ac8f81385963e6": "log4j 1.2.11",               // SocketNode.class
	"ed5d53deb29f737808521dd6284c2d7a873a59140e702295a80bd0f26988f53a": "log4j 1.2.5",                // SocketNode.class
	"f3b815a2b3c74851ff1b94e414c36f576fbcdf52b82b805b2e18322b3f5fc27c": "log4j 1.2.12",               // SocketNode.class
	"fbda3cfc5853ab4744b853398f2b3580505f5a7d67bfb200716ef6ae5be3c8b7": "log4j 1.2.13-1.2.14",        // SocketNode.class
	"287c1d40f2a4bc0055b32b45f12f01bdc2a27379ec33fe13a084bf69a1f4c6e1": "log4j 1.2.15.v201012070815", // SocketNode.class
}
