package filter

import (
	"io/ioutil"
	"testing"
)

type v struct {
	version    string
	vulnerable bool
}

func TestFilterJndiManager(t *testing.T) {
	for _, cand := range []v{
		v{"2.1", true},
		v{"2.2", true},
		v{"2.3", true},
		v{"2.4", true},
		v{"2.4.1", true},
		v{"2.5", true},
		v{"2.6", true},
		v{"2.6.1", true},
		v{"2.6.2", true},
		v{"2.7", true},
		v{"2.8", true},
		v{"2.8.1", true},
		v{"2.8.2", true},
		v{"2.9.0", true},
		v{"2.9.1", true},
		v{"2.10.0", true},
		v{"2.11.0", true},
		v{"2.11.1", true},
		v{"2.11.2", true},
		v{"2.12.0", true},
		v{"2.12.1", true},
		v{"2.12.2", false},
		v{"2.13.0", true},
		v{"2.13.1", true},
		v{"2.13.2", true},
		v{"2.13.3", true},
		v{"2.13-3-debian", true},
		v{"2.14.0", true},
		v{"2.14.1", true},
		v{"2.15.0", true},
		v{"2.16.0", true},
		v{"2.16.0-debian", true},
		v{"2.17.0", true},
		v{"2.17.1", false},
	} {
		file := "../testdata/JndiManager.class-" + cand.version
		buf, err := ioutil.ReadFile(file)
		if err != nil {
			t.Logf("can't open %s: %v", file, err)
			continue
		}
		if verdict := IsVulnerableClass(buf, "jndimanager.class", CheckAllVulnerabilities); (verdict != nil) != cand.vulnerable {
			if cand.vulnerable {
				t.Errorf("found %s not to be vulnerable (but it is)", file)
			} else {
				t.Errorf("found %s to be vulnerable (but it is not)", file)
			}
		} else {
			t.Logf("%s: %s", file, verdict)
		}
	}
}

func TestFilterJndiLookup(t *testing.T) {
	for _, cand := range []v{
		v{"2.0", true},
		v{"2.0.1", true},
		v{"2.0.2", true},
		v{"2.0-beta9", true},
		v{"2.0-rc1", true},
		v{"2.0-rc2", true},
		v{"2.1", true},
		v{"2.2", true},
		v{"2.3", true},
		v{"2.4", true},
		v{"2.4.1", true},
		v{"2.5", true},
		v{"2.6", true},
		v{"2.6.1", true},
		v{"2.6.2", true},
		v{"2.7", true},
		v{"2.8", true},
		v{"2.8.1", true},
		v{"2.8.2", true},
		v{"2.9.0", true},
		v{"2.9.1", true},
		v{"2.10.0", true},
		v{"2.11.0", true},
		v{"2.11.1", true},
		v{"2.11.2", true},
		v{"2.12.0", true},
		v{"2.12.1", true},
		v{"2.13.0", true},
		v{"2.13.1", true},
		v{"2.13.2", true},
		v{"2.13.3", true},
		v{"2.13-3-debian", true},
		v{"2.14.0", true},
		v{"2.14.1", true},
		v{"2.15.0", true},
		v{"2.16.0", true},
		v{"2.17.0", false}, // JndiLookup.class is equal to the one in 2.17.1
		v{"2.17.1", false},
	} {
		file := "../testdata/JndiLookup.class-" + cand.version
		buf, err := ioutil.ReadFile(file)
		if err != nil {
			t.Logf("can't open %s: %v", file, err)
			continue
		}
		if verdict := IsVulnerableClass(buf, "jndilookup.class", CheckAllVulnerabilities); (verdict != nil) != cand.vulnerable {
			if cand.vulnerable {
				t.Errorf("found %s not to be vulnerable (but it is)", file)
			} else {
				t.Errorf("found %s to be vulnerable (but it is not)", file)
			}
		} else {
			t.Logf("%s: %s", file, verdict)
		}
	}
}

func TestFilterSocketNode(t *testing.T) {
	for _, cand := range []v{
		v{"1.2.4", true},
		v{"1.2.5", true},
		v{"1.2.6", true},
		v{"1.2.7", true},
		v{"1.2.8", true},
		v{"1.2.9", true},
		v{"1.2.11", true},
		v{"1.2.12", true},
		v{"1.2.13", true},
		v{"1.2.14", true},
		v{"1.2.15", true},
		v{"1.2.16", true},
		v{"1.2.17", true},
		v{"1.2.17-debian", false},
	} {
		file := "../testdata/SocketNode.class-" + cand.version
		buf, err := ioutil.ReadFile(file)
		if err != nil {
			t.Logf("can't open %s: %v", file, err)
			continue
		}
		if verdict := IsVulnerableClass(buf, "socketnode.class", CheckAllVulnerabilities); (verdict != nil) != cand.vulnerable {
			if cand.vulnerable {
				t.Errorf("found %s not to be vulnerable (but it is)", file)
			} else {
				t.Errorf("found %s to be vulnerable (but it is not)", file)
			}
		} else {
			t.Logf("%s: %s", file, verdict)
		}
	}
}
