package appendedzip

import (
	"archive/zip"
	"os"
	"testing"
)

func TestAppendedZip(t *testing.T) {
	for _, sample := range []string{
		"data512",
		"data8192",
		"data8190",
		"doublezip",
		"fakeheader8192",
		"fakeheader512",
		"regular",
	} {
		t.Log("Reading " + sample + " ...")
		f, err := os.Open("testdata/" + sample)
		if _, err := zip.OpenReader("testdata/" + sample); err == nil {
			t.Logf("Note: %s can be opened by archive/zip", sample)
		}
		if err != nil {
			t.Fatal(err)
		}
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		zr, err := NewReader(f, fi.Size())
		if err != nil {
			t.Error(err)
		} else {
			t.Log("found zip in " + sample)
			t.Logf("%+v", zr)
		}
	}
}
