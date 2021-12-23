package appendedzip

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
)

func OpenFile(file string) (*zip.Reader, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	return NewReader(f, fi.Size())
}

// NewReader searches for ZIP beginning-of-file signatures ('P' 'K'
// 03 04) in r and tries to read the file starting at that offset
// using an encryption-enabled archive/zip, returning a *zip.Reader
// for the first valid entry, or an error.
func NewReader(r io.ReaderAt, size int64) (*zip.Reader, error) {
	const BUFSIZE = 4096
	var buf [BUFSIZE + 4]byte
	for i := int64(0); (i-1)*BUFSIZE < size; i++ {
		len, err := r.ReadAt(buf[:], i*BUFSIZE)
		if err != nil && err != io.EOF {
			break
		}

		n := 0
		for {
			m := bytes.Index(buf[n:len], []byte("PK\x03\x04"))
			if m == -1 {
				break
			}
			off := i*BUFSIZE + int64(n+m)
			ssize := size - int64(off)
			sr := io.NewSectionReader(r, int64(off), ssize)
			if zr, ze := zip.NewReader(sr, ssize+1); ze == nil {
				return zr, nil
			}
			n += m + 1
		}
		if err == io.EOF {
			break
		}
	}
	return nil, errors.New("No zip file found")
}
