package main

import (
	"github.com/hillu/local-log4j-vuln-scanner/filter"

	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: %s: <infile> <outfile>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}
	zr, err := zip.OpenReader(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "open (read): %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
	defer zr.Close()
	of, err := os.Create(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "open (write): %s: %v\n", os.Args[2], err)
		os.Exit(1)
	}
	zw := zip.NewWriter(of)
	for _, member := range zr.File {
		r, err := member.Open()
		if err != nil {
			fmt.Fprintf(os.Stderr, "open (read): %s::%s: %v\n", os.Args[1], member.Name, err)
			discardZip(os.Args[2], of, zw)
			os.Exit(1)
		}
		buf := bytes.NewBuffer(nil)
		if _, err := io.Copy(buf, r); err != nil {
			fmt.Fprintf(os.Stderr, "read: %s::%s %v\n", os.Args[1], member.Name, err)
			discardZip(os.Args[2], of, zw)
			os.Exit(1)
		}
		content := buf.Bytes()

		if desc := filter.IsVulnerableClass(content, member.Name, true); desc != "" {
			fmt.Printf("Filtering out %s (%s)\n", member.Name, desc)
			r.Close()
			continue
		}

		w, err := zw.Create(member.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "open (write): %s::%s: %v\n", os.Args[2], member.Name, err)
			discardZip(os.Args[2], of, zw)
			os.Exit(1)
		}

		if _, err := io.Copy(w, buf); err != nil {
			fmt.Fprintf(os.Stderr, "write: %s::%s %v\n", os.Args[2], member.Name, err)
			discardZip(os.Args[2], of, zw)
			os.Exit(1)
		}
		r.Close()
	}
	if err := zw.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "finalize: %s: %v", os.Args[2], err)
	}
	of.Close()
	fmt.Printf("\nWriting to %s done\n", os.Args[2])
}

func discardZip(name string, of *os.File, zw *zip.Writer) {
	fmt.Printf("\nRemoving output file %s", os.Args[2])
	zw.Close()
	of.Close()
	os.Remove(name)
}
