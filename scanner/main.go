package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/hillu/local-log4j-vuln-scanner/filter"
)

var logFile = os.Stdout
var errFile = os.Stderr

func handleTar(path string, ra io.Reader, sz int64) {
	if verbose {
		fmt.Fprintf(logFile, "Inspecting %s...\n", path)
	}
	gzf, err := gzip.NewReader(ra)
	if err != nil {
		fmt.Println(err)
		return
	}

	tr := tar.NewReader(gzf)
	for true {
		file, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(logFile, "can't open archive file: %s (size %d): %v\n", path, sz, err)
			return
		}
		if file.Typeflag == tar.TypeDir {
			continue
		}
		switch strings.ToLower(filepath.Ext(file.Name)) {
		case ".jar", ".war", ".ear", ".zip":
			buf, err := ioutil.ReadAll(tr)
			if err != nil {
				fmt.Fprintf(logFile, "can't open TAR file member for reading: %s (%s): %v\n", path, file.Name, err)
				continue
			}
			handleJar(path+"::"+file.Name, bytes.NewReader(buf), int64(len(buf)))
		default:
			buf, err := ioutil.ReadAll(tr)
			if err != nil {
				fmt.Fprintf(logFile, "can't open TAR file member for reading: %s (%s): %v\n", path, file.Name, err)
				continue
			}
			identifyClassFile(ioutil.NopCloser(bytes.NewReader(buf)), path, file.Name)
		}
	}
}

func handleJar(path string, ra io.ReaderAt, sz int64) {
	if verbose {
		fmt.Fprintf(logFile, "Inspecting %s...\n", path)
	}
	zr, err := zip.NewReader(ra, sz)
	if err != nil {
		fmt.Fprintf(logFile, "cant't open JAR file: %s (size %d): %v\n", path, sz, err)
		return
	}
	for _, file := range zr.File {
		if file.FileInfo().IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(file.Name)) {
		case ".jar", ".war", ".ear", ".zip":
			fr, err := file.Open()
			if err != nil {
				fmt.Fprintf(logFile, "can't open JAR file member for reading: %s (%s): %v\n", path, file.Name, err)
				continue
			}
			buf, err := ioutil.ReadAll(fr)
			fr.Close()
			if err != nil {
				fmt.Fprintf(logFile, "can't read JAR file member: %s (%s): %v\n", path, file.Name, err)
			}
			handleJar(path+"::"+file.Name, bytes.NewReader(buf), int64(len(buf)))
		default:
			fr, err := file.Open()
			if err != nil {
				fmt.Fprintf(logFile, "can't open JAR file member for reading: %s (%s): %v\n", path, file.Name, err)
				continue
			}
			identifyClassFile(fr, path, file.Name)
		}
	}
}

func identifyClassFile(fr io.ReadCloser, path string, name string) {
	// Identify class files by magic bytes
	buf := bytes.NewBuffer(nil)
	if _, err := io.CopyN(buf, fr, 4); err != nil {
		if err != io.EOF && !quiet {
			fmt.Fprintf(logFile, "can't read magic from JAR file member: %s (%s): %v\n", path, name, err)
		}
		fr.Close()
		return
	} else if !bytes.Equal(buf.Bytes(), []byte{0xca, 0xfe, 0xba, 0xbe}) {
		fr.Close()
		return
	}
	_, err := io.Copy(buf, fr)
	fr.Close()
	if err != nil {
		if !quiet {
			fmt.Fprintf(logFile, "can't read JAR file member: %s (%s): %v\n", path, name, err)
		}
		return
	}
	if desc := filter.IsVulnerableClass(buf.Bytes(), name, !ignoreV1); desc != "" {
		fmt.Fprintf(logFile, "indicator for vulnerable component found in %s (%s): %s\n", path, name, desc)
	}
}

type excludeFlags []string

func (flags *excludeFlags) String() string {
	return fmt.Sprint(*flags)
}

func (flags *excludeFlags) Set(value string) error {
	*flags = append(*flags, filepath.Clean(value))
	return nil
}

func (flags excludeFlags) Has(path string) bool {
	for _, exclude := range flags {
		if path == exclude {
			return true
		}
	}
	return false
}

var excludes excludeFlags
var verbose bool
var logFileName string
var quiet bool
var ignoreV1 bool

func main() {
	flag.Var(&excludes, "exclude", "paths to exclude (can be used multiple times)")
	flag.BoolVar(&verbose, "verbose", false, "log every archive file considered")
	flag.StringVar(&logFileName, "log", "", "log file to write output to")
	flag.BoolVar(&quiet, "quiet", false, "no ouput unless vulnerable")
	flag.BoolVar(&ignoreV1, "ignore-v1", false, "ignore log4j 1.x versions")
	flag.Parse()

	if !quiet {
		fmt.Printf("%s - a simple local log4j vulnerability scanner\n\n", filepath.Base(os.Args[0]))
	}

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [--verbose] [--quiet] [--ignore-v1] [--exclude <path>] [--log <file>] [ paths ... ]\n", os.Args[0])
		os.Exit(1)
	}

	if logFileName != "" {
		f, err := os.Create(logFileName)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Could not create log file")
			os.Exit(2)
		}
		logFile = f
		errFile = f
		defer f.Close()
	}

	for _, root := range flag.Args() {
		filepath.Walk(filepath.Clean(root), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				fmt.Fprintf(errFile, "%s: %s\n", path, err)
				return nil
			}
			if excludes.Has(path) {
				return filepath.SkipDir
			}
			if info.IsDir() {
				return nil
			}
			switch ext := strings.ToLower(filepath.Ext(path)); ext {
			case ".jar", ".war", ".ear", ".zip", ".gz", ".tgz":
				f, err := os.Open(path)
				if err != nil {
					fmt.Fprintf(errFile, "can't open %s: %v\n", path, err)
					return nil
				}
				defer f.Close()
				sz, err := f.Seek(0, os.SEEK_END)
				if err != nil {
					fmt.Fprintf(errFile, "can't seek in %s: %v\n", path, err)
					return nil
				}
				if _, err := f.Seek(0, os.SEEK_END); err != nil {
					fmt.Fprintf(errFile, "can't seek in %s: %v\n", path, err)
					return nil
				}
				switch ext {
				case ".gz", ".tgz":
					ff, _ := os.Open(path)
					defer ff.Close()
					handleTar(path, ff, sz)
				default:
					handleJar(path, f, sz)
				}
			default:
				return nil
			}
			return nil
		})
	}

	if !quiet {
		fmt.Println("\nScan finished")
	}
}
