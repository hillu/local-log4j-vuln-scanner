package main

import (
	"archive/zip"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hillu/local-log4j-vuln-scanner/filter"
)

var logFile = os.Stdout
var errFile = os.Stderr

func handleJar(path string, ra io.ReaderAt, sz int64, wg *sync.WaitGroup) {
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
		case ".jar", ".war", ".ear":
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
			wg.Add(1)
			defer wg.Done()
			go handleJar(path+"::"+file.Name, bytes.NewReader(buf), int64(len(buf)), wg)
		default:
			fr, err := file.Open()
			if err != nil {
				fmt.Fprintf(logFile, "can't open JAR file member for reading: %s (%s): %v\n", path, file.Name, err)
				continue
			}

			// Identify class filess by magic bytes
			buf := bytes.NewBuffer(nil)
			if _, err := io.CopyN(buf, fr, 4); err != nil {
				if err != io.EOF && !quiet {
					fmt.Fprintf(logFile, "can't read magic from JAR file member: %s (%s): %v\n", path, file.Name, err)
				}
				fr.Close()
				continue
			} else if !bytes.Equal(buf.Bytes(), []byte{0xca, 0xfe, 0xba, 0xbe}) {
				fr.Close()
				continue
			}
			_, err = io.Copy(buf, fr)
			fr.Close()
			if err != nil {
				fmt.Fprintf(logFile, "can't read JAR file member: %s (%s): %v\n", path, file.Name, err)
				continue
			}
			if info := filter.IsVulnerableClass(buf.Bytes(), file.Name, vulns); info != nil {
				fmt.Fprintf(logFile, "indicator for vulnerable component found in %s (%s): %s %s %s\n",
					path, file.Name, info.Filename, info.Version, info.Vulnerabilities&vulns)
				continue
			}
		}
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
var vulns filter.Vulnerabilities
var ignoreVulns filter.Vulnerabilities = filter.CVE_2021_45046 | filter.CVE_2021_44832
var ignoreV1 bool
var network bool

func main() {
	flag.Var(&excludes, "exclude", "paths to exclude (can be used multiple times)")
	flag.BoolVar(&verbose, "verbose", false, "log every archive file considered")
	flag.StringVar(&logFileName, "log", "", "log file to write output to")
	flag.BoolVar(&quiet, "quiet", false, "no ouput unless vulnerable")
	flag.BoolVar(&ignoreV1, "ignore-v1", false, "ignore log4j 1.x versions")
	flag.Var(&ignoreVulns, "ignore-vulns", "ignore vulnerabilities")
	flag.BoolVar(&network, "scan-network", false, "search network filesystems")

	flag.Parse()

	if ignoreV1 {
		ignoreVulns |= filter.CVE_2019_17571
	}
	vulns = filter.CheckAllVulnerabilities ^ ignoreVulns

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

	fmt.Fprintf(logFile, "Checking for vulnerabilities: %s\n", vulns)
	var wg sync.WaitGroup
	for _, root := range flag.Args() {
		filepath.Walk(filepath.Clean(root), func(path string, info os.FileInfo, err error) error {
			if isPseudoFS(path) {
				if !quiet {
					fmt.Fprintf(logFile, "Skipping %s: pseudo filesystem\n", path)
				}
				return filepath.SkipDir
			}
			if !network && isNetworkFS(path) {
				if !quiet {
					fmt.Fprintf(logFile, "Skipping %s: network filesystem\n", path)
				}
				return filepath.SkipDir
			}

			if !quiet {
				fmt.Fprintf(logFile, "examining %s\n", path)
			}
			if err != nil {
				fmt.Fprintf(errFile, "%s: %s\n", path, err)
				return nil
			}
			if excludes.Has(path) {
				if !quiet {
					fmt.Fprintf(logFile, "Skipping %s: explicitly excluded\n", path)
				}
				return filepath.SkipDir
			}
			if info.IsDir() {
				return nil
			}
			switch ext := strings.ToLower(filepath.Ext(path)); ext {
			case ".jar", ".war", ".ear":
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
				wg.Add(1)
				defer wg.Done()
				go handleJar(path, f, sz, &wg)
			default:
				return nil
			}
			return nil
		})
	}
	wg.Wait()
	if !quiet {
		fmt.Println("\nScan finished")
	}
}
