# Simple local log4j vulnerability scanner

(Written in Go because, you know, "write once, run anywhere.")

This is a simple tool that can be used to find vulnerable instances of
log4j 1.x and 2.x (CVE-2019-17571, CVE-2021-44228) in installations of
Java software such as web applications. JAR and WAR archives are
inspected and class files that are known to be vulnerable are flagged.
The scan happens recursively: WAR files containing WAR files
containing JAR files containing vulnerable class files ought to be
flagged properly.

This tool currently checks for known build artifacts that have been
obtained through Maven. From-source rebuilds as they are done for
Linux distributions may not be recognized.

# Usage

``` console
$ ./log4j-vuln-scanner /path/to/app1 /path/to/app2 …
```

# License

GNU General Public License, version 3

# Author

Hilko Bengen <<bengen@hilluzination.de>>
