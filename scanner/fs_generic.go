// +build !linux,!darwin

package main

func isPseudoFS(string) bool { return false }

func isNetworkFS(string) bool { return false }
