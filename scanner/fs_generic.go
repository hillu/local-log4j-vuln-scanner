// +build !linux,!darwin

package main

func isNetworkFS(string) bool { return false }
