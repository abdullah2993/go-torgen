package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/abdullah2993/torgen"
)

const (
	v3PrivateFile = "hs_ed25519_secret_key"
	v3PublicFile  = "hs_ed25519_public_key"
	hostname      = "hostname"
	v2PrivateFile = "private_key"
)

func main() {
	var v3, override bool
	flag.BoolVar(&v3, "v3", false, "Generate V3")
	flag.BoolVar(&override, "override", false, "Overrite existing file")
	flag.Parse()

	if v3 {
		key, err := torgen.GenerateV3()
		if err != nil {
			printErr("Unable to generate key: %v", err)
		}

		tryWriteFile(hostname, []byte(key.Hostname), override)
		tryWriteFile(v3PrivateFile, []byte(key.PrivateKey), override)
		tryWriteFile(v3PublicFile, []byte(key.PublicKey), override)

	} else {
		key, err := torgen.Generate()
		if err != nil {
			printErr("Unable to generate key: %v", err)
		}
		tryWriteFile(hostname, []byte(key.Hostname), override)
		tryWriteFile(v2PrivateFile, []byte(key.PrivateKey), override)
	}
}

func tryWriteFile(name string, data []byte, override bool) {
	_, err := os.Stat(name)
	if (err == nil && override) || os.IsNotExist(err) {
		ioutil.WriteFile(name, data, 0666)
	} else if err != nil {
		printErr("Unable to write file[%s]: %v", name, err)
	} else {
		printErr("File alreay exists: %s", name)
	}
}

func printErr(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg, args...)
	os.Exit(1)
}
