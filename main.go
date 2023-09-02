package main

import (
	"flag"
	"log"
)

type cmdline struct {
	inFile  string
	outFile string
	caOnly  bool
}

func main() {
	cmdline := cmdline{}

	flag.StringVar(&cmdline.inFile, "in", "in.pem", "input pem file")
	flag.StringVar(&cmdline.outFile, "out", "out.pem", "output pem file")
	flag.BoolVar(&cmdline.caOnly, "ca", false, "ca only")

	flag.Parse()

	if err := perform(&cmdline); err != nil {
		log.Fatal(err)
	}
}
