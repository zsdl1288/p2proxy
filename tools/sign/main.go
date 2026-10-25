// Command sign manages the key that signs p2proxy releases.
//
//	go run ./tools/sign genkey
//	    prints a new private key (keep it secret: GitHub secret UPDATE_SIGNING_KEY)
//	    and its public key (GitHub variable UPDATE_PUBLIC_KEY)
//	go run ./tools/sign -tag v1.2.0 dist/checksums.txt
//	    signs the checksums for that tag with $UPDATE_SIGNING_KEY,
//	    writing dist/checksums.txt.sig
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	log.SetFlags(0)
	tag := flag.String("tag", "", "release tag being signed")
	flag.Parse()

	if flag.Arg(0) == "genkey" {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("private (secret UPDATE_SIGNING_KEY):", base64.StdEncoding.EncodeToString(priv.Seed()))
		fmt.Println("public  (variable UPDATE_PUBLIC_KEY):", base64.StdEncoding.EncodeToString(pub))
		return
	}
	if flag.NArg() != 1 || *tag == "" {
		log.Fatal("usage: sign genkey | sign -tag TAG FILE")
	}
	seed, err := base64.StdEncoding.DecodeString(os.Getenv("UPDATE_SIGNING_KEY"))
	if err != nil || len(seed) != ed25519.SeedSize {
		log.Fatal("UPDATE_SIGNING_KEY is missing or malformed")
	}
	sums, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}
	// Must match signedMessage in update.go.
	msg := append([]byte("p2proxy release "+*tag+"\n"), sums...)
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), msg)
	if err := os.WriteFile(flag.Arg(0)+".sig", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644); err != nil {
		log.Fatal(err)
	}
}
