package main

import (
	_ "embed"

	"github.com/mkawserm/abesh/cmd"

	_ "github.com/amjadjibon/triggers/gorilla"

	_ "github.com/mkawserm/abesh/example/echo"
)

//go:embed manifest.yaml
var manifestBytes []byte

func main() {
	cmd.ManifestBytes = manifestBytes
	cmd.Execute()
}
