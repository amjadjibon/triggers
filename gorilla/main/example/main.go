package main

import (
	"embed"
	_ "embed"

	"github.com/mkawserm/abesh/cmd"
	"github.com/spf13/cobra"

	"github.com/amjadjibon/triggers/gorilla/capability/gorilla"
	_ "github.com/amjadjibon/triggers/gorilla/capability/gorilla"

	_ "github.com/mkawserm/abesh/example/echo"
)

//go:embed manifest.yaml
var manifestBytes []byte

//go:embed data
var staticDataFiles embed.FS

var manifestFilePathList []string

var embeddedRunCMD2 = &cobra.Command{
	Use:   "embedded-run2",
	Short: "Run the platform in embedded mode 2",
	Long:  "Run all platform components with the embedded manifest as source manifest",
	Run: func(c *cobra.Command, args []string) {
		p := cmd.EmbeddedPlatformSetup(manifestFilePathList)
		t := p.GetTriggersCapability()["abesh:trigger:gorilla"]
		srv := t.(*gorilla.HttpServerGorilla)
		srv.AddEmbeddedStaticFS("/data/", staticDataFiles)
		p.Run()
	},
}

func main() {
	embeddedRunCMD2.PersistentFlags().StringSliceVar(&manifestFilePathList, "manifest", []string{}, "Manifest file path list (ex: /home/manifest1.yaml,/home/manifest2.yaml)")
	cmd.AddCommand(embeddedRunCMD2)

	cmd.ManifestBytes = manifestBytes
	cmd.Execute()
}
