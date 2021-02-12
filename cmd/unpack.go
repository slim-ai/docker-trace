package dockertrace

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path"

	"github.com/alexflint/go-arg"
	"github.com/nathants/docker-trace/lib"
)

func init() {
	lib.Commands["unpack"] = unpack
}

type unpackArgs struct {
	Name     string `arg:"positional,required"`
	NoRename bool   `arg:"-r,--no-rename" default:"false"`
	NoUntar  bool   `arg:"-u,--no-untar" default:"false"`
}

func (unpackArgs) Description() string {
	return "\ntrace things in a container\n"
}

func unpack() {
	var args unpackArgs
	arg.MustParse(&args)

	shell := fmt.Sprintf("set -eou pipefail; docker save %s | tar xf -", args.Name)
	cmd := exec.Command("bash", "-c", shell)
	err := cmd.Run()
	if err != nil {
		lib.Logger.Fatal("error:", shell, err)
	}

	bytes, err := ioutil.ReadFile("manifest.json")
	if err != nil {
		lib.Logger.Fatal("error:", err)
	}

	var manifest []Manifest
	err = json.Unmarshal(bytes, &manifest)
	if err != nil {
		lib.Logger.Fatal("error:", err)
	}

	if len(manifest) != 1 {
		lib.Logger.Fatal("error: bad manifest size ", len(manifest))
	}

	layerNames := make(map[string]string)
	for i, layerID := range manifest[0].Layers {
		layerID = path.Dir(layerID)
		layerNames[layerID] = fmt.Sprintf("layer%02d", i)
	}

	if !args.NoRename {
		for _, layerTar := range manifest[0].Layers {
			err := renameSymlink(layerTar, layerNames)
			if err != nil {
				lib.Logger.Fatal("error:", err)
			}
			err = renameDirectory(layerTar, layerNames)
			if err != nil {
				lib.Logger.Fatal("error:", err)
			}
		}
	}

	if !args.NoUntar {
		for _, layerTar := range manifest[0].Layers {
			err := untarLayer(args.NoRename, layerTar, layerNames)
			if err != nil {
				lib.Logger.Fatal("error:", err)
			}
		}
	}

	if !args.NoUntar {
		for _, layerTar := range manifest[0].Layers {
			err := deleteLayerExtras(args.NoRename, layerTar, layerNames)
			if err != nil {
			    lib.Logger.Fatal("error:", err)
			}
		}
	}

}

func deleteLayerExtras(noRename bool, layerTar string, layerNames map[string]string) error {
	layerID := path.Base(path.Dir(layerTar))
	if !noRename {
		var ok bool
		layerID, ok = layerNames[layerID]
		if !ok {
			return fmt.Errorf("error: %s %v", layerID, layerNames)
		}
	}
	for _, name := range []string{"json", "VERSION", "layer.tar"} {
		err := os.Remove(path.Join(layerID, name))
		if err != nil {
			return err
		}
	}
	return nil
}

func untarLayer(noRename bool, layerTar string, layerNames map[string]string) error {
	layerID := path.Base(path.Dir(layerTar))
	if !noRename {
		var ok bool
		layerID, ok = layerNames[layerID]
		if !ok {
			return fmt.Errorf("error: %s %v", layerID, layerNames)
		}
	}
	cmd := exec.Command("tar", "xf", "layer.tar")
	cmd.Dir = layerID
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("%w %s", err, layerID)
	}
	return nil
}

func renameSymlink(layerTar string, layerNames map[string]string) error {
	link, err := os.Readlink(layerTar)
	if err == nil {
		err := os.Remove(layerTar)
		if err != nil {
			return err
		}
		layerID := path.Base(path.Dir(link))
		layerName, ok := layerNames[layerID]
		if !ok {
			lib.Logger.Fatal("error:", layerID, layerNames)
		}
		err = os.Symlink(
			path.Join("..", layerName, "layer.tar"),
			path.Join(layerTar),
		)
		if err != nil {
			return err
		}
	}
	return nil
}

func renameDirectory(layerTar string, layerNames map[string]string) error {
	layerID := path.Base(path.Dir(layerTar))
	layerName, ok := layerNames[layerID]
	if !ok {
		return fmt.Errorf("error: %s %v", layerID, layerNames)
	}
	err := os.Rename(layerID, layerName)
	if err != nil {
		return err
	}
	return nil
}

type Manifest struct {
	Layers []string `json:"layers"`
}

type RootFS struct {
	DiffIDs []string `json:"diff_ids"`
}

type Config struct {
	RootFS RootFS `json:"rootfs"`
}
