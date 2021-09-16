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
	lib.Args["unpack"] = unpackArgs{}
}

type unpackArgs struct {
	Name     string `arg:"positional,required"`
	NoRename bool   `arg:"-r,--no-rename" default:"false"`
	NoUntar  bool   `arg:"-u,--no-untar" default:"false"`
}

func (unpackArgs) Description() string {
	return "\nunpack a container into directories and files\n"
}

func unpack() {
	var args unpackArgs
	arg.MustParse(&args)

	shell := fmt.Sprintf("set -eou pipefail; docker save %s | tar xf -", args.Name)
	cmd := exec.Command("bash", "-c", shell)
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		lib.Logger.Fatal("error:", shell, err)
	}

	bytes, err := ioutil.ReadFile("manifest.json")
	if err != nil {
		lib.Logger.Fatal("error:", err)
	}

	var manifests []lib.Manifest

	err = json.Unmarshal(bytes, &manifests)
	if err != nil {
		lib.Logger.Fatal("error:", err)
	}

	manifest, err := lib.FindManifest(manifests, args.Name)
	if err != nil {
	    lib.Logger.Fatal("error: ", err)
	}

	layerNames := make(map[string]string)
	for i, layerID := range manifest.Layers {
		layerID = path.Dir(layerID)
		layerNames[layerID] = fmt.Sprintf("layer%02d", i)
	}

	if !args.NoRename {
		for _, layerTar := range manifest.Layers {
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
		for _, layerTar := range manifest.Layers {
			err := untarLayer(args.NoRename, layerTar, layerNames)
			if err != nil {
				lib.Logger.Fatal("error:", err)
			}
		}
	}

	if !args.NoUntar {
		for _, layerTar := range manifest.Layers {
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
