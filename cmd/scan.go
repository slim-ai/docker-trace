package dockertrace

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/alexflint/go-arg"
	"github.com/moby/moby/client"
	"github.com/nathants/docker-trace/lib"
)

func init() {
	lib.Commands["scan"] = scan
}

type scanArgs struct {
	Name string `arg:"positional,required"`
}

func (scanArgs) Description() string {
	return "\nscan a container and dump metadata and utf8 content\n"
}

func scan() {
	var args scanArgs
	arg.MustParse(&args)
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}

	var manifest []scanManifest
	var files []*scanFile

	r, err := cli.ImageSave(ctx, []string{args.Name})
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	defer func() { _ = r.Close() }()
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		if header == nil {
			continue
		}
		switch header.Typeflag {
		case tar.TypeReg:
			if path.Base(header.Name) == "layer.tar" {
				files = append(files, scanLayer(header.Name, tr)...)
			} else if header.Name == "manifest.json" {
				var data bytes.Buffer
				_, err := io.Copy(&data, tr)
				if err != nil {
					lib.Logger.Fatal("error: ", err)
				}
				err = json.Unmarshal(data.Bytes(), &manifest)
				if err != nil {
					lib.Logger.Fatal("error:", err)
				}
			}
		}
	}

	if len(manifest) != 1 {
		lib.Logger.Fatal("error: bad manifest size ", len(manifest))
	}

	layers := make(map[string]int)
	for i, layer := range manifest[0].Layers {
		layers[layer] = i
	}

	for _, f := range files {
		i, ok := layers[f.Layer]
		if !ok {
			lib.Logger.Fatal("error: no layer", f.Layer)
		}
		f.LayerIndex = i
		f.Layer = ""
	}

	sort.Slice(files, func(i, j int) bool { return files[i].LayerIndex < files[j].LayerIndex })
	sort.SliceStable(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	for _, f := range files {
		fmt.Println(f.LayerIndex, f.Path)
	}

}

type scanFile struct {
	LayerIndex  int
	Layer       string
	Path        string
	LinkTarget  string
	Change      string
	Mode        int64
	Size        int64
	ModTime     time.Time
	Hash        string
	ContentType string
	Uid         int
	Gid         int
}

func scanLayer(layer string, r io.Reader) []*scanFile {
	var result []*scanFile
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
		if header == nil {
			continue
		}
		switch header.Typeflag {
		case tar.TypeReg:
			var data bytes.Buffer
			_, err := io.Copy(&data, tr)
			if err != nil {
				lib.Logger.Fatal("error: ", err)
			}
			contentType := "binary"
			if utf8.Valid(data.Bytes()) {
				contentType = "utf8"
			}
			sum := sha1.Sum(data.Bytes())
			hash := hex.EncodeToString(sum[:])
			result = append(result, &scanFile{
				Layer:       layer,
				Path:        "/" + header.Name,
				Mode:        header.Mode,
				Size:        header.Size,
				ModTime:     header.ModTime,
				Hash:        hash,
				ContentType: contentType,
				Uid:         header.Uid,
				Gid:         header.Gid,
			})
		case tar.TypeSymlink:
			result = append(result, &scanFile{
				Layer:      layer,
				Path:       "/" + header.Name,
				Mode:       header.Mode,
				ModTime:    header.ModTime,
				LinkTarget: header.Linkname,
				Uid:        header.Uid,
				Gid:        header.Gid,
			})
		case tar.TypeDir:
			result = append(result, &scanFile{
				Layer:   layer,
				Path:    "/" + header.Name,
				Mode:    header.Mode,
				ModTime: header.ModTime,
				Uid:     header.Uid,
				Gid:     header.Gid,
			})
		}
	}
	return result
}

type scanManifest struct {
	Layers []string `json:"layers"`
}
