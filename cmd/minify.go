package dockertrace

import (
	"archive/tar"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/nathants/docker-trace/lib"
	"github.com/satori/go.uuid"
)

func init() {
	lib.Commands["minify"] = minify
	lib.Args["minify"] = minifyArgs{}
}

type minifyArgs struct {
	ContainerIn  string `arg:"positional,required"`
	ContainerOut string `arg:"positional,required"`
}

func (minifyArgs) Description() string {
	return "\nminify a container keeping files passed on stdin\n"
}

func minify() {
	var args minifyArgs
	arg.MustParse(&args)
	ctx := context.Background()
	uid := uuid.NewV4().String()
	//
	files, layers, err := lib.Scan(ctx, args.ContainerIn)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	//
	includePaths := make(map[string]interface{})
	bytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	for _, path := range strings.Split(string(bytes), "\n") {
		path = strings.Trim(path, " ")
		path = strings.ReplaceAll(path, "//", "/")
		if path != "" {
			includePaths[path] = nil
		}
	}
	//
	includeFiles := make(map[string]*lib.ScanFile)
	var last *lib.ScanFile
	links := make(map[string]string)
	for _, f := range files {
		if f.LinkTarget != "" {
			links[f.Path] = f.LinkTarget
		}
	}
	//
	// recursively resolve all symlinks
	for p := range includePaths {
		last := ""
		for {
			if last == p {
				break // break when no further change
			}
			last = p
			parts := strings.Split(strings.TrimLeft(p, "/"), "/")
			for i := 0; i <= len(parts); i++ {
				subPath := "/" + path.Join(parts[:i]...)
				link, ok := links[subPath]
				if ok {
					if link[:1] != "/" {
						link = path.Join(path.Dir(subPath), link)
					}
					includePaths[subPath] = nil
					includePaths[link] = nil
					for j := range parts[:i] {
						parts[j] = ""
					}
					parts[0] = link
				}
			}
			p2 := path.Join(parts...)
			includePaths[p2] = nil
			p = p2
		}
	}
	//
	for _, f := range files {
		_, ok := includePaths[strings.TrimRight(f.Path, "/")]
		if !ok {
			atRoot := len(strings.Split(f.Path, "/")) == 2 && f.LinkTarget != "" // always include root level symlinks
			ldHackArch := strings.HasPrefix(f.Path, "/usr/lib/ld-") // why is bpftrace missing this access? repro: sh -c whoami
			ldHackAlpine := strings.HasPrefix(f.Path, "/lib/ld-") // why is bpftrace missing this access? repro: sh -c whoami
			if !(atRoot || ldHackArch || ldHackAlpine) {
				continue
			}
			includePaths[f.Path] = nil
		}
		if last != nil && f.Path != last.Path {
			includeFiles[last.Path] = last
		}
		last = f
	}
	includeFiles[last.Path] = last
	//
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	//
	r, err := cli.ImageSave(ctx, []string{args.ContainerIn})
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	tr := tar.NewReader(r)
	w, err := os.OpenFile("/tmp/image.tar."+uid, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	tw := tar.NewWriter(w)
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
				minifyLayer(header.Name, tr, tw, layers, includeFiles)
			}
		}
	}
	err = tw.Close()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	err = w.Close()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	//
	f, err := os.OpenFile("/tmp/Dockerfile."+uid, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	lines, err := lib.Dockerfile(ctx, args.ContainerIn)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	_, err = f.WriteString("FROM scratch\n")
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	_, err = f.WriteString(fmt.Sprintf("ADD /tmp/image.tar.%s /\n", uid))
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	for _, line := range lines {
		_, err := f.WriteString(line + "\n")
		if err != nil {
			lib.Logger.Fatal("error: ", err)
		}
	}
	err = f.Close()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	//
	w, err = os.OpenFile("/tmp/context.tar."+uid, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	tw = tar.NewWriter(w)
	//
	fi, err := os.Stat("/tmp/image.tar." + uid)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	header, err := tar.FileInfoHeader(fi, "")
	header.Name = "/tmp/image.tar." + uid
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	err = tw.WriteHeader(header)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	err = r.Close()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	r, err = os.Open("/tmp/image.tar." + uid)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	_, err = io.Copy(tw, r)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	//
	fi, err = os.Stat("/tmp/Dockerfile." + uid)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	header, err = tar.FileInfoHeader(fi, "")
	header.Name = "/tmp/Dockerfile." + uid
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	err = tw.WriteHeader(header)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	err = r.Close()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	r, err = os.Open("/tmp/Dockerfile." + uid)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	_, err = io.Copy(tw, r)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	//
	err = tw.Close()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	err = w.Close()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	//
	err = r.Close()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	r, err = os.Open("/tmp/context.tar." + uid)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	//
	out, err := cli.ImageBuild(ctx, r, types.ImageBuildOptions{
		NoCache:    true,
		Tags:       []string{args.ContainerOut},
		Dockerfile: "/tmp/Dockerfile." + uid,
		Remove:     true,
	})
	defer func() { _ = out.Body.Close() }()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	//
	scanner := bufio.NewScanner(out.Body)
	val := make(map[string]string)
	for scanner.Scan() {
		err := json.Unmarshal(scanner.Bytes(), &val)
		if err == nil {
			lib.Logger.Println(strings.Trim(val["stream"], "\n"))
		}
	}
	err = scanner.Err()
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	if val["stream"] != "Successfully tagged "+args.ContainerOut+"\n" {
		lib.Logger.Fatal("error: failed to build " + args.ContainerOut)
	}
	//
	err = os.Remove("/tmp/image.tar." + uid)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	err = os.Remove("/tmp/context.tar." + uid)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	err = os.Remove("/tmp/Dockerfile." + uid)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
}

func minifyLayer(layer string, r io.Reader, tw *tar.Writer, layers map[string]int, includeFiles map[string]*lib.ScanFile) {
	layerIndex, ok := layers[layer]
	if !ok {
		panic(layer)
	}
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
		includeFile, ok := includeFiles["/"+header.Name]
		if !ok {
			continue
		}
		if includeFile.LayerIndex != layerIndex {
			continue
		}
		switch header.Typeflag {
		case tar.TypeReg:
			err := tw.WriteHeader(header)
			if err != nil {
				lib.Logger.Fatal("error: ", err)
			}
			_, err = io.Copy(tw, tr)
			if err != nil {
				lib.Logger.Fatal("error: ", err)
			}
		case tar.TypeSymlink:
			err := tw.WriteHeader(header)
			if err != nil {
				lib.Logger.Fatal("error: ", err)
			}
			_, err = io.Copy(tw, tr)
			if err != nil {
				lib.Logger.Fatal("error: ", err)
			}
		case tar.TypeDir:
			err := tw.WriteHeader(header)
			if err != nil {
				lib.Logger.Fatal("error: ", err)
			}
			_, err = io.Copy(tw, tr)
			if err != nil {
				lib.Logger.Fatal("error: ", err)
			}
		default:
		}
	}
}
