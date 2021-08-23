package lib

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/avast/retry-go"
	"github.com/docker/docker/client"
	"github.com/mattn/go-isatty"
)

var Commands = make(map[string]func())

type Manifest struct {
	Config   string
	Layers   []string
	RepoTags []string
}

type DockerfileHistory struct {
	CreatedBy string `json:"created_by"`
}

type DockerfileConfig struct {
	History []DockerfileHistory `json:"history"`
}

func SignalHandler(cancel func()) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		Logger.Println("signal handler")
		cancel()
	}()
}

func functionName(i interface{}) string {
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}

func DropLinesWithAny(s string, tokens ...string) string {
	var lines []string
outer:
	for _, line := range strings.Split(s, "\n") {
		for _, token := range tokens {
			if strings.Contains(line, token) {
				continue outer
			}
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func Pformat(i interface{}) string {
	val, err := json.MarshalIndent(i, "", "    ")
	if err != nil {
		panic(err)
	}
	return string(val)
}

func Retry(ctx context.Context, fn func() error) error {
	count := 0
	attempts := 6
	return retry.Do(
		func() error {
			if count != 0 {
				Logger.Printf("retry %d/%d for %v\n", count, attempts-1, functionName(fn))
			}
			count++
			err := fn()
			if err != nil {
				return err
			}
			return nil
		},
		retry.Context(ctx),
		retry.LastErrorOnly(true),
		retry.Attempts(uint(attempts)),
		retry.Delay(150*time.Millisecond),
	)
}

func Assert(cond bool, format string, a ...interface{}) {
	if !cond {
		panic(fmt.Sprintf(format, a...))
	}
}

func Panic1(err error) {
	if err != nil {
		panic(err)
	}
}

func Panic2(x interface{}, e error) interface{} {
	if e != nil {
		Logger.Fatalf("fatal: %s\n", e)
	}
	return x
}

func Contains(parts []string, part string) bool {
	for _, p := range parts {
		if p == part {
			return true
		}
	}
	return false
}

func Chunk(xs []string, chunkSize int) [][]string {
	var xss [][]string
	xss = append(xss, []string{})
	for _, x := range xs {
		xss[len(xss)-1] = append(xss[len(xss)-1], x)
		if len(xss[len(xss)-1]) == chunkSize {
			xss = append(xss, []string{})
		}
	}
	return xss
}

func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func StringOr(s *string, d string) string {
	if s == nil {
		return d
	}
	return *s
}

func color(code int) func(string) string {
	return func(s string) string {
		if isatty.IsTerminal(os.Stdout.Fd()) {
			return fmt.Sprintf("\033[%dm%s\033[0m", code, s)
		}
		return s
	}
}

var (
	Red     = color(31)
	Green   = color(32)
	Yellow  = color(33)
	Blue    = color(34)
	Magenta = color(35)
	Cyan    = color(36)
	White   = color(37)
)

func FindManifest(manifests []Manifest, name string) (Manifest, error) {
	for _, m := range manifests {
		// find by imageID
		if strings.HasPrefix(m.Config, name) {
			return m, nil
		}
		// find by tag
		if strings.Contains(name, ":") {
			for _, tag := range m.RepoTags {
				if tag == name {
					return m, nil
				}
			}
		} else {
			err := fmt.Errorf("name must include a tag or be an imageID, got: %s", name)
			Logger.Println("error:", err)
			return Manifest{}, err
		}
	}
	err := fmt.Errorf(Pformat(manifests) + "\ntag not found in manifest")
	Logger.Println("error:", err)
	return Manifest{}, err
}

func Scan(ctx context.Context, name string) ([]*ScanFile, map[string]int, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		Logger.Println("error:", err)
		return nil, nil, err
	}

	var manifests []Manifest
	var files []*ScanFile

	r, err := cli.ImageSave(ctx, []string{name})
	if err != nil {
		Logger.Println("error:", err)
		return nil, nil, err
	}
	defer func() { _ = r.Close() }()
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			Logger.Println("error:", err)
			return nil, nil, err
		}
		if header == nil {
			continue
		}
		switch header.Typeflag {
		case tar.TypeReg:
			if path.Base(header.Name) == "layer.tar" {
				layerFiles, err := ScanLayer(header.Name, tr)
				if err != nil {
					Logger.Println("error:", err)
					return nil, nil, err
				}
				files = append(files, layerFiles...)
			} else if header.Name == "manifest.json" {
				var data bytes.Buffer
				_, err := io.Copy(&data, tr)
				if err != nil {
					Logger.Println("error:", err)
					return nil, nil, err
				}
				err = json.Unmarshal(data.Bytes(), &manifests)
				if err != nil {
					Logger.Println("error:", err)
					return nil, nil, err
				}
			}
		}
	}

	manifest, err := FindManifest(manifests, name)
	if err != nil {
		Logger.Println("error:", err)
		return nil, nil, err
	}

	layers := make(map[string]int)
	for i, layer := range manifest.Layers {
		layers[layer] = i
	}

	for _, f := range files {
		i, ok := layers[f.Layer]
		if !ok {
			err := fmt.Errorf("error: no layer %s", f.Layer)
			Logger.Println("error:", err)
			return nil, nil, err
		}
		f.LayerIndex = i
		f.Layer = ""
	}

	sort.Slice(files, func(i, j int) bool { return files[i].LayerIndex < files[j].LayerIndex })
	sort.SliceStable(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	// keep only last update to the file, not all updates across all layers
	var result []*ScanFile
	var last *ScanFile
	for _, f := range files {
		if last != nil && f.Path != last.Path {
			result = append(result, last)
		}
		last = f
	}
	if last.Path != result[len(result)-1].Path {
		result = append(result, last)
	}
	return result, layers, nil
}

type ScanFile struct {
	LayerIndex  int
	Layer       string
	Path        string
	LinkTarget  string
	Mode        fs.FileMode
	Size        int64
	ModTime     time.Time
	Hash        string
	ContentType string
	Uid         int
	Gid         int
}

func ScanLayer(layer string, r io.Reader) ([]*ScanFile, error) {
	var result []*ScanFile
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			Logger.Println("error:", err)
			return nil, err
		}
		if header == nil {
			continue
		}
		switch header.Typeflag {
		case tar.TypeReg:
			var data bytes.Buffer
			_, err := io.Copy(&data, tr)
			if err != nil {
				Logger.Println("error:", err)
				return nil, err
			}
			contentType := "binary"
			if utf8.Valid(data.Bytes()) {
				contentType = "utf8"
			}
			sum := sha1.Sum(data.Bytes())
			hash := hex.EncodeToString(sum[:])
			result = append(result, &ScanFile{
				Layer:       layer,
				Path:        "/" + header.Name,
				Mode:        header.FileInfo().Mode(),
				Size:        header.Size,
				ModTime:     header.ModTime,
				Hash:        hash,
				ContentType: contentType,
				Uid:         header.Uid,
				Gid:         header.Gid,
			})
		case tar.TypeSymlink:
			result = append(result, &ScanFile{
				Layer:      layer,
				Path:       "/" + header.Name,
				Mode:       header.FileInfo().Mode(),
				ModTime:    header.ModTime,
				LinkTarget: header.Linkname,
				Uid:        header.Uid,
				Gid:        header.Gid,
			})
		case tar.TypeDir:
			result = append(result, &ScanFile{
				Layer:   layer,
				Path:    "/" + header.Name,
				Mode:    header.FileInfo().Mode(),
				ModTime: header.ModTime,
				Uid:     header.Uid,
				Gid:     header.Gid,
			})
		}
	}
	return result, nil
}

func Dockerfile(ctx context.Context, name string) ([]string, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		Logger.Println("error:", err)
		return nil, err
	}

	var manifests []Manifest
	configs := make(map[string]*DockerfileConfig)

	r, err := cli.ImageSave(ctx, []string{name})
	if err != nil {
		Logger.Println("error:", err)
		return nil, err
	}
	defer func() { _ = r.Close() }()
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			Logger.Println("error:", err)
			return nil, err
		}
		if header == nil {
			continue
		}
		switch header.Typeflag {
		case tar.TypeReg:
			if header.Name == "manifest.json" {
				var data bytes.Buffer
				_, err := io.Copy(&data, tr)
				if err != nil {
					Logger.Println("error:", err)
					return nil, err
				}
				err = json.Unmarshal(data.Bytes(), &manifests)
				if err != nil {
					Logger.Println("error:", err)
					return nil, err
				}
			} else if strings.HasSuffix(header.Name, ".json") {
				var data bytes.Buffer
				_, err := io.Copy(&data, tr)
				if err != nil {
					Logger.Println("error:", err)
					return nil, err
				}
				config := DockerfileConfig{}
				err = json.Unmarshal(data.Bytes(), &config)
				if err != nil {
					Logger.Println("error:", err)
					return nil, err
				}
				configs[header.Name] = &config
			}

		}
	}

	manifest, err := FindManifest(manifests, name)
	if err != nil {
		Logger.Println("error:", err)
		return nil, err
	}

	config, ok := configs[manifest.Config]
	if !ok {
		err := fmt.Errorf("no such config: %s", manifest.Config)
		Logger.Println("error:", err)
		return nil, err
	}

	var result []string

	for _, h := range config.History {
		if strings.Contains(h.CreatedBy, " #(nop) ") {
			line := h.CreatedBy
			line = strings.Split(line, " #(nop) ")[1]
			line = strings.TrimLeft(line, " ")
			line = strings.ReplaceAll(line, `" `, `", `)
			if !strings.HasPrefix(line, "ADD ") && !strings.HasPrefix(line, "COPY ") && !strings.HasPrefix(line, "LABEL ") && line != `CMD ["bash"]` {
				result = append(result, line)
			}
		}
	}
	return result, nil
}
