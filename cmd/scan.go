package dockertrace

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/nathants/docker-trace/lib"
)

func init() {
	lib.Commands["scan"] = scan
	lib.Args["scan"] = scanArgs{}
}

type scanArgs struct {
	Name      string `arg:"positional,required"`
}

func (scanArgs) Description() string {
	return "\nscan a container and list filesystem contents\n"
}

func valueOrDash(x interface{}) string {
	y := fmt.Sprint(x)
	if y == "" {
		return "-"
	}
	return y
}

func scan() {
	var args scanArgs
	arg.MustParse(&args)
	ctx := context.Background()
	files, _, err := lib.Scan(ctx, args.Name, "", true)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	header := []string{
		"path",
		"layer",
		"size",
		"mode",
		"link-target",
		"sha256",
		"content-type",
	}
	fmt.Fprintln(os.Stderr, strings.Join(header, "\t"))
	for _, file := range files {
		vals := []string{
			valueOrDash(file.Path),
			valueOrDash(file.LayerIndex),
			valueOrDash(file.Size),
			valueOrDash(fs.FileMode(file.Mode).String()),
			valueOrDash(file.LinkTarget),
			valueOrDash(file.Hash),
			valueOrDash(file.ContentType),
		}
		fmt.Println(strings.Join(vals, "\t"))
	}
}
