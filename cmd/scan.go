package dockertrace

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/alexflint/go-arg"
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
	files, _, err := lib.Scan(ctx, args.Name)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	for _, file := range files {
		fmt.Println(file.Path, file.LayerIndex, file.Size, fs.FileMode(file.Mode).String(), file.Hash)
	}
}
