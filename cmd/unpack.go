package dockertrace

import (
	"fmt"
	"github.com/alexflint/go-arg"
	"github.com/nathants/docker-trace/lib"
)

func init() {
	lib.Commands["unpack"] = unpack
}

type unpackArgs struct {
	Name string `arg:"positional"`
}

func (unpackArgs) Description() string {
	return "\ntrace things in a container\n"
}

func unpack() {
	var args unpackArgs
	arg.MustParse(&args)
	fmt.Println(args.Name)
}
