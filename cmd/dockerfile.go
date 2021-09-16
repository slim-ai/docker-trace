package dockertrace

import (
	"context"
	"fmt"
	"strings"

	"github.com/alexflint/go-arg"
	"github.com/nathants/docker-trace/lib"
)

func init() {
	lib.Commands["dockerfile"] = dockerfile
	lib.Args["dockerfile"] = dockerfileArgs{}
}

type dockerfileArgs struct {
	Name string `arg:"positional,required"`
}

func (dockerfileArgs) Description() string {
	return "\nscan a container and print the dockerfile\n"
}

func dockerfile() {
	var args dockerfileArgs
	arg.MustParse(&args)
	ctx := context.Background()
	lines, err := lib.Dockerfile(ctx, args.Name)
	if err != nil {
		lib.Logger.Fatal("error: ", err)
	}
	fmt.Println(strings.Join(lines, "\n"))
}
