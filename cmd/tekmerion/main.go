// Command tekmerion is the Tekmerion CLI.
//
//	tekmerion prepare -project P -checkout DIR -work DIR [-ariadne BIN] [-allow-network] [-sources auto|always|never]
//	tekmerion locate  -work DIR CLASS NAME DESCRIPTOR
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/tswierszcz/tekmerion/internal/manifest"
	"github.com/tswierszcz/tekmerion/internal/prepare"
	"github.com/tswierszcz/tekmerion/internal/sourceindex"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var err error
	switch os.Args[1] {
	case "prepare":
		err = cmdPrepare(ctx, os.Args[2:])
	case "locate":
		err = cmdLocate(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "tekmerion:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  tekmerion prepare -project FILE -checkout DIR -work DIR [-ariadne BIN] [-allow-network] [-sources auto|always|never]
  tekmerion locate  -work DIR CLASS NAME DESCRIPTOR`)
	os.Exit(2)
}

func cmdPrepare(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("prepare", flag.ExitOnError)
	project := fs.String("project", "", "project manifest (tekmerion-project-1)")
	checkout := fs.String("checkout", "", "existing git checkout containing the target revision")
	work := fs.String("work", "", "work directory to create; must not exist")
	bin := fs.String("ariadne", "", "ariadne binary; omit to skip research index")
	allowNet := fs.Bool("allow-network", false, "allow a recipe that declares network \"allowed\"")
	sources := fs.String("sources", "auto", "pass -sources to research index: auto, always or never")
	_ = fs.Parse(args)
	if *project == "" || *checkout == "" || *work == "" || fs.NArg() > 0 {
		fs.Usage()
		os.Exit(2)
	}
	p, raw, err := manifest.LoadProject(*project)
	if err != nil {
		return err
	}
	res, err := prepare.Prepare(ctx, prepare.Options{Project: p, ProjectRaw: raw, Checkout: *checkout, Work: *work,
		AllowNetwork: *allowNet, Ariadne: *bin, Sources: *sources, Stderr: os.Stderr})
	if err != nil {
		return err
	}
	r := res.Run
	fmt.Printf("commit      %s\nsource      %s (%d files)\napp         %s %s\nclasspath   %s (%d jars)\nsource map  %d of %d methods located\n",
		r.Source.Commit, r.Source.TreeSHA256, r.Source.Files, r.Artifacts.App.SHA256, r.Artifacts.App.Path,
		r.Artifacts.ClasspathSHA256, len(r.Artifacts.Classpath), r.SourceIndex.Located, r.SourceIndex.Methods)
	if r.Analysis != nil {
		fmt.Printf("analysis    %s\n", r.Analysis.AnalysisID)
	}
	fmt.Printf("manifest    %s\n", filepath.Join(res.Work, "run-manifest.json"))
	return nil
}

func cmdLocate(args []string) error {
	fs := flag.NewFlagSet("locate", flag.ExitOnError)
	work := fs.String("work", "", "prepared work directory")
	_ = fs.Parse(args)
	if *work == "" || fs.NArg() != 3 {
		fs.Usage()
		os.Exit(2)
	}
	ix, err := sourceindex.Load(filepath.Join(*work, "source-index.json"))
	if err != nil {
		return err
	}
	loc := ix.Resolve(sourceindex.Method{Class: fs.Arg(0), Name: fs.Arg(1), Descriptor: fs.Arg(2)}, nil)
	b, _ := json.MarshalIndent(loc, "", "  ")
	fmt.Println(string(b))
	return nil
}
