// Command tekmerion is the Tekmerion CLI.
//
//	tekmerion prepare -project P -checkout DIR -work DIR [-ariadne BIN] [-allow-network] [-sources auto|always|never]
//	tekmerion locate  -work DIR CLASS NAME DESCRIPTOR
//	tekmerion audit   -fixture -state NEW_DIR [-contract DIR] [-budget FILE]
//	tekmerion resume  -state DIR
//	tekmerion status  -state DIR
//	tekmerion report  -state DIR [-format markdown|json]
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/tswierszcz/tekmerion/internal/ariadne"
	"github.com/tswierszcz/tekmerion/internal/audit"
	"github.com/tswierszcz/tekmerion/internal/experiment"
	"github.com/tswierszcz/tekmerion/internal/gateway"
	"github.com/tswierszcz/tekmerion/internal/hunt"
	"github.com/tswierszcz/tekmerion/internal/jsonx"
	"github.com/tswierszcz/tekmerion/internal/llm"
	"github.com/tswierszcz/tekmerion/internal/manifest"
	"github.com/tswierszcz/tekmerion/internal/openrouter"
	"github.com/tswierszcz/tekmerion/internal/prepare"
	"github.com/tswierszcz/tekmerion/internal/pricing"
	"github.com/tswierszcz/tekmerion/internal/recon"
	"github.com/tswierszcz/tekmerion/internal/sourceindex"
	"github.com/tswierszcz/tekmerion/internal/state"
	"github.com/tswierszcz/tekmerion/internal/validate"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var err error
	switch os.Args[1] {
	case "audit", "resume", "status", "report":
		err = cmdAudit(ctx, os.Args[1], os.Args[2:])
	case "hunt":
		err = cmdHunt(ctx, os.Args[2:])
	case "experiment":
		err = cmdExperiment(ctx, os.Args[2:])
	case "validate":
		err = cmdValidate(ctx, os.Args[2:])
	case "recon":
		err = cmdRecon(ctx, os.Args[2:])
	case "infer":
		err = cmdInfer(ctx, os.Args[2:])
	case "estimate":
		err = cmdEstimate(ctx, os.Args[2:])
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
  tekmerion validate -experiment EXPERIMENT_STATE (-print-context | -state NEW_DIR (-offline | -replay FILE | -model FILE -prices FILE -budget FILE))
  tekmerion experiment -hunt HUNT_STATE -work DIR -spec FILE -candidate ID -state NEW_DIR
  tekmerion hunt -recon RECON_STATE -work DIR -ariadne BIN -state NEW_DIR (-offline | -replay FILE | -model FILE -prices FILE -budget FILE)
  tekmerion recon -work DIR -ariadne BIN -state NEW_DIR (-offline | -replay FILE | -model FILE -prices FILE -budget FILE)
  tekmerion infer -request FILE -prices FILE -budget FILE -state NEW_DIR [-attempts N] [-timeout-seconds N]
  tekmerion estimate -plan FILE -prices FILE [-budget FILE] [-state DIR] [-at RFC3339]
  tekmerion prepare -project FILE -checkout DIR -work DIR [-ariadne BIN] [-allow-network] [-sources auto|always|never]
  tekmerion locate  -work DIR CLASS NAME DESCRIPTOR
  tekmerion audit   -fixture -state NEW_DIR [-contract DIR] [-budget FILE]
  tekmerion resume  -state DIR
  tekmerion status  -state DIR
  tekmerion report  -state DIR [-format markdown|json]`)
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

func cmdAudit(ctx context.Context, command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	dir := fs.String("state", "", "persistent fixture audit directory")
	var fixture *bool
	var contractDir, format, budgetFile *string
	if command == "audit" {
		budgetFile = fs.String("budget", "", "optional tekmerion-budget-1 JSON configuration")
		fixture = fs.Bool("fixture", false, "explicitly replay the pinned contract fixtures")
		contractDir = fs.String("contract", "contracts/ariadne/v1", "pinned Ariadne contract directory")
	}
	if command == "report" {
		format = fs.String("format", "markdown", "markdown or json")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || fs.NArg() != 0 {
		return fmt.Errorf("%s requires -state DIR and no positional arguments", command)
	}
	switch command {
	case "audit":
		if !*fixture {
			return fmt.Errorf("only explicit -fixture audits are implemented")
		}
		var budget *state.BudgetConfig
		if *budgetFile != "" {
			raw, err := os.ReadFile(*budgetFile)
			if err != nil {
				return err
			}
			config, err := state.ParseBudget(raw)
			if err != nil {
				return err
			}
			budget = &config
		}
		if err := audit.StartFixtureBudget(ctx, *dir, *contractDir, budget); err != nil {
			return err
		}
		if err := resumeRun(ctx, *dir); err != nil {
			return err
		}
	case "resume":
		if err := resumeRun(ctx, *dir); err != nil {
			return err
		}
	case "report":
		raw, err := audit.Report(ctx, *dir, *format)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(raw)
		return err
	}
	snapshot, err := audit.Status(ctx, *dir)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(raw))
	return nil
}

func cmdEstimate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("estimate", flag.ContinueOnError)
	planFile := fs.String("plan", "", "finite workload plan")
	pricesFile := fs.String("prices", "", "normalized offline pricing snapshot")
	budgetFile := fs.String("budget", "", "optional budget to check")
	stateDir := fs.String("state", "", "append forecast and inputs to an existing run")
	at := fs.String("at", "", "explicit RFC3339 estimate timestamp; default current UTC time")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *planFile == "" || *pricesFile == "" || fs.NArg() != 0 {
		return fmt.Errorf("estimate requires -plan FILE and -prices FILE")
	}
	now := time.Now().UTC()
	if *at != "" {
		var err error
		now, err = time.Parse(time.RFC3339, *at)
		if err != nil {
			return err
		}
	}
	planRaw, err := os.ReadFile(*planFile)
	if err != nil {
		return err
	}
	priceRaw, err := os.ReadFile(*pricesFile)
	if err != nil {
		return err
	}
	var budget *state.BudgetConfig
	var store *state.Store
	var snapshot *state.Snapshot
	if *stateDir != "" {
		store, err = state.Open(ctx, *stateDir)
		if err != nil {
			return err
		}
		defer store.Close()
		snapshot, err = store.Snapshot(ctx)
		if err != nil {
			return err
		}
		if snapshot.Budget != nil {
			budget = &snapshot.Budget.Config
		}
	}
	if *budgetFile != "" {
		raw, err := os.ReadFile(*budgetFile)
		if err != nil {
			return err
		}
		value, err := state.ParseBudget(raw)
		if err != nil {
			return err
		}
		if budget != nil && *budget != value {
			return fmt.Errorf("estimate budget differs from immutable run budget")
		}
		budget = &value
	}
	if snapshot != nil {
		plan, err := pricing.ParsePlan(planRaw)
		if err != nil {
			return err
		}
		if plan.TargetIdentity != snapshot.Run.ManifestSHA {
			return fmt.Errorf("saved forecast target_identity must equal the run manifest_sha256")
		}
	}
	estimate, err := pricing.Build(planRaw, priceRaw, now, budget)
	if err != nil {
		return err
	}
	report, err := json.MarshalIndent(estimate, "", "  ")
	if err != nil {
		return err
	}
	report = append(report, '\n')
	if store != nil {
		planArtifact, err := store.Put(ctx, planRaw, "application/json")
		if err != nil {
			return err
		}
		priceArtifact, err := store.Put(ctx, priceRaw, "application/json")
		if err != nil {
			return err
		}
		reportArtifact, err := store.Put(ctx, report, "application/json")
		if err != nil {
			return err
		}
		if err := store.AddForecast(ctx, snapshot.Run.ID, reportArtifact.SHA, planArtifact.SHA, priceArtifact.SHA); err != nil {
			return err
		}
	}
	_, err = os.Stdout.Write(report)
	return err
}

func cmdInfer(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("infer", flag.ContinueOnError)
	requestFile := fs.String("request", "", "explicit role/model/provider/messages JSON; sends a paid request")
	pricesFile := fs.String("prices", "", "saved normalized pricing snapshot")
	budgetFile := fs.String("budget", "", "immutable run budget")
	dir := fs.String("state", "", "new run state directory")
	attempts := fs.Int("attempts", 1, "maximum attempts including retries (1..5)")
	timeout := fs.Int("timeout-seconds", 30, "deadline per request (1..120 seconds)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *requestFile == "" || *pricesFile == "" || *budgetFile == "" || *dir == "" || fs.NArg() != 0 {
		return fmt.Errorf("infer requires -request, -prices, -budget and a new -state directory")
	}
	requestRaw, err := os.ReadFile(*requestFile)
	if err != nil {
		return err
	}
	var request llm.Request
	if err := jsonx.Decode(requestRaw, &request, false); err != nil {
		return err
	}
	if err := request.Validate(); err != nil {
		return err
	}
	priceRaw, err := os.ReadFile(*pricesFile)
	if err != nil {
		return err
	}
	prices, err := pricing.ParseSnapshot(priceRaw)
	if err != nil {
		return err
	}
	if _, _, _, err := pricing.Bound(prices, request.Model, request.Provider, request.InputTokenBound, request.MaxOutputTokens, time.Now()); err != nil {
		return err
	}
	budgetRaw, err := os.ReadFile(*budgetFile)
	if err != nil {
		return err
	}
	budget, err := state.ParseBudget(budgetRaw)
	if err != nil {
		return err
	}
	task := gateway.Task{Schema: gateway.TaskSchema, Request: request, PricingSHA: pricing.Hash(priceRaw), MaxAttempts: *attempts, TimeoutSeconds: *timeout}
	taskRaw, err := json.Marshal(task)
	if err != nil {
		return err
	}
	if _, err := gateway.Parse(taskRaw); err != nil {
		return err
	}
	client, err := openrouter.New(openrouter.Config{APIKey: os.Getenv("OPENROUTER_API_KEY"), Timeout: time.Duration(*timeout) * time.Second})
	if err != nil {
		return err
	}
	if err := client.Check(request); err != nil {
		return err
	}
	store, err := state.Create(ctx, *dir)
	if err != nil {
		return err
	}
	defer store.Close()
	if _, err := store.Put(ctx, priceRaw, "application/json"); err != nil {
		return err
	}
	requestArtifact, err := store.Put(ctx, requestRaw, "application/json")
	if err != nil {
		return err
	}
	taskArtifact, err := store.Put(ctx, taskRaw, "application/json")
	if err != nil {
		return err
	}
	manifest := gateway.Manifest{Schema: gateway.RunSchema, Mode: "model", TaskID: request.Role, RequestSHA: requestArtifact.SHA, PricingSHA: task.PricingSHA, Budget: budget}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	a, err := store.Put(ctx, manifestRaw, "application/json")
	if err != nil {
		return err
	}
	if _, err := store.StartBudget(ctx, a.SHA, []state.TaskInput{{ID: request.Role, Stage: request.Role, InputSHA: taskArtifact.SHA, Paid: true}}, budget); err != nil {
		return err
	}
	result, err := gateway.Execute(ctx, store, request.Role, client, nil)
	if err != nil {
		return err
	}
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(output))
	return nil
}
func resumeRun(ctx context.Context, dir string) error {
	store, err := state.Open(ctx, dir)
	if err != nil {
		return err
	}
	snap, err := store.Snapshot(ctx)
	if err != nil {
		store.Close()
		return err
	}
	raw, err := store.Get(ctx, snap.Run.ManifestSHA)
	if err != nil {
		store.Close()
		return err
	}
	var kind struct {
		Schema string `json:"schema_version"`
	}
	if err := jsonx.Decode(raw, &kind, true); err != nil {
		store.Close()
		return err
	}
	if kind.Schema == validate.RunSchema {
		needsModel := false
		for _, t := range snap.Tasks {
			if t.Paid && t.Status != "completed" && t.Status != "failed" {
				needsModel = true
			}
		}
		store.Close()
		var provider llm.Provider
		if needsModel {
			client, err := openrouter.New(openrouter.Config{APIKey: os.Getenv("OPENROUTER_API_KEY"), Timeout: 2 * time.Minute})
			if err != nil {
				return err
			}
			provider = client
		}
		return validate.Resume(ctx, dir, provider)
	}
	if kind.Schema == experiment.RunSchema {
		store.Close()
		return experiment.Resume(ctx, dir)
	}
	if kind.Schema == hunt.RunSchema {
		needsModel := false
		for _, t := range snap.Tasks {
			if t.Paid && t.Status != "completed" && t.Status != "failed" {
				needsModel = true
			}
		}
		store.Close()
		var provider llm.Provider
		if needsModel {
			client, err := openrouter.New(openrouter.Config{APIKey: os.Getenv("OPENROUTER_API_KEY"), Timeout: 2 * time.Minute})
			if err != nil {
				return err
			}
			provider = client
		}
		return hunt.Resume(ctx, dir, provider, nil)
	}
	if kind.Schema == recon.RunSchema {
		var manifest recon.Manifest
		if err := jsonx.Decode(raw, &manifest, false); err != nil {
			store.Close()
			return err
		}
		needsModel := false
		for _, task := range snap.Tasks {
			if task.ID == "recon" && task.Status != "completed" && task.Status != "failed" {
				needsModel = manifest.Mode == "recon-model"
			}
		}
		store.Close()
		var provider llm.Provider
		if needsModel {
			client, err := openrouter.New(openrouter.Config{APIKey: os.Getenv("OPENROUTER_API_KEY"), Timeout: 2 * time.Minute})
			if err != nil {
				return err
			}
			provider = client
		}
		return recon.Resume(ctx, dir, provider)
	}
	if kind.Schema != gateway.RunSchema {
		store.Close()
		return audit.ResumeFixture(ctx, dir)
	}
	defer store.Close()
	if snap.Run.Status == "completed" {
		return nil
	}
	var manifest gateway.Manifest
	if err := jsonx.Decode(raw, &manifest, false); err != nil {
		return err
	}
	if snap.Run.Status == "failed" {
		return fmt.Errorf("model run failed; inspect status/report for retained evidence")
	}
	var task gateway.Task
	for _, queued := range snap.Tasks {
		if queued.ID == manifest.TaskID {
			raw, err := store.Get(ctx, queued.InputSHA)
			if err != nil {
				return err
			}
			task, err = gateway.Parse(raw)
			if err != nil {
				return err
			}
		}
	}
	if task.TimeoutSeconds == 0 {
		return fmt.Errorf("model task missing from saved run")
	}
	client, err := openrouter.New(openrouter.Config{APIKey: os.Getenv("OPENROUTER_API_KEY"), Timeout: time.Duration(task.TimeoutSeconds) * time.Second})
	if err != nil {
		return err
	}
	_, err = gateway.Execute(ctx, store, manifest.TaskID, client, nil)
	return err
}

func cmdRecon(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("recon", flag.ContinueOnError)
	work := fs.String("work", "", "TM1 prepared work directory with api roots")
	binary := fs.String("ariadne", "", "Ariadne query binary")
	dir := fs.String("state", "", "new Recon state directory")
	offline := fs.Bool("offline", false, "deterministic inventory baseline; no model calls")
	replay := fs.String("replay", "", "saved Recon response JSON to validate locally")
	model := fs.String("model", "", "tekmerion-recon-model-1 config; explicitly sends source context")
	prices := fs.String("prices", "", "normalized model pricing snapshot")
	budget := fs.String("budget", "", "optional local or required model run budget")
	limits := recon.DefaultLimits()
	fs.IntVar(&limits.MaxEntries, "max-entries", limits.MaxEntries, "maximum entry methods in Recon context")
	fs.IntVar(&limits.MaxPages, "max-pages", limits.MaxPages, "maximum discovery pages per operation")
	fs.IntVar(&limits.MaxBytes, "max-context-bytes", limits.MaxBytes, "serialized source/API context cap")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *work == "" || *binary == "" || *dir == "" || fs.NArg() != 0 {
		return fmt.Errorf("recon requires -work, -ariadne and new -state directory")
	}
	options := recon.Options{Work: *work, State: *dir, Limits: limits, Offline: *offline, Querier: &ariadne.CLI{Binary: *binary, Bundle: filepath.Join(*work, "bundle"), Evidence: ariadne.Recorder{Root: filepath.Join(*dir, "ariadne-invocations")}}}
	if *replay != "" {
		raw, err := os.ReadFile(*replay)
		if err != nil {
			return err
		}
		options.Replay = raw
	}
	var provider llm.Provider
	if *budget != "" {
		raw, err := os.ReadFile(*budget)
		if err != nil {
			return err
		}
		value, err := state.ParseBudget(raw)
		if err != nil {
			return err
		}
		options.Budget = &value
	}
	if *model != "" {
		raw, err := os.ReadFile(*model)
		if err != nil {
			return err
		}
		var config recon.Config
		if err := jsonx.Decode(raw, &config, false); err != nil {
			return err
		}
		options.Model = &config
		if *prices == "" {
			return fmt.Errorf("model Recon requires -prices")
		}
		priceRaw, err := os.ReadFile(*prices)
		if err != nil {
			return err
		}
		options.Prices = priceRaw
		client, err := openrouter.New(openrouter.Config{APIKey: os.Getenv("OPENROUTER_API_KEY"), Timeout: 2 * time.Minute})
		if err != nil {
			return err
		}
		provider = client
	}
	if err := recon.Start(ctx, options); err != nil {
		return err
	}
	if err := recon.Resume(ctx, *dir, provider); err != nil {
		return err
	}
	return cmdAudit(ctx, "status", []string{"-state", *dir})
}

func cmdHunt(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("hunt", flag.ContinueOnError)
	parent := fs.String("recon", "", "completed Recon state directory")
	work := fs.String("work", "", "same prepared input used by Recon")
	binary := fs.String("ariadne", "", "Ariadne binary")
	dir := fs.String("state", "", "new derived Hunt state directory")
	offline := fs.Bool("offline", false, "prepare bounded tasks; no semantic Hunt or model calls")
	replay := fs.String("replay", "", "tekmerion-hunt-replay-1 outputs keyed by unit ID")
	model := fs.String("model", "", "tekmerion-hunt-model-1 config; explicitly sends source context")
	prices := fs.String("prices", "", "normalized model pricing snapshot")
	budget := fs.String("budget", "", "explicit budget for this derived Hunt run")
	maxUnits := fs.Int("max-units", 8, "maximum planned units in this wave (1..64)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *parent == "" || *work == "" || *binary == "" || *dir == "" || fs.NArg() != 0 {
		return fmt.Errorf("hunt requires -recon, -work, -ariadne and new -state")
	}
	o := hunt.Options{Recon: *parent, Work: *work, State: *dir, Binary: *binary, MaxUnits: *maxUnits, Offline: *offline}
	if *replay != "" {
		raw, err := os.ReadFile(*replay)
		if err != nil {
			return err
		}
		o.Replay = raw
	}
	if *budget != "" {
		raw, err := os.ReadFile(*budget)
		if err != nil {
			return err
		}
		v, err := state.ParseBudget(raw)
		if err != nil {
			return err
		}
		o.Budget = &v
	}
	var provider llm.Provider
	if *model != "" {
		raw, err := os.ReadFile(*model)
		if err != nil {
			return err
		}
		var config hunt.Config
		if err := jsonx.Decode(raw, &config, false); err != nil {
			return err
		}
		o.Model = &config
		if *prices == "" {
			return fmt.Errorf("model Hunt requires -prices")
		}
		o.Prices, err = os.ReadFile(*prices)
		if err != nil {
			return err
		}
		client, err := openrouter.New(openrouter.Config{APIKey: os.Getenv("OPENROUTER_API_KEY"), Timeout: 2 * time.Minute})
		if err != nil {
			return err
		}
		provider = client
	}
	if err := hunt.Start(ctx, o); err != nil {
		return err
	}
	if err := hunt.Resume(ctx, *dir, provider, nil); err != nil {
		return err
	}
	return cmdAudit(ctx, "status", []string{"-state", *dir})
}

func cmdExperiment(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("experiment", flag.ContinueOnError)
	parent := fs.String("hunt", "", "completed Hunt state directory")
	work := fs.String("work", "", "same prepared input used by Hunt")
	spec := fs.String("spec", "", "tekmerion-experiment-1 spec with a checked-in harness")
	candidate := fs.String("candidate", "", "candidate ID from the Hunt run")
	dir := fs.String("state", "", "new derived experiment state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("experiment takes no positional arguments")
	}
	if err := experiment.Start(ctx, experiment.Options{Hunt: *parent, Work: *work, Spec: *spec, Candidate: *candidate, State: *dir}); err != nil {
		return err
	}
	if err := experiment.Resume(ctx, *dir); err != nil {
		return err
	}
	return cmdAudit(ctx, "status", []string{"-state", *dir})
}

func cmdValidate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	parent := fs.String("experiment", "", "completed experiment state directory")
	dir := fs.String("state", "", "new derived validation state directory")
	printContext := fs.Bool("print-context", false, "print the verifier context (with its input_identity) and exit")
	offline := fs.Bool("offline", false, "no independent review; replay and decision still run")
	replay := fs.String("replay", "", "recorded tekmerion-validate-result-1 output")
	model := fs.String("model", "", "tekmerion-validate-model-1 config; explicitly sends source context")
	prices := fs.String("prices", "", "normalized model pricing snapshot")
	budget := fs.String("budget", "", "explicit budget for this validation run")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *parent == "" || fs.NArg() != 0 {
		return fmt.Errorf("validate requires -experiment and no positional arguments")
	}
	if *printContext {
		c, _, err := validate.BuildContext(ctx, *parent)
		if err != nil {
			return err
		}
		raw, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(raw))
		return nil
	}
	if *dir == "" {
		return fmt.Errorf("validate requires -state NEW_DIR")
	}
	o := validate.Options{Experiment: *parent, State: *dir, Offline: *offline}
	if *replay != "" {
		raw, err := os.ReadFile(*replay)
		if err != nil {
			return err
		}
		o.Replay = raw
	}
	if *budget != "" {
		raw, err := os.ReadFile(*budget)
		if err != nil {
			return err
		}
		v, err := state.ParseBudget(raw)
		if err != nil {
			return err
		}
		o.Budget = &v
	}
	var provider llm.Provider
	if *model != "" {
		raw, err := os.ReadFile(*model)
		if err != nil {
			return err
		}
		var config validate.Config
		if err := jsonx.Decode(raw, &config, false); err != nil {
			return err
		}
		o.Model = &config
		if *prices == "" {
			return fmt.Errorf("model validation requires -prices")
		}
		if o.Prices, err = os.ReadFile(*prices); err != nil {
			return err
		}
		client, err := openrouter.New(openrouter.Config{APIKey: os.Getenv("OPENROUTER_API_KEY"), Timeout: 2 * time.Minute})
		if err != nil {
			return err
		}
		provider = client
	}
	if err := validate.Start(ctx, o); err != nil {
		return err
	}
	if err := validate.Resume(ctx, *dir, provider); err != nil {
		return err
	}
	return cmdAudit(ctx, "status", []string{"-state", *dir})
}
