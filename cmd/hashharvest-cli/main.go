// Command hashharvest-cli scans a folder for hashes, as the HashHarvest app
// does, and writes the results as CSV or JSON. It does not save to the
// app's scan history.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"slices"
	"sort"
	"strings"

	"github.com/labgeek/HashHarvest/internal/db"
	"github.com/labgeek/HashHarvest/internal/extractor"
	"github.com/labgeek/HashHarvest/internal/manifest"
	"github.com/labgeek/HashHarvest/internal/scanner"
	"github.com/labgeek/HashHarvest/internal/version"
)

// Exit codes.
const (
	exitOK      = 0 // everything was scanned
	exitFailed  = 1 // the scan or writing its output failed, or it was cancelled
	exitUsage   = 2 // the command was wrong
	exitSkipped = 3 // the scan finished, but something could not be read
)

const usage = `Usage: hashharvest-cli [flags] <folder>

Scan <folder> for MD5, SHA1, SHA256 and SHA512 hashes, or hash its files.
Results go to standard output, or with -o to a file that gets a
<file>.manifest.json next to it. Reported skips are listed on standard error.
Text mode silently excludes unsupported extensions and unsearched document parts.
See USAGE.md for coverage and link restrictions.

Flags:
`

const exitHelp = `
Exit codes:
  0  scan and output completed without reported skips (not a coverage guarantee)
  1  the scan or writing its output failed, or it was cancelled
  2  the command was wrong
  3  the scan finished with reported skips
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

type options struct {
	folder, mode, format, out string
	types                     []string
	force                     bool
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	opts, code, done := parse(args, stdout, stderr)
	if done {
		return code
	}
	if opts.out != "" && !opts.force {
		for _, path := range []string{opts.out, manifest.Path(opts.out)} {
			if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
				fmt.Fprintf(stderr, "hashharvest-cli: %s already exists; use -force to overwrite it\n", path)
				return exitUsage
			}
		}
	}

	scannedAt := db.NowISO()
	result, err := scanner.Scanner{HashTypes: opts.types, Mode: opts.mode}.Scan(ctx, opts.folder, func(e scanner.Event) {
		switch e := e.(type) {
		case scanner.FileSkipped:
			fmt.Fprintln(stderr, e.Message)
		case scanner.Note:
			fmt.Fprintln(stderr, "Note:", e.Message)
		}
	})
	if err != nil {
		fmt.Fprintln(stderr, "hashharvest-cli: scan failed:", err)
		return exitFailed
	}

	if err := write(opts, scannedAt, result, stdout); err != nil {
		fmt.Fprintln(stderr, "hashharvest-cli:", err)
		return exitFailed
	}
	fmt.Fprintf(stderr, "Scanned %s, found %s, skipped %d\n",
		count(result.FilesScanned(), "file", "files"), count(result.HashesFound(), "hash", "hashes"), result.SkippedFiles())
	if result.SkippedFiles() > 0 {
		return exitSkipped
	}
	return exitOK
}

// parse reads the command line. done means run should return code now.
func parse(args []string, stdout, stderr io.Writer) (opts options, code int, done bool) {
	flags := flag.NewFlagSet("hashharvest-cli", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, usage)
		flags.PrintDefaults()
		fmt.Fprint(stderr, exitHelp)
	}
	flags.StringVar(&opts.mode, "mode", "text", `"text" finds hashes in documents; "file" hashes eligible regular files regardless of extension`)
	types := flags.String("types", strings.Join(extractor.HashTypes, ","), "comma-separated hash types")
	flags.StringVar(&opts.format, "format", "", `"csv" or "json" (default: json if -o ends in .json, else csv)`)
	flags.StringVar(&opts.out, "o", "", "write results to this file, with a manifest next to it")
	flags.BoolVar(&opts.force, "force", false, "let -o overwrite existing files")
	showVersion := flags.Bool("version", false, "print the version and exit")

	fail := func(format string, a ...any) (options, int, bool) {
		fmt.Fprintf(stderr, "hashharvest-cli: "+format+" (see -h)\n", a...)
		return opts, exitUsage, true
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return opts, exitOK, true
		}
		return opts, exitUsage, true // flags has printed the error
	}
	if *showVersion {
		fmt.Fprintln(stdout, "hashharvest-cli "+version.Version)
		return opts, exitOK, true
	}
	if flags.NArg() != 1 {
		return fail("give exactly one folder, after any flags")
	}
	opts.folder = flags.Arg(0)
	if opts.mode != "text" && opts.mode != "file" {
		return fail(`-mode must be "text" or "file", not %q`, opts.mode)
	}
	if opts.format == "" {
		opts.format = "csv"
		if strings.HasSuffix(strings.ToLower(opts.out), ".json") {
			opts.format = "json"
		}
	}
	if opts.format != "csv" && opts.format != "json" {
		return fail(`-format must be "csv" or "json", not %q`, opts.format)
	}
	for _, name := range strings.Split(*types, ",") {
		name = strings.ToUpper(strings.TrimSpace(name))
		if !slices.Contains(extractor.HashTypes, name) {
			return fail("-types: unknown hash type %q (use %s)", name, strings.Join(extractor.HashTypes, ", "))
		}
		if !slices.Contains(opts.types, name) {
			opts.types = append(opts.types, name)
		}
	}
	sort.Strings(opts.types)
	if opts.force && opts.out == "" {
		return fail("-force only applies to -o")
	}
	return opts, exitOK, false
}

func write(opts options, scannedAt string, result *scanner.Result, stdout io.Writer) error {
	render, export, format := extractor.CSVBytes, extractor.ExportCSV, "CSV"
	if opts.format == "json" {
		render, export, format = extractor.JSONBytes, extractor.ExportJSON, "JSON"
	}
	if opts.out == "" {
		_, err := stdout.Write(render(result.Results))
		return err
	}
	if err := export(opts.out, result.Results); err != nil {
		return err
	}
	skipped := []manifest.SkippedFile{}
	for _, e := range result.Errors {
		skipped = append(skipped, manifest.SkippedFile{Path: e.Path, Reason: e.Message})
	}
	err := manifest.Write(opts.out, format, result.Results, manifest.Scan{
		Folder: opts.folder, ScannedAt: scannedAt, Mode: opts.mode, HashTypes: opts.types,
		FilesScanned: result.FilesScanned(), HashesFound: result.HashesFound(),
		SkippedFiles: result.SkippedFiles(), Skipped: &skipped,
	})
	if err != nil {
		return fmt.Errorf("results written to %s, but the manifest failed: %w", opts.out, err)
	}
	return nil
}

func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
