package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// A credential is read from, in order: the deprecated command-line flag, the
// file named by <ENV>_FILE (mount it from a Secret), then the <ENV> variable
// (secretKeyRef). A flag puts the value in the process arguments, where ps and
// /proc/<pid>/cmdline show it, so it is kept only for compatibility and logs a
// deprecation warning that names the flag, never the value. Setting both
// <ENV>_FILE and <ENV> is an error, as is an empty or unreadable file. With
// none of the three, the flag's public development default applies.
type credential struct {
	flag string // flag name without the dash, such as "secret"
	env  string // environment variable, such as "VWS_SECRET_KEY"
}

func credConsoleToken() credential {
	return credential{flag: "console-token", env: "VWS_CONSOLE_TOKEN"}
}
func credAccessKey() credential { return credential{flag: "access-key", env: "VWS_ACCESS_KEY"} }
func credSecret() credential    { return credential{flag: "secret", env: "VWS_SECRET_KEY"} }

// credentialEnv is the lookup that resolveCredential uses; tests replace it.
type credentialEnv struct {
	lookup   func(string) (string, bool)
	readFile func(string) ([]byte, error)
}

func osCredentialEnv() credentialEnv {
	return credentialEnv{lookup: os.LookupEnv, readFile: os.ReadFile}
}

// resolveCredential returns the value for c and whether it was given (by flag,
// file or env) rather than left at the default. flagValue is the parsed flag.
func resolveCredential(ctx context.Context, fs *flag.FlagSet, env credentialEnv, logger *slog.Logger, c credential, flagValue string) (string, bool, error) {
	fileVar := c.env + "_FILE"
	path, hasFile := env.lookup(fileVar)
	value, hasEnv := env.lookup(c.env)
	hasFile, hasEnv = hasFile && path != "", hasEnv && value != ""
	if flagGiven(fs, c.flag) {
		logger.WarnContext(ctx, "deprecated credential flag: its value is visible in the process arguments; use the environment variable or its _FILE form",
			slog.String("flag", "-"+c.flag), slog.String("env", c.env), slog.String("file_env", fileVar))
		return flagValue, true, nil
	}
	if hasFile && hasEnv {
		return "", false, fmt.Errorf("%s and %s are both set; set only one", fileVar, c.env)
	}
	if hasFile {
		raw, err := env.readFile(path)
		if err != nil {
			return "", false, fmt.Errorf("%s: %w", fileVar, err)
		}
		v := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
		if v == "" {
			return "", false, fmt.Errorf("%s %s: %w", fileVar, path, errEmptyCredential)
		}
		return v, true, nil
	}
	if hasEnv {
		return value, true, nil
	}
	return flagValue, false, nil
}

var errEmptyCredential = errors.New("the file is empty")

func flagGiven(fs *flag.FlagSet, name string) bool {
	given := false
	fs.Visit(func(f *flag.Flag) { given = given || f.Name == name })
	return given
}
