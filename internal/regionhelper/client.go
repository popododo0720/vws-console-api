package regionhelper

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"time"
)

// Client invokes an installed helper binary directly.
type Client struct {
	Path string
}

// WriteRegistration replaces the public registration identity.
func (c Client) WriteRegistration(ctx context.Context, data []byte) error {
	return c.run(ctx, "registration-write", "", data)
}

// WriteToken replaces the encrypted PVE token.
func (c Client) WriteToken(ctx context.Context, data []byte) error {
	return c.run(ctx, "token-write", "", data)
}

// WriteLease replaces the public lease document.
func (c Client) WriteLease(ctx context.Context, data []byte) error {
	return c.run(ctx, "lease-write", "", data)
}

// Lock acquires a named mkdir lock; an existing lock is an error.
func (c Client) Lock(ctx context.Context, name string) error {
	return c.run(ctx, "lock", name, nil)
}

// Unlock removes a named empty lock directory.
func (c Client) Unlock(ctx context.Context, name string) error {
	return c.run(ctx, "unlock", name, nil)
}

// WriteSnippet replaces a cloud-init snippet.
func (c Client) WriteSnippet(ctx context.Context, name string, data []byte) error {
	return c.run(ctx, "snippet-write", name, data)
}

// DeleteSnippet removes a cloud-init snippet.
func (c Client) DeleteSnippet(ctx context.Context, name string) error {
	return c.run(ctx, "snippet-delete", name, nil)
}

func (c Client) run(ctx context.Context, verb, name string, data []byte) error {
	if !filepath.IsAbs(c.Path) {
		return errors.New("helper binary path must be absolute")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	args := []string{verb}
	if name != "" {
		args = append(args, name)
	}
	cmd := exec.CommandContext(ctx, c.Path, args...)
	cmd.Stdin = bytes.NewReader(data)
	if err := cmd.Run(); err != nil {
		return errors.New("region helper execution failed")
	}
	return nil
}
