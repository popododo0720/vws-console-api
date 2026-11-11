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
	return c.run(ctx, data, "registration-write")
}

// WriteToken replaces the encrypted PVE token.
func (c Client) WriteToken(ctx context.Context, data []byte) error {
	return c.run(ctx, data, "token-write")
}

// WriteLease replaces the public lease document.
func (c Client) WriteLease(ctx context.Context, data []byte) error {
	return c.run(ctx, data, "lease-write")
}

// Lock acquires a named mkdir lock; an existing lock is an error.
func (c Client) Lock(ctx context.Context, name string) error {
	if !validLockName(name) {
		return errors.New("invalid lock name")
	}
	return c.run(ctx, nil, "lock", name)
}

// Unlock removes a named empty lock directory.
func (c Client) Unlock(ctx context.Context, name string) error {
	if !validLockName(name) {
		return errors.New("invalid lock name")
	}
	return c.run(ctx, nil, "unlock", name)
}

// WriteSnippet replaces a cloud-init snippet.
func (c Client) WriteSnippet(ctx context.Context, name string, data []byte) error {
	if !validSnippetName(name) {
		return errors.New("invalid snippet name")
	}
	return c.run(ctx, data, "snippet-write", name)
}

// DeleteSnippet removes a cloud-init snippet.
func (c Client) DeleteSnippet(ctx context.Context, name string) error {
	if !validSnippetName(name) {
		return errors.New("invalid snippet name")
	}
	return c.run(ctx, nil, "snippet-delete", name)
}

func (c Client) run(ctx context.Context, data []byte, args ...string) error {
	if !filepath.IsAbs(c.Path) {
		return errors.New("helper binary path must be absolute")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Path, args...)
	cmd.Stdin = bytes.NewReader(data)
	if err := cmd.Run(); err != nil {
		return errors.New("region helper execution failed")
	}
	return nil
}
