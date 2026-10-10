// Package cloud is the kernel. Every surface calls it, and it calls exactly
// one backend method. It normalizes requests, derives idempotency keys, and
// rejects a result that names another account. It stores nothing.
package cloud
