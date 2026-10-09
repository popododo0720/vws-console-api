// Package resource is the one vocabulary for VWS resources.
//
// The console JSON API is this package's encoding. The EC2 Query and S3
// surfaces translate into and out of these types, so an instance id, a state
// name, and a client token mean the same thing on every surface.
//
// A non-zero ID or text value is well formed. Constructors validate.
// This package imports only the standard library.
package resource
