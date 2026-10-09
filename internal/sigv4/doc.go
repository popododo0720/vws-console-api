// Package sigv4 checks the shape of a signature and the HMAC for header
// authentication. It is not an identity product: the caller supplies the
// secret for an access key. Presigned query strings are refused.
package sigv4
