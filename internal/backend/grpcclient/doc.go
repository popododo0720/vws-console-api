// Package grpcclient calls the internal compute, storage, and network
// services over the vws-proto resource API. It is the only package that
// sees protobuf. The rest of the process talks to backend.Set.
package grpcclient
