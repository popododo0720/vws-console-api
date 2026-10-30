// Package service names this process in logs, traces, and metrics.
package service

// Name is the service.name of the console API. obs.Setup reads
// OTEL_SERVICE_NAME first; the deployment sets it to the same value.
const Name = "console-api"
