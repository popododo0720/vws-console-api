package resource

import "regexp"

// RegistrationFailureMessage permits only classified self-check diagnostics across
// the registration transport and operator status boundary. Upstream errors may
// contain credentials even in their caller-visible fields.
func RegistrationFailureMessage(err error) string {
	if err == nil {
		return ""
	}
	e := AsError(err)
	if e.Code == CodeConflict && e.Message == "cluster_name differs from registration" {
		return e.Message
	}
	if e.Code != CodeUnavailable {
		return ""
	}
	if regexp.MustCompile(`^pool "[A-Za-z0-9][A-Za-z0-9._-]{0,63}": ` +
		`(missing (Pool\.Audit|VM\.Audit)|does not exist|` +
		`privileges could not be verified|existence could not be verified)$`).MatchString(e.Message) {
		return e.Message
	}
	switch e.Message {
	case "registration self-check failed: instance_types",
		"registration self-check failed: privileges",
		"registration self-check failed: cluster_name",
		"registration self-check failed: storages",
		"registration self-check failed: dr_storage",
		"registration self-check failed: pbs_connection",
		"registration self-check failed: pbs_privileges":
		return e.Message
	default:
		return ""
	}
}

// RegionRouteMissing is the error of a region daemon that answers but does not
// serve the route, because it is older than the console that called it.
const RegionRouteMissing = "region daemon does not serve this route; upgrade vws-region"

// ConnectionTestTooLarge is the error of a region daemon whose connection test
// request exceeds its 64 KiB limit; RegionResponseTooLarge is the client's own
// error for a daemon reply over the response limit. Both are PayloadTooLarge.
const (
	ConnectionTestTooLarge = "connection test exceeds 64 KiB"
	RegionResponseTooLarge = "region response exceeds the limit"
)

// RegionFailureMessage admits operator diagnostics, never upstream response bodies.
func RegionFailureMessage(err error) string {
	if err == nil {
		return ""
	}
	if message := RegistrationFailureMessage(err); message != "" {
		return message
	}
	e := AsError(err)
	if e.Code == CodeUnavailable {
		switch e.Message {
		case "not ready", "region pool check failed", "region status unavailable",
			"connection test busy", "connection test failed", "region daemon returned an invalid connection test",
			"deregistration failed", RegionRouteMissing:
			return e.Message
		}
	}
	return ""
}
