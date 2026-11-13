package resource

// RegistrationFailureMessage permits only fixed self-check classifications across
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
	switch e.Message {
	case "registration self-check failed: instance_types",
		"registration self-check failed: privileges",
		"registration self-check failed: cluster_name",
		"registration self-check failed: storages":
		return e.Message
	default:
		return ""
	}
}
