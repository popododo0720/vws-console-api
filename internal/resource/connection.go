package resource

// ConnectionResult is the outcome of one ordered connection check.
type ConnectionResult string

// Connection check outcomes.
const (
	ConnectionPass    ConnectionResult = "PASS"
	ConnectionFail    ConnectionResult = "FAIL"
	ConnectionSkipped ConnectionResult = "SKIPPED"
)

// ConnectionStep contains only safe diagnostics, never upstream response text.
type ConnectionStep struct {
	Name    string           `json:"name"`
	Result  ConnectionResult `json:"result"`
	Message string           `json:"message"`
}
