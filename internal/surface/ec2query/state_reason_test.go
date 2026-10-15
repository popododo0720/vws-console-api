package ec2query

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestStateReasonOnDescribeInstancesXML(t *testing.T) {
	failedID, err := resource.Parse[resource.InstanceID]("i-0fedcba9876543210")
	if err != nil {
		t.Fatal(err)
	}
	runningID, err := resource.Parse[resource.InstanceID]("i-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	const message = "Server.InternalError: " +
		"An internal error caused the instance to terminate during launch"
	failed := marshalInstance(t, resource.Instance{
		ID:    failedID,
		State: resource.InstanceTerminated,
		StateReason: resource.StateReason{
			Code:    "Server.InternalError",
			Message: message,
		},
	})
	if !strings.Contains(failed, "<instanceState><code>48</code><name>terminated</name></instanceState>") {
		t.Fatalf("state xml %s", failed)
	}
	wantReason := "<stateReason><code>Server.InternalError</code><message>" + message + "</message></stateReason>"
	if !strings.Contains(failed, wantReason) {
		t.Fatalf("reason xml %s", failed)
	}
	running := marshalInstance(t, resource.Instance{ID: runningID, State: resource.InstanceRunning})
	if strings.Contains(running, "stateReason") {
		t.Fatalf("running xml %s", running)
	}
	if !strings.Contains(running, "<instanceState><code>16</code><name>running</name></instanceState>") {
		t.Fatalf("running state %s", running)
	}
}

func marshalInstance(t *testing.T, inst resource.Instance) string {
	t.Helper()
	body, err := xml.Marshal(describeInstancesXML{
		Reservations: struct {
			Items []reservationItem `xml:"item"`
		}{Items: []reservationItem{{Instances: instanceItems([]resource.Instance{inst})}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
