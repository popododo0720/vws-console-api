package resource

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestCapabilityDocumentGolden(t *testing.T) {
	want, err := os.ReadFile("testdata/capabilities.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc RegionCapabilities
	dec := json.NewDecoder(bytes.NewReader(want))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	got, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if string(append(got, '\n')) != string(want) {
		t.Errorf("document drifted from the golden:\n%s", got)
	}
}

func TestCapabilityDocumentValidation(t *testing.T) {
	reason := func(s ActionState) ActionCapability {
		return ActionCapability{State: s, ReasonCode: "Code", Reason: "why"}
	}
	for _, tc := range []struct {
		name    string
		key     string
		action  ActionCapability
		wantErr bool
	}{
		{"supported mutation", "ec2:RunInstances", ActionCapability{State: ActionSupported}, false},
		{"unsupported mutation", "ec2:AllocateAddress", reason(ActionUnsupported), false},
		{"empty read", "ec2:DescribeAddresses", ActionCapability{State: ActionEmpty}, false},
		{"partial read", "ec2:DescribeImages", reason(ActionPartial), false},
		{"unknown key keeps its state", "ec2:DescribeFleets", ActionCapability{State: ActionEmpty}, false},
		{"empty mutation", "ec2:AllocateAddress", ActionCapability{State: ActionEmpty}, true},
		{"unsupported read", "ec2:DescribeAddresses", reason(ActionUnsupported), true},
		{"partial without reason", "ec2:CreateVolume", ActionCapability{State: ActionPartial, ReasonCode: "C"}, true},
		{"partial without reasonCode", "ec2:CreateVolume", ActionCapability{State: ActionPartial, Reason: "why"}, true},
		{"unsupported without reason", "vws:OpenConsole", ActionCapability{State: ActionUnsupported}, true},
		{"missing state", "ec2:RunInstances", ActionCapability{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := RegionCapabilities{
				Region:  "pve-seoul-1",
				Kind:    RegionKindProxmox,
				Actions: map[string]ActionCapability{tc.key: tc.action},
			}
			if err := doc.Validate(); (err != nil) != tc.wantErr {
				t.Errorf("Validate() = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

func TestCapabilityDocumentRefusesUnknownStateAndKind(t *testing.T) {
	for _, body := range []string{
		`{"region":"r","kind":"proxmox","actions":{"ec2:RunInstances":{"state":"maybe"}}}`,
		`{"region":"r","kind":"azure","actions":{}}`,
	} {
		var doc RegionCapabilities
		if err := json.Unmarshal([]byte(body), &doc); err == nil {
			t.Errorf("Unmarshal(%s) accepted", body)
		}
	}
	if err := (RegionCapabilities{Kind: RegionKindAWS}).Validate(); err == nil {
		t.Error("a document without a region validated")
	}
	if err := (RegionCapabilities{Region: "r"}).Validate(); err == nil {
		t.Error("a document without a kind validated")
	}
}

func TestActionMissingFromTheDocument(t *testing.T) {
	doc := RegionCapabilities{Region: "pve-seoul-1", Kind: RegionKindProxmox}
	if got := doc.Mutation(ActionAllocateAddress).State; got != ActionUnsupported {
		t.Errorf("missing mutation is %v, want unsupported", got)
	}
	if got := doc.Read(ReadDescribeAddresses).State; got != ActionEmpty {
		t.Errorf("missing read is %v, want empty", got)
	}
}
