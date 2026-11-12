package awssdk

import (
	"context"
	"encoding"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/smithy-go"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

func mutationCall[R resource.Request[R], T resource.Owned](
	t *testing.T, req R, call func(*Backend, context.Context, backend.Mutation, R) (resource.Accepted[T], error),
) func(*Backend, backend.Mutation) error {
	t.Helper()
	return func(b *Backend, m backend.Mutation) error {
		got, err := call(b, t.Context(), m, req)
		if err != nil {
			return err
		}
		if got.Operation.ID.IsZero() || got.Operation.Action != req.Action() ||
			got.Operation.OwnerID != m.Account || got.Operation.State != resource.OperationSucceeded ||
			len(got.Items) != 1 || len(got.Operation.Targets) != 1 {
			return fmt.Errorf("invalid acceptance: %+v", got)
		}
		item := got.Items[0]
		if item.Owner() != m.Account || item.Identity() != got.Operation.Targets[0].ID() {
			return fmt.Errorf("invalid target: %+v", got)
		}
		switch row := any(item).(type) {
		case resource.Instance:
			wantTag := "fixture"
			if req.Action() == resource.ActionDeleteTags {
				wantTag = ""
			}
			if row.State != resource.InstanceRunning || row.Tags["Name"] != wantTag {
				return fmt.Errorf("instance: %+v", row)
			}
		case resource.InstanceStateChange:
			current, previous := resource.InstanceRunning, resource.InstanceRunning
			switch req.Action().String() {
			case "StartInstances":
				current, previous = resource.InstancePending, resource.InstanceStopped
			case "StopInstances":
				current = resource.InstanceStopping
			case "TerminateInstances":
				current = resource.InstanceShuttingDown
			default:
			}
			if row.Current != current || row.Previous != previous {
				return fmt.Errorf("state change: %+v", row)
			}
		case resource.Snapshot:
			if req.Action() == resource.ActionCreateSnapshot &&
				(row.State != resource.SnapshotPending || row.VolumeSize != 8 || row.Tags["Name"] != "fixture") {
				return fmt.Errorf("snapshot: %+v", row)
			}
		}
		return nil
	}
}

func TestMutationsThroughProxy(t *testing.T) {
	id := mustParse[resource.InstanceID](t, "i-0123456789abcdef0")
	image := mustParse[resource.ImageID](t, "ami-0123456789abcdef0")
	subnet := mustParse[resource.SubnetID](t, "subnet-0123456789abcdef0")
	volume := mustParse[resource.VolumeID](t, "vol-0123456789abcdef0")
	snapshot := mustParse[resource.SnapshotID](t, "snap-0123456789abcdef0")
	m := backend.Mutation{Scope: backend.Scope{
		Account: mustParse[resource.AccountID](t, "123456789012"), Region: "us-east-1",
	}, Key: "first"}
	ids := []resource.InstanceID{id}
	tags := map[string]string{"Name": "fixture"}
	tagValue := "fixture"
	run := resource.RunInstancesRequest{
		ImageID: image, InstanceType: "t3.micro", Count: 1, KeyName: "fixture", UserData: "guest data",
		Tags: tags, RootVolumeType: resource.VolumeGP3, RootVolumeSize: 10,
		RootIops: 4000, RootThroughput: 150, RootVolumeKept: true,
		NetworkInterfaces: []resource.NetworkInterfaceSpec{{DeviceIndex: 0, SubnetID: subnet}},
		ExtraVolumes: []resource.LaunchVolume{{
			Device: "/dev/sdf", SizeGiB: 12, Type: resource.VolumeGP3, Iops: 3000, Throughput: 125,
		}},
	}
	cases := []struct {
		action string
		call   func(*Backend, backend.Mutation) error
	}{
		{"RunInstances", mutationCall(t, run, (*Backend).RunInstances)},
		{"StartInstances", mutationCall(t, resource.StartInstancesRequest{IDs: ids}, (*Backend).StartInstances)},
		{"StopInstances", mutationCall(t, resource.StopInstancesRequest{IDs: ids}, (*Backend).StopInstances)},
		{"RebootInstances", mutationCall(t, resource.RebootInstancesRequest{IDs: ids}, (*Backend).RebootInstances)},
		{"TerminateInstances", mutationCall(t, resource.TerminateInstancesRequest{IDs: ids}, (*Backend).TerminateInstances)},
		{"CreateTags", mutationCall(t, resource.CreateTagsRequest{IDs: ids, Tags: tags}, (*Backend).CreateTags)},
		{"DeleteTags", mutationCall(t, resource.DeleteTagsRequest{IDs: ids, Tags: []resource.TagSelector{
			{Key: "any"}, {Key: "empty", Value: new(string)}, {Key: "Name", Value: &tagValue},
		}}, (*Backend).DeleteTags)},
		{"CreateSnapshot", mutationCall(t, resource.CreateSnapshotRequest{
			VolumeID: volume, Description: "backup", Tags: tags,
		}, (*Backend).CreateSnapshot)},
		{"DeleteSnapshot", mutationCall(t, resource.DeleteSnapshotRequest{ID: snapshot}, (*Backend).DeleteSnapshot)},
	}
	inventory, err := os.ReadFile("testdata/instances.xml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			received := make(chan url.Values, 8)
			b := setupOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Error(err)
				}
				w.Header().Set("Content-Type", "text/xml")
				action := r.Form.Get("Action")
				if action == "DescribeImages" {
					fmt.Fprint(w, `<DescribeImagesResponse><imagesSet><item><rootDeviceName>/dev/sda1</rootDeviceName>`+
						`</item></imagesSet></DescribeImagesResponse>`)
					return
				}
				if action == "DescribeInstances" {
					xml := strings.ReplaceAll(string(inventory), "<nextToken>upstream-second</nextToken>", "")
					if tc.action == "DeleteTags" {
						xml = strings.ReplaceAll(xml, "<key>Name</key><value>fixture</value>", "<key>retained</key><value>yes</value>")
					}
					fmt.Fprint(w, xml)
					return
				}
				received <- r.Form
				if action != tc.action {
					t.Errorf("Action=%s want %s", action, tc.action)
				}
				switch action {
				case "RunInstances":
					fmt.Fprint(w, `<RunInstancesResponse><reservationId>r-0123456789abcdef0</reservationId><instancesSet><item>`+
						`<instanceId>i-0123456789abcdef0</instanceId><imageId>ami-0123456789abcdef0</imageId>`+
						`<instanceState><name>running</name></instanceState>`+
						`<tagSet><item><key>Name</key><value>fixture</value></item></tagSet>`+
						`</item></instancesSet></RunInstancesResponse>`)
				case "StartInstances", "StopInstances", "TerminateInstances":
					current, previous := "pending", "stopped"
					switch action {
					case "StopInstances":
						current, previous = "stopping", "running"
					case "TerminateInstances":
						current, previous = "shutting-down", "running"
					}
					fmt.Fprintf(w, `<%sResponse><instancesSet><item><instanceId>%s</instanceId>`+
						`<currentState><name>%s</name></currentState><previousState><name>%s</name></previousState>`+
						`</item></instancesSet></%sResponse>`, action, id, current, previous, action)
				case "CreateSnapshot":
					fmt.Fprintf(w, `<CreateSnapshotResponse><snapshotId>%s</snapshotId><volumeId>%s</volumeId>`+
						`<volumeSize>8</volumeSize><status>pending</status>`+
						`<tagSet><item><key>Name</key><value>fixture</value></item></tagSet></CreateSnapshotResponse>`,
						snapshot, volume)
				default:
					fmt.Fprintf(w, `<%sResponse><return>true</return></%sResponse>`, action, action)
				}
			}))
			var tokens []string
			for _, key := range []string{"first", "first", "second"} {
				attempt := m
				attempt.Key = key
				if err := tc.call(b, attempt); err != nil {
					t.Fatal(err)
				}
				form := <-received
				tokens = append(tokens, form.Get("ClientToken"))
				switch tc.action {
				case "RunInstances":
					for field, want := range map[string]string{
						"ImageId": image.String(), "MinCount": "1", "MaxCount": "1", "InstanceType": "t3.micro",
						"UserData": base64.StdEncoding.EncodeToString([]byte(run.UserData)), "KeyName": "fixture",
						"NetworkInterface.1.SubnetId": subnet.String(), "NetworkInterface.1.DeviceIndex": "0",
						"BlockDeviceMapping.1.DeviceName": "/dev/sda1", "BlockDeviceMapping.1.Ebs.VolumeSize": "10",
						"BlockDeviceMapping.1.Ebs.VolumeType": "gp3", "BlockDeviceMapping.1.Ebs.Iops": "4000",
						"BlockDeviceMapping.1.Ebs.Throughput": "150", "BlockDeviceMapping.1.Ebs.DeleteOnTermination": "false",
						"BlockDeviceMapping.2.DeviceName": "/dev/sdf", "BlockDeviceMapping.2.Ebs.VolumeSize": "12",
						"TagSpecification.1.ResourceType": "instance", "TagSpecification.1.Tag.1.Value": "fixture",
					} {
						if form.Get(field) != want {
							t.Errorf("%s=%q want %q", field, form.Get(field), want)
						}
					}
					if form.Has("SubnetId") {
						t.Error("subnet and network interfaces were both sent")
					}
				case "CreateTags", "DeleteTags":
					if form.Get("ResourceId.1") != id.String() {
						t.Errorf("resources: %v", form)
					}
					if tc.action == "DeleteTags" &&
						(form.Has("Tag.1.Value") || !form.Has("Tag.2.Value") || form.Get("Tag.3.Value") != "fixture") {
						t.Errorf("tag selector semantics lost: %v", form)
					}
				case "CreateSnapshot":
					if form.Get("VolumeId") != volume.String() || form.Get("Description") != "backup" ||
						form.Get("TagSpecification.1.ResourceType") != "snapshot" {
						t.Errorf("snapshot request: %v", form)
					}
				case "DeleteSnapshot":
					if form.Get("SnapshotId") != snapshot.String() {
						t.Errorf("snapshot request: %v", form)
					}
				default:
					if form.Get("InstanceId.1") != id.String() {
						t.Errorf("instance request: %v", form)
					}
				}
			}
			if tc.action == "RunInstances" {
				if len(tokens[0]) != 64 || strings.Trim(tokens[0], "0123456789abcdef") != "" ||
					tokens[0] != tokens[1] || tokens[0] == tokens[2] {
					t.Fatalf("tokens: %v", tokens)
				}
			} else if tokens[0] != "" || tokens[1] != "" || tokens[2] != "" {
				t.Fatalf("unsupported ClientToken sent: %v", tokens)
			}
			for _, field := range []string{"account", "region"} {
				foreign := m
				if field == "account" {
					foreign.Account = mustParse[resource.AccountID](t, "111111111111")
				} else {
					foreign.Region = "us-west-2"
				}
				err := tc.call(b, foreign)
				var domain *resource.Error
				if !errors.As(err, &domain) || domain.Field != field {
					t.Fatalf("foreign %s: %v", field, err)
				}
				if len(received) != 0 {
					t.Fatal("foreign scope reached origin")
				}
			}
		})
	}
}

func TestLaunchWithImageDefaults(t *testing.T) {
	b := setupOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("Action") != "RunInstances" || r.Form.Get("SubnetId") != "subnet-0123456789abcdef0" {
			t.Errorf("launch request: %v", r.Form)
		}
		for _, field := range []string{
			"NetworkInterface.1.SubnetId", "BlockDeviceMapping.1.DeviceName",
			"TagSpecification.1.ResourceType", "UserData", "KeyName",
		} {
			if r.Form.Has(field) {
				t.Errorf("image default overridden: %s", field)
			}
		}
		fmt.Fprint(w, `<RunInstancesResponse><reservationId>r-0123456789abcdef0</reservationId><instancesSet><item>`+
			`<instanceId>i-0123456789abcdef0</instanceId><imageId>ami-0123456789abcdef0</imageId>`+
			`<instanceState><name>pending</name></instanceState></item></instancesSet></RunInstancesResponse>`)
	}))
	_, err := b.RunInstances(t.Context(), backend.Mutation{Scope: backend.Scope{
		Account: mustParse[resource.AccountID](t, "123456789012"), Region: "us-east-1",
	}}, resource.RunInstancesRequest{
		ImageID: mustParse[resource.ImageID](t, "ami-0123456789abcdef0"), InstanceType: "t3.micro", Count: 1,
		SubnetID: mustParse[resource.SubnetID](t, "subnet-0123456789abcdef0"),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMutationAWSErrorCode(t *testing.T) {
	var calls atomic.Int32
	b := setupOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `<Response><Errors><Error><Code>InvalidInstanceID.NotFound</Code>`+
			`<Message>missing instance</Message></Error></Errors></Response>`)
	}))
	_, err := b.StopInstances(t.Context(), backend.Mutation{Scope: backend.Scope{
		Account: mustParse[resource.AccountID](t, "123456789012"), Region: "us-east-1",
	}}, resource.StopInstancesRequest{
		IDs: []resource.InstanceID{mustParse[resource.InstanceID](t, "i-0123456789abcdef0")},
	})
	var domain *resource.Error
	var api smithy.APIError
	if !errors.As(err, &domain) || !errors.As(domain, &api) ||
		api.ErrorCode() != "InvalidInstanceID.NotFound" ||
		!strings.Contains(domain.Message, api.ErrorCode()) || calls.Load() != 1 {
		t.Fatalf("AWS code lost: %v calls=%d", err, calls.Load())
	}
}

func mustParse[T any, PT interface {
	*T
	encoding.TextUnmarshaler
}](t *testing.T, raw string) T {
	t.Helper()
	value, err := resource.Parse[T, PT](raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
