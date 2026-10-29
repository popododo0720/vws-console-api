package grpcclient_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sigv4"
	"github.com/popododo0720/vws-console-api/internal/surface/ec2query"
)

// unknownTypeVolumes is vws-storage serving every volume with one stored
// type. Any other storage call is Unimplemented.
type unknownTypeVolumes struct {
	storagev1.UnimplementedVolumeServiceServer
	typ storagev1.VolumeType
}

func (s unknownTypeVolumes) GetVolume(
	_ context.Context, req *storagev1.GetVolumeRequest,
) (*storagev1.Volume, error) {
	return &storagev1.Volume{
		Name: req.GetName(),
		Spec: &storagev1.VolumeSpec{SizeGib: 8, Type: s.typ},
		Status: &storagev1.VolumeStatus{
			Observed: &commonv1.ObservedState{State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY},
		},
	}, nil
}

// #337 AC2: a call that needs the volume type, on a stored volume whose
// type this build cannot name (UNSPECIFIED, or a type a later vws-proto
// added), answers EC2's UnknownVolumeType ("The specified volume type is
// unsupported", EC2 API Reference, Error codes) instead of InternalError.
// ModifyVolume on the EC2 surface first reads the volume by id, so that read
// answers the same code.
func TestVolumeActionOnUnknownTypeIsUnknownVolumeType(t *testing.T) {
	for _, typ := range []storagev1.VolumeType{
		storagev1.VolumeType_VOLUME_TYPE_UNSPECIFIED, storagev1.VolumeType(99),
	} {
		h, cred, now := ec2OverGRPC(t, unknownTypeVolumes{typ: typ})
		const vol = "vol-0123456789abcdef0"
		for _, params := range []map[string]string{
			{"Action": "AttachVolume", "VolumeId": vol, "InstanceId": "i-0123456789abcdef0", "Device": "/dev/sdf"},
			{"Action": "ModifyVolume", "VolumeId": vol, "Size": "16"},
			{"Action": "CreateSnapshot", "VolumeId": vol},
			{"Action": "DescribeVolumes", "VolumeId.1": vol},
		} {
			form := url.Values{}
			form.Set("Version", ec2query.Version)
			for k, v := range params {
				form.Set(k, v)
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://127.0.0.1:8081/",
				strings.NewReader(form.Encode()))
			req.Host = req.URL.Host
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if err := sigv4.Sign(req, cred, sigv4.ServiceEC2, resource.RegionName, now); err != nil {
				t.Fatal(err)
			}
			res := httptest.NewRecorder()
			h.ServeHTTP(res, req)
			if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), "<Code>UnknownVolumeType</Code>") {
				t.Errorf("%s on a %s volume: want 400 UnknownVolumeType, got %d %s", params["Action"], typ, res.Code, res.Body)
			}
		}
	}
}
