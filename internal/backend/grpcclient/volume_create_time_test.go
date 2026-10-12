package grpcclient

import (
	"testing"
	"time"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestVolumeCreateTimeComesFromStorage(t *testing.T) {
	at := time.Date(2026, 10, 12, 14, 51, 50, 0, time.UTC)
	got, err := volumeModel(&storagev1.Volume{
		Name:       volumeName("a123456789012", "vol-0123456789abcdef0"),
		Spec:       &storagev1.VolumeSpec{SizeGib: 1, Type: storagev1.VolumeType_VOLUME_TYPE_STANDARD},
		Status:     &storagev1.VolumeStatus{Observed: &commonv1.ObservedState{State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY}},
		CreateTime: timestamppb.New(at),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !got.CreateTime.Equal(at) {
		t.Fatalf("CreateTime = %v, want %v", got.CreateTime, at)
	}
}
