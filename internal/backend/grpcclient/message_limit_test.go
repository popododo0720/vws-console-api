package grpcclient

import (
	"context"
	"net"
	"strings"
	"testing"

	storagev1 "github.com/popododo0720/vws-proto/gen/go/vws/storage/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

type bigObject struct {
	storagev1.UnimplementedObjectServiceServer
	size int
}

func (s bigObject) GetObject(context.Context, *storagev1.GetObjectRequest) (*storagev1.Object, error) {
	return &storagev1.Object{Name: "x", Labels: map[string]string{"pad": strings.Repeat("x", s.size)}}, nil
}

func TestClientReceivesEightMiB(t *testing.T) {
	lis := bufconn.Listen(MaxMessageBytes())
	srv := grpc.NewServer(grpc.MaxSendMsgSize(MaxMessageBytes()))
	storagev1.RegisterObjectServiceServer(srv, bigObject{size: 8<<20 - 1024})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///storage",
		append(dialOptions(), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	out, err := storagev1.NewObjectServiceClient(conn).GetObject(context.Background(), &storagev1.GetObjectRequest{Name: "x"})
	if err != nil || len(out.GetLabels()["pad"]) != 8<<20-1024 {
		t.Fatalf("receive: %v", err)
	}
}
