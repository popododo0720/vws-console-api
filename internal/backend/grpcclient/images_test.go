package grpcclient

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"
	computev1 "github.com/popododo0720/vws-proto/gen/go/vws/compute/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// imageListSrv serves image pages in the order a test gives them. The page
// token is the next page's index.
type imageListSrv struct {
	computev1.UnimplementedImageServiceServer
	mu          sync.Mutex
	pages       [][]*computev1.Image
	parents     []string
	listErr     error
	getImage    func(name string) error
	getImageArg string
}

func (s *imageListSrv) GetImage(_ context.Context, req *computev1.GetImageRequest) (*computev1.Image, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getImageArg = req.GetName()
	if s.getImage == nil {
		return nil, status.Error(codes.Unimplemented, "unused")
	}
	if err := s.getImage(req.GetName()); err != nil {
		return nil, err
	}
	return &computev1.Image{Name: req.GetName()}, nil
}

func (s *imageListSrv) ListImages(
	_ context.Context, req *computev1.ListImagesRequest,
) (*computev1.ListImagesResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.parents = append(s.parents, req.GetParent())
	if s.listErr != nil {
		return nil, s.listErr
	}
	page := 0
	if req.GetPageToken() != "" {
		parsed, err := strconv.Atoi(req.GetPageToken())
		if err != nil || parsed < 0 || parsed >= len(s.pages) {
			return nil, toStatus(resource.Invalid("pageToken", "malformed"))
		}
		page = parsed
	}
	if page >= len(s.pages) {
		return nil, toStatus(resource.Invalid("pageToken", "malformed"))
	}
	next := ""
	if page+1 < len(s.pages) {
		next = strconv.Itoa(page + 1)
	}
	return &computev1.ListImagesResponse{Images: s.pages[page], NextPageToken: next}, nil
}

func startImageList(t *testing.T, srv *imageListSrv) computeClient {
	t.Helper()
	lis := bufconn.Listen(MaxMessageBytes())
	server := grpc.NewServer()
	computev1.RegisterImageServiceServer(server, srv)
	go func() { _ = server.Serve(lis) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///images",
		append(dialOptions(), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}))...,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return computeClient{&api{images: computev1.NewImageServiceClient(conn)}}
}

func TestDescribeImagesReadsCompute(t *testing.T) {
	caller := mustAccount(t)
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	own := imagePB(t, caller, "ami-00000000000000001", project(caller), "base")
	public := imagePB(t, caller, "ami-00000000000000002", project(other), "shared")
	seed := &computev1.Image{
		Name: imageName(project(caller), "ami-00000000000000003"),
		Spec: &computev1.ImageSpec{Family: "debian-12"},
		Status: &computev1.ImageStatus{Observed: &commonv1.ObservedState{
			State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		}},
	}
	volume := &computev1.Image{
		Name: imageName(project(caller), "ami-00000000000000006"),
		Spec: &computev1.ImageSpec{
			Family: "from-volume",
			Source: &computev1.ImageSpec_Volume{Volume: volumeName(project(other), "vol-01234567")},
		},
		Status: &computev1.ImageStatus{Observed: &commonv1.ObservedState{
			State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		}},
	}
	srv := &imageListSrv{
		pages:    [][]*computev1.Image{{own, public}, {seed, volume}},
		getImage: func(string) error { return nil },
	}
	client := startImageList(t, srv)
	page, err := client.DescribeImages(context.Background(), backend.Scope{Account: caller}, resource.ImageQuery{
		Page: resource.PageRequest{Size: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(srv.parents) != 2 || srv.parents[0] != regionParent(project(caller)) || srv.parents[1] != srv.parents[0] {
		t.Fatalf("parents %v", srv.parents)
	}
	got := map[resource.ImageID]resource.Image{}
	for _, img := range page.Items {
		got[img.ID] = img
	}
	for _, want := range []struct {
		id     string
		owner  resource.AccountID
		name   string
		public bool
		state  string
	}{
		{"ami-00000000000000001", caller, "base", false, "available"},
		{"ami-00000000000000002", other, "shared", true, "available"},
		{"ami-00000000000000003", caller, "debian-12", false, "available"},
		{"ami-00000000000000006", other, "from-volume", true, "available"},
		{"ami-0123456789abcdef0", caller, "vws-1", false, "available"},
	} {
		img, ok := got[mustImage(t, want.id)]
		if !ok {
			t.Fatalf("%s is missing from %+v", want.id, page.Items)
		}
		if img.OwnerID != want.owner || img.Name != want.name || img.Public != want.public || img.State != want.state {
			t.Fatalf("%s = %+v, want owner %s name %q public %v state %s",
				want.id, img, want.owner, want.name, want.public, want.state)
		}
	}
	if len(got) != 5 {
		t.Fatalf("images %+v", page.Items)
	}
}

func TestDescribeImagesPrivateCopyFromAnotherProject(t *testing.T) {
	caller := mustAccount(t)
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	id := mustImage(t, "ami-00000000000000004")
	copied := imagePB(t, caller, id.String(), project(other), "copy")
	srv := &imageListSrv{
		pages:    [][]*computev1.Image{{copied}},
		getImage: func(string) error { return toStatus(resource.NotFound(resource.KindImage, id.String())) },
	}
	client := startImageList(t, srv)
	page, err := client.DescribeImages(context.Background(), backend.Scope{Account: caller}, resource.ImageQuery{
		Page: resource.PageRequest{Size: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || page.Items[0].ID != id || page.Items[0].OwnerID != caller || page.Items[0].Public {
		t.Fatalf("private copy %+v", page.Items)
	}
	if want := imageName(project(other), id.String()); srv.getImageArg != want {
		t.Fatalf("checked %q, want %q", srv.getImageArg, want)
	}
}

func TestDescribeImagesOwnerLookupFailureIsAnError(t *testing.T) {
	caller := mustAccount(t)
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	id := mustImage(t, "ami-00000000000000004")
	copied := imagePB(t, caller, id.String(), project(other), "copy")
	srv := &imageListSrv{
		pages:    [][]*computev1.Image{{copied}},
		getImage: func(string) error { return status.Error(codes.Unavailable, "image store down") },
	}
	client := startImageList(t, srv)
	_, err = client.DescribeImages(context.Background(), backend.Scope{Account: caller}, resource.ImageQuery{
		Owner: caller, Page: resource.PageRequest{Size: 50},
	})
	if resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("got %v, want the owner lookup error", err)
	}
}

func TestDescribeImagesPublicImageFromAnotherProject(t *testing.T) {
	caller := mustAccount(t)
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	id := mustImage(t, "ami-00000000000000005")
	public := imagePB(t, caller, id.String(), project(other), "shared")
	srv := &imageListSrv{
		pages:    [][]*computev1.Image{{public}},
		getImage: func(string) error { return nil },
	}
	client := startImageList(t, srv)
	page, err := client.DescribeImages(context.Background(), backend.Scope{Account: caller}, resource.ImageQuery{
		Page: resource.PageRequest{Size: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || page.Items[0].ID != id || page.Items[0].OwnerID != other || !page.Items[0].Public {
		t.Fatalf("public image %+v", page.Items)
	}
	if want := imageName(project(other), id.String()); srv.getImageArg != want {
		t.Fatalf("checked %q, want %q", srv.getImageArg, want)
	}
}

func TestDescribeImagesCatalogWinsADuplicate(t *testing.T) {
	caller := mustAccount(t)
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	id := mustImage(t, "ami-0123456789abcdef0")
	duplicate := imagePB(t, caller, id.String(), project(other), "other")
	srv := &imageListSrv{
		pages:    [][]*computev1.Image{{duplicate}},
		getImage: func(string) error { return nil },
	}
	client := startImageList(t, srv)
	page, err := client.DescribeImages(context.Background(), backend.Scope{Account: caller}, resource.ImageQuery{
		Page: resource.PageRequest{Size: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].ID != id || page.Items[0].OwnerID != caller ||
		page.Items[0].Public || page.Items[0].Name != "vws-1" {
		t.Fatalf("catalog duplicate %+v", page.Items)
	}
}

func TestDescribeImagesListFailureIsRetryable(t *testing.T) {
	client := startImageList(t, &imageListSrv{
		pages:   [][]*computev1.Image{{}},
		listErr: status.Error(codes.Unavailable, "image store down"),
	})
	_, err := client.DescribeImages(context.Background(), backend.Scope{Account: mustAccount(t)}, resource.ImageQuery{
		Page: resource.PageRequest{Size: 50},
	})
	if resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("got %v", err)
	}
}

func TestImageStateOf(t *testing.T) {
	for _, tc := range []struct {
		state commonv1.ReconciliationState
		want  string
	}{
		{commonv1.ReconciliationState_RECONCILIATION_STATE_PENDING, "pending"},
		{commonv1.ReconciliationState_RECONCILIATION_STATE_RECONCILING, "pending"},
		{commonv1.ReconciliationState_RECONCILIATION_STATE_READY, "available"},
		{commonv1.ReconciliationState_RECONCILIATION_STATE_DELETING, "deregistered"},
		{commonv1.ReconciliationState_RECONCILIATION_STATE_ERROR, "failed"},
		{commonv1.ReconciliationState_RECONCILIATION_STATE_UNSPECIFIED, "available"},
	} {
		if got := imageStateOf(tc.state); got != tc.want {
			t.Fatalf("%s = %q, want %q", tc.state, got, tc.want)
		}
	}
}

func TestDescribeImagesOwnerSelfExcludesPublicImages(t *testing.T) {
	caller := mustAccount(t)
	other, err := resource.Parse[resource.AccountID]("210987654321")
	if err != nil {
		t.Fatal(err)
	}
	public := imagePB(t, caller, "ami-00000000000000002", project(other), "shared")
	srv := &imageListSrv{
		pages:    [][]*computev1.Image{{public}},
		getImage: func(string) error { return nil },
	}
	client := startImageList(t, srv)
	page, err := client.DescribeImages(context.Background(), backend.Scope{Account: caller}, resource.ImageQuery{
		Owner: caller, Page: resource.PageRequest{Size: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, img := range page.Items {
		if img.OwnerID != caller {
			t.Fatalf("owner filter kept %+v", img)
		}
	}
	if len(page.Items) != 1 || page.Items[0].ID.String() != "ami-0123456789abcdef0" {
		t.Fatalf("owner filter %+v, want the catalog", page.Items)
	}
}

func TestDescribeImagesSingleUnknownIDIsNotFound(t *testing.T) {
	client := startImageList(t, &imageListSrv{pages: [][]*computev1.Image{{}}})
	id := mustImage(t, "ami-00000000000000009")
	_, err := client.DescribeImages(context.Background(), backend.Scope{Account: mustAccount(t)}, resource.ImageQuery{
		IDs: []resource.ImageID{id}, Page: resource.PageRequest{Size: 50},
	})
	if resource.CodeOf(err) != resource.CodeNotFound {
		t.Fatalf("got %v", err)
	}
	if want := "The image id '[" + id.String() + "]' does not exist"; resource.AsError(err).Message != want {
		t.Fatalf("message %q, want %q", resource.AsError(err).Message, want)
	}
}

func TestDescribeImagesSkipsABadRecord(t *testing.T) {
	caller := mustAccount(t)
	good := imagePB(t, caller, "ami-00000000000000001", project(caller), "base")
	bad := &computev1.Image{Name: imageName(project(caller), "not-an-image")}
	client := startImageList(t, &imageListSrv{pages: [][]*computev1.Image{{bad, good}}})
	page, err := client.DescribeImages(context.Background(), backend.Scope{Account: caller}, resource.ImageQuery{
		Page: resource.PageRequest{Size: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || page.Items[0].ID != mustImage(t, "ami-00000000000000001") {
		t.Fatalf("images %+v", page.Items)
	}
}

// imagePB is one compute image copied from a snapshot in sourceProject.
func imagePB(t *testing.T, caller resource.AccountID, id, sourceProject, family string) *computev1.Image {
	t.Helper()
	return &computev1.Image{
		Name: imageName(project(caller), id),
		Spec: &computev1.ImageSpec{
			Family: family,
			Source: &computev1.ImageSpec_Snapshot{Snapshot: snapshotName(sourceProject, "snap-01234567")},
		},
		Status: &computev1.ImageStatus{Observed: &commonv1.ObservedState{
			State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY,
		}},
	}
}
