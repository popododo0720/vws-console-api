package iamclient

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/cryptotest"
	"time"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sshkey"
)

type keyPairServer struct {
	iamv1.UnimplementedKeyPairServiceServer
	mu         sync.Mutex
	key        *iamv1.KeyPair
	imports    []*iamv1.ImportKeyPairRequest
	deletes    []*iamv1.DeleteKeyPairRequest
	lists      []*iamv1.ListKeyPairsRequest
	lost       bool
	bad        bool
	deleteLost int
	listErr    error
}

func (s *keyPairServer) ImportKeyPair(
	ctx context.Context, req *iamv1.ImportKeyPairRequest,
) (*longrunningpb.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := ctx.Deadline(); !ok {
		return nil, status.Error(codes.Internal, "no deadline")
	}
	if s.key != nil && (len(s.imports) == 0 || req.GetRequestId() != s.imports[0].GetRequestId()) {
		return nil, status.Error(codes.AlreadyExists, "duplicate")
	}
	s.imports = append(s.imports, req)
	if req.GetPublicKey() != s.imports[0].GetPublicKey() {
		st, err := status.New(codes.Aborted, "request changed").WithDetails(
			&errdetails.ErrorInfo{Metadata: map[string]string{"aws_code": "IdempotentParameterMismatch"}})
		if err != nil {
			return nil, err
		}
		return nil, st.Err()
	}
	s.key = &iamv1.KeyPair{
		Name: req.GetParent() + "/keyPairs/key-00000000000000001", Labels: req.GetLabels(),
		Spec: &iamv1.KeyPairSpec{KeyName: req.GetKeyName(), Region: req.GetRegion(), PublicKey: req.GetPublicKey()},
	}
	if s.lost {
		s.lost = false
		return nil, status.Error(codes.Unavailable, "response lost after commit")
	}
	response, err := anypb.New(s.key)
	return &longrunningpb.Operation{Done: true, Result: &longrunningpb.Operation_Response{Response: response}}, err
}

func (s *keyPairServer) ListKeyPairs(
	_ context.Context, req *iamv1.ListKeyPairsRequest,
) (*iamv1.ListKeyPairsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lists = append(s.lists, req)
	if s.listErr != nil {
		return nil, s.listErr
	}
	out := &iamv1.ListKeyPairsResponse{}
	if s.bad {
		out.KeyPairs = append(out.KeyPairs, &iamv1.KeyPair{
			Name: "projects/999999999999/keyPairs/key-00000000000000001",
		})
	}
	if s.key != nil && (req.GetRegion() == "" || req.GetRegion() == s.key.GetSpec().GetRegion()) &&
		(len(req.GetKeyNames()) == 0 || slices.Contains(req.GetKeyNames(), s.key.GetSpec().GetKeyName())) {
		out.KeyPairs = append(out.KeyPairs, s.key)
	}
	return out, nil
}

func (s *keyPairServer) DeleteKeyPair(
	_ context.Context, req *iamv1.DeleteKeyPairRequest,
) (*longrunningpb.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes = append(s.deletes, req)
	s.key = nil
	if s.deleteLost > 0 {
		s.deleteLost--
		return nil, status.Error(codes.Unavailable, "delete response lost after commit")
	}
	return &longrunningpb.Operation{Done: true}, nil
}

func keyPairConnection(t *testing.T, s *keyPairServer) *grpc.ClientConn {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	iamv1.RegisterKeyPairServiceServer(server, s)
	go func() {
		if err := server.Serve(listener); err != nil {
			t.Errorf("serve IAM: %v", err)
		}
	}()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close IAM: %v", err)
		}
	})
	return conn
}

func keyPairMutation(t *testing.T) backend.Mutation {
	t.Helper()
	account, err := resource.Parse[resource.AccountID]("123456789012")
	if err != nil {
		t.Fatal(err)
	}
	return backend.Mutation{Scope: backend.Scope{Account: account, Region: "pve-test-1"}, Key: "client-token"}
}

func TestIAMKeyPairImportRestartAndRetry(t *testing.T) {
	s := &keyPairServer{lost: true}
	conn := keyPairConnection(t, s)
	m := keyPairMutation(t)
	pair, err := sshkey.Generate(resource.KeyTypeEd25519, strings.NewReader(strings.Repeat("a", 36)))
	if err != nil {
		t.Fatal(err)
	}
	req := resource.CreateKeyPairRequest{Name: "login", PublicKey: pair.Public}
	for range 2 {
		client := New(conn, Options{Backoff: time.Millisecond})
		got, err := client.CreateKeyPair(t.Context(), m, req)
		if err != nil || len(got.Items) != 1 || got.Items[0].Material != "" ||
			got.Operation.State != resource.OperationSucceeded {
			t.Fatalf("import after restart: %+v %v", got, err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.imports) != 3 {
		t.Fatalf("imports = %d", len(s.imports))
	}
	for _, req := range s.imports {
		if req.GetParent() != "projects/123456789012" || req.GetRegion() != m.Region ||
			req.GetPublicKey() != pair.Public || !uuidV4.MatchString(req.GetRequestId()) ||
			req.GetRequestId() != s.imports[0].GetRequestId() {
			t.Fatal("import scope, public key or stable request ID changed")
		}
	}
}

func TestIAMKeyPairCreateDescribeDelete(t *testing.T) {
	for _, format := range []resource.KeyFormat{resource.KeyFormatPEM, resource.KeyFormatPPK} {
		t.Run(string(format), func(t *testing.T) {
			cryptotest.SetGlobalRandom(t, 779)
			s := &keyPairServer{lost: true}
			conn := keyPairConnection(t, s)
			client := New(conn, Options{Backoff: time.Millisecond})
			m := keyPairMutation(t)
			req := resource.CreateKeyPairRequest{Name: "login", Type: resource.KeyTypeRSA, Format: format}
			created, err := client.CreateKeyPair(t.Context(), m, req)
			if err != nil {
				t.Fatal(err)
			}
			key := created.Items[0]
			if format == resource.KeyFormatPPK {
				if err := sshkey.VerifyPPK(key.Material); err != nil {
					t.Fatal(err)
				}
			} else if !strings.HasPrefix(key.Material, "-----BEGIN RSA PRIVATE KEY-----") {
				t.Fatal("created RSA is not PKCS#1 PEM")
			}
			page, err := client.DescribeKeyPairs(t.Context(), m.Scope, resource.KeyPairQuery{Names: []string{"login"}})
			if err != nil || len(page.Items) != 1 || page.Items[0].Fingerprint != key.Fingerprint ||
				page.Items[0].Material != "" {
				t.Fatalf("describe = %+v %v", page, err)
			}
			again, err := New(conn, Options{}).CreateKeyPair(t.Context(), m, req)
			if resource.CodeOf(err) != resource.CodeAlreadyExists || len(again.Items) != 0 {
				t.Fatalf("duplicate create = %v", err)
			}
			if s.imports[0].GetRequestId() != keyPairRequestID(m, "CreateKeyPair\x00"+req.Name) {
				t.Fatal("create request ID must depend only on mutation scope, name and token")
			}
			for _, sent := range s.imports {
				if sent.GetRequestId() != s.imports[0].GetRequestId() {
					t.Fatal("create retry changed request ID")
				}
			}
			deleted, err := client.DeleteKeyPair(t.Context(), m, resource.DeleteKeyPairRequest{Name: "login"})
			if err != nil || deleted.Items[0].ID != key.ID || deleted.Operation.Action != resource.ActionDeleteKeyPair {
				t.Fatalf("delete = %+v %v", deleted, err)
			}
			for _, selector := range []resource.DeleteKeyPairRequest{{Name: "login"}, {ID: key.ID}} {
				again, err := New(conn, Options{}).DeleteKeyPair(t.Context(), m, selector)
				if err != nil || again.Operation.State != resource.OperationSucceeded || len(again.Items) != 0 {
					t.Fatalf("delete after client restart = %+v %v", again, err)
				}
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if len(s.deletes) != 1 || s.deletes[0].GetName() != "projects/123456789012/keyPairs/"+key.ID.String() ||
				!uuidV4.MatchString(s.deletes[0].GetRequestId()) || s.lists[0].GetRegion() != m.Region {
				t.Fatal("delete name/request ID or list region changed")
			}
		})
	}
}

func TestIAMKeyPairDeleteLostResponse(t *testing.T) {
	s := &keyPairServer{deleteLost: MaxAttempts}
	conn := keyPairConnection(t, s)
	client := New(conn, Options{Backoff: time.Millisecond})
	m := keyPairMutation(t)
	pair, err := sshkey.Generate(resource.KeyTypeEd25519, strings.NewReader(strings.Repeat("a", 36)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateKeyPair(t.Context(), m,
		resource.CreateKeyPairRequest{Name: "login", PublicKey: pair.Public}); err != nil {
		t.Fatal(err)
	}
	req := resource.DeleteKeyPairRequest{Name: "login"}
	if _, err := client.DeleteKeyPair(t.Context(), m, req); resource.CodeOf(err) != resource.CodeUnavailable {
		t.Fatalf("lost delete response = %v", err)
	}
	got, err := New(conn, Options{}).DeleteKeyPair(t.Context(), m, req)
	if err != nil || got.Operation.State != resource.OperationSucceeded || len(got.Operation.Targets) != 0 {
		t.Fatalf("retry after committed delete = %+v %v", got, err)
	}
	for _, sent := range s.deletes {
		if sent.GetRequestId() != s.deletes[0].GetRequestId() {
			t.Fatal("delete retry changed request ID")
		}
	}
}

func TestIAMKeyPairDeleteSelectionErrors(t *testing.T) {
	id, err := resource.Parse[resource.KeyPairID]("key-00000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		req     resource.DeleteKeyPairRequest
		listErr error
		want    resource.Code
	}{
		{
			"missing project",
			resource.DeleteKeyPairRequest{Name: "login"},
			status.Error(codes.NotFound, "project missing"),
			resource.CodeNotFound,
		},
		{"two selectors", resource.DeleteKeyPairRequest{Name: "login", ID: id}, nil, resource.CodeInvalidArgument},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &keyPairServer{listErr: tc.listErr}
			client := New(keyPairConnection(t, s), Options{})
			_, err := client.DeleteKeyPair(t.Context(), keyPairMutation(t), tc.req)
			if resource.CodeOf(err) != tc.want || len(s.deletes) != 0 {
				t.Fatalf("delete selection error = %v, deletes = %d", err, len(s.deletes))
			}
		})
	}
}

func TestIAMKeyPairSkipsBadFilteredRecords(t *testing.T) {
	s := new(keyPairServer)
	client := New(keyPairConnection(t, s), Options{})
	m := keyPairMutation(t)
	pair, err := sshkey.Generate(resource.KeyTypeEd25519, strings.NewReader(strings.Repeat("a", 36)))
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.CreateKeyPair(t.Context(), m,
		resource.CreateKeyPairRequest{Name: "login", PublicKey: pair.Public})
	if err != nil {
		t.Fatal(err)
	}
	id := created.Items[0].ID
	s.mu.Lock()
	s.bad = true
	s.mu.Unlock()
	for _, q := range []resource.KeyPairQuery{{IDs: []resource.KeyPairID{id}}, {Names: []string{"login"}}} {
		page, err := client.DescribeKeyPairs(t.Context(), m.Scope, q)
		if err != nil || len(page.Items) != 1 || page.Items[0].ID != id {
			t.Fatalf("mixed filtered listing = %+v %v", page, err)
		}
	}
	deleted, err := client.DeleteKeyPair(t.Context(), m, resource.DeleteKeyPairRequest{ID: id})
	if err != nil || len(deleted.Items) != 1 || deleted.Items[0].ID != id {
		t.Fatalf("delete with unrelated corrupt record = %+v %v", deleted, err)
	}
}

func TestIAMKeyPairBoundaryAndMissing(t *testing.T) {
	s := new(keyPairServer)
	client := New(keyPairConnection(t, s), Options{})
	m := keyPairMutation(t)
	_, err := client.CreateKeyPair(t.Context(), m, resource.CreateKeyPairRequest{
		Name: "login", PublicKey: "invalid\nprivate-material",
	})
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("malformed import = %v", err)
	}
	_, err = client.DescribeKeyPairs(t.Context(), m.Scope, resource.KeyPairQuery{Names: make([]string, 201)})
	if resource.CodeOf(err) != resource.CodeInvalidArgument {
		t.Fatalf("name bound = %v", err)
	}
	s.mu.Lock()
	if len(s.imports)+len(s.lists) != 0 {
		t.Fatal("bad input reached IAM")
	}
	s.mu.Unlock()
	_, err = client.DescribeKeyPairs(t.Context(), m.Scope, resource.KeyPairQuery{Names: []string{"missing"}})
	if resource.CodeOf(err) != resource.CodeNotFound || resource.AsError(err).Kind != resource.KindKeyPair {
		t.Fatalf("missing name = %v", err)
	}
	s.mu.Lock()
	s.bad = true
	s.mu.Unlock()
	_, err = client.DescribeKeyPairs(t.Context(), m.Scope, resource.KeyPairQuery{Names: []string{"login"}})
	if resource.CodeOf(err) != resource.CodeNotFound || resource.AsError(err).Kind != resource.KindKeyPair {
		t.Fatalf("foreign resource must not satisfy the selector = %v", err)
	}
	page, err := client.DescribeKeyPairs(t.Context(), m.Scope, resource.KeyPairQuery{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("invalid inventory record was not skipped: %+v %v", page, err)
	}
}
