package console

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/surface/iamquery"
)

type blockingIAMCreate struct {
	iam.Directory
	entered chan struct{}
	release chan struct{}
}

func (b *blockingIAMCreate) CreateUser(ctx context.Context, a resource.AccountID, name, path string) (iam.User, error) {
	if name == "slow" {
		close(b.entered)
		select {
		case <-b.release:
		case <-ctx.Done():
			return iam.User{}, ctx.Err()
		}
	}
	return b.Directory.CreateUser(ctx, a, name, path)
}

func TestIAMCreateDifferentKeysRunConcurrently(t *testing.T) {
	e := iamEnv(t)
	b := &blockingIAMCreate{Directory: e.fake, entered: make(chan struct{}), release: make(chan struct{})}
	e.h.(*handler).iamRunner = iamquery.NewRunner(iamquery.Config{
		Admin: b, Authorizer: iam.WithRoot(e.root, e.fake),
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	slow, fast := make(chan *httptest.ResponseRecorder, 1), make(chan *httptest.ResponseRecorder, 1)
	defer func() { close(b.release); <-slow }()
	go func() {
		slow <- e.do(t, "POST", "/api/v1/iam/users", `{"userName":"slow"}`,
			map[string]string{"Authorization": "Bearer tok", "Idempotency-Key": "slow"})
	}()
	select {
	case <-b.entered:
	case <-ctx.Done():
		t.Fatal("slow create did not reach the backend")
	}
	go func() {
		fast <- e.do(t, "POST", "/api/v1/iam/users", `{"userName":"fast"}`,
			map[string]string{"Authorization": "Bearer tok", "Idempotency-Key": "fast"})
	}()
	select {
	case rec := <-fast:
		iamStatus(t, rec, http.StatusOK)
	case <-ctx.Done():
		t.Fatal("another key waited for the slow backend call")
	}
}

func TestIAMCreateEvictsAtCapacity(t *testing.T) {
	e := iamEnv(t)
	headers := map[string]string{"Authorization": "Bearer tok"}
	for i := range 4097 {
		name := "user" + strconv.Itoa(i)
		headers["Idempotency-Key"] = name
		iamStatus(t, e.do(t, "POST", "/api/v1/iam/users", `{"userName":"`+name+`"}`, headers), http.StatusOK)
		*e.clock = e.clock.Add(time.Second)
	}
	headers["Idempotency-Key"] = "user4096"
	iamStatus(t, e.do(t, "POST", "/api/v1/iam/users", `{"userName":"user4096"}`, headers), http.StatusOK)
	headers["Idempotency-Key"] = "user0"
	iamStatus(t, e.do(t, "POST", "/api/v1/iam/users", `{"userName":"user0"}`, headers), http.StatusConflict)
}
