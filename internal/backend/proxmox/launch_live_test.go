package proxmox

import (
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

func TestLaunchLiveRunTags(t *testing.T) {
	for _, tc := range []struct {
		name, run string
		live      bool
	}{
		{"live", "run-997", true},
		{"shortest", "0", true},
		{"longest", "a" + strings.Repeat("-", 39), true},
		{"ordinary", "run-997", false},
		{"ordinary unrestricted", "Not a run ID", false},
		{"absent", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, m, req := finalizeBackend(t)
			w.b.cfg.LiveTests, req.Count = tc.live, 1
			if tc.run != "" {
				req.Tags["vws-live-run"] = tc.run
			}
			accepted, err := w.b.RunInstances(t.Context(), m, req)
			checkLaunch(t, err)
			var writes []url.Values
			w.intercept = func(_ http.ResponseWriter, r *http.Request) bool {
				if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/config") {
					checkLaunch(t, r.ParseForm())
					writes = append(writes, r.Form)
				}
				return false
			}
			// A new backend has only the upstream clone description to recover the run ID.
			w.b, err = New(t.Context(), w.b.client, Identity(w.b), w.b.cfg)
			checkLaunch(t, err)
			checkLaunch(t, w.b.FinalizeLaunches(t.Context(), admitFinalize))
			cfg, err := w.b.client.VMConfig(t.Context(), launchVM(t, w, 0))
			checkLaunch(t, err)
			tag := "vws.live." + tc.run
			want := tc.live && tc.run != ""
			if slices.Contains(strings.Split(cfg.Tags, ";"), tag) != want {
				t.Fatalf("live=%v run=%q tags=%q", tc.live, tc.run, cfg.Tags)
			}
			tagWrites := 0
			for _, fields := range writes {
				if !fields.Has("tags") {
					continue
				}
				tagWrites++
				tags := strings.Split(fields.Get("tags"), ";")
				if fields.Get("digest") == "" || fields.Get("description") != cfg.Description ||
					slices.Contains(tags, tag) != want || !strings.Contains(fields.Get("tags"), "vws.k.") ||
					!strings.Contains(fields.Get("tags"), "vws.f.") ||
					!strings.Contains(fields.Get("tags"), "vws.n.") ||
					!strings.Contains(fields.Get("tags"), "vws.r.") {
					t.Fatalf("launch tag write=%v", fields)
				}
			}
			if tagWrites != 1 {
				t.Fatalf("tag writes=%d: %v", tagWrites, writes)
			}
			if !want && strings.Contains(cfg.Tags, "vws.live.") {
				t.Fatalf("unexpected system live tag: %q", cfg.Tags)
			}
			page, err := w.b.DescribeInstances(t.Context(), m.Scope, resource.InstanceQuery{})
			if err != nil || len(page.Items) != 1 || !reflect.DeepEqual(page.Items[0].Tags, req.Tags) {
				t.Fatalf("describe=%+v error=%v", page, err)
			}
			if _, _, ok := DecodeTag(tag); ok {
				t.Fatalf("system tag decoded as user tag: %q", tag)
			}
			before := len(writes)
			retry, err := w.b.RunInstances(t.Context(), m, req)
			checkLaunch(t, err)
			checkLaunch(t, w.b.FinalizeLaunches(t.Context(), admitFinalize))
			if !reflect.DeepEqual(retry.Items, accepted.Items) || len(w.forms) != 1 || len(writes) != before {
				t.Fatalf("retry changed launch: %+v clones=%d writes=%v", retry, len(w.forms), writes)
			}
		})
	}
}

func TestLaunchLiveRunRejectsInvalidBeforeClone(t *testing.T) {
	for _, run := range []string{"", "-run", "Run", "a.b", "a_b", "a/b", "a;b", "a\nb", strings.Repeat("a", 41)} {
		t.Run(run, func(t *testing.T) {
			w, m, req := finalizeBackend(t)
			w.b.cfg.LiveTests = true
			req.Tags["vws-live-run"] = run
			_, err := w.b.RunInstances(t.Context(), m, req)
			if resource.CodeOf(err) != resource.CodeInvalidArgument {
				t.Fatalf("invalid run ID %q: %v", run, err)
			}
			if len(w.forms) != 0 || slices.ContainsFunc(w.f.RequestMethods(), func(method string) bool {
				return method != http.MethodGet
			}) {
				t.Fatalf("invalid run ID mutated PVE: %v", w.f.Requests())
			}
		})
	}
}

func TestLaunchLiveRunResumesFinalize(t *testing.T) {
	w, m, req := finalizeBackend(t)
	w.b.cfg.LiveTests, req.Count = true, 1
	req.Tags["vws-live-run"] = "resume-997"
	accepted, err := w.b.RunInstances(t.Context(), m, req)
	checkLaunch(t, err)
	w.intercept = func(rw http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodPut && r.ParseForm() == nil && r.Form.Has("tags") {
			rw.WriteHeader(http.StatusBadRequest)
			_, _ = rw.Write([]byte(`{"message":"lost completion write"}`))
			return true
		}
		return false
	}
	if err := w.b.FinalizeLaunches(t.Context(), admitFinalize); err == nil {
		t.Fatal("completion write failure was ignored")
	}
	w.intercept = nil
	w.b, err = New(t.Context(), w.b.client, Identity(w.b), w.b.cfg)
	checkLaunch(t, err)
	retry, err := w.b.RunInstances(t.Context(), m, req)
	checkLaunch(t, err)
	if !reflect.DeepEqual(retry.Items, accepted.Items) || len(w.forms) != 1 {
		t.Fatalf("restart replaced launch: %+v clones=%d", retry, len(w.forms))
	}
	checkLaunch(t, w.b.FinalizeLaunches(t.Context(), admitFinalize))
	checkLaunch(t, w.b.FinalizeLaunches(t.Context(), admitFinalize))
	cfg, err := w.b.client.VMConfig(t.Context(), launchVM(t, w, 0))
	checkLaunch(t, err)
	count := 0
	for _, tag := range strings.Split(cfg.Tags, ";") {
		if tag == "vws.live.resume-997" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("live run tag count=%d config=%+v", count, cfg)
	}
	assertFinalized(t, w, m, accepted)
}
