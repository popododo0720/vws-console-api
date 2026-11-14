package console

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/popododo0720/vws-lib/obs"

	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/server"
	"github.com/popododo0720/vws-console-api/internal/surface/iamquery"
)

func iamRoutes() map[string]string {
	return map[string]string{
		"GET /api/v1/iam/users":                         "ListUsers",
		"POST /api/v1/iam/users":                        "CreateUser",
		"GET /api/v1/iam/users/{name}":                  "GetUser",
		"DELETE /api/v1/iam/users/{name}":               "DeleteUser",
		"POST /api/v1/iam/users/{name}/login-profile":   "CreateLoginProfile",
		"PATCH /api/v1/iam/users/{name}/login-profile":  "UpdateLoginProfile",
		"DELETE /api/v1/iam/users/{name}/login-profile": "DeleteLoginProfile",
	}
}

type iamOperationKey struct{}

type iamInput struct {
	UserName              *string `json:"userName"`
	Path                  *string `json:"path"`
	Password              *string `json:"password"`
	PasswordResetRequired *bool   `json:"passwordResetRequired"`
}

func (h *handler) prepareIAM(w http.ResponseWriter, r *http.Request, c resource.Caller) (*iamquery.Operation, error) {
	params := make(url.Values)
	names := map[string]string{"marker": "Marker", "maxItems": "MaxItems", "pathPrefix": "PathPrefix"}
	for k, values := range r.URL.Query() {
		name, ok := names[k]
		if !ok {
			return nil, resource.Invalid("Input", "unsupported query parameter")
		}
		params[name] = values
	}
	if r.ContentLength != 0 {
		var in *iamInput
		if err := decode(w, r, &in); err != nil {
			return nil, err
		}
		if in == nil {
			return nil, resource.Invalid("Input", "expected one JSON object")
		}
		for k, value := range map[string]*string{
			"UserName": in.UserName, "Path": in.Path, "Password": in.Password,
		} {
			if value != nil {
				params.Add(k, *value)
			}
		}
		if in.PasswordResetRequired != nil {
			params.Add("PasswordResetRequired", strconv.FormatBool(*in.PasswordResetRequired))
		}
	}
	if name := r.PathValue("name"); name != "" {
		params.Add("UserName", name)
	}
	return h.iamRunner.Prepare(r.Context(), c, iamquery.Input{Action: iamRoutes()[r.Pattern], Params: params})
}

func (h *handler) serveIAM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	action := iamRoutes()[r.Pattern]
	op, err := h.prepareIAM(w, r, c)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	r = r.WithContext(context.WithValue(ctx, iamOperationKey{}, op))
	var result any
	if strings.HasPrefix(action, "Create") {
		c, token, ok := h.begin(w, r)
		if !ok {
			return
		}
		key := iamReplayKey{account: c.Account, principal: c.Principal, token: action + ":" + token.String()}
		in := iamCreate{key: key, fingerprint: op.Fingerprint(), now: h.now()}
		result, err = h.iamReplay.create(ctx, in, op.Run)
	} else {
		result, err = op.Run()
	}
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func writeIAMError(w http.ResponseWriter, r *http.Request, err error) {
	e := resource.AsError(err)
	action := ""
	if fn, ok := routeAction(r.Pattern); ok && fn != nil {
		action, _ = fn(r)
	}
	status, code := iamquery.ErrorCode(strings.TrimPrefix(action, "iam:"), err)
	if e.Code == resource.CodeUnauthenticated {
		status, code = http.StatusUnauthorized, "Unauthenticated"
	}
	if e.Code == resource.CodeIdempotencyMismatch {
		status, code = statusOf(e.Code), e.Code.String()
	}
	if status >= http.StatusInternalServerError {
		if out, ok := w.(*iamResponse); ok {
			server.RecordFailure(out.ResponseWriter, err)
		} else {
			server.RecordFailure(w, err)
		}
	}
	writeJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": e.Message}, "requestId": obs.RequestID(r.Context()),
	})
}

type iamResponse struct {
	http.ResponseWriter
	status int
}

func (w *iamResponse) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *iamResponse) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	server.RecordFailure(w.ResponseWriter, err)
	if err != nil {
		return n, fmt.Errorf("write IAM response: %w", err)
	}
	return n, nil
}

func (h *handler) iamCall(w http.ResponseWriter, r *http.Request) {
	_, pattern := h.mux.Handler(r)
	if action, ok := iamRoutes()[pattern]; ok {
		out := &iamResponse{ResponseWriter: w, status: http.StatusOK}
		defer func(ctx context.Context) {
			h.log.InfoContext(ctx, "console IAM request", slog.String("action", "iam:"+action),
				slog.Int("outcome", out.status), slog.String("request_id", obs.RequestID(ctx)))
		}(r.Context())
		w = out
	}
	h.gate(w, r)
}
