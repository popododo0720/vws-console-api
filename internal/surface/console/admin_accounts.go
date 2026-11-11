package console

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/popododo0720/vws-lib/obs"
	"go.opentelemetry.io/otel/trace"

	"github.com/popododo0720/vws-console-api/internal/admin/store"
	"github.com/popododo0720/vws-console-api/internal/audit"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/server"
	"github.com/popododo0720/vws-console-api/internal/service"
)

type accountView struct {
	ID             string               `json:"awsAccountId"`
	RoleARN        string               `json:"roleArn"`
	ExternalID     store.SecretMetadata `json:"externalId"`
	AllowedRegions []string             `json:"allowedRegions"`
	Version        store.Version        `json:"-"`
}

func viewAccount(v store.AWSAccount) accountView {
	return accountView{v.ID, v.RoleARN, v.ExternalID, v.AllowedRegions, v.Version}
}

type accountInput struct {
	ID             *string   `json:"awsAccountId"`
	RoleARN        *string   `json:"roleArn"`
	ExternalID     *string   `json:"externalId"`
	AllowedRegions *[]string `json:"allowedRegions"`
}

func (h *handler) adminWriteAccount(w http.ResponseWriter, r *http.Request) {
	if !h.adminReady(w, r) {
		return
	}
	if h.adminKey == nil {
		writeErr(w, r, &resource.Error{Code: resource.CodeUnavailable, Message: "admin writes require credentials.kek_file"})
		return
	}
	var v store.AWSAccount
	if r.Method != http.MethodPost {
		id := r.PathValue("id")
		if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(id) {
			writeErr(w, r, resource.Invalid("awsAccountId", "must be 12 digits"))
			return
		}
		match := r.Header.Get("If-Match")
		if match == "" && r.Method == http.MethodPatch {
			writeErr(w, r, resource.Invalid("If-Match", "required"))
			return
		}
		var err error
		v, err = h.registry.AWSAccounts().Get(r.Context(), id)
		if err != nil {
			adminError(w, r, err)
			return
		}
		setAuditAccount(w, id)
		if match != "" && match != strconv.Quote(strconv.FormatInt(int64(v.Version), 10)) {
			adminError(w, r, store.ErrConflict)
			return
		}
	}
	if r.Method == http.MethodDelete {
		if err := h.registry.AWSAccounts().Delete(r.Context(), v.ID, v.Version); err != nil {
			adminError(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var in *accountInput
	if err := decode(w, r, &in); err != nil {
		writeErr(w, r, err)
		return
	}
	if in == nil {
		writeErr(w, r, resource.Invalid("body", "expected one JSON object"))
		return
	}
	if in.ID != nil {
		if r.Method == http.MethodPatch && *in.ID != v.ID {
			writeErr(w, r, resource.Invalid("awsAccountId", "must match path"))
			return
		}
		v.ID = *in.ID
	}
	if in.RoleARN != nil {
		v.RoleARN = *in.RoleARN
	}
	if in.AllowedRegions != nil {
		v.AllowedRegions = *in.AllowedRegions
	}
	if regexp.MustCompile(`^[0-9]{12}$`).MatchString(v.ID) {
		setAuditAccount(w, v.ID)
	}
	if err := validateAccount(v, in.ExternalID, r.Method == http.MethodPost); err != nil {
		writeErr(w, r, err)
		return
	}
	if in.ExternalID != nil {
		sealed, err := h.adminKey.Seal([]byte(*in.ExternalID), v.ID)
		if err != nil {
			adminError(w, r, err)
			return
		}
		v.SealedExternalID, v.ExternalID = sealed, store.DescribeSecret(*in.ExternalID)
	}
	var err error
	status := http.StatusOK
	if r.Method == http.MethodPost {
		v, err = h.registry.AWSAccounts().Create(r.Context(), v)
		status = http.StatusCreated
	} else {
		v, err = h.registry.AWSAccounts().Update(r.Context(), v)
	}
	if err != nil {
		adminError(w, r, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(int64(v.Version), 10)))
	writeJSON(w, status, viewAccount(v))
}

func validateAccount(v store.AWSAccount, external *string, create bool) error {
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(v.ID) {
		return resource.Invalid("awsAccountId", "must be 12 digits")
	}
	role, ok := strings.CutPrefix(v.RoleARN, "arn:aws:iam::"+v.ID+":role/")
	path, name := "", role
	if i := strings.LastIndex(role, "/"); i >= 0 {
		path, name = "/"+role[:i+1], role[i+1:]
	}
	if !ok || len(v.RoleARN) > 2048 || len(path) > 512 ||
		!regexp.MustCompile(`^[\w+=,.@-]{1,64}$`).MatchString(name) ||
		(path != "" && !regexp.MustCompile(`^/[\x21-\x7e]+/$`).MatchString(path)) {
		return resource.Invalid("roleArn", "must name an IAM role in awsAccountId")
	}
	if create && external == nil || external != nil &&
		(len(*external) < 2 || len(*external) > 1224 || !regexp.MustCompile(`^[\w+=,.@:/-]+$`).MatchString(*external)) {
		return resource.Invalid("externalId", "must be 2 to 1224 STS ExternalId characters")
	}
	seen := make(map[string]bool)
	for _, region := range v.AllowedRegions {
		if seen[region] || strings.HasPrefix(region, "pve-") ||
			!regexp.MustCompile(`^(af|ap|ca|cn|eu|il|me|mx|sa|us)(-[a-z]+)+-[1-9][0-9]*$`).MatchString(region) {
			return resource.Invalid("allowedRegions", "must contain unique AWS region names")
		}
		seen[region] = true
	}
	if len(seen) == 0 {
		return resource.Invalid("allowedRegions", "at least one AWS region is required")
	}
	return nil
}

type adminResponse struct {
	http.ResponseWriter
	status int
	id     string
}

func setAuditAccount(w http.ResponseWriter, id string) {
	if out, ok := w.(*adminResponse); ok {
		out.id = id
	}
}

func (w *adminResponse) WriteHeader(status int) {
	w.status = status
	if status >= http.StatusInternalServerError {
		server.RecordFailure(w.ResponseWriter, errors.New("admin change failed"))
	}
	w.ResponseWriter.WriteHeader(status)
}

func accountAction(pattern string) string {
	switch pattern {
	case "POST /api/v1/admin/aws-accounts":
		return "AdminRegisterAwsAccount"
	case "PATCH /api/v1/admin/aws-accounts/{id}":
		return "AdminUpdateAwsAccount"
	case "DELETE /api/v1/admin/aws-accounts/{id}":
		return "AdminRemoveAwsAccount"
	case "POST /api/v1/admin/regions":
		return "AdminRegisterRegion"
	case "PATCH /api/v1/admin/regions/{name}":
		return "AdminUpdateRegion"
	case "DELETE /api/v1/admin/regions/{name}":
		return "AdminRemoveRegion"
	}
	return ""
}

func (h *handler) auditAccount(w *adminResponse, r *http.Request, c resource.Caller, action string, start time.Time) {
	if h.audit == nil {
		return
	}
	result := audit.Accepted
	if w.status >= http.StatusBadRequest {
		result = audit.Error(strconv.Itoa(w.status))
		if w.status == http.StatusForbidden || w.status == http.StatusUnauthorized {
			result = audit.Denied
		}
	}
	err := h.audit.Record(r.Context(), audit.Entry{
		RequestID: obs.RequestID(r.Context()), TraceID: trace.SpanContextFromContext(r.Context()).TraceID().String(),
		PrincipalARN: c.Principal, Account: c.Account.String(), Destination: audit.Admin,
		Service: service.Name, Action: action, ResourceIDs: []string{w.id}, Result: result,
		Latency: h.now().Sub(start), SourceIP: h.clientIP(r),
	})
	if err != nil {
		server.RecordFailure(w.ResponseWriter, errors.New("admin audit write failed"))
	}
}
