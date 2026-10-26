package iamclient

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// vwsKeyID is the shape of a vws-iam access key id. Any other id names no
// vws-iam key and is answered as missing without a call.
var vwsKeyID = regexp.MustCompile(`^AKIA[A-Z2-7]{16}$`)

// secretLen is the length of a vws-iam secret access key.
const secretLen = 40

// CreateAccessKey implements iam.Admin over AccessKeyService.CreateAccessKey.
// The secret is in the result only: it never reaches a span, a log record
// or an error, and nothing keeps it. vws-iam does not replay the call, so it
// is sent once: a retry after a lost response would create a second key.
// want must be the user's ARN when the user is read before the call.
func (a STSAdmin) CreateAccessKey(
	ctx context.Context, account resource.AccountID, user string, want iam.AuthorizedPrincipal,
) (out iam.NewAccessKey, err error) {
	var keyID string
	ctx, end := a.observeKey(ctx, "CreateAccessKey", true, account, user, "", &keyID)
	defer func() { end(err) }()
	if err := want.Require(); err != nil {
		return iam.NewAccessKey{}, err
	}
	if !entityName(user) {
		return iam.NewAccessKey{}, entityNotFound("user", user)
	}
	u, err := a.keyUser(ctx, account, user, want)
	if err != nil {
		return iam.NewAccessKey{}, err
	}
	resp, err := call(ctx, a.accessKeys.CreateAccessKey, &iamv1.CreateAccessKeyRequest{
		Parent: userResource(account, user), RequestId: newRequestID(),
	})
	if err != nil {
		return iam.NewAccessKey{}, keyError(err, "user", user)
	}
	meta, err := keyMeta(account, u, resp.GetAccessKey())
	if err != nil {
		return iam.NewAccessKey{}, err
	}
	keyID = meta.AccessKeyID
	if len(resp.GetSecretAccessKey()) != secretLen {
		return iam.NewAccessKey{}, resource.Internal(
			errors.New("vws-iam CreateAccessKey returned a secret of the wrong length"))
	}
	return iam.NewAccessKey{AccessKeyMeta: meta, Secret: resp.GetSecretAccessKey()}, nil
}

// ListAccessKeys implements iam.Admin over AccessKeyService.ListAccessKeys,
// every page, sorted by key id. want must be the user's ARN when the user is
// read before the pages and again after them.
func (a STSAdmin) ListAccessKeys(
	ctx context.Context, account resource.AccountID, user string, want iam.AuthorizedPrincipal,
) (out []iam.AccessKeyMeta, err error) {
	ctx, end := a.observe(ctx, "ListAccessKeys", false, account, user, "")
	defer func() { end(err) }()
	if err := want.Require(); err != nil {
		return nil, err
	}
	if !entityName(user) {
		return nil, entityNotFound("user", user)
	}
	u, err := a.keyUser(ctx, account, user, want)
	if err != nil {
		return nil, err
	}
	out = []iam.AccessKeyMeta{}
	token := ""
	for {
		page, err := retry(ctx, a.backoff, a.accessKeys.ListAccessKeys, &iamv1.ListAccessKeysRequest{
			Parent: userResource(account, user), PageSize: 100, PageToken: token,
		})
		if err != nil {
			return nil, keyError(err, "user", user)
		}
		for _, k := range page.GetAccessKeys() {
			meta, err := keyMeta(account, u, k)
			if err != nil {
				return nil, err
			}
			out = append(out, meta)
		}
		token = page.GetNextPageToken()
		if token == "" {
			break
		}
	}
	if _, err := a.keyUser(ctx, account, user, want); err != nil {
		return nil, err
	}
	slices.SortFunc(out, func(x, y iam.AccessKeyMeta) int { return strings.Compare(x.AccessKeyID, y.AccessKeyID) })
	return out, nil
}

// DeleteAccessKey implements iam.Admin over AccessKeyService.DeleteAccessKey,
// replayed by request_id, so it is retried. It sends no etag: vws-iam bumps
// a key's version on every use, so an etag read here could already be
// stale. want must be the user's ARN when the user is read before the call.
func (a STSAdmin) DeleteAccessKey(
	ctx context.Context, account resource.AccountID, user, keyID string, want iam.AuthorizedPrincipal,
) (err error) {
	ctx, end := a.observeKey(ctx, "DeleteAccessKey", true, account, user, "", &keyID)
	defer func() { end(err) }()
	if err := want.Require(); err != nil {
		return err
	}
	if !entityName(user) {
		return entityNotFound("user", user)
	}
	if _, err := a.keyUser(ctx, account, user, want); err != nil {
		return err
	}
	if !vwsKeyID.MatchString(keyID) {
		return iam.EntityNotFound("Access Key", keyID)
	}
	op, err := retry(ctx, a.backoff, a.accessKeys.DeleteAccessKey, &iamv1.DeleteAccessKeyRequest{
		Name: userResource(account, user) + "/accessKeys/" + keyID, RequestId: newRequestID(),
	})
	if err != nil {
		return keyError(err, "Access Key", keyID)
	}
	return opError(op, "Access Key", keyID)
}

// keyUser reads the user an access key call acts on and checks that want is
// its ARN.
func (a STSAdmin) keyUser(
	ctx context.Context, account resource.AccountID, user string, want iam.AuthorizedPrincipal,
) (iam.User, error) {
	return a.GetUser(ctx, account, user, want)
}

// keyError maps a vws-iam failure of an access key call. LimitExceeded is
// the AWS AccessKeysPerUser quota, and Throttling a 503 the SDK retries.
// NotFound names what the caller named.
func keyError(err error, what, name string) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	if st.Code() == codes.ResourceExhausted {
		for _, d := range st.Details() {
			if info, ok := d.(*errdetails.ErrorInfo); ok {
				switch info.GetMetadata()["aws_code"] {
				case "LimitExceeded":
					return iam.AccessKeysPerUserExceeded()
				case "Throttling":
					return backendUnavailable(err)
				}
			}
		}
	}
	return entityError(err, what, name)
}

// keyMeta maps one vws-iam key of user to the AWS AccessKeyMetadata. A key
// of another user, a malformed id or an unknown state is an internal error.
func keyMeta(account resource.AccountID, u iam.User, k *iamv1.AccessKey) (iam.AccessKeyMeta, error) {
	parent, id, ok := strings.Cut(k.GetName(), "/accessKeys/")
	if !ok || !sameResource(parent, userResource(account, u.Name)) || !userResourceInAccount(account, parent) {
		return iam.AccessKeyMeta{}, resource.Internal(errors.New("vws-iam returned a key of another user"))
	}
	if !vwsKeyID.MatchString(id) {
		return iam.AccessKeyMeta{}, resource.Internal(errors.New("vws-iam returned a malformed access key id"))
	}
	var state string
	switch k.GetSpec().GetState() { //nolint:exhaustive // any other state is an internal error.
	case iamv1.AccessKeyState_ACCESS_KEY_STATE_ACTIVE:
		state = "Active"
	case iamv1.AccessKeyState_ACCESS_KEY_STATE_INACTIVE:
		state = "Inactive"
	default:
		return iam.AccessKeyMeta{}, resource.Internal(
			errors.New("vws-iam returned access key " + id + " in state " + k.GetSpec().GetState().String()))
	}
	if k.GetCreateTime() == nil {
		return iam.AccessKeyMeta{}, resource.Internal(
			errors.New("vws-iam returned access key " + id + " with no create time"))
	}
	return iam.AccessKeyMeta{UserName: u.Name, AccessKeyID: id, Status: state, Created: k.GetCreateTime().AsTime()}, nil
}
