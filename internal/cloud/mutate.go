package cloud

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// idempotencyVersion is part of every key. Changing the derivation requires a
// new version: retries that cross that deploy will not dedupe.
const idempotencyVersion = "vws-idem-v1"

func mutate[R resource.Request[R], T resource.Owned](
	ctx context.Context,
	s *Service,
	c resource.Caller,
	token resource.ClientToken,
	req R,
	call func(context.Context, backend.Mutation, R) (resource.Accepted[T], error),
) (resource.Accepted[T], error) {
	if token.IsZero() {
		return resource.Accepted[T]{}, resource.Invalid("clientToken", "required")
	}
	req, err := req.Normalize()
	if err != nil {
		return resource.Accepted[T]{}, err
	}
	m, err := mutation(c, token, req)
	if err != nil {
		return resource.Accepted[T]{}, resource.Internal(err)
	}
	acc, err := call(ctx, m, req)
	if err != nil {
		return resource.Accepted[T]{}, err
	}
	if err := guardAccepted(c.Account, acc); err != nil {
		return resource.Accepted[T]{}, err
	}
	s.audit.InfoContext(ctx, "mutation accepted",
		"action", req.Action().String(),
		"account", c.Account.String(),
		"subject", c.Subject,
		"operation", acc.Operation.ID.String())
	return acc, nil
}

func readOne[Q resource.Query[Q], T resource.Owned](
	ctx context.Context,
	c resource.Caller,
	q Q,
	call func(context.Context, backend.Scope, Q) (T, error),
) (T, error) {
	var zero T
	q, err := q.Normalize()
	if err != nil {
		return zero, err
	}
	item, err := call(ctx, scope(c), q)
	if err != nil {
		return zero, err
	}
	if err := guardOwner(c.Account, item); err != nil {
		return zero, err
	}
	return item, nil
}

func readPage[Q resource.Query[Q], T resource.Owned](
	ctx context.Context,
	c resource.Caller,
	q Q,
	call func(context.Context, backend.Scope, Q) (resource.Page[T], error),
) (resource.Page[T], error) {
	q, err := q.Normalize()
	if err != nil {
		return resource.Page[T]{}, err
	}
	page, err := call(ctx, scope(c), q)
	if err != nil {
		return resource.Page[T]{}, err
	}
	for _, item := range page.Items {
		if err := guardOwner(c.Account, item); err != nil {
			return resource.Page[T]{}, err
		}
	}
	return page, nil
}

func callScoped(ctx context.Context, c resource.Caller, call func(context.Context, backend.Scope) error) error {
	return call(ctx, scope(c))
}

func guardAccepted[T resource.Owned](account resource.AccountID, acc resource.Accepted[T]) error {
	if acc.Operation.ID.IsZero() || acc.Operation.State.String() == "" {
		return resource.Internal(errors.New("backend returned no operation"))
	}
	if len(acc.Items) == 0 {
		return resource.Internal(errors.New("backend returned no resources"))
	}
	ids := map[string]struct{}{}
	for _, item := range acc.Items {
		if err := guardOwner(account, item); err != nil {
			return err
		}
		ids[item.Identity()] = struct{}{}
	}
	if len(acc.Operation.Targets) != len(ids) {
		return resource.Internal(errors.New("operation targets do not match the result"))
	}
	for _, target := range acc.Operation.Targets {
		if _, ok := ids[target.ID()]; !ok {
			return resource.Internal(errors.New("operation target is not in the result"))
		}
	}
	return nil
}

func guardOwner(account resource.AccountID, item resource.Owned) error {
	if item.Owner() != account {
		return resource.Internal(errors.New("backend returned another account"))
	}
	return nil
}

func mutation[R resource.Request[R]](c resource.Caller, token resource.ClientToken, req R) (backend.Mutation, error) {
	k := sha256.New()
	for _, part := range []string{idempotencyVersion, c.Account.String(), req.Action().String(), token.String()} {
		_, _ = k.Write([]byte(part))
		_, _ = k.Write([]byte{0})
	}
	canon, err := canonical(req)
	if err != nil {
		return backend.Mutation{}, err
	}
	f := sha256.Sum256(append([]byte(idempotencyVersion+"\x00"), canon...))
	return backend.Mutation{
		Scope:       scope(c),
		Key:         hex.EncodeToString(k.Sum(nil)),
		Fingerprint: hex.EncodeToString(f[:]),
	}, nil
}

func canonical(req any) ([]byte, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		return nil, err
	}
	out, err := json.Marshal(prune(tree))
	if err != nil {
		return nil, err
	}
	return out, nil
}

func prune(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case bool:
		if !x {
			return nil
		}
		return x
	case float64:
		if x == 0 {
			return nil
		}
		return x
	case string:
		if x == "" {
			return nil
		}
		return x
	case []any:
		var out []any
		for _, item := range x {
			if p := prune(item); p != nil {
				out = append(out, p)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for key, item := range x {
			if p := prune(item); p != nil {
				out[key] = p
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	default:
		return v
	}
}
