package iamclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
	"github.com/popododo0720/vws-console-api/internal/sshkey"
)

func keyPairRequestID(m backend.Mutation, action string) string {
	sum := sha256.Sum256([]byte(m.Account.String() + "\x00" + m.Region + "\x00" + action + "\x00" + m.Key))
	sum[6], sum[8] = sum[6]&0x0f|0x40, sum[8]&0x3f|0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", sum[:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

func keyPairError(err error, name string) error {
	for _, detail := range status.Convert(err).Details() {
		if info, ok := detail.(*errdetails.ErrorInfo); ok && info.GetMetadata()["aws_code"] == "IdempotentParameterMismatch" {
			return resource.IdempotencyMismatch()
		}
	}
	if status.Code(err) == codes.NotFound {
		return resource.NotFound(resource.KindKeyPair, name)
	}
	if status.Code(err) == codes.AlreadyExists {
		return resource.AlreadyExists(resource.KindKeyPair, name)
	}
	return authError(err)
}

func keyPairOperationError(op *longrunningpb.Operation, err error, name string) error {
	if err != nil {
		return keyPairError(err, name)
	}
	if op == nil || !op.GetDone() {
		return resource.Internal(errors.New("vws-iam returned no completed key pair operation"))
	}
	if op.GetError() != nil {
		return keyPairError(status.ErrorProto(op.GetError()), name)
	}
	return nil
}

func keyPairModel(s backend.Scope, in *iamv1.KeyPair) (resource.KeyPair, error) {
	local, ok := strings.CutPrefix(in.GetName(), projectName(s.Account)+"/keyPairs/")
	id, err := resource.Parse[resource.KeyPairID](local)
	if !ok || err != nil || s.Region != "all" && in.GetSpec().GetRegion() != s.Region {
		return resource.KeyPair{}, resource.Internal(errors.New("vws-iam returned a key pair outside the requested scope"))
	}
	pub, err := sshkey.ParsePublic(in.GetSpec().GetPublicKey())
	if err != nil {
		return resource.KeyPair{}, resource.Internal(errors.New("vws-iam returned an invalid public key"))
	}
	fingerprint := pub.AWSFingerprint
	if sha1 := in.GetLabels()["vws-key-sha1"]; sha1 != "" {
		fingerprint = sshkey.ColonHex(sha1)
	}
	return resource.KeyPair{
		Regional: resource.Regional{Region: in.GetSpec().GetRegion()}, ID: id, OwnerID: s.Account,
		Name: in.GetSpec().GetKeyName(), Fingerprint: fingerprint, Type: pub.Type,
	}, nil
}

// DescribeKeyPairs reads IAM's regional namespace without a region transport.
func (c *Client) DescribeKeyPairs(
	ctx context.Context, s backend.Scope, q resource.KeyPairQuery,
) (resource.Page[resource.KeyPair], error) {
	q, err := q.Normalize()
	if err != nil {
		return resource.Page[resource.KeyPair]{}, err
	}
	items, err := c.listKeyPairs(ctx, s, q)
	if err != nil {
		return resource.Page[resource.KeyPair]{}, err
	}
	for _, name := range q.Names {
		if !slices.ContainsFunc(items, func(k resource.KeyPair) bool { return k.Name == name }) {
			return resource.Page[resource.KeyPair]{}, resource.NotFound(resource.KindKeyPair, name)
		}
	}
	for _, id := range q.IDs {
		if !slices.ContainsFunc(items, func(k resource.KeyPair) bool { return k.ID == id }) {
			return resource.Page[resource.KeyPair]{}, resource.NotFound(resource.KindKeyPair, id.String())
		}
	}
	slices.SortFunc(items, func(a, b resource.KeyPair) int { return strings.Compare(a.ID.String(), b.ID.String()) })
	if q.Page.Token != "" {
		index := slices.IndexFunc(items, func(k resource.KeyPair) bool { return k.ID.String() == q.Page.Token })
		if index < 0 {
			return resource.Page[resource.KeyPair]{}, resource.Invalid("pageToken", "unknown")
		}
		items = items[index+1:]
	}
	out := resource.Page[resource.KeyPair]{Items: items}
	if len(items) > q.Page.Size {
		out.Items = items[:q.Page.Size]
		out.NextToken = out.Items[len(out.Items)-1].ID.String()
	}
	return out, nil
}

func (c *Client) listKeyPairs(
	ctx context.Context, s backend.Scope, q resource.KeyPairQuery,
) ([]resource.KeyPair, error) {
	ctx, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	if len(q.Names) > 200 {
		return nil, resource.Invalid("keyNames", "at most 200 names")
	}
	region := s.Region
	if region == "all" {
		region = ""
	}
	var items []resource.KeyPair
	token := ""
	for {
		resp, err := retry(ctx, c.backoff, c.keyPairs.ListKeyPairs, &iamv1.ListKeyPairsRequest{
			Parent: projectName(s.Account), Region: region, KeyNames: q.Names, PageSize: 100, PageToken: token,
		})
		if err != nil {
			return nil, keyPairError(err, "")
		}
		for _, raw := range resp.GetKeyPairs() {
			key, err := keyPairModel(s, raw)
			if err != nil {
				c.logger().WarnContext(ctx, "skipping invalid IAM key pair", slog.String("reason", "invalid record"))
				continue
			}
			if len(q.IDs) == 0 || slices.Contains(q.IDs, key.ID) {
				items = append(items, key)
			}
		}
		next := resp.GetNextPageToken()
		if next == "" {
			break
		}
		if next == token {
			return nil, resource.Internal(errors.New("vws-iam repeated a key pair cursor"))
		}
		token = next
	}
	return items, nil
}

// CreateKeyPair keeps private material local, preserving EC2 PEM/PPK formats.
// IAM imports only the public key and atomically reserves its regional name.
func (c *Client) CreateKeyPair(
	ctx context.Context, m backend.Mutation, req resource.CreateKeyPairRequest,
) (resource.Accepted[resource.KeyPair], error) {
	req, err := req.Normalize()
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	var pair sshkey.Pair
	labels := map[string]string{}
	requestID := keyPairRequestID(m, "ImportKeyPair")
	if req.PublicKey != "" {
		pub, err := sshkey.ParsePublic(req.PublicKey)
		if err != nil {
			return resource.Accepted[resource.KeyPair]{}, resource.Invalid("publicKeyMaterial", "invalid public key")
		}
		pair.Public = pub.Line
	} else {
		pair, err = sshkey.Generate(req.Type, rand.Reader)
		if err != nil {
			return resource.Accepted[resource.KeyPair]{}, resource.Internal(err)
		}
		if req.Type == resource.KeyTypeRSA {
			labels["vws-key-sha1"] = strings.ReplaceAll(pair.AWSFingerprint, ":", "")
		}
		requestID = keyPairRequestID(m, "CreateKeyPair\x00"+req.Name)
	}
	op, err := retry(ctx, c.backoff, c.keyPairs.ImportKeyPair, &iamv1.ImportKeyPairRequest{
		Parent: projectName(m.Account), Region: m.Region, KeyName: req.Name,
		PublicKey: pair.Public, Labels: labels, RequestId: requestID,
	})
	if err := keyPairOperationError(op, err, req.Name); err != nil {
		// EC2 generated creates return Duplicate, never replayed private material.
		if req.PublicKey == "" && resource.CodeOf(err) == resource.CodeIdempotencyMismatch {
			return resource.Accepted[resource.KeyPair]{}, resource.AlreadyExists(resource.KindKeyPair, req.Name)
		}
		return resource.Accepted[resource.KeyPair]{}, err
	}
	raw := new(iamv1.KeyPair)
	if err := op.GetResponse().UnmarshalTo(raw); err != nil {
		return resource.Accepted[resource.KeyPair]{}, resource.Internal(err)
	}
	if raw.GetSpec().GetKeyName() != req.Name || raw.GetSpec().GetPublicKey() != pair.Public {
		return resource.Accepted[resource.KeyPair]{}, resource.Internal(errors.New("vws-iam returned a different key pair"))
	}
	key, err := keyPairModel(m.Scope, raw)
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	key.Material = pair.Private
	if req.Format == resource.KeyFormatPPK {
		key.Material = pair.PPK(req.Name)
	}
	return acceptedKeyPair(m, resource.ActionCreateKeyPair, key)
}

// DeleteKeyPair resolves selectors in the caller's region before deleting.
func (c *Client) DeleteKeyPair(
	ctx context.Context, m backend.Mutation, req resource.DeleteKeyPairRequest,
) (resource.Accepted[resource.KeyPair], error) {
	if !req.ID.IsZero() && req.Name != "" {
		return resource.Accepted[resource.KeyPair]{}, resource.InvalidCombination("keyName", "specify either name or ID")
	}
	q := resource.KeyPairQuery{}
	if !req.ID.IsZero() {
		q.IDs = []resource.KeyPairID{req.ID}
	}
	if req.Name != "" {
		q.Names = []string{req.Name}
	}
	if _, err := req.Normalize(); err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	items, err := c.listKeyPairs(ctx, m.Scope, q)
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	if len(items) == 0 {
		return acceptedKeyPair(m, resource.ActionDeleteKeyPair)
	}
	key := items[0]
	op, err := retry(ctx, c.backoff, c.keyPairs.DeleteKeyPair, &iamv1.DeleteKeyPairRequest{
		Name:      projectName(m.Account) + "/keyPairs/" + key.ID.String(),
		RequestId: keyPairRequestID(m, "DeleteKeyPair"), AllowMissing: true,
	})
	if err := keyPairOperationError(op, err, key.Name); err != nil {
		return resource.Accepted[resource.KeyPair]{}, err
	}
	return acceptedKeyPair(m, resource.ActionDeleteKeyPair, key)
}

func acceptedKeyPair(
	m backend.Mutation, action resource.Action, keys ...resource.KeyPair,
) (resource.Accepted[resource.KeyPair], error) {
	sum := sha256.Sum256([]byte(keyPairRequestID(m, action.String())))
	id, err := resource.NewOperationID(resource.ServiceCompute, fmt.Sprintf("%x", sum[:20]))
	if err != nil {
		return resource.Accepted[resource.KeyPair]{}, resource.Internal(err)
	}
	out := resource.Accepted[resource.KeyPair]{
		Operation: resource.Operation{
			ID: id, OwnerID: m.Account, Action: action, State: resource.OperationSucceeded,
		},
		Items: keys,
	}
	for _, key := range keys {
		out.Operation.Targets = append(out.Operation.Targets, key.ID.Ref())
	}
	return out, nil
}
