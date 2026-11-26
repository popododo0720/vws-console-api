package regionset

import (
	"context"
	"errors"

	"github.com/popododo0720/vws-console-api/internal/backend"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

type keyPairClient interface {
	CreateKeyPair(context.Context, backend.Mutation, resource.CreateKeyPairRequest) (
		resource.Accepted[resource.KeyPair], error)
	DeleteKeyPair(context.Context, backend.Mutation, resource.DeleteKeyPairRequest) (
		resource.Accepted[resource.KeyPair], error)
	DescribeKeyPairs(context.Context, backend.Scope, resource.KeyPairQuery) (resource.Page[resource.KeyPair], error)
}

func (c compute) CreateKeyPair(
	ctx context.Context, m backend.Mutation, req resource.CreateKeyPairRequest,
) (resource.Accepted[resource.KeyPair], error) {
	if c.keys == nil {
		return resource.Accepted[resource.KeyPair]{}, resource.Unsupported("Action", "key pairs require -iam=grpc")
	}
	return c.keys.CreateKeyPair(ctx, m, req)
}

func (c compute) DeleteKeyPair(
	ctx context.Context, m backend.Mutation, req resource.DeleteKeyPairRequest,
) (resource.Accepted[resource.KeyPair], error) {
	if c.keys == nil {
		return resource.Accepted[resource.KeyPair]{}, resource.Unsupported("Action", "key pairs require -iam=grpc")
	}
	return c.keys.DeleteKeyPair(ctx, m, req)
}

// RunInstances resolves KeyName in IAM before any region request and hands
// its public key to the region with the launch. The key is set after the
// kernel computed the request fingerprint, so the fingerprint never depends
// on it.
func (c compute) RunInstances(
	ctx context.Context, m backend.Mutation, req resource.RunInstancesRequest,
) (resource.Accepted[resource.Instance], error) {
	req.PublicKey = ""
	if req.KeyName != "" {
		if c.keys == nil {
			return resource.Accepted[resource.Instance]{}, resource.Unsupported("keyName", "key pairs require -iam=grpc")
		}
		page, err := c.keys.DescribeKeyPairs(ctx, m.Scope, resource.KeyPairQuery{Names: []string{req.KeyName}})
		if err != nil {
			return resource.Accepted[resource.Instance]{}, err
		}
		for _, key := range page.Items {
			if key.Name == req.KeyName {
				req.PublicKey = key.PublicKey
				break
			}
		}
		if req.PublicKey == "" {
			return resource.Accepted[resource.Instance]{},
				resource.Internal(errors.New("IAM returned no public key for the key name"))
		}
	}
	return c.Compute.RunInstances(ctx, m, req)
}
