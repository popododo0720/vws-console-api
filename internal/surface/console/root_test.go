package console

import (
	"github.com/popododo0720/vws-console-api/internal/cloud"
	"github.com/popododo0720/vws-console-api/internal/iam"
	"github.com/popododo0720/vws-console-api/internal/resource"
)

// rootConfig serves bearer "tok" as the account root, authorized by the
// static root key: the pre-login behaviour every older test relies on.
func rootConfig(svc *cloud.Service, account resource.AccountID) Config {
	return Config{
		Service: svc,
		IAM:     iam.NewStatic("AKIDEXAMPLE", "secret", account),
		Auth:    BearerTokens{"tok": {Account: account, Subject: "t", Principal: iam.RootARN(account), Root: true}},
	}
}
