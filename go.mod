module github.com/popododo0720/vws-console-api

go 1.26.0

toolchain go1.26.9

require (
	cloud.google.com/go/longrunning v1.3.0
	github.com/popododo0720/vws-proto v0.3.0
	golang.org/x/crypto v0.57.0
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260928230214-8a89bd6388cc
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.60.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20261005182115-fad411399dd8 // indirect
)

replace github.com/popododo0720/vws-proto => ./third_party/vws-proto
