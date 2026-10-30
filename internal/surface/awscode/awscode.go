// Package awscode holds the AWS error tables of the console API's surfaces.
//
// The tables are policy: which AWS error code and HTTP status a resource.Code
// and resource.Kind become on EC2 Query and S3 REST. errs defines the shape
// and the lookup. A combination missing from a table answers InternalFailure
// and the surface counts the miss (docs/rules.md).
package awscode

import (
	"net/http"

	"github.com/popododo0720/vws-lib/errs"

	"github.com/popododo0720/vws-console-api/internal/resource"
)

// Code converts a resource.Code to the shared errs.Code. The two sets are the
// same set in the same order; TestCodesMatchErrCodes fails if they drift.
func Code(c resource.Code) errs.Code { return errs.Code(c) }

// Kind converts a resource.Kind to the shared errs.Kind. The two sets are the
// same set in the same order; TestCodesMatchErrCodes fails if they drift.
func Kind(k resource.Kind) errs.Kind { return errs.Kind(k) }

// EC2Default is the EC2 Query answer for a (Code, Kind) without a Kind
// override. Every Code has an entry so a miss means a new Code shipped
// without a mapping, which TestAWSEC2TableIsComplete catches.
//
//nolint:gochecknoglobals // a read-only table, the point of this package.
var EC2Default = map[errs.Code]errs.AWSEntry{
	errs.CodeUnspecified:         {HTTP: http.StatusInternalServerError, Code: "InternalError"},
	errs.CodeInvalidArgument:     {HTTP: http.StatusBadRequest, Code: "InvalidParameterValue"},
	errs.CodeNotFound:            {HTTP: http.StatusBadRequest, Code: "InvalidParameterValue"},
	errs.CodeAlreadyExists:       {HTTP: http.StatusBadRequest, Code: "InvalidParameterValue"},
	errs.CodeConflict:            {HTTP: http.StatusBadRequest, Code: "IncorrectInstanceState"},
	errs.CodeIdempotencyMismatch: {HTTP: http.StatusBadRequest, Code: "IdempotentParameterMismatch"},
	errs.CodeUnauthenticated:     {HTTP: http.StatusUnauthorized, Code: "AuthFailure"},
	errs.CodePermissionDenied:    {HTTP: http.StatusForbidden, Code: "UnauthorizedOperation"},
	errs.CodeResourceExhausted:   {HTTP: http.StatusServiceUnavailable, Code: "RequestLimitExceeded"},
	errs.CodePayloadTooLarge:     {HTTP: http.StatusBadRequest, Code: "InvalidParameterValue"},
	errs.CodeUnavailable:         {HTTP: http.StatusServiceUnavailable, Code: "Unavailable"},
	errs.CodeUnimplemented:       {HTTP: http.StatusBadRequest, Code: "InvalidAction"},
	errs.CodeInternal:            {HTTP: http.StatusInternalServerError, Code: "InternalError"},
}

// EC2ByKind overrides EC2Default for one Kind. The ids carry the AWS message,
// so the code names the kind where AWS does.
//
//nolint:gochecknoglobals // a read-only table, the point of this package.
var EC2ByKind = map[errs.Code]map[errs.Kind]errs.AWSEntry{
	errs.CodeNotFound: {
		errs.KindInstance:      {HTTP: http.StatusBadRequest, Code: "InvalidInstanceID.NotFound"},
		errs.KindImage:         {HTTP: http.StatusBadRequest, Code: "InvalidAMIID.NotFound"},
		errs.KindSubnet:        {HTTP: http.StatusBadRequest, Code: "InvalidSubnetID.NotFound"},
		errs.KindVpc:           {HTTP: http.StatusBadRequest, Code: "InvalidVpcID.NotFound"},
		errs.KindVolume:        {HTTP: http.StatusBadRequest, Code: "InvalidVolume.NotFound"},
		errs.KindSecurityGroup: {HTTP: http.StatusBadRequest, Code: "InvalidGroup.NotFound"},
		errs.KindKeyPair:       {HTTP: http.StatusBadRequest, Code: "InvalidKeyPair.NotFound"},
		errs.KindAddress:       {HTTP: http.StatusBadRequest, Code: "InvalidAllocationID.NotFound"},
		errs.KindSnapshot:      {HTTP: http.StatusBadRequest, Code: "InvalidSnapshot.NotFound"},
	},
	errs.CodeAlreadyExists: {
		errs.KindSecurityGroup: {HTTP: http.StatusBadRequest, Code: "InvalidGroup.Duplicate"},
		errs.KindKeyPair:       {HTTP: http.StatusBadRequest, Code: "InvalidKeyPair.Duplicate"},
	},
	errs.CodeConflict: {
		// A key pair is not an instance: EC2's IncorrectState is the
		// resource-neutral state error (#291).
		errs.KindVolume:  {HTTP: http.StatusBadRequest, Code: "IncorrectState"},
		errs.KindKeyPair: {HTTP: http.StatusBadRequest, Code: "IncorrectState"},
		errs.KindVpc:     {HTTP: http.StatusBadRequest, Code: "DependencyViolation"},
		errs.KindSubnet:  {HTTP: http.StatusBadRequest, Code: "DependencyViolation"},
	},
}

// S3Default is the S3 REST answer for a (Code, Kind) without a Kind override.
//
//nolint:gochecknoglobals // a read-only table, the point of this package.
var S3Default = map[errs.Code]errs.AWSEntry{
	errs.CodeUnspecified:         {HTTP: http.StatusInternalServerError, Code: "InternalError"},
	errs.CodeInvalidArgument:     {HTTP: http.StatusBadRequest, Code: "InvalidArgument"},
	errs.CodeNotFound:            {HTTP: http.StatusNotFound, Code: "NoSuchBucket"},
	errs.CodeAlreadyExists:       {HTTP: http.StatusConflict, Code: "BucketAlreadyExists"},
	errs.CodeConflict:            {HTTP: http.StatusConflict, Code: "BucketNotEmpty"},
	errs.CodeIdempotencyMismatch: {HTTP: http.StatusConflict, Code: "OperationAborted"},
	errs.CodeUnauthenticated:     {HTTP: http.StatusForbidden, Code: "AccessDenied"},
	errs.CodePermissionDenied:    {HTTP: http.StatusForbidden, Code: "AccessDenied"},
	errs.CodeResourceExhausted:   {HTTP: http.StatusServiceUnavailable, Code: "SlowDown"},
	errs.CodePayloadTooLarge:     {HTTP: http.StatusBadRequest, Code: "EntityTooLarge"},
	errs.CodeUnavailable:         {HTTP: http.StatusServiceUnavailable, Code: "ServiceUnavailable"},
	errs.CodeUnimplemented:       {HTTP: http.StatusNotImplemented, Code: "NotImplemented"},
	errs.CodeInternal:            {HTTP: http.StatusInternalServerError, Code: "InternalError"},
}

// S3ByKind overrides S3Default for one Kind.
//
//nolint:gochecknoglobals // a read-only table, the point of this package.
var S3ByKind = map[errs.Code]map[errs.Kind]errs.AWSEntry{
	errs.CodeNotFound: {
		errs.KindObject: {HTTP: http.StatusNotFound, Code: "NoSuchKey"},
	},
	errs.CodeAlreadyExists: {
		errs.KindObject: {HTTP: http.StatusPreconditionFailed, Code: "PreconditionFailed"},
	},
}

// EC2 looks up the EC2 Query entry for a resource error.
func EC2(code resource.Code, kind resource.Kind) (errs.AWSEntry, bool) {
	return errs.AWSTable{Default: EC2Default, ByKind: EC2ByKind}.Lookup(Code(code), Kind(kind))
}

// S3 looks up the S3 REST entry for a resource error.
func S3(code resource.Code, kind resource.Kind) (errs.AWSEntry, bool) {
	return errs.AWSTable{Default: S3Default, ByKind: S3ByKind}.Lookup(Code(code), Kind(kind))
}
