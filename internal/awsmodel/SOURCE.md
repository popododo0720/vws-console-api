# EC2 service model

The unmodified source is botocore tag `1.44.1`, commit
`0827014f7ae2cf33e70475c3168f8ed2d687a013`, API version `2016-11-15`.

Source: https://raw.githubusercontent.com/boto/botocore/1.44.1/botocore/data/ec2/2016-11-15/service-2.json

The uncompressed file is 4,234,826 bytes with 811 operations. Its SHA256 is
`0a555a258ede57c3883d06ace705a8bbd1c972bf190ac7e369e215eb72d2d87a`.
`LoadEC2` checks this digest before decoding.

To refresh, choose a botocore release, download its `service-2.json` to
`$TMPDIR`, independently check the release commit and SHA256, then run:

```sh
gzip -9 -n -c "$TMPDIR/service-2.json" > internal/awsmodel/ec2-2016-11-15.json.gz
go generate ./internal/surface/ec2query/...
go test -race -count=1 ./internal/awsmodel/... ./internal/surface/ec2query/...
```

Update this record, `ec2Digest`, the generator's source header and the operation
count test together. Review all key differences and deviation entries.
Tests, generation and CI use only the committed model and never download it.

Spelling follows botocore's `EC2Serializer`: use `queryName`, otherwise
`locationName` with its first letter capitalized, otherwise the member name.
Lists flatten to `.N` irrespective of their member's location name. Structures
join members with dots. Only top-level required members mark generated keys
required; nested requirements do not make an optional parent required.
