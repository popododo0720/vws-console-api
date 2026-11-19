package resource

// MaxObjectBytes is the largest request body the signature check and the AWS
// proxy buffer: 4 MiB. Larger bodies belong on a path that does not buffer
// them here.
const MaxObjectBytes = 4 << 20
