package resource

// Image states, as EC2 names them. A registered image is pending until its
// copy is done.
const (
	ImagePending   = "pending"
	ImageAvailable = "available"
)

// RegisterImageRequest registers a machine image whose root volume is a copy
// of one completed snapshot the caller owns.
type RegisterImageRequest struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	SnapshotID  SnapshotID `json:"snapshotId"`
}

// Action returns RegisterImage.
func (RegisterImageRequest) Action() Action { return ActionRegisterImage }

// Normalize checks the name, the description and the snapshot. EC2 takes a
// name of 3 to 128 letters, digits and ( ) [ ] space . / - ' @ _, and a
// description of at most 255 characters.
func (r RegisterImageRequest) Normalize() (RegisterImageRequest, error) {
	if r.Name == "" {
		return RegisterImageRequest{}, MissingParameter("name", "The request must contain the parameter name")
	}
	if !validImageName(r.Name) {
		return RegisterImageRequest{}, InvalidImageName(r.Name)
	}
	if len([]rune(r.Description)) > 255 {
		return RegisterImageRequest{}, Invalid("description", "must be at most 255 characters")
	}
	if r.SnapshotID.IsZero() {
		return RegisterImageRequest{}, MissingParameter("snapshotId", "The request must contain the parameter snapshotId")
	}
	return r, nil
}

func validImageName(name string) bool {
	if len(name) < 3 || len(name) > 128 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '(' || r == ')' || r == '[' || r == ']' || r == ' ' || r == '.' ||
			r == '/' || r == '-' || r == '\'' || r == '@' || r == '_':
		default:
			return false
		}
	}
	return true
}

// InvalidImageName reports an image name EC2 does not take. EC2 answers
// InvalidAMIName.Malformed.
func InvalidImageName(name string) *Error {
	return &Error{
		Code: CodeInvalidArgument, Kind: KindImage, Field: "name",
		Message: "AMI names must be between 3 and 128 characters long, and may contain letters, numbers, " +
			"spaces and ( ) [ ] . / - ' @ _: " + name,
	}
}

// IsInvalidImageName reports whether e came from InvalidImageName.
func IsInvalidImageName(e *Error) bool {
	return e != nil && e.Code == CodeInvalidArgument && e.Kind == KindImage && e.Field == "name"
}

// SnapshotNotCompleted refuses an image from a snapshot whose copy is not
// done: the image would copy a volume that is still being read. EC2 answers
// a resource in the wrong state with IncorrectState.
func SnapshotNotCompleted(id SnapshotID) *Error {
	return Conflict(KindSnapshot, id.String(), "Snapshot '"+id.String()+"' is not in the completed state.")
}
