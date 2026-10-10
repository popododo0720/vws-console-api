package resource

// Snapshot states. A create is pending until the next read, then completed.
const (
	SnapshotPending   = "pending"
	SnapshotCompleted = "completed"
)

// Snapshot is a copy of one volume.
type Snapshot struct {
	ID          SnapshotID `json:"snapshotId"`
	OwnerID     AccountID  `json:"ownerId"`
	VolumeID    VolumeID   `json:"volumeId"`
	VolumeSize  int64      `json:"volumeSize"`
	State       string     `json:"state"`
	Description string     `json:"description,omitempty"`
}

// Owner returns the account that owns the snapshot.
func (s Snapshot) Owner() AccountID { return s.OwnerID }

// Identity returns the snapshot id.
func (s Snapshot) Identity() string { return s.ID.String() }

// CreateSnapshotRequest copies a volume.
type CreateSnapshotRequest struct {
	VolumeID    VolumeID `json:"volumeId"`
	Description string   `json:"description,omitempty"`
}

// Action returns CreateSnapshot.
func (CreateSnapshotRequest) Action() Action { return ActionCreateSnapshot }

// Normalize checks the volume and the description length.
func (r CreateSnapshotRequest) Normalize() (CreateSnapshotRequest, error) {
	if r.VolumeID.IsZero() {
		return CreateSnapshotRequest{}, Invalid("volumeId", "required")
	}
	if len(r.Description) > 255 {
		return CreateSnapshotRequest{}, Invalid("description", "malformed")
	}
	return r, nil
}

// DeleteSnapshotRequest deletes one snapshot.
type DeleteSnapshotRequest struct {
	ID SnapshotID `json:"snapshotId"`
}

// Action returns DeleteSnapshot.
func (DeleteSnapshotRequest) Action() Action { return ActionDeleteSnapshot }

// Normalize checks the id.
func (r DeleteSnapshotRequest) Normalize() (DeleteSnapshotRequest, error) {
	if r.ID.IsZero() {
		return DeleteSnapshotRequest{}, Invalid("snapshotId", "required")
	}
	return r, nil
}

// SnapshotQuery selects snapshots.
type SnapshotQuery struct {
	IDs  []SnapshotID `json:"snapshotIds,omitempty"`
	Page PageRequest  `json:"page,omitempty"`
}

// Normalize canonicalizes the page.
func (q SnapshotQuery) Normalize() (SnapshotQuery, error) {
	page, err := q.Page.Normalize()
	if err != nil {
		return SnapshotQuery{}, err
	}
	q.Page = page
	return q, nil
}
