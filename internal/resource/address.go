package resource

import "strings"

// Address is a static public address. Domain is "vpc".
type Address struct {
	ID         AddressID  `json:"allocationId"`
	OwnerID    AccountID  `json:"ownerId"`
	PublicIP   string     `json:"publicIp,omitempty"`
	Domain     string     `json:"domain,omitempty"`
	InstanceID InstanceID `json:"instanceId,omitzero"`
}

// Owner returns the account that owns the address.
func (a Address) Owner() AccountID { return a.OwnerID }

// Identity returns the allocation id.
func (a Address) Identity() string { return a.ID.String() }

// AllocateAddressRequest reserves an address.
type AllocateAddressRequest struct {
	Domain string `json:"domain,omitempty"`
}

// Action returns AllocateAddress.
func (AllocateAddressRequest) Action() Action { return ActionAllocateAddress }

// Normalize defaults the domain to vpc.
func (r AllocateAddressRequest) Normalize() (AllocateAddressRequest, error) {
	if r.Domain == "" {
		r.Domain = "vpc"
	}
	if r.Domain != "vpc" {
		return AllocateAddressRequest{}, Invalid("domain", "must be vpc")
	}
	return r, nil
}

// ReleaseAddressRequest releases one address.
type ReleaseAddressRequest struct {
	ID AddressID `json:"allocationId"`
}

// Action returns ReleaseAddress.
func (ReleaseAddressRequest) Action() Action { return ActionReleaseAddress }

// Normalize checks the id.
func (r ReleaseAddressRequest) Normalize() (ReleaseAddressRequest, error) {
	if r.ID.IsZero() {
		return ReleaseAddressRequest{}, Invalid("allocationId", "required")
	}
	return r, nil
}

// associationPrefix starts an EC2 association id. An address has at most one
// association, so the id reuses the allocation id digits.
const associationPrefix = "eipassoc-"

// AssociationID returns the association id of address id.
func AssociationID(id AddressID) string {
	return associationPrefix + strings.TrimPrefix(id.String(), KindAddress.info().prefix)
}

// ParseAssociationID returns the address an association id names.
func ParseAssociationID(s string) (AddressID, error) {
	digits, ok := strings.CutPrefix(s, associationPrefix)
	if !ok {
		return AddressID{}, Invalid("associationId", "malformed")
	}
	id, err := Parse[AddressID](KindAddress.info().prefix + digits)
	if err != nil {
		return AddressID{}, Invalid("associationId", "malformed")
	}
	return id, nil
}

// AssociationNotFound reports a DisassociateAddress whose association does
// not exist: the address is unknown, or it has no association. EC2 answers
// InvalidAssociationID.NotFound for both.
func AssociationNotFound(id AddressID) *Error {
	return &Error{Code: CodeNotFound, Kind: KindAddress, ID: AssociationID(id), Field: "associationId", Message: "association not found"}
}

// IsAssociationNotFound reports whether e came from AssociationNotFound.
func IsAssociationNotFound(e *Error) bool {
	return e != nil && e.Code == CodeNotFound && e.Kind == KindAddress && e.Field == "associationId"
}

// AssociateAddressRequest attaches an address to an instance's network
// interface. It replaces an existing association.
type AssociateAddressRequest struct {
	ID         AddressID  `json:"allocationId"`
	InstanceID InstanceID `json:"instanceId"`
}

// Action returns AssociateAddress.
func (AssociateAddressRequest) Action() Action { return ActionAssociateAddress }

// Normalize checks both ids.
func (r AssociateAddressRequest) Normalize() (AssociateAddressRequest, error) {
	if r.ID.IsZero() {
		return AssociateAddressRequest{}, Invalid("allocationId", "required")
	}
	if r.InstanceID.IsZero() {
		return AssociateAddressRequest{}, Invalid("instanceId", "required")
	}
	return r, nil
}

// DisassociateAddressRequest detaches an address. An unknown or idle address
// is AssociationNotFound.
type DisassociateAddressRequest struct {
	ID AddressID `json:"allocationId"`
}

// Action returns DisassociateAddress.
func (DisassociateAddressRequest) Action() Action { return ActionDisassociateAddress }

// Normalize checks the id.
func (r DisassociateAddressRequest) Normalize() (DisassociateAddressRequest, error) {
	if r.ID.IsZero() {
		return DisassociateAddressRequest{}, Invalid("allocationId", "required")
	}
	return r, nil
}

// AddressQuery selects addresses.
type AddressQuery struct {
	IDs       []AddressID `json:"allocationIds,omitempty"`
	PublicIPs []string    `json:"publicIps,omitempty"`
	Page      PageRequest `json:"page,omitempty"`
}

// Normalize canonicalizes the page.
func (q AddressQuery) Normalize() (AddressQuery, error) {
	page, err := q.Page.Normalize()
	if err != nil {
		return AddressQuery{}, err
	}
	q.Page = page
	return q, nil
}
