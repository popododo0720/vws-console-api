package resource

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
