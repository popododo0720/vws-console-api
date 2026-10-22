package iamquery

import "github.com/popododo0720/vws-console-api/internal/iam"

type userXML struct {
	Path       string `xml:"Path,omitempty"`
	UserName   string `xml:"UserName,omitempty"`
	UserID     string `xml:"UserId"`
	Arn        string `xml:"Arn"`
	CreateDate string `xml:"CreateDate,omitempty"`
}

func toUser(u iam.User) userXML {
	return userXML{Path: u.Path, UserName: u.Name, UserID: u.ID, Arn: u.ARN, CreateDate: stamp(u.Created)}
}

type groupXML struct {
	Path       string `xml:"Path"`
	GroupName  string `xml:"GroupName"`
	GroupID    string `xml:"GroupId"`
	Arn        string `xml:"Arn"`
	CreateDate string `xml:"CreateDate"`
}

func toGroup(g iam.Group) groupXML {
	return groupXML{Path: g.Path, GroupName: g.Name, GroupID: g.ID, Arn: g.ARN, CreateDate: stamp(g.Created)}
}

type roleXML struct {
	Path                     string `xml:"Path"`
	RoleName                 string `xml:"RoleName"`
	RoleID                   string `xml:"RoleId"`
	Arn                      string `xml:"Arn"`
	CreateDate               string `xml:"CreateDate"`
	AssumeRolePolicyDocument string `xml:"AssumeRolePolicyDocument"`
	Description              string `xml:"Description,omitempty"`
	MaxSessionDuration       int    `xml:"MaxSessionDuration"`
}

func toRole(r iam.Role) roleXML {
	return roleXML{
		Path: r.Path, RoleName: r.Name, RoleID: r.ID, Arn: r.ARN, CreateDate: stamp(r.Created),
		AssumeRolePolicyDocument: policyDoc(r.TrustPolicy),
		Description:              r.Description,
		MaxSessionDuration:       r.MaxSessionDuration,
	}
}

type policyXML struct {
	PolicyName                    string `xml:"PolicyName"`
	PolicyID                      string `xml:"PolicyId"`
	Arn                           string `xml:"Arn"`
	Path                          string `xml:"Path"`
	DefaultVersionID              string `xml:"DefaultVersionId"`
	AttachmentCount               int    `xml:"AttachmentCount"`
	PermissionsBoundaryUsageCount int    `xml:"PermissionsBoundaryUsageCount"`
	IsAttachable                  bool   `xml:"IsAttachable"`
	Description                   string `xml:"Description,omitempty"`
	CreateDate                    string `xml:"CreateDate"`
	UpdateDate                    string `xml:"UpdateDate"`
}

func toPolicy(p iam.ManagedPolicy) policyXML {
	version := p.DefaultVersion
	if version == "" {
		version = "v1"
	}
	return policyXML{
		PolicyName: p.Name, PolicyID: p.ID, Arn: p.ARN, Path: p.Path, DefaultVersionID: version,
		AttachmentCount: p.AttachmentCount, IsAttachable: true, Description: p.Description,
		CreateDate: stamp(p.Created), UpdateDate: stamp(p.Updated),
	}
}

type attachedXML struct {
	PolicyName string `xml:"PolicyName"`
	PolicyArn  string `xml:"PolicyArn"`
}

type keyMetaXML struct {
	UserName    string `xml:"UserName"`
	AccessKeyID string `xml:"AccessKeyId"`
	Status      string `xml:"Status"`
	CreateDate  string `xml:"CreateDate"`
}

type accessKeyXML struct {
	UserName        string `xml:"UserName"`
	AccessKeyID     string `xml:"AccessKeyId"`
	Status          string `xml:"Status"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	CreateDate      string `xml:"CreateDate"`
}

type accessKeyLastUsedXML struct {
	LastUsedDate string `xml:"LastUsedDate,omitempty"`
	ServiceName  string `xml:"ServiceName"`
	Region       string `xml:"Region"`
}

type accessKeyLastUsedResult struct {
	AccessKeyLastUsed accessKeyLastUsedXML `xml:"AccessKeyLastUsed"`
	UserName          string               `xml:"UserName"`
}

func toAccessKeyLastUsed(u iam.AccessKeyLastUsed) accessKeyLastUsedResult {
	used := accessKeyLastUsedXML{ServiceName: "N/A", Region: "N/A"}
	if !u.LastUsed.IsZero() {
		used.LastUsedDate = stamp(u.LastUsed)
		used.ServiceName = u.Service
		used.Region = u.Region
	}
	if used.ServiceName == "" {
		used.ServiceName = "N/A"
	}
	if used.Region == "" {
		used.Region = "N/A"
	}
	return accessKeyLastUsedResult{AccessKeyLastUsed: used, UserName: u.UserName}
}

// mfaDeviceXML is the GetMFADevice result. vws-iam carries no FIDO
// certification levels, so Certifications is present and empty.
type mfaDeviceXML struct {
	UserName       string   `xml:"UserName,omitempty"`
	SerialNumber   string   `xml:"SerialNumber"`
	EnableDate     string   `xml:"EnableDate,omitempty"`
	Certifications struct{} `xml:"Certifications"`
}

func toMFADevice(d iam.MFADevice) mfaDeviceXML {
	out := mfaDeviceXML{UserName: d.UserName, SerialNumber: d.SerialNumber}
	if !d.Enabled.IsZero() {
		out.EnableDate = stamp(d.Enabled)
	}
	return out
}

type policyVersionXML struct {
	Document         string `xml:"Document,omitempty"`
	VersionID        string `xml:"VersionId"`
	IsDefaultVersion bool   `xml:"IsDefaultVersion"`
	CreateDate       string `xml:"CreateDate"`
}

// policyVersionsResult is the ListPolicyVersions result. AWS leaves out the
// document here; GetPolicyVersion returns it.
type policyVersionsResult struct {
	Versions    []policyVersionXML `xml:"Versions>member"`
	IsTruncated bool               `xml:"IsTruncated"`
	Marker      string             `xml:"Marker,omitempty"`
}

type credentialsXML struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

type loginProfileXML struct {
	UserName              string `xml:"UserName"`
	CreateDate            string `xml:"CreateDate"`
	PasswordResetRequired bool   `xml:"PasswordResetRequired"`
}

func toLoginProfile(p iam.LoginProfile) loginProfileXML {
	return loginProfileXML{UserName: p.UserName, CreateDate: stamp(p.Created)}
}
