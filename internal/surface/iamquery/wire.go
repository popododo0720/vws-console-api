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
	return policyXML{
		PolicyName: p.Name, PolicyID: p.ID, Arn: p.ARN, Path: p.Path, DefaultVersionID: "v1",
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
