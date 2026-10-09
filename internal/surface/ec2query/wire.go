package ec2query

import "github.com/popododo0720/vws-console-api/internal/resource"

type runInstancesXML struct {
	XMLName       struct{}    `xml:"RunInstancesResponse"`
	RequestID     string      `xml:"requestId"`
	ReservationID string      `xml:"reservationId"`
	Instances     instanceSet `xml:"instancesSet"`
}

type describeInstancesXML struct {
	XMLName      struct{} `xml:"DescribeInstancesResponse"`
	RequestID    string   `xml:"requestId"`
	NextToken    string   `xml:"nextToken,omitempty"`
	Reservations struct {
		Items []reservationItem `xml:"item"`
	} `xml:"reservationSet"`
}

type reservationItem struct {
	ReservationID string      `xml:"reservationId"`
	Instances     instanceSet `xml:"instancesSet"`
}

type instanceSet struct {
	Items []instanceItem `xml:"item"`
}

type instanceItem struct {
	InstanceID   string   `xml:"instanceId"`
	ImageID      string   `xml:"imageId"`
	InstanceType string   `xml:"instanceType"`
	SubnetID     string   `xml:"subnetId"`
	Zone         string   `xml:"placement>availabilityZone"`
	PrivateIP    string   `xml:"privateIpAddress,omitempty"`
	State        stateXML `xml:"instanceState"`
}

type stateXML struct {
	Code int    `xml:"code"`
	Name string `xml:"name"`
}

type stopInstancesXML struct {
	XMLName   struct{} `xml:"StopInstancesResponse"`
	RequestID string   `xml:"requestId"`
	Instances struct {
		Items []stateItem `xml:"item"`
	} `xml:"instancesSet"`
}

type stateItem struct {
	InstanceID    string   `xml:"instanceId"`
	CurrentState  stateXML `xml:"currentState"`
	PreviousState stateXML `xml:"previousState"`
}

type createSubnetXML struct {
	XMLName   struct{}   `xml:"CreateSubnetResponse"`
	RequestID string     `xml:"requestId"`
	Subnet    subnetItem `xml:"subnet"`
}

type describeSubnetsXML struct {
	XMLName   struct{} `xml:"DescribeSubnetsResponse"`
	RequestID string   `xml:"requestId"`
	NextToken string   `xml:"nextToken,omitempty"`
	Subnets   struct {
		Items []subnetItem `xml:"item"`
	} `xml:"subnetSet"`
}

type subnetItem struct {
	SubnetID string `xml:"subnetId"`
	Cidr     string `xml:"cidrBlock"`
	State    string `xml:"state"`
}

type errorXML struct {
	XMLName   struct{} `xml:"Response"`
	Code      string   `xml:"Errors>Error>Code"`
	Message   string   `xml:"Errors>Error>Message"`
	RequestID string   `xml:"RequestID"`
}

func instanceItems(items []resource.Instance) instanceSet {
	var out instanceSet
	for _, inst := range items {
		out.Items = append(out.Items, instanceItem{
			InstanceID:   inst.ID.String(),
			ImageID:      inst.ImageID.String(),
			InstanceType: inst.InstanceType,
			SubnetID:     inst.SubnetID.String(),
			Zone:         inst.Zone,
			PrivateIP:    inst.PrivateIP,
			State:        stateXMLOf(inst.State),
		})
	}
	return out
}

func stateXMLOf(s resource.InstanceState) stateXML {
	return stateXML{Code: s.EC2Code(), Name: s.String()}
}

func subnetXML(s resource.Subnet) subnetItem {
	return subnetItem{SubnetID: s.ID.String(), Cidr: s.Cidr, State: s.State.String()}
}
