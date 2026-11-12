// Package awsmodel reads the pinned botocore EC2 service description.
package awsmodel

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
)

const ec2Digest = "0a555a258ede57c3883d06ace705a8bbd1c972bf190ac7e369e215eb72d2d87a"

//go:embed ec2-2016-11-15.json.gz
var files embed.FS

// Model contains the input contract of an AWS service.
type Model struct {
	Metadata struct {
		APIVersion string `json:"apiVersion"`
	} `json:"metadata"`
	OperationsByName map[string]operation `json:"operations"`
	Shapes           map[string]shape     `json:"shapes"`
}

type operation struct {
	Name  string    `json:"name"`
	Input reference `json:"input"`
}

type reference struct {
	Shape        string `json:"shape"`
	LocationName string `json:"locationName"`
	QueryName    string `json:"queryName"`
}

type shape struct {
	Type     string               `json:"type"`
	Members  map[string]reference `json:"members"`
	Member   reference            `json:"member"`
	Required []string             `json:"required"`
	Enum     []string             `json:"enum"`
	Min      *float64             `json:"min"`
	Max      *float64             `json:"max"`
}

// LoadEC2 verifies and decodes the committed EC2 model without network access.
func LoadEC2() (*Model, error) {
	raw, err := files.ReadFile("ec2-2016-11-15.json.gz")
	if err != nil {
		return nil, fmt.Errorf("read embedded EC2 model: %w", err)
	}
	return load(raw)
}

func load(raw []byte) (_ *Model, err error) {
	z, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("open EC2 model gzip: %w", err)
	}
	defer func() {
		if closeErr := z.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close EC2 model gzip: %w", closeErr)
		}
	}()
	data, err := io.ReadAll(z)
	if err != nil {
		return nil, fmt.Errorf("decompress EC2 model: %w", err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != ec2Digest {
		return nil, fmt.Errorf("EC2 model digest mismatch: got %s, want %s", got, ec2Digest)
	}
	var model Model
	if err := json.Unmarshal(data, &model); err != nil {
		return nil, fmt.Errorf("decode EC2 model: %w", err)
	}
	return &model, nil
}

// Operations returns the model's operation names in lexical order.
func (m *Model) Operations() []string {
	return slices.Sorted(maps.Keys(m.OperationsByName))
}
