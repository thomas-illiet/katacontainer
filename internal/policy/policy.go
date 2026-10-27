package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
)

const (
	ProtocolTCP uint8 = 6
	ProtocolUDP uint8 = 17
)

type Document struct {
	Egress []Rule `json:"egress"`
}

type Rule struct {
	CIDRs    []string `json:"cidrs"`
	Protocol string   `json:"protocol"`
	Ports    []uint16 `json:"ports"`
}

type Entry struct {
	Prefix   netip.Prefix
	Protocol uint8
	Port     uint16
}

func Load(path string) ([]Entry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	var doc Document
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	return Normalize(doc)
}

func Normalize(doc Document) ([]Entry, error) {
	if len(doc.Egress) == 0 {
		return nil, errors.New("policy must contain at least one egress rule")
	}
	seen := map[string]struct{}{}
	entries := make([]Entry, 0)
	for i, rule := range doc.Egress {
		if len(rule.CIDRs) == 0 || len(rule.Ports) == 0 {
			return nil, fmt.Errorf("egress rule %d must contain cidrs and ports", i)
		}
		var protocol uint8
		switch strings.ToUpper(rule.Protocol) {
		case "TCP":
			protocol = ProtocolTCP
		case "UDP":
			protocol = ProtocolUDP
		default:
			return nil, fmt.Errorf("egress rule %d has unsupported protocol %q", i, rule.Protocol)
		}
		for _, rawCIDR := range rule.CIDRs {
			prefix, err := netip.ParsePrefix(rawCIDR)
			if err != nil {
				return nil, fmt.Errorf("egress rule %d: invalid CIDR %q: %w", i, rawCIDR, err)
			}
			prefix = prefix.Masked()
			for _, port := range rule.Ports {
				if port == 0 {
					return nil, fmt.Errorf("egress rule %d: port 0 is not allowed", i)
				}
				key := fmt.Sprintf("%s/%d/%d", prefix, protocol, port)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				entries = append(entries, Entry{Prefix: prefix, Protocol: protocol, Port: port})
			}
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Prefix.String() != entries[j].Prefix.String() {
			return entries[i].Prefix.String() < entries[j].Prefix.String()
		}
		if entries[i].Protocol != entries[j].Protocol {
			return entries[i].Protocol < entries[j].Protocol
		}
		return entries[i].Port < entries[j].Port
	})
	return entries, nil
}
