// Package acl decides which client addresses may reach a shared service.
package acl

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// List is a set of allowed address ranges. The zero value allows nothing.
type List struct {
	prefixes []netip.Prefix
	all      bool
}

// Parse builds a List from IP addresses and CIDR ranges.
// The unspecified address (0.0.0.0, ::) or a range with a zero-length prefix allows every address.
// It returns an error for an empty list or an unparsable entry.
func Parse(entries []string) (List, error) {
	if len(entries) == 0 {
		return List{}, errors.New("allowlist is empty")
	}
	var list List
	for _, entry := range entries {
		prefix, err := parsePrefix(strings.TrimSpace(entry))
		if err != nil {
			return List{}, err
		}
		if prefix.Bits() == 0 {
			list.all = true
			continue
		}
		list.prefixes = append(list.prefixes, prefix)
	}
	return list, nil
}

// Allows reports whether addr is inside one of the ranges or the list allows every address.
func (l List) Allows(addr netip.Addr) bool {
	if l.all {
		return true
	}
	addr = addr.Unmap().WithZone("")
	for _, prefix := range l.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func parsePrefix(entry string) (netip.Prefix, error) {
	if !strings.Contains(entry, "/") {
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("parse allowlist entry %q: %w", entry, err)
		}
		addr = addr.Unmap().WithZone("")
		if addr.IsUnspecified() {
			return netip.PrefixFrom(addr, 0), nil
		}
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	prefix, err := netip.ParsePrefix(entry)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("parse allowlist entry %q: %w", entry, err)
	}
	return prefix.Masked(), nil
}
