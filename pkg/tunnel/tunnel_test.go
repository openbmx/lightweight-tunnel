package tunnel

import (
	"testing"
)

func TestGetPeerIP(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		want      string
		expectErr bool
	}{
		{
			name:  "switch from .1 to .2",
			input: "10.0.0.1/24",
			want:  "10.0.0.2/24",
		},
		{
			name:  "switch from .2 to .1",
			input: "10.0.0.2/24",
			want:  "10.0.0.1/24",
		},
		{
			name:      "invalid broadcast octet",
			input:     "10.0.0.255/24",
			expectErr: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetPeerIP(tt.input)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got)
			}
		})
	}
}

func TestGetServerTunnelIP(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		want      string
		expectErr bool
	}{
		{
			name:  "client IP .2 derives server .1",
			input: "10.0.0.2/24",
			want:  "10.0.0.1",
		},
		{
			name:  "client IP .3 derives server .1",
			input: "10.0.0.3/24",
			want:  "10.0.0.1",
		},
		{
			name:  "client IP .100 derives server .1",
			input: "10.0.0.100/24",
			want:  "10.0.0.1",
		},
		{
			name:  "already server IP .1 returns .1",
			input: "10.0.0.1/24",
			want:  "10.0.0.1",
		},
		{
			name:      "invalid format - no CIDR",
			input:     "10.0.0.1",
			expectErr: true,
		},
		{
			name:      "invalid IP address",
			input:     "invalid/24",
			expectErr: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getServerTunnelIP(tt.input)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.String() != tt.want {
				t.Fatalf("expected %s, got %s", tt.want, got.String())
			}
		})
	}
}
