package p2p

import "testing"

func TestDetectNATType(t *testing.T) {
	tests := []struct {
		name       string
		localAddr  string
		publicAddr string
		want       NATType
	}{
		{
			name:       "no nat full cone",
			localAddr:  "192.168.1.10:4000",
			publicAddr: "192.168.1.10:4000",
			want:       NATOpenOrFullCone,
		},
		{
			name:       "port preserved different ip",
			localAddr:  "10.0.0.2:5000",
			publicAddr: "8.8.8.8:5000",
			want:       NATPortRestrictedCone,
		},
		{
			name:       "port changed symmetric",
			localAddr:  "10.0.0.2:5000",
			publicAddr: "8.8.8.8:62000",
			want:       NATSymmetric,
		},
		{
			name:       "parse failure unknown",
			localAddr:  "bad-addr",
			publicAddr: "8.8.8.8:62000",
			want:       NATUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectNATType(tt.localAddr, tt.publicAddr); got != tt.want {
				t.Fatalf("DetectNATType() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestParseNATType(t *testing.T) {
	if got := ParseNATType("symmetric"); got != NATSymmetric {
		t.Fatalf("ParseNATType(symmetric) = %s", got)
	}
	if got := ParseNATType("unknown-value"); got != NATUnknown {
		t.Fatalf("ParseNATType(invalid) = %s", got)
	}
}
