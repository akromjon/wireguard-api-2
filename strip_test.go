package main

import (
	"strings"
	"testing"
)

func TestStripQuickConfig(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr string
	}{
		{
			name: "basic",
			in:   "[Interface]\nAddress = 10.66.0.1/16\nListenPort = 51820\nPrivateKey = k\nPostUp = iptables -A x\n\n[Peer]\nPublicKey = p\nAllowedIPs = 10.66.0.2/32\n",
			want: "[Interface]\nListenPort = 51820\nPrivateKey = k\n\n[Peer]\nPublicKey = p\nAllowedIPs = 10.66.0.2/32\n\n",
		},
		{
			name: "all dropped keys, mixed case",
			in:   "[interface]\naddress = a\nMTU = 1420\ndns = 1.1.1.1\nTable = off\npreup = x\nPreDown = x\nPOSTUP = x\nPostDown = x\nSaveConfig = true\nListenPort = 1\n",
			want: "[interface]\nListenPort = 1\n\n",
		},
		{
			name: "peer keeps same names",
			in:   "[Peer]\nDNS = 1.1.1.1\nTable = off\n",
			want: "[Peer]\nDNS = 1.1.1.1\nTable = off\n\n",
		},
		{
			name: "section switch",
			in:   "[Interface]\nListenPort = 1\n[Peer]\nAddress = kept\n[Interface]\nAddress = dropped\n",
			want: "[Interface]\nListenPort = 1\n[Peer]\nAddress = kept\n[Interface]\n\n",
		},
		{
			name: "trim and comments",
			in:   "  [Interface]\t\n\tListenPort = 1   # port\n# Client foo\n  Address=10.0.0.1/24 # addr\n",
			want: "[Interface]\nListenPort = 1   # port\n# Client foo\n\n",
		},
		{
			name: "crlf",
			in:   "[Interface]\r\nAddress = a\r\nListenPort = 1\r\n",
			want: "[Interface]\r\nListenPort = 1\r\n\n",
		},
		{
			name: "no final newline",
			in:   "[Interface]\nListenPort = 1",
			want: "[Interface]\nListenPort = 1\n\n",
		},
		{
			name: "whitespace-only final fragment",
			in:   "[Interface]\n   ",
			want: "[Interface]\n\n",
		},
		{
			name: "empty",
			in:   "",
			want: "\n",
		},
		{
			name:    "bad SaveConfig",
			in:      "[Interface]\nSaveConfig = maybe\n",
			wantErr: "SaveConfig",
		},
		{
			name: "header-protection and awg keys kept",
			in:   "[Interface]\nJc = 4\nH1 = 1\nI1 = <b 0x01>\nHeaderProtectionKey = abc\n",
			want: "[Interface]\nJc = 4\nH1 = 1\nI1 = <b 0x01>\nHeaderProtectionKey = abc\n\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := stripQuickConfig([]byte(tc.in))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v (output %q)", tc.wantErr, err, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}
