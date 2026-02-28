package cloud

import (
	"testing"
)

func TestParseAWSSGs_OpenIngress(t *testing.T) {
	input := `{
		"SecurityGroups": [{
			"GroupId": "sg-123",
			"GroupName": "wide-open",
			"IpPermissions": [{
				"FromPort": 22,
				"ToPort": 22,
				"IpProtocol": "tcp",
				"IpRanges": [{"CidrIp": "0.0.0.0/0"}],
				"Ipv6Ranges": []
			}, {
				"FromPort": 443,
				"ToPort": 443,
				"IpProtocol": "tcp",
				"IpRanges": [{"CidrIp": "10.0.0.0/8"}],
				"Ipv6Ranges": []
			}]
		}]
	}`
	rules, totalSGs := parseAWSSGs(input)
	if totalSGs != 1 {
		t.Errorf("expected 1 SG, got %d", totalSGs)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 open rule (SSH), got %d", len(rules))
	}
	if rules[0].Port != "22" {
		t.Errorf("expected port 22, got %s", rules[0].Port)
	}
	if rules[0].Source != "0.0.0.0/0" {
		t.Errorf("expected source 0.0.0.0/0, got %s", rules[0].Source)
	}
}

func TestParseAWSSGs_AllPorts(t *testing.T) {
	input := `{
		"SecurityGroups": [{
			"GroupId": "sg-456",
			"GroupName": "all-ports",
			"IpPermissions": [{
				"IpProtocol": "-1",
				"IpRanges": [{"CidrIp": "0.0.0.0/0"}],
				"Ipv6Ranges": []
			}]
		}]
	}`
	rules, _ := parseAWSSGs(input)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Port != "all" {
		t.Errorf("expected port 'all', got %s", rules[0].Port)
	}
}

func TestParseAWSFlowLogs_Enabled(t *testing.T) {
	input := `{"FlowLogs": [{"FlowLogId": "fl-123"}]}`
	if !parseAWSFlowLogs(input) {
		t.Error("expected flow logs enabled")
	}
}

func TestParseAWSFlowLogs_Disabled(t *testing.T) {
	input := `{"FlowLogs": []}`
	if parseAWSFlowLogs(input) {
		t.Error("expected flow logs disabled")
	}
}

func TestParseAWSPublicIPs(t *testing.T) {
	input := `{"Addresses": [{"PublicIp": "1.2.3.4"}, {"PublicIp": "5.6.7.8"}]}`
	ips := parseAWSPublicIPs(input)
	if len(ips) != 2 {
		t.Fatalf("expected 2 IPs, got %d", len(ips))
	}
}

func TestPortRange(t *testing.T) {
	cases := []struct {
		from, to *int
		want     string
	}{
		{intPtr(22), intPtr(22), "22"},
		{intPtr(80), intPtr(443), "80-443"},
		{nil, nil, "all"},
	}
	for _, c := range cases {
		got := portRange(c.from, c.to)
		if got != c.want {
			t.Errorf("portRange(%v, %v) = %q, want %q", c.from, c.to, got, c.want)
		}
	}
}

func intPtr(n int) *int { return &n }
