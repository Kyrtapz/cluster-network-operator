package ip

import (
	configv1 "github.com/openshift/api/config/v1"
	"net"
	"testing"

	. "github.com/onsi/gomega"
)

func TestAddrPool(t *testing.T) {
	g := NewGomegaWithT(t)
	testcases := []struct {
		cidr string
		ok   bool
	}{
		{
			"10.0.0.0/24",
			true,
		},
		{
			"10.0.0.0/24",
			false,
		},
		{
			"10.0.2.0/24",
			true,
		},
		{
			"fe80:1:2:3::/64",
			true,
		},
		{
			"fe80:1:2:3:4::/80",
			false,
		},
	}

	pool := IPPool{}
	for idx, tc := range testcases {
		_, cidr, err := net.ParseCIDR(tc.cidr)
		g.Expect(err).NotTo(HaveOccurred())
		err = pool.Add(*cidr)
		if tc.ok {
			g.Expect(err).NotTo(HaveOccurred(), "tc %d", idx)
		} else {
			g.Expect(err).To(HaveOccurred(), "tc %d", idx)
		}
	}
}

func TestNetsOverlap(t *testing.T) {
	g := NewGomegaWithT(t)
	testcases := []struct {
		cidr1    string
		cidr2    string
		expected bool
	}{
		{
			"10.0.0.0/24",
			"10.0.1.0/24",
			false,
		},
		//
		{
			"10.0.0.0/22",
			"10.0.0.0/24",
			true,
		},
		{
			"10.0.0.0/24",
			"10.0.0.0/22",
			true,
		},
		{
			"10.0.0.0/22",
			"10.0.3.0/24",
			true,
		},
		{
			"fe80:1:2:3::/64",
			"fe80:1:2:3:4::/80",
			true,
		},
	}

	for _, tc := range testcases {
		_, c1, err := net.ParseCIDR(tc.cidr1)
		g.Expect(err).NotTo(HaveOccurred())
		_, c2, err := net.ParseCIDR(tc.cidr2)
		g.Expect(err).NotTo(HaveOccurred())

		g.Expect(NetsOverlap(*c1, *c2)).To(Equal(tc.expected))

	}
}

func TestLastIP(t *testing.T) {
	g := NewGomegaWithT(t)

	testcases := []struct {
		cidr     string
		expected string
	}{
		{
			"10.0.0.0/24",
			"10.0.0.255",
		},
		{
			"10.0.0.128/30",
			"10.0.0.131",
		},
		{
			"fe80:1:2:3::/64",
			"fe80:1:2:3:ffff:ffff:ffff:ffff",
		},
	}

	for _, tc := range testcases {
		_, cidr, err := net.ParseCIDR(tc.cidr)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(lastIP(*cidr).String()).To(Equal(tc.expected))
	}
}

func TestIPsToStrings(t *testing.T) {
	g := NewGomegaWithT(t)

	testcases := []struct {
		ips      []configv1.IP
		expected []string
	}{
		{
			[]configv1.IP{"10.0.0.1", "10.0.0.2"},
			[]string{"10.0.0.1", "10.0.0.2"},
		},
		{
			[]configv1.IP{},
			[]string{},
		},
		{
			[]configv1.IP{"fe80:1:2:3::"},
			[]string{"fe80:1:2:3::"},
		},
	}

	for _, tc := range testcases {
		res := IPsToStrings(tc.ips)
		g.Expect(res).To(Equal(tc.expected))
	}
}

func TestStringsToIPs(t *testing.T) {
	g := NewGomegaWithT(t)

	testcases := []struct {
		ips      []string
		expected []configv1.IP
	}{
		{
			[]string{"10.0.0.1", "10.0.0.2"},
			[]configv1.IP{"10.0.0.1", "10.0.0.2"},
		},
		{
			[]string{},
			[]configv1.IP{},
		},
		{
			[]string{"fe80:1:2:3::"},
			[]configv1.IP{"fe80:1:2:3::"},
		},
	}

	for _, tc := range testcases {
		res := StringsToIPs(tc.ips)
		g.Expect(res).To(Equal(tc.expected))
	}
}
