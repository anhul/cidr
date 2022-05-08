import pytest
from cidr import Cidr


class TestCidr:
    cidrs = [Cidr("192.168.0.1/1"),
             Cidr("192.168.0.1/8"),
             Cidr("192.168.0.1/13"),
             Cidr("192.168.0.1/16"),
             Cidr("192.168.0.1/19"),
             Cidr("192.168.0.1/24"),
             Cidr("192.168.0.1/26"),
             Cidr("192.168.0.1/32")]

    netmasks = ["128.0.0.0",
                "255.0.0.0",
                "255.248.0.0",
                "255.255.0.0",
                "255.255.224.0",
                "255.255.255.0",
                "255.255.255.192",
                "255.255.255.255"]
    count = len(cidrs)

    def test_get_netmask(self):
        for item in range(self.count):
            assert self.cidrs[item].get_netmask() == self.netmasks[item]


