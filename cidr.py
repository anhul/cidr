import argparse
import re

CIDR_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")
IPV4_LENGTH = 32


def _parse_args():
    parser = argparse.ArgumentParser(
        description="CIDR converter"
    )
    parser.add_argument("CIDR",
                        action="store",
                        default="",
                        help="CIDR notation")
    args = parser.parse_args()
    return args


class Cidr:
    def __init__(self, cidr):
        if self._is_valid_cidr(cidr):
            self.cidr = cidr
        else:
            raise WrongCidrNotation(cidr)
        self.ip = ""
        self.suffix = 0
        self.octets = []
        self._split_cidr()

    def _is_valid_cidr(self, cidr):
        match = re.match(CIDR_RE, cidr)
        if not match:
            return False
        ip, prefix = cidr.split("/")
        if not all([0 <= int(octet) <= 255 for octet in ip.split(".")]):
            return False
        if not 1 <= int(prefix) <= 32:
            return False
        return True

    def _split_cidr(self):
        self.ip, suffix = self.cidr.split("/")
        self.suffix = int(suffix)
        self.octets = [int(octet) for octet in self.ip.split(".")]
        self.host_bits_in_octet = self._host_bits_per_octet()

    def _ip_to_decimal(self):
        octets = [int(octet) for octet in self.ip.split(".")]
        return sum([256**(3-i)*octets[i] for i in range(4)])

    def _host_bits_per_octet(self):
        host_bits_per_octet = [0, 0, 0, 0]
        host_bits_num = IPV4_LENGTH - self.suffix
        for i in range(3, -1, -1):
            if 0 < host_bits_num <= 8:
                host_bits_per_octet[i] = host_bits_num
                break
            elif host_bits_num > 8:
                host_bits_per_octet[i] = 8
                host_bits_num -= 8
        return host_bits_per_octet

    def get_first_ip(self):
        masked_octets = self.octets.copy()
        for index, octet in enumerate(self.octets):
            bits_num = self.host_bits_in_octet[index]
            if bits_num:
                masked_octets[index] = octet & int("0b" + (8-bits_num)*"1" + bits_num*"0", 2)
        return ".".join(map(str, masked_octets))

    def get_last_ip(self):
        masked_octets = self.octets.copy()
        for index, octet in enumerate(self.octets):
            bits_num = self.host_bits_in_octet[index]
            if bits_num:
                masked_octets[index] = octet | int("0b" + (8-bits_num)*"0" + bits_num*"1", 2)
        return ".".join(map(str, masked_octets))


    def get_netmask(self):
        mask = self.suffix*"1" + (IPV4_LENGTH - self.suffix)*"0"
        bin_octets = [mask[0:8], mask[8:16], mask[16:24], mask[24:32]]
        dec_octets = [str(int("0b" + bin_octet, 2)) for bin_octet in bin_octets]
        return ".".join(dec_octets)

    def get_number_of_ips(self):
        return pow(2, IPV4_LENGTH-self.suffix)



class WrongCidrNotation(Exception):
    def __init__(self, cidr, message="A wrong format of the CIDR notation"):
        self.message = message
        self.cidr = cidr
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}: {self.cidr}"


if __name__ == '__main__':
    args = _parse_args()
    cidr_obj = Cidr(args.CIDR)

    print(f"CIDR range: {cidr_obj.cidr}")
    print(f"Netmask: {cidr_obj.get_netmask()}")
    print(f"Number of IPs: {cidr_obj.get_number_of_ips()}")
    print(f"First IP: {cidr_obj.get_first_ip()}")
    print(f"Last IP: {cidr_obj.get_last_ip()}")
