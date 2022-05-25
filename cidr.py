import argparse
import re

CIDR_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")
IPV4_LENGTH = 32
MAX_IPS = 10


def _parse_args():
    parser = argparse.ArgumentParser(
        description="CIDR converter"
    )
    parser.add_argument("CIDR",
                        action="store",
                        default="",
                        help="CIDR notation")
    parser.add_argument("--max_ips",
                        action="store",
                        type=int,
                        default=None,
                        help="Maximum number of consecutive IPs to output")
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
        self.octet_host_bits_num = []
        self.octet_min_max_host_value = []
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
        self.octet_host_bits_num = self._get_octet_host_bits_num()
        self.octet_min_max_host_value = self._get_octet_min_max_host_value()

    def _ip_to_decimal(self):
        octets = [int(octet) for octet in self.ip.split(".")]
        return sum([256**(3-i)*octets[i] for i in range(4)])

    def _get_octet_host_bits_num(self):
        host_bits_per_octet = [0, 0, 0, 0]
        host_bits_total = IPV4_LENGTH - self.suffix
        for i in range(3, -1, -1):
            if 0 < host_bits_total <= 8:
                host_bits_per_octet[i] = host_bits_total
                break
            elif host_bits_total > 8:
                host_bits_per_octet[i] = 8
                host_bits_total -= 8
        return host_bits_per_octet
    
    def _get_octet_min_max_host_value(self):
        min_max_host_values = []
        for index, octet in enumerate(self.octets):
            host_bits_num = self.octet_host_bits_num[index]
            if host_bits_num:
                min_value = octet & int("0b" + (8-host_bits_num)*"1" + host_bits_num*"0", 2)
                max_value = octet | int("0b" + (8-host_bits_num)*"0" + host_bits_num*"1", 2)
            else:
                min_value = max_value = octet
            min_max_host_values.append((min_value, max_value))
        return min_max_host_values

    def get_first_ip(self):
        return ".".join(map(lambda x: str(x[0]), self.octet_min_max_host_value))

    def get_last_ip(self):
        return ".".join(map(lambda x: str(x[1]), self.octet_min_max_host_value))

    def get_netmask(self):
        mask = self.suffix*"1" + (IPV4_LENGTH - self.suffix)*"0"
        bin_octets = [mask[0:8], mask[8:16], mask[16:24], mask[24:32]]
        dec_octets = [str(int("0b" + bin_octet, 2)) for bin_octet in bin_octets]
        return ".".join(dec_octets)

    def get_number_of_ips(self):
        return pow(2, IPV4_LENGTH-self.suffix)

    def get_ips(self, max_ips=MAX_IPS):
        count = 0
        (o1_min, o1_max), (o2_min, o2_max), (o3_min, o3_max), (o4_min, o4_max) = self.octet_min_max_host_value
        for o1 in range(o1_min, o1_max + 1):
            for o2 in range(o2_min, o2_max + 1):
                for o3 in range(o3_min, o3_max + 1):
                    for o4 in range(o4_min, o4_max + 1):
                        if count < max_ips:
                            count += 1
                            yield f"{o1}.{o2}.{o3}.{o4}"


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
    if args.max_ips is not None:
        print(f"First {args.max_ips} IPs:")
        ips = cidr_obj.get_ips(args.max_ips)
    else:
        print(f"First {MAX_IPS} IPs:")
        ips = cidr_obj.get_ips()
    for ip in ips:
        print(ip)
