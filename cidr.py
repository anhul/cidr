import argparse
import re

CIDR_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")


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
        if self.__is_valid_cidr(cidr):
            self.cidr = cidr
        else:
            raise WrongCidrNotation(cidr)
        self.ip = ""
        self.suffix = 0
        self.ip_octets = []
        self.__split_cidr()

    def __is_valid_cidr(self, cidr):
        match = re.match(CIDR_RE, cidr)
        if not match:
            return False
        ip, prefix = cidr.split("/")
        if not all([0 <= int(octet) <= 255 for octet in ip.split(".")]):
            return False
        if not 1 <= int(prefix) <= 32:
            return False
        return True

    def __split_cidr(self):
        self.ip, suffix = self.cidr.split("/")
        self.suffix = int(suffix)
        self.octets = [int(octet) for octet in self.ip.split(".")]

    def get_netmask(self):
        mask = self.suffix*"1" + (32 - self.suffix)*"0"
        mask_bin_octets = [mask[0:8], mask[8:16], mask[16:24], mask[24:32]]
        mask_dec_octets = [str(int("0b" + bin_octet, 2)) for bin_octet in mask_bin_octets]
        return ".".join(mask_dec_octets)

    def __ip_to_decimal(self):
        octets = [int(octet) for octet in self.ip.split(".")]
        return sum([256**(3-i)*octets[i] for i in range(4)])


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
    # print(cidr_obj._Cidr__ip_to_decimal())
    print(cidr_obj.get_netmask())
