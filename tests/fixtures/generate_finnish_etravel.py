#!/usr/bin/env python3

import json
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

ROOT = Path(__file__).resolve().parents[2]
CAN = b"123456"
PACE_OID = bytes.fromhex("04007F00070202040204")
NONCE = bytes.fromhex("0102030405060708090A0B0C0D0E0F10")
TERMINAL_MAPPING = 3
TERMINAL_EPHEMERAL = 4
CARD_MAPPING = 1
CARD_EPHEMERAL = 2
CURVE_P = int("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53", 16)
CURVE_A = int("7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826", 16)
CURVE_B = int("04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11", 16)
CURVE_G_X = int("1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E", 16)
CURVE_G_Y = int("8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315", 16)


def tlv(tag, value):
    if tag <= 0xFF:
        encoded = bytes([tag])
    else:
        encoded = tag.to_bytes(2, "big")
    if len(value) < 0x80:
        encoded += bytes([len(value)])
    else:
        size = (len(value).bit_length() + 7) // 8
        encoded += bytes([0x80 | size]) + len(value).to_bytes(size, "big")
    return encoded + value


def parse_one(data):
    tag = data[0]
    start = 1
    if tag & 0x1F == 0x1F:
        while data[start] & 0x80:
            start += 1
        start += 1
        encoded_tag = data[:start]
    else:
        encoded_tag = data[:1]
    first = data[start]
    start += 1
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        length = int.from_bytes(data[start:start + count], "big")
        start += count
    return tag, encoded_tag, data[:start], data[start:start + length], data[start + length:]


def derive(secret, counter):
    return sha256(secret + counter.to_bytes(4, "big")).digest()


def encrypt(key, iv, data):
    return Cipher(algorithms.AES256(key), modes.CBC(iv)).encryptor().update(data)


def pad(data):
    return data + b"\x80" + bytes((-len(data) - 1) % 16)


def cmac(key, data):
    value = CMAC(algorithms.AES256(key))
    value.update(data)
    return value.finalize()


def increment(sequence):
    return (int.from_bytes(sequence, "big") + 1).to_bytes(16, "big")


def private(value):
    return ec.derive_private_key(value, ec.BrainpoolP384R1())


def public(value):
    return value.public_key().public_numbers()


def encoded(point):
    return b"\x04" + point.x.to_bytes(48, "big") + point.y.to_bytes(48, "big")


def add_points(first, second):
    curve = ec.BrainpoolP384R1()
    p = CURVE_P
    a = CURVE_A
    if first.x == second.x and first.y == second.y:
        slope = (3 * first.x * first.x + a) * pow(2 * first.y, -1, p) % p
    else:
        slope = (second.y - first.y) * pow(second.x - first.x, -1, p) % p
    x = (slope * slope - first.x - second.x) % p
    y = (slope * (first.x - x) - first.y) % p
    return ec.EllipticCurvePublicNumbers(x, y, curve)


def shared_x(value, point):
    return scalar_multiply(value, point).x.to_bytes(48, "big")


def token(key, point):
    data = tlv(0x06, PACE_OID) + tlv(0x86, encoded(point))
    return cmac(key, tlv(0x7F49, data))[:8]


def apdu(cla, ins, p1, p2, data=b"", le=None):
    result = bytes([cla, ins, p1, p2])
    if data:
        result += bytes([len(data)]) + data
    if le is not None:
        result += bytes([le])
    return result


def card_access():
    pace = tlv(0x06, PACE_OID) + tlv(0x02, b"\x02") + tlv(0x80, b"\x0D")
    return tlv(0x31, tlv(0x30, pace))


def dg1():
    mrz = b"IDFINX00000000100000000000000<<<<<<<<<<<<<<0001012F3001018FIN<<<<<<<<<<<0SPECIMEN<<PERSON<<<<<<<<<<<<"
    return tlv(0x61, tlv(0x5C, b"\x01\x01\x01\x02\x01\x0E\x01\x1D") + tlv(0x5F1F, mrz))


def facial_record(image):
    facial_information = bytes.fromhex("0000000000000000000000000000")
    image_information = bytes.fromhex("0100") + (1).to_bytes(2, "big") + (1).to_bytes(2, "big") + bytes.fromhex("000000000000")
    face = (32 + len(image)).to_bytes(4, "big") + b"\x00\x00" + facial_information + image_information + image
    header = bytes.fromhex("4641430001010100") + (14 + len(face)).to_bytes(4, "big") + b"\x00\x01"
    record = tlv(0x7F60, tlv(0xA1, tlv(0x80, b"\x01\x01")) + tlv(0x5F2E, header + face))
    return tlv(0x75, tlv(0x7F61, tlv(0x02, b"\x01") + record))


def dg14():
    info = tlv(0x06, bytes.fromhex("04007F000702010301")) + tlv(0x02, b"\x02") + tlv(0x83, b"\x0D")
    return tlv(0x31, tlv(0x30, info))


def sod():
    algorithms = tlv(0x31, tlv(0x30, tlv(0x06, bytes.fromhex("608648016503040201"))))
    digests = tlv(0x31, tlv(0x04, sha256(dg1()).digest()) + tlv(0x04, sha256(facial_record(JPEG)).digest()))
    content = tlv(0x30, algorithms + tlv(0x30, digests))
    return tlv(0x77, tlv(0x30, tlv(0x06, bytes.fromhex("2A864886F70D010702")) + tlv(0xA0, content)))


class Card:
    def __init__(self):
        self.records = []
        self.mapping = private(CARD_MAPPING)
        self.nonce = NONCE
        self.ssc = NONCE
        self.files = {"0101": dg1(), "0102": facial_record(JPEG), "010E": dg14(), "011D": sod()}
        self.file = None

    def record(self, command, data=b"", status=0x9000):
        self.records.append({
            "id": f"record-{len(self.records) + 1:04d}",
            "kind": "command",
            "command": list(command),
            "response": {"data": list(data), "status": status},
        })

    def handshake(self, command):
        length = command[4]
        data = command[5:5 + length]
        outer = parse_one(data)[3]
        if not outer:
            encrypted = encrypt(derive(CAN, 3), bytes(16), self.nonce)
            return tlv(0x7C, tlv(0x80, encrypted))
        tag, _, _, value, _ = parse_one(outer)
        if tag == 0x81:
            terminal = parse_public(value)
            product = scalar_multiply(CARD_MAPPING, terminal.public_numbers())
            self.mapped = add_points(self.base_times_nonce(), product)
            return tlv(0x7C, tlv(0x82, encoded(public(self.mapping))))
        if tag == 0x83:
            terminal = parse_public(value)
            self.card_ephemeral = scalar_multiply(CARD_EPHEMERAL, self.mapped)
            shared = shared_x(CARD_EPHEMERAL, terminal.public_numbers())
            terminal_shared = shared_x(TERMINAL_EPHEMERAL, self.card_ephemeral)
            assert shared == terminal_shared
            self.encryption_key = derive(shared, 1)
            self.authentication_key = derive(shared, 2)
            return tlv(0x7C, tlv(0x84, encoded(self.card_ephemeral)))
        if tag == 0x85:
            assert value == token(self.authentication_key, self.card_ephemeral)
            return tlv(0x7C, tlv(0x86, token(self.authentication_key, self.terminal_ephemeral)))
        raise AssertionError(f"Unexpected PACE tag {tag:02X}")

    def base_times_nonce(self):
        base = private(1).public_key().public_numbers()
        return scalar_multiply(int.from_bytes(self.nonce, "big"), base)

    def secure_response(self, data=b""):
        self.ssc = increment(self.ssc)
        mac_input = self.ssc
        response = b""
        if data:
            iv = encrypt(self.encryption_key, bytes(16), self.ssc)
            encrypted = encrypt(self.encryption_key, iv, pad(data))
            response = tlv(0x87, b"\x01" + encrypted)
            mac_input += response
        status_object = tlv(0x99, b"\x90\x00")
        mac_input += status_object
        checksum = cmac(self.authentication_key, pad(mac_input))[:8]
        return response + status_object + tlv(0x8E, checksum)


def parse_public(value):
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.BrainpoolP384R1(), value)


def scalar_multiply(value, point):
    assert (point.y * point.y - point.x * point.x * point.x - CURVE_A * point.x - CURVE_B) % CURVE_P == 0
    p = CURVE_P
    a = CURVE_A
    result = None
    addend = point
    while value:
        if value & 1:
            result = addend if result is None else add_points(result, addend)
        addend = add_points(addend, addend)
        value >>= 1
    assert result is not None
    return result


def main():
    global JPEG
    base = ec.EllipticCurvePublicNumbers(CURVE_G_X, CURVE_G_Y, ec.BrainpoolP384R1())
    assert encoded(scalar_multiply(2, base)) == encoded(public(private(2)))
    JPEG = bytes.fromhex("FFD8FFE000104A46494600010100000100010000FFD9")
    card = Card()
    select_access = apdu(0, 0xA4, 2, 0x0C, bytes.fromhex("011C"))
    card.record(select_access)
    read_access = apdu(0, 0xB0, 0, 0, le=0)
    card.record(read_access, card_access())

    set_at = apdu(0, 0x22, 0xC1, 0xA4, tlv(0x80, PACE_OID) + tlv(0x83, b"\x02") + tlv(0x84, b"\x0D"))
    card.record(set_at)
    ga = apdu(0x10, 0x86, 0, 0, tlv(0x7C, b""), 0)
    card.record(ga, card.handshake(ga))
    terminal_mapping = private(TERMINAL_MAPPING)
    ga = apdu(0x10, 0x86, 0, 0, tlv(0x7C, tlv(0x81, encoded(public(terminal_mapping)))), 0)
    card.record(ga, card.handshake(ga))
    terminal_point = scalar_multiply(TERMINAL_EPHEMERAL, card.mapped)
    card.terminal_ephemeral = terminal_point
    ga = apdu(0x10, 0x86, 0, 0, tlv(0x7C, tlv(0x83, encoded(terminal_point))), 0)
    card.record(ga, card.handshake(ga))
    terminal_token = token(card.authentication_key, card.card_ephemeral)
    ga = apdu(0, 0x86, 0, 0, tlv(0x7C, tlv(0x85, terminal_token)), 0)
    card.record(ga, card.handshake(ga))

    commands = [apdu(0, 0xA4, 4, 0x0C, bytes.fromhex("A0000002471001"))]
    for fid, data in card.files.items():
        commands.append(apdu(0, 0xA4, 2, 0x0C, bytes.fromhex(fid)))
        offset = 0
        while offset < len(data):
            length = min(0xE0, len(data) - offset)
            le = 0 if offset == 0 else length
            commands.append((apdu(0, 0xB0, offset >> 8, offset & 0xFF, le=le), data[offset:offset + length]))
            offset += length

    for item in commands:
        if isinstance(item, tuple):
            command, response_data = item
        else:
            command, response_data = item, b""
        protected = Session(card.encryption_key, card.authentication_key, card.ssc).protect(command)
        card.ssc = increment(card.ssc)
        card.record(protected, card.secure_response(response_data))

    trace = {
        "schema_version": 1,
        "records": [{"kind": "reset", "mode": "cold", "atr": {"width": 8, "elements": [59, 127, 150, 0, 0]}, "id": "reset-1"}] + card.records,
    }
    destination = ROOT / "tests/fixtures/traces/finnish-etravel-synthetic-001.json"
    destination.write_text(json.dumps(trace, indent=2) + "\n")
    print(destination)


class Session:
    def __init__(self, encryption_key, authentication_key, sequence):
        self.encryption_key = encryption_key
        self.authentication_key = authentication_key
        self.sequence = sequence

    def protect(self, command):
        sequence = increment(self.sequence)
        header = bytes([command[0] | 0x0C]) + command[1:4]
        data, le = command_payload(command)
        body = b""
        if data:
            iv = encrypt(self.encryption_key, bytes(16), sequence)
            body += tlv(0x87, b"\x01" + encrypt(self.encryption_key, iv, pad(data)))
        if le is not None:
            body += tlv(0x97, bytes([le]))
        mac_input = sequence + pad(header) + pad(body)
        body += tlv(0x8E, cmac(self.authentication_key, mac_input)[:8])
        return header + bytes([len(body)]) + body + b"\x00"


def command_payload(command):
    if len(command) == 4:
        return b"", None
    if len(command) == 5:
        return b"", command[4]
    length = command[4]
    if len(command) == 5 + length:
        return command[5:], None
    assert len(command) == 6 + length
    return command[5:5 + length], command[-1]


if __name__ == "__main__":
    main()
