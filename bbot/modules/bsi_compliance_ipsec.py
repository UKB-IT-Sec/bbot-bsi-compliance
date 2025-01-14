from bbot.modules.base import BaseModule
from bbot.core.event.base import BaseEvent
import datetime
import socket
import subprocess
import json

ENCR_IKEV1 = {
    "ENCR-3DES": {"name": "ENCR-3DES", "iana": b"\x00\x05", "length": 0},
    "NULL": {"name": "NULL", "iana": b"\x00\x0b", "length": 0},
    "ENCR-AES-CCM-8-128": {"name": "ENCR-AES-CCM-8-128", "iana": b"\x00\x0e", "length": b"\x00\x80"},
    "ENCR-AES-CCM-8-256": {"name": "ENCR-AES-CCM-8-256", "iana": b"\x00\x0e", "length": b"\x01\x00"},
    "ENCR-AES-GCM-8-128": {"name": "ENCR-AES-GCM-8-128", "iana": b"\x00\x12", "length": b"\x00\x80"},
    "ENCR-AES-GCM-8-256": {"name": "ENCR-AES-GCM-8-256", "iana": b"\x00\x12", "length": b"\x01\x00"},
    "ENCR-AES-GMAC-128": {"name": "ENCR-AES-GMAC-128", "iana": b"\x00\x17", "length": b"\x00\x80"},
    "ENCR-AES-GMAC-256": {"name": "ENCR-AES-GMAC-256", "iana": b"\x00\x17", "length": b"\x01\x00"},
    "ENCR-BLOWFISH-CBC-128": {"name": "ENCR-BLOWFISH-CBC-128", "iana": b"\x00\x03", "length": b"\x00\x80"},
    "ENCR-BLOWFISH-CBC-256": {"name": "ENCR-BLOWFISH-CBC-128", "iana": b"\x00\x03", "length": b"\x01\x00"},
    "ENCR-CAMELLIA-CBC-128": {"name": "ENCR-CAMELLIA-CBC-128", "iana": b"\x00\x08", "length": b"\x00\x80"},
    "ENCR-CAMELLIA-CBC-256": {"name": "ENCR-CAMELLIA-CBC-256", "iana": b"\x00\x08", "length": b"\x01\x00"},
    "ENCR-SERPENT-CBC-128": {"name": "ENCR-SERPENT-CBC-128", "iana": b"\x00\xfc", "length": b"\x00\x80"},
    "ENCR-SERPENT-CBC-256": {"name": "ENCR-SERPENT-CBC-256", "iana": b"\x00\xfc", "length": b"\x01\x00"},
    "ENCR-TWOFISH-CBC-128": {"name": "ENCR-TWOFISH-CBC-128", "iana": b"\x00\xfd", "length": b"\x00\x80"},
    "ENCR-TWOFISH-CBC-256": {"name": "ENCR-TWOFISH-CBC-256", "iana": b"\x00\xfd", "length": b"\x01\x00"},
}

INTEG_IKEV1 = {
    "MD5": {"name": "MD5", "iana": b"\x00\x01"},
    "SHA": {"name": "SHA", "iana": b"\x00\x02"},
    "AES-GMAC-128": {"name": "AES-GMAC-128", "iana": b"\x00\x0b"},
    "AES-GMAC-192": {"name": "AES-GMAC-192", "iana": b"\x00\x0c"},
    "AES-GMAC-256": {"name": "AES-GMAC-256", "iana": b"\x00\x0d"},
}

DH_IKEV1 = {
    "768-bit-MODP-Group": {"name": "768-bit-MODP-Group", "iana": b"\x00\x01"},
    "1024-bit-MODP-Group": {"name": "1024-bit-MODP-Group", "iana": b"\x00\x02"},
    "1536-bit-MODP-Group": {"name": "1536-bit-MODP-Group", "iana": b"\x00\x05"},
    "2048-bit-MODP-Group": {"name": "2048-bit-MODP-Group", "iana": b"\x00\x0e"},
    "6144-bit-MODP-Group": {"name": "6144-bit-MODP-Group", "iana": b"\x00\x11"},
    "8192-bit-MODP-Group": {"name": "8192-bit-MODP-Group", "iana": b"\x00\x12"},
    "1024s160-bit-MODP-Group": {"name": "1024s160-bit-MODP-Group", "iana": b"\x00\x16"},
    "2048s224-bit-MODP-Group": {"name": "2048s224-bit-MODP-Group", "iana": b"\x00\x17"},
    "2048s256-bit-MODP-Group": {"name": "2048s256-bit-MODP-Group", "iana": b"\x00\x18"},
    "192-bit-random-ECP-group": {"name": "192-bit-random-ECP-group", "iana": b"\x00\x19"},
    "224-bit-random-ECP-group": {"name": "224-bit-random-ECP-group", "iana": b"\x00\x1a"},
    "brainpoolP224r1": {"name": "brainpoolP224r1", "iana": b"\x00\x1b"},
    "CURVE25519": {"name": "CURVE25519", "iana": b"\x00\x1f"},
}

AUTH_IKEV1 = {
    "PSK": {"name": "PSK", "iana": b"\x00\x01"},
    "DDS-SIGNATURES": {"name": "DDS-SIGNATURES", "iana": b"\x00\x02"},
    "RSA-SIGNATURES": {"name": "RSA-SIGNATURES", "iana": b"\x00\x03"},
    "RSA-ENCR": {"name": "RSA-ENCR", "iana": b"\x00\x04"},
    "RSA-ENCR-REVISED": {"name": "RSA-ENCR-REVISED", "iana": b"\x00\x05"},
}

# Recommendations of BSI for IKEv2:
BSI_ENCR_IKEV1 = {
    "ENCR-AES-CBC-128": {
        "name": "ENCR-AES-CBC-128",
        "iana": b"\x00\x07",
        "length": b"\x00\x80",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.1",
    },
    "ENCR-AES-CBC-256": {
        "name": "ENCR-AES-CBC-256",
        "iana": b"\x00\x07",
        "length": b"\x01\x00",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.1",
    },
    "ENCR-AES-CTR-128": {
        "name": "ENCR-AES-CTR-128",
        "iana": b"\x00\x0d",
        "length": b"\x00\x80",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.1",
    },
    "ENCR-AES-CTR-256": {
        "name": "ENCR-AES-CTR-256",
        "iana": b"\x00\x0d",
        "length": b"\x01\x00",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.1",
    },
    "ENCR-AES-GCM-16-128": {
        "name": "ENCR-AES-GCM-16-128",
        "iana": b"\x00\x14",
        "length": b"\x00\x80",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.1",
    },
    "ENCR-AES-GCM-16-256": {
        "name": "ENCR-AES-GCM-16-256",
        "iana": b"\x00\x14",
        "length": b"\x01\x00",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.1",
    },
    "ENCR-AES-GCM-12-128": {
        "name": "ENCR-AES-GCM-12-128",
        "iana": b"\x00\x13",
        "length": b"\x00\x80",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.1",
    },
    "ENCR-AES-GCM-12-256": {
        "name": "ENCR-AES-GCM-12-256",
        "iana": b"\x00\x13",
        "length": b"\x01\x00",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.1",
    },
    "ENCR-AES-CCM-16-128": {
        "name": "ENCR-AES-CCM-16-128",
        "iana": b"\x00\x10",
        "length": b"\x00\x80",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.1",
    },
    "ENCR-AES-CCM-16-256": {
        "name": "ENCR-AES-CCM-16-256",
        "iana": b"\x00\x10",
        "length": b"\x01\x00",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.1",
    },
    "ENCR-AES-CCM-12-128": {
        "name": "ENCR-AES-CCM-12-128",
        "iana": b"\x00\x0f",
        "length": b"\x00\x80",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.1",
    },
    "ENCR-AES-CCM-12-256": {
        "name": "ENCR-AES-CCM-12-256",
        "iana": b"\x00\x0f",
        "length": b"\x01\x00",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.1",
    },
}

BSI_INTEG_IKEV1 = {
    "AUTH-AES-XCBC-96": {
        "name": "AUTH-AES-XCBC-96",
        "iana": b"\x00\x09",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.3",
    },
    "AUTH-HMAC-SHA2-256-128": {
        "name": "AUTH-HMAC-SHA2-256-128",
        "iana": b"\x00\x05",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.3",
    },
    "AUTH-HMAC-SHA2-512-256": {
        "name": "AUTH-HMAC-SHA2-512-256",
        "iana": b"\x00\x07",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.3",
    },
    "AUTH-HMAC-SHA2-384-192": {
        "name": "AUTH-HMAC-SHA2-384-192",
        "iana": b"\x00\x06",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.3",
    },
}

BSI_DH_IKEV1 = {
    "3072-bit-MODP-Group": {
        "name": "3072-bit-MODP-Group",
        "iana": b"\x00\x0f",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.4",
    },
    "4096-bit-MODP-Group": {
        "name": "4096-bit-MODP-Group",
        "iana": b"\x00\x10",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.4",
    },
    "256-bit-random-ECP-group": {
        "name": "256-bit-random-ECP-group",
        "iana": b"\x00\x13",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.4",
    },
    "384-bit-random-ECP-group": {
        "name": "384-bit-random-ECP-group",
        "iana": b"\x00\x14",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.4",
    },
    "521-bit-random-ECP-group": {
        "name": "521-bit-random-ECP-group",
        "iana": b"\x00\x15",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.4",
    },
    "brainpoolP256r1": {
        "name": "brainpoolP256r1",
        "iana": b"\x00\x1c",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.4",
    },
    "brainpoolP384r1": {
        "name": "brainpoolP384r1",
        "iana": b"\x00\x1d",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.4",
    },
    "brainpoolP512r1": {
        "name": "brainpoolP512r1",
        "iana": b"\x00\x1e",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.4",
    },
}

BSI_AUTH_IKEV1 = {
    "ECDSA-256-secp256r1": {
        "name": "ECDSA-256-secp256r1",
        "iana": b"\x00\x09",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.5",
    },
    "ECDSA-384-secp256r1": {
        "name": "ECDSA-384-secp256r1",
        "iana": b"\x00\x0a",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.5",
    },
    "ECDSA-512-secp256r1": {
        "name": "ECDSA-512-secp256r1",
        "iana": b"\x00\x0b",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.5",
    },
    "ECDSA-256-brainpoolP256r1": {
        "name": "ECDSA-256-brainpoolP256r1",
        "iana": b"\x00\x0e",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.5",
    },
    "ECDSA-384-brainpoolP384r1": {
        "name": "ECDSA-384-brainpoolP384r1",
        "iana": b"\x00\x0e",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.5",
    },
    "ECDSA-512-brainpoolP512r1": {
        "name": "ECDSA-512-brainpoolP512r1",
        "iana": b"\x00\x0e",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.5",
    },
    "RSASSA-PSS": {
        "name": "RSASSA-PSS",
        "iana": b"\x00\x0e",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.5",
    },
    "ECGDSA-256-brainpoolP256r1": {
        "name": "ECGDSA-256-brainpoolP256r1",
        "iana": b"\x00\x0e",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.5",
    },
    "ECGDSA-384-brainpoolP384r1": {
        "name": "ECGDSA-384-brainpoolP384r1",
        "iana": b"\x00\x0e",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.5",
    },
    "ECGDSA-512-brainpoolP512r1": {
        "name": "ECGDSA-512-brainpoolP512r1",
        "iana": b"\x00\x0e",
        "valid_until": 2030,
        "reason": "TR-02102-3 | 3.2.5",
    },
}


class bsi_compliance_ipsec(BaseModule):
    watched_events = ["IP_ADDRESS"]
    produced_events = ["BSI_COMPLIANCE_RESULT", "FINDING"]
    flags = [
        "active",
        "safe",
        "report",
    ]
    meta = {"description": "Checks Algorithms used by the Target - IPSEC"}
    options = {"compliant_until": ""}
    options_desc = {"compliant_until": "Configuration compliant until year (e.g. 2026)"}
    _max_event_handlers = 2
    _type = "check"

    async def setup(self):
        self.compliant_until = self.config.get("compliant_until", "")
        if not self.compliant_until:
            self.compliant_until = datetime.datetime.now().year + 2
        self.compliant_until = int(self.compliant_until)
        return True

    def create_socket(self):
        try:
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            return udp_socket
        except socket.error as e:
            print(f"Socket creation failed: {e}")
            return None

    def close_socket(self, sock):
        try:
            sock.close()
        except AttributeError:
            print("Error: Invalid socket object")
        except OSError as e:
            print(f"Error: Failed to close socket - {e}")

    def send_receive(self, sock, data, server_ip, server_port):
        try:
            sock.sendto(data, (server_ip, server_port))

            response, _ = sock.recvfrom(4096)
            return response

        except sock.timeout:
            print("Socket timeout occurred: No response received")
            return None

        except sock.error as e:
            print(f"Socket error occurred: {e}")
            return None

    async def update_expiration(self, target, event, tags):
        for x in BSI_AUTH_IKEV1.values():
            if x["valid_until"] < self.compliant_until:
                await self.emit_event(
                    {
                        "host": target,
                        "description": x["name"]
                        + " is only valid until "
                        + str(x["valid_until"])
                        + ": Please check suppoerted Algorithms",
                    },
                    "FINDING",
                    source=event,
                    tags=tags,
                )
                AUTH_IKEV1[x["name"]] = {
                    "name": x["name"],
                    "iana": x["iana"],
                    "valid_until": x["valid_until"],
                    "reason": x["reason"],
                }

        for x in BSI_DH_IKEV1.values():
            if x["valid_until"] < self.compliant_until:
                await self.emit_event(
                    {
                        "host": target,
                        "description": x["name"]
                        + " is only valid until "
                        + str(x["valid_until"])
                        + ": Please check suppoerted Algorithms",
                    },
                    "FINDING",
                    source=event,
                    tags=tags,
                )
                DH_IKEV1[x["name"]] = {
                    "name": x["name"],
                    "iana": x["iana"],
                    "valid_until": x["valid_until"],
                    "reason": x["reason"],
                }

        for x in BSI_INTEG_IKEV1.values():
            if x["valid_until"] < self.compliant_until:
                await self.emit_event(
                    {
                        "host": target,
                        "description": x["name"]
                        + " is only valid until "
                        + str(x["valid_until"])
                        + ": Please check suppoerted Algorithms",
                    },
                    "FINDING",
                    source=event,
                    tags=tags,
                )
                INTEG_IKEV1[x["name"]] = {
                    "name": x["name"],
                    "iana": x["iana"],
                    "valid_until": x["valid_until"],
                    "reason": x["reason"],
                }
        for x in BSI_ENCR_IKEV1.values():
            if x["valid_until"] < self.compliant_until:
                await self.emit_event(
                    {
                        "host": target,
                        "description": x["name"]
                        + " is only valid until "
                        + str(x["valid_until"])
                        + ": Please check suppoerted Algorithms",
                    },
                    "FINDING",
                    source=event,
                    tags=tags,
                )
                ENCR_IKEV1[x["name"]] = {
                    "name": x["name"],
                    "length": x["length"],
                    "iana": x["iana"],
                    "valid_until": x["valid_until"],
                    "reason": x["reason"],
                }
        return

    def build_special_packet(self, input_enc, input_hash, input_auth, input_dh):
        packet = (
            b"\x1c\xf8\x70\x53\x79\xde\x38\x77"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x01\x10\x02\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x50"
            b"\x00\x00\x00\x34"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x28"
            b"\x01\x01\x00\x01"
            b"\x00\x00\x00\x20"
            b"\x01\x01\x00\x00"
        )

        encr_algo = b"\x80\x01" + input_enc
        hash_algo = b"\x80\x02" + input_hash
        auth_algo = b"\x80\x03" + input_auth
        dh_group = b"\x80\x04" + input_dh

        prop_end = b"\x80\x0b\x00\x01\x80\x0c\x2a\x30"

        packet += encr_algo + hash_algo + auth_algo + dh_group + prop_end

        return packet

    def build_packet(self, input_enc, input_key_length, input_hash, input_auth, input_dh):
        packet = (
            b"\x1c\xf8\x75\x53\x79\xde\x38\x77"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x01\x10\x02\x00"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x54"
            b"\x00\x00\x00\x38"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x01"
            b"\x00\x00\x00\x2c"
            b"\x01\x01\x00\x01"
            b"\x00\x00\x00\x24"
            b"\x01\x01\x00\x00"
        )

        encr_algo = b"\x80\x01" + input_enc
        enc_length = b"\x80\x0e" + input_key_length
        hash_algo = b"\x80\x02" + input_hash
        auth_algo = b"\x80\x03" + input_auth
        dh_group = b"\x80\x04" + input_dh

        prop_end = b"\x80\x0b\x00\x01\x80\x0c\x2a\x30"

        packet += encr_algo + enc_length + hash_algo + auth_algo + dh_group + prop_end

        return packet

    def find_init_algs(self, target_ip, target_port):
        udp_sock = self.create_socket()

        for encr_alg in ENCR_IKEV1.keys():
            for integ_alg in INTEG_IKEV1.keys():
                for auth_alg in AUTH_IKEV1.keys():
                    for dh_group in DH_IKEV1.keys():
                        if ENCR_IKEV1[encr_alg].get("length") == 0:
                            response = self.send_receive(
                                udp_sock,
                                self.build_special_packet(
                                    ENCR_IKEV1[encr_alg].get("iana"),
                                    INTEG_IKEV1[integ_alg].get("iana"),
                                    AUTH_IKEV1[auth_alg].get("iana"),
                                    DH_IKEV1[dh_group].get("iana"),
                                ),
                                target_ip,
                                target_port,
                            )
                        else:
                            response = self.send_receive(
                                udp_sock,
                                self.build_packet(
                                    ENCR_IKEV1[encr_alg].get("iana"),
                                    ENCR_IKEV1[encr_alg].get("length"),
                                    INTEG_IKEV1[integ_alg].get("iana"),
                                    AUTH_IKEV1[auth_alg].get("iana"),
                                    DH_IKEV1[dh_group].get("iana"),
                                ),
                                target_ip,
                                target_port,
                            )

                        if response:
                            hex_response = response.hex()

                            if hex_response.find("01100200") != -1:
                                encr_worked = ENCR_IKEV1[encr_alg].get("name")
                                integ_worked = INTEG_IKEV1[integ_alg].get("name")
                                auth_worked = AUTH_IKEV1[auth_alg].get("name")
                                dh_worked = DH_IKEV1[dh_group].get("name")
                                self.close_socket(udp_sock)
                                return encr_worked, integ_worked, auth_worked, dh_worked

        self.close_socket(udp_sock)
        return None, None, None, None

    def test_algorithms(self, encr_alg, integ_alg, auth_alg, dh_group, target_ip, target_port):
        udp_sock = self.create_socket()

        if ENCR_IKEV1[encr_alg]["length"] == 0:
            response = self.send_receive(
                udp_sock,
                self.build_special_packet(
                    ENCR_IKEV1[encr_alg].get("iana"),
                    INTEG_IKEV1[integ_alg].get("iana"),
                    AUTH_IKEV1[auth_alg].get("iana"),
                    DH_IKEV1[dh_group].get("iana"),
                ),
                target_ip,
                target_port,
            )
        else:
            response = self.send_receive(
                udp_sock,
                self.build_packet(
                    ENCR_IKEV1[encr_alg].get("iana"),
                    ENCR_IKEV1[encr_alg].get("length"),
                    INTEG_IKEV1[integ_alg].get("iana"),
                    AUTH_IKEV1[auth_alg].get("iana"),
                    DH_IKEV1[dh_group].get("iana"),
                ),
                target_ip,
                target_port,
            )

        if response:
            hex_response = response.hex()
            if hex_response.find("01100200") != -1:
                return 1

        self.close_socket(udp_sock)

    def compliance_check(self, target_ip, target_port):
        invalid_algorithms = {
            "found_encr_algorithms": [],
            "found_integ_algorithms": [],
            "found_auth_methods": [],
            "found_dh_groups": [],
        }

        encr_worked, integ_worked, auth_worked, dh_worked = self.find_init_algs(target_ip, target_port)

        # Encryption Test
        for x in ENCR_IKEV1.keys():
            if self.test_algorithms(x, integ_worked, auth_worked, dh_worked, target_ip, target_port) == 1:
                invalid_algorithms["found_encr_algorithms"].append({"name": x})

        # Integrity Test
        for x in INTEG_IKEV1.keys():
            if self.test_algorithms(encr_worked, x, auth_worked, dh_worked, target_ip, target_port) == 1:
                invalid_algorithms["found_integ_algorithms"].append({"name": x})

        # Authentication Test
        for x in AUTH_IKEV1.keys():
            if self.test_algorithms(encr_worked, integ_worked, x, dh_worked, target_ip, target_port) == 1:
                invalid_algorithms["found_auth_methods"].append({"name": x})

        # DH-Group Test
        for x in DH_IKEV1.keys():
            if self.test_algorithms(encr_worked, integ_worked, auth_worked, x, target_ip, target_port) == 1:
                invalid_algorithms["found_dh_groups"].append({"name": x})

        return invalid_algorithms

    async def generate_output(self, target, source_event, tags):
        await self.update_expiration(target, source_event, tags)
        host = target.split(":")[0]
        port = int(target.split(":")[1])
        invalid_algorithms = self.compliance_check(host, port)
        compliance_data = {
            "host": host,
            "port": port,
            "invalid_algorithms": invalid_algorithms,
        }
        await self.emit_event(compliance_data, "BSI_COMPLIANCE_RESULT", source=source_event, tags=tags)

    async def handle_event(self, event: BaseEvent):
        _input = {event.data + ":500": event}
        command = ["fingerprintx", "-U", "--json"]
        async for line in self.helpers.run_live(command, input=list(_input), stderr=subprocess.DEVNULL):
            try:
                j = json.loads(line)
            except Exception as e:
                self.debug(f'Error parsing line "{line}" as JSON: {e}')
                break
            ip = j.get("ip", "")
            host = j.get("host", ip)
            port = str(j.get("port", ""))
            tags = "IPSEC"
            banner = j.get("metadata", {}).get("banner", "").strip()
            if port:
                port_data = f"{host}:{port}"
            protocol = j.get("protocol", "")
            if host and port and protocol:
                source_event = _input.get(port_data)
                protocol_data = {"host": host, "protocol": protocol.upper()}
                if port:
                    protocol_data["port"] = port
                if banner:
                    protocol_data["banner"] = banner
                if protocol_data["protocol"] == "IPSEC":
                    await self.generate_output(port_data, source_event, tags)
