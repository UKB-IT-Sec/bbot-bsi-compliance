from bbot.modules.base import BaseModule
import socket
from datetime import datetime


BSI_KEX_ALGORITHMS = [
    {"name": "diffie-hellman-group-exchange-sha256", "valid_until": 2029},
    {"name": "diffie-hellman-group15-sha512", "valid_until": 2029},
    {"name": "diffie-hellman-group16-sha512", "valid_until": 2029},
    {"name": "ecdh-sha2-nistp256", "valid_until": 2029},
    {"name": "ecdh-sha2-nistp384", "valid_until": 2029},
    {"name": "ecdh-sha2-nistp521", "valid_until": 2029},
]

BSI_ENCRYPTION_ALGORITHMS = [
    {"name": "AEAD_AES_128_GCM", "valid_until": 2029},
    {"name": "AEAD_AES_256_GCM", "valid_until": 2029},
    {"name": "aes128-ctr", "valid_until": 2029},
    {"name": "aes192-ctr", "valid_until": 2029},
    {"name": "aes256-ctr", "valid_until": 2029},
]

BSI_MAC_ALGORITHMS = [{"name": "hmac-sha2-256", "valid_until": 2029}, {"name": "hmac-sha2-512", "valid_until": 2029}]

BSI_SERVER_HOST_KEY_ALGORITHMS = [
    {"name": "pgp-sign-dss", "valid_until": 2029},
    {"name": "ecdsa-sha2-nistp256", "valid_until": 2029},
    {"name": "ecdsa-sha2-nistp384", "valid_until": 2029},
    {"name": "ecdsa-sha2-nistp521", "valid_until": 2029},
    {"name": "x509v3-ecdsa-sha2-nistp256", "valid_until": 2029},
    {"name": "x509v3-ecdsa-sha2-nistp384", "valid_until": 2029},
    {"name": "x509v3-ecdsa-sha2-nistp521", "valid_until": 2029},
]

CURRENT_YEAR = datetime.now().year


class bsi_compliance_ssh(BaseModule):
    watched_events = ["PROTOCOL"]
    produced_events = ["BSI_COMPLIANCE_RESULT", "FINDING", "VULNERABILITY"]
    flags = [
        "active",
        "safe",
        "report",
    ]  # active = Makes active connections to target systems, safe = Non-intrusive, safe to run, report = Generates a report at the end of the scan,
    meta = {"description": "Checks Algorithms used by the Target - SSH"}
    options = {"version": "1.0"}
    options_desc = {"version": "Version based of last fundamental Change"}
    _max_event_handlers = 2
    _type = "check"

    async def handle_event(self, event):
        if "SSH" in event.data["protocol"]:  # Tests if the protocol matches
            target_ip = event.data["host"]  # gets IP_Address of Target
            target_port = event.data["port"]  # gets Port of Target
            target_algorithms = self.get_algorithms(target_ip, target_port)

            if target_algorithms != 0:
                target_algorithms = self.parser(target_algorithms)
                compliance_test_result = self.check_compliance(target_algorithms)
                compliance_data = {
                    "host": target_ip,
                    "port": target_port,
                    "found_algorithms": target_algorithms,
                    "invalid_algorithms": compliance_test_result,
                }
                await self.emit_event(compliance_data, "BSI_COMPLIANCE_RESULT", source=event, tags="SSH")
            else:
                compliance_data = {
                    "host": target_ip,
                    "port": target_port,
                    "description": "Server supports SSH protocol version 1, please upgrade to version 2!",
                    "severity": "CRITICAL",
                }
                await self.emit_event(compliance_data, "VULNERABILITY", source=event, tags="SSH")

    def get_algorithms(self, target_ip, target_port):
        sock = socket.create_connection((target_ip, target_port), 5)
        recv_server_ssh_version = sock.recv(60).decode()

        if "SSH-2" not in recv_server_ssh_version:
            return 0

        sock.send(bytes("SSH-2.0-UKB\r\n", "utf8"))  # Say Hello
        recv_packet_length = int.from_bytes(sock.recv(4), "big")
        recv_padding_length = int.from_bytes(sock.recv(1), "big")
        recv_payload = sock.recv(recv_packet_length - recv_padding_length - 1)
        recv_SSH_MSG_KEX_INIT = recv_payload[17:]  # Cuts of SSH_MSG_KEX_INIT Header
        return recv_SSH_MSG_KEX_INIT

    def parser(self, algorithms_string):
        result = {
            "KEX": [],
            "SERVER_HOST_KEY": [],
            "ENCRYPTION_CLIENT_TO_SERVER": [],
            "ENCRYPTION_SERVER_TO_CLIENT": [],
            "MAC_CLIENT_TO_SERVER": [],
            "MAC_SERVER_TO_CLIENT": [],
            "COMPRESSION_CLIENT_TO_SERVER": [],
            "COMPRESSION_SERVER_TO_CLIENT": [],
        }
        current_index = 0

        # KEX_ALGORITHMS
        list_length1 = int.from_bytes(algorithms_string[current_index : current_index + 4], "big") + 4
        result["KEX"] = algorithms_string[current_index + 4 : list_length1].decode("utf-8").split(",")
        current_index = current_index + list_length1

        # SERVER_HOST_KEY_ALGORITHMS
        list_length2 = int.from_bytes(algorithms_string[current_index : current_index + 4], "big") + 4
        result["SERVER_HOST_KEY"] = (
            algorithms_string[current_index + 4 : current_index + list_length2].decode("utf-8").split(",")
        )
        current_index = current_index + list_length2

        # ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER
        list_length3 = int.from_bytes(algorithms_string[current_index : current_index + 4], "big") + 4
        result["ENCRYPTION_CLIENT_TO_SERVER"] = (
            algorithms_string[current_index + 4 : current_index + list_length3].decode("utf-8").split(",")
        )
        current_index = current_index + list_length3

        # ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT
        list_length4 = int.from_bytes(algorithms_string[current_index : current_index + 4], "big") + 4
        result["ENCRYPTION_SERVER_TO_CLIENT"] = (
            algorithms_string[current_index + 4 : current_index + list_length4].decode("utf-8").split(",")
        )
        current_index = current_index + list_length4

        # MAC_ALGORITHMS_CLIENT_TO_SERVER
        list_length4 = int.from_bytes(algorithms_string[current_index : current_index + 4], "big") + 4
        result["MAC_CLIENT_TO_SERVER"] = (
            algorithms_string[current_index + 4 : current_index + list_length4].decode("utf-8").split(",")
        )
        current_index = current_index + list_length4

        # MAC_ALGORITHMS_SERVER_TO_CLIENT
        list_length5 = int.from_bytes(algorithms_string[current_index : current_index + 4], "big") + 4
        result["MAC_SERVER_TO_CLIENT"] = (
            algorithms_string[current_index + 4 : current_index + list_length5].decode("utf-8").split(",")
        )
        current_index = current_index + list_length5

        # COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER
        list_length6 = int.from_bytes(algorithms_string[current_index : current_index + 4], "big") + 4
        result["COMPRESSION_CLIENT_TO_SERVER"] = (
            algorithms_string[current_index + 4 : current_index + list_length6].decode("utf-8").split(",")
        )
        current_index = current_index + list_length6

        # COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT
        list_length7 = int.from_bytes(algorithms_string[current_index : current_index + 4], "big") + 4
        result["COMPRESSION_SERVER_TO_CLIENT"] = (
            algorithms_string[current_index + 4 : current_index + list_length7].decode("utf-8").split(",")
        )

        return result

    def check_invalid_algorithms(self):
        [
            print(algorithm["name"] + " is not valid anymore, please update BSI Guidelines!")
            for algorithm in BSI_KEX_ALGORITHMS
            if algorithm["valid_until"] < CURRENT_YEAR
        ]
        [
            print(algorithm["name"] + " is not valid anymore, please update BSI Guidelines!")
            for algorithm in BSI_SERVER_HOST_KEY_ALGORITHMS
            if algorithm["valid_until"] < CURRENT_YEAR
        ]
        [
            print(algorithm["name"] + " is not valid anymore, please update BSI Guidelines!")
            for algorithm in BSI_MAC_ALGORITHMS
            if algorithm["valid_until"] < CURRENT_YEAR
        ]
        [
            print(algorithm["name"] + " is not valid anymore, please update BSI Guidelines!")
            for algorithm in BSI_ENCRYPTION_ALGORITHMS
            if algorithm["valid_until"] < CURRENT_YEAR
        ]

    def check_compliance(self, parsed_algorithms):
        temp = {
            "KEX": parsed_algorithms["KEX"],
            "SHK": parsed_algorithms["SERVER_HOST_KEY"],
            "ENC": parsed_algorithms["ENCRYPTION_SERVER_TO_CLIENT"],
            "MAC": parsed_algorithms["MAC_SERVER_TO_CLIENT"],
        }

        [temp["KEX"].remove(algorithm["name"]) for algorithm in BSI_KEX_ALGORITHMS if algorithm["name"] in temp["KEX"]]
        [
            temp["SHK"].remove(algorithm["name"])
            for algorithm in BSI_SERVER_HOST_KEY_ALGORITHMS
            if algorithm["name"] in temp["SHK"]
        ]
        [
            (
                print(algorithm["name"] + " Algorithm is only valid for Key_length of 3000 Bit/ 250 Bit")
                if "pgp-sign-dss" in algorithm["name"]
                else None
            )
            for algorithm in BSI_SERVER_HOST_KEY_ALGORITHMS
            if algorithm["name"] in temp["SHK"]
        ]
        [
            temp["ENC"].remove(algorithm["name"])
            for algorithm in BSI_ENCRYPTION_ALGORITHMS
            if algorithm["name"] in temp["ENC"]
        ]
        [temp["MAC"].remove(algorithm["name"]) for algorithm in BSI_MAC_ALGORITHMS if algorithm["name"] in temp["MAC"]]

        return 0 if not any(temp.values()) else temp
