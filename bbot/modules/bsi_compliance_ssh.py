from bbot.modules.base import BaseModule
import socket, copy
import datetime


BSI_KEX_ALGORITHMS = {
    "diffie-hellman-group-exchange-sha256": {
        "name": "diffie-hellman-group-exchange-sha256",
        "valid_until": 2030,
        "description": "TR-02102-4 | 3.3",
    },
    "diffie-hellman-group15-sha512": {"name": "diffie-hellman-group15-sha512", "valid_until": 2030},
    "diffie-hellman-group16-sha512": {"name": "diffie-hellman-group16-sha512", "valid_until": 2030},
    "ecdh-sha2-nistp256": {
        "name": "ecdh-sha2-nistp256",
        "valid_until": 2030,
        "description": "TR-02102-4 | 3.3",
    },
    "ecdh-sha2-nistp384": {
        "name": "ecdh-sha2-nistp384",
        "valid_until": 2030,
        "description": "TR-02102-4 | 3.3",
    },
    "ecdh-sha2-nistp521": {
        "name": "ecdh-sha2-nistp521",
        "valid_until": 2030,
        "description": "TR-02102-4 | 3.3",
    },
}

BSI_ENCRYPTION_ALGORITHMS = {
    "AEAD_AES_128_GCM": {"name": "AEAD_AES_128_GCM", "valid_until": 2030},
    "AEAD_AES_256_GCM": {"name": "AEAD_AES_256_GCM", "valid_until": 2030},
    "aes128-ctr": {"name": "aes128-ctr", "valid_until": 2030},
    "aes192-ctr": {"name": "aes192-ctr", "valid_until": 2030},
    "aes256-ctr": {"name": "aes256-ctr", "valid_until": 2030},
}

BSI_MAC_ALGORITHMS = {
    "hmac-sha2-256": {"name": "hmac-sha2-256", "valid_until": 2030},
    "hmac-sha2-512": {"name": "hmac-sha2-512", "valid_until": 2030},
}

BSI_SERVER_HOST_KEY_ALGORITHMS = {
    "pgp-sign-dss": {
        "name": "pgp-sign-dss",
        "valid_until": 2029,
        "description": "TR-02102-4 | 3.6",
    },
    "ecdsa-sha2-nistp256": {
        "name": "ecdsa-sha2-nistp256",
        "valid_until": 2030,
        "description": "TR-02102-4 | 3.6",
    },
    "ecdsa-sha2-nistp384": {
        "name": "ecdsa-sha2-nistp384",
        "valid_until": 2030,
        "description": "TR-02102-4 | 3.6",
    },
    "ecdsa-sha2-nistp521": {
        "name": "ecdsa-sha2-nistp521",
        "valid_until": 2030,
        "description": "TR-02102-4 | 3.6",
    },
    "x509v3-ecdsa-sha2-nistp256": {
        "name": "x509v3-ecdsa-sha2-nistp256",
        "valid_until": 2030,
        "description": "TR-02102-4 | 3.6",
    },
    "x509v3-ecdsa-sha2-nistp384": {
        "name": "x509v3-ecdsa-sha2-nistp384",
        "valid_until": 2030,
        "description": "TR-02102-4 | 3.6",
    },
    "x509v3-ecdsa-sha2-nistp521": {
        "name": "x509v3-ecdsa-sha2-nistp521",
        "valid_until": 2030,
        "description": "TR-02102-4 | 3.6",
    },
}


class bsi_compliance_ssh(BaseModule):
    watched_events = ["PROTOCOL"]
    produced_events = ["BSI_COMPLIANCE_RESULT", "FINDING", "VULNERABILITY"]
    flags = [
        "active",
        "safe",
        "report",
    ]  # active = Makes active connections to target systems, safe = Non-intrusive, safe to run, report = Generates a report at the end of the scan,
    meta = {"description": "Checks Algorithms used by the Target - SSH"}
    _max_event_handlers = 4
    _type = "scan"
    options = {"compliant_until": ""}
    options_desc = {"compliant_until": "Configuration compliant until year (e.g. 2026)"}

    async def setup(self):
        self.compliant_until = self.config.get("compliant_until", "")
        if not self.compliant_until:
            self.compliant_until = datetime.datetime.now().year + 2
        self.compliant_until = int(self.compliant_until)
        return True

    async def handle_event(self, event):
        if "SSH" in event.data["protocol"]:  # Tests if the protocol matches

            # Check for outdated BSI Algorithms
            [
                await self.emit_event(
                    {
                        "host": event.data["host"],
                        "description": algorithm["name"]
                        + " is only valid until "
                        + str(algorithm["valid_until"])
                        + ": Please check suppoerted Algorithms",
                    },
                    "FINDING",
                    source=event,
                    tags="SSH",
                )
                for algorithm in BSI_KEX_ALGORITHMS.values()
                if algorithm["valid_until"] < self.compliant_until
            ]
            [
                await self.emit_event(
                    {
                        "host": event.data["host"],
                        "description": algorithm["name"]
                        + " is only valid until "
                        + str(algorithm["valid_until"])
                        + ": Please check suppoerted Algorithms",
                    },
                    "FINDING",
                    source=event,
                    tags="SSH",
                )
                for algorithm in BSI_SERVER_HOST_KEY_ALGORITHMS.values()
                if algorithm["valid_until"] < self.compliant_until
            ]
            [
                await self.emit_event(
                    {
                        "host": event.data["host"],
                        "description": algorithm["name"]
                        + " is only valid until "
                        + str(algorithm["valid_until"])
                        + ": Please check suppoerted Algorithms",
                    },
                    "FINDING",
                    source=event,
                    tags="SSH",
                )
                for algorithm in BSI_MAC_ALGORITHMS.values()
                if algorithm["valid_until"] < self.compliant_until
            ]
            [
                await self.emit_event(
                    {
                        "host": event.data["host"],
                        "description": algorithm["name"]
                        + " is only valid until "
                        + str(algorithm["valid_until"])
                        + ": Please check suppoerted Algorithms",
                    },
                    "FINDING",
                    source=event,
                    tags="SSH",
                )
                for algorithm in BSI_ENCRYPTION_ALGORITHMS.values()
                if algorithm["valid_until"] < self.compliant_until
            ]

            # Check for Server Algorithms

            target_ip = event.data["host"]  # gets IP_Address of Target
            target_port = event.data["port"]  # gets Port of Target
            target_algorithms = self.get_algorithms(target_ip, target_port)
            if target_algorithms != 0:
                parsed_algorithms = self.parser(target_algorithms)
                found_algorithms = self.filter_output_types(self.convert_list_to_dict(parsed_algorithms))
                invalid_algorithms = self.check_compliance(parsed_algorithms)
                if not invalid_algorithms:
                    invalid_algorithms = None
                else:
                    invalid_algorithms = self.filter_output_types(
                        self.convert_list_to_dict(invalid_algorithms)
                )

                compliance_data = {
                    "host": target_ip,
                    "port": target_port,
                    "found_algorithms": found_algorithms,
                    "invalid_algorithms": invalid_algorithms,
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

    def filter_output_types(self, input_list):
        del input_list["ENCRYPTION_CLIENT_TO_SERVER"]
        del input_list["MAC_CLIENT_TO_SERVER"]
        del input_list["COMPRESSION_CLIENT_TO_SERVER"]
        del input_list["COMPRESSION_SERVER_TO_CLIENT"]
        return input_list

    def convert_list_to_dict(self, input_list):
        parsed_algorithm = copy.deepcopy(input_list)
        for index, values in enumerate(parsed_algorithm["KEX"]):
            parsed_algorithm["KEX"][index] = {"name": values}
            for names in BSI_KEX_ALGORITHMS.keys():
                if values.__contains__(names):
                    parsed_algorithm["KEX"][index] = BSI_KEX_ALGORITHMS[names]

        for index, values in enumerate(parsed_algorithm["SERVER_HOST_KEY"]):
            parsed_algorithm["SERVER_HOST_KEY"][index] = {"name": values}
            for names in BSI_SERVER_HOST_KEY_ALGORITHMS.keys():
                if values.__contains__(names):
                    parsed_algorithm["SERVER_HOST_KEY"][index] = BSI_SERVER_HOST_KEY_ALGORITHMS[names]

        for index, values in enumerate(parsed_algorithm["ENCRYPTION_CLIENT_TO_SERVER"]):
            parsed_algorithm["ENCRYPTION_CLIENT_TO_SERVER"][index] = {"name": values}

        for index, values in enumerate(parsed_algorithm["ENCRYPTION_SERVER_TO_CLIENT"]):
            parsed_algorithm["ENCRYPTION_SERVER_TO_CLIENT"][index] = {"name": values}
            for names in BSI_ENCRYPTION_ALGORITHMS.keys():
                if values.__contains__(names):
                    parsed_algorithm["ENCRYPTION_SERVER_TO_CLIENT"][index] = BSI_ENCRYPTION_ALGORITHMS[names]

        for index, values in enumerate(parsed_algorithm["MAC_CLIENT_TO_SERVER"]):
            parsed_algorithm["MAC_CLIENT_TO_SERVER"][index] = {"name": values}

        for index, values in enumerate(parsed_algorithm["MAC_SERVER_TO_CLIENT"]):
            parsed_algorithm["MAC_SERVER_TO_CLIENT"][index] = {"name": values}
            for names in BSI_MAC_ALGORITHMS.keys():
                if values.__contains__(names):
                    parsed_algorithm["MAC_SERVER_TO_CLIENT"][index] = BSI_MAC_ALGORITHMS[names]

        for index, values in enumerate(parsed_algorithm["COMPRESSION_CLIENT_TO_SERVER"]):
            parsed_algorithm["COMPRESSION_CLIENT_TO_SERVER"][index] = {"name": values}

        for index, values in enumerate(parsed_algorithm["COMPRESSION_SERVER_TO_CLIENT"]):
            parsed_algorithm["COMPRESSION_SERVER_TO_CLIENT"][index] = {"name": values}

        return parsed_algorithm

    def check_compliance(self, input_list):
        temp = copy.deepcopy(input_list)

        for algorithm in BSI_KEX_ALGORITHMS.values():
            for value in temp["KEX"]:
                if value.__contains__(algorithm["name"]):
                    temp["KEX"].remove(value)
        for algorithm in BSI_SERVER_HOST_KEY_ALGORITHMS.values():
            for value in temp["SERVER_HOST_KEY"]:
                if value.__contains__(algorithm["name"]):
                    temp["SERVER_HOST_KEY"].remove(value)
        for algorithm in BSI_ENCRYPTION_ALGORITHMS.values():
            for value in temp["ENCRYPTION_SERVER_TO_CLIENT"]:
                if value.__contains__(algorithm["name"]):
                    temp["ENCRYPTION_SERVER_TO_CLIENT"].remove(value)
        for algorithm in BSI_MAC_ALGORITHMS.values():
            for value in temp["MAC_SERVER_TO_CLIENT"]:
                if value.__contains__(algorithm["name"]):
                    temp["MAC_SERVER_TO_CLIENT"].remove(value)

        return 0 if not any(temp.values()) else temp
