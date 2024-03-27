import datetime
from bbot.modules.base import BaseModule
from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ServerScanStatusEnum,
)
from sslyze.errors import ServerHostnameCouldNotBeResolved
import socket
from tlslite.api import *

# TR-02102-2 | 3.3.1.1, 3.3.1.2 und 3.3.1.3
# Cipher suites with the pattern TLS_RSA_PSK_* do not provide Perfect Forward Secrecy
CIPHER_SUITES_TLS_1_2 = {
    # 3.3.1.1
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256" : {
        "name": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": {
        "name": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": {
        "name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": {
        "name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_ECDHE_ECDSA_WITH_AES_128_CCM": {
        "name": "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_ECDHE_ECDSA_WITH_AES_256_CCM": {
        "name": "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": {
        "name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": {
        "name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": {
        "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": {
        "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256": {
        "name": "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256": {
        "name": "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256": {
        "name": "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384": {
        "name": "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256": {
        "name": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256": {
        "name": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": {
        "name": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": {
        "name": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_DHE_RSA_WITH_AES_128_CCM": {
        "name": "TLS_DHE_RSA_WITH_AES_128_CCM",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    "TLS_DHE_RSA_WITH_AES_256_CCM": {
        "name": "TLS_DHE_RSA_WITH_AES_256_CCM",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.1",
    },
    # 3.3.1.2
    "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256": {
        "name": "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.2",
    },
    "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384": {
        "name": "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.2",
    },
    "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256": {
        "name": "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.2",
    },
    "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384": {
        "name": "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.2",
    },
    "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256": {
        "name": "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.2",
    },
    "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384": {
        "name": "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.2",
    },
    "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256": {
        "name": "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.2",
    },
    "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384": {
        "name": "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.2",
    },
    "TLS_DH_DSS_WITH_AES_128_CBC_SHA256": {
        "name": "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.2",
    },
    "TLS_DH_DSS_WITH_AES_256_CBC_SHA256": {
        "name": "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.2",
    },
    "TLS_DH_DSS_WITH_AES_128_GCM_SHA256": {
        "name": "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.2",
    },
    "TLS_DH_DSS_WITH_AES_256_GCM_SHA384": {
        "name": "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.2",
    },
    "TLS_DH_RSA_WITH_AES_128_CBC_SHA256": {
        "name": "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.2",
    },
    "TLS_DH_RSA_WITH_AES_256_CBC_SHA256": {
        "name": "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.2",
    },
    "TLS_DH_RSA_WITH_AES_128_GCM_SHA256": {
        "name": "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.2",
    },
    "TLS_DH_RSA_WITH_AES_256_GCM_SHA384": {
        "name": "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.2",
    },
    # 3.3.1.3
    "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256": {
        "name": "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.3",
    },
    "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384": {
        "name": "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.3",
    },
    "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256": {
        "name": "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.3",
    },
    "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384": {
        "name": "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.3",
    },
    "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256": {
        "name": "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.3",
    },
    "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256": {
        "name": "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.3",
    },
    "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384": {
        "name": "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.3",
    },
    "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256": {
        "name": "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.3",
    },
    "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384": {
        "name": "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.3",
    },
    "TLS_DHE_PSK_WITH_AES_128_CCM": {
        "name": "TLS_DHE_PSK_WITH_AES_128_CCM",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.3",
    },
    "TLS_DHE_PSK_WITH_AES_256_CCM": {
        "name": "TLS_DHE_PSK_WITH_AES_256_CCM",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.3.1.3",
    },
    "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256": {
        "name": "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.3",
    },
    "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384": {
        "name": "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.3",
    },
    "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256": {
        "name": "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.3",
    },
    "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384": {
        "name": "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
        "valid_until": 2026,
        "reason": "Keine Perfect Forward Secrecy Tr-02102-2 | 3.3.1.3",
    },
}

# TR-02102-2 | 3.4.4
CIPHER_SUITES_TLS_1_3 = {
    "TLS_AES_128_GCM_SHA256": {
        "name": "TLS_AES_128_GCM_SHA256",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.4.4",
    },
    "TLS_AES_256_GCM_SHA384": {
        "name": "TLS_AES_256_GCM_SHA384",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.4.4",
    },
    "TLS_AES_128_CCM_SHA256": {
        "name": "TLS_AES_128_CCM_SHA256",
        "valid_until": 2029,
        "reason": "Empfohlen in TR-02102-2 | 3.4.4",
    },
}

tls_enabled_protocols = ["MQTT5", "HTTPS", "SMTPS", "MQTT3", "RDP", "POP3S", "LDAPS", "IMAPS", "Kafka"]
class bsi_compliance_tls(BaseModule):
    """
    Check discovered TLS services for compliance with BSI KRITIS standards
    """

    watched_events = ["PROTOCOL"]
    produced_events = ["BSI_COMPLIANCE_RESULT", "VULNERABILITY", "FINDING"]
    flags = ["active", "safe"]
    deps_pip = ["sslyze~=5.2.0", "tlslite-ng~=0.7.6"]
    meta = {"description": "Check discovered TLS services for compliance with BSI KRITIS standards"}
    options = {"compliant_until": ""}
    options_desc = {"compliant_until": "Configuration compliant until year (e.g. 2026)"}

    async def setup(self):
        self.compliant_until = self.config.get("compliant_until", "")
        if not self.compliant_until:
            self.compliant_until = datetime.datetime.now().year + 2
        self.compliant_until = int(self.compliant_until)
        return True

    async def handle_event(self, event):
        if event.data["protocol"] not in tls_enabled_protocols:
            self.verbose(f"Skipping {event.data['protocol']} because it is not a TLS protocol")
            return

        self.info(f"Checking host {event.host}:{event.port} for TLS compliance until year {self.compliant_until}")

        # Create a new scanner and queue the scan
        try:
            scan_request = [
                ServerScanRequest(
                    server_location=ServerNetworkLocation(hostname=event.host, port=int(event.port))
                )
            ]
        except ServerHostnameCouldNotBeResolved:
            self.error(f"Could not resolve hostname: {event.host}")
            return
        scanner = Scanner()
        scanner.queue_scans(scan_request)

        try:
            all_scan_requests = [
                ServerScanRequest(
                    server_location=ServerNetworkLocation(hostname=event.host, port=int(event.port))
                ),
            ]
        except ServerHostnameCouldNotBeResolved:
            # Handle bad input ie. invalid hostnames
            self.error("Error resolving the supplied hostnames")
            return

        # Then queue all the scans
        scanner = Scanner()
        scanner.queue_scans(all_scan_requests)
        
        # Parse the results
        output_data = {
            "found_algorithms":
            {
                "PROTOCOLS": [],
                "TLS_1_2_CIPHERS": [], 
                "TLS_1_3_CIPHERS": [],
                "EXTENSIONS": []
            },
            "invalid_algorithms": {
                "PROTOCOLS": [],
                "TLS_1_2_CIPHERS": [],
                "TLS_1_3_CIPHERS": [],
                "EXTENSIONS": []
            }
        }
        self.event = event

        # Since we are only scanning one server, we can just get the results
        result = scanner.get_results().__next__()
        
        # Check if connection to the server was successful
        if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            self.error(f"Could not connect to {result.server_location.hostname}")
            raise Exception(f"Could not connect to {result.server_location.hostname}")

        # If the connection was successful, the scan result is populated
        assert result.scan_result
        scan_result = result.scan_result

        # Check if insecure SSL/TLS versions are supported
        if len(scan_result.ssl_2_0_cipher_suites.result.accepted_cipher_suites) > 0:
            output_data["found_algorithms"]["PROTOCOLS"].append("SSL 2.0")
            output_data["invalid_algorithms"]["PROTOCOLS"].append("SSL 2.0")
            self.verbose(f"SSL 2.0 is supported")
        if len(scan_result.ssl_3_0_cipher_suites.result.accepted_cipher_suites) > 0:
            output_data["found_algorithms"]["PROTOCOLS"].append("SSL 3.0")
            output_data["invalid_algorithms"]["PROTOCOLS"].append("SSL 3.0")
            self.verbose(f"SSL 3.0 is supported")
        if len(scan_result.tls_1_0_cipher_suites.result.accepted_cipher_suites) > 0:
            output_data["found_algorithms"]["PROTOCOLS"].append("TLS 1.0")
            output_data["invalid_algorithms"]["PROTOCOLS"].append("TLS 1.0")
            self.verbose(f"TLS 1.0 is supported")
        if len(scan_result.tls_1_1_cipher_suites.result.accepted_cipher_suites) > 0:
            output_data["found_algorithms"]["PROTOCOLS"].append("TLS 1.1")
            output_data["invalid_algorithms"]["PROTOCOLS"].append("TLS 1.1")
            self.verbose(f"TLS 1.1 is supported")

        # Check if TLS 1.2 is supported and check cipher suites
        secure_tls_1_2_ciphers, insecure_tls_1_2_ciphers = [], []
        lucky13_vulnerable = False
        if len(scan_result.tls_1_2_cipher_suites.result.accepted_cipher_suites) > 0:
            self.verbose(f"TLS 1.2 is supported")
            output_data["found_algorithms"]["PROTOCOLS"].append("TLS 1.2")
            secure_tls_1_2_ciphers, insecure_tls_1_2_ciphers, lucky13_vulnerable = self.check_tls_1_2_cipher_suites(scan_result.tls_1_2_cipher_suites.result.accepted_cipher_suites)
            output_data["found_algorithms"]["TLS_1_2_CIPHERS"].append(secure_tls_1_2_ciphers + insecure_tls_1_2_ciphers)
            output_data["invalid_algorithms"]["TLS_1_2_CIPHERS"].append(insecure_tls_1_2_ciphers)
            
        else:
            output_data["invalid_algorithms"]["PROTOCOLS"].append("TLS 1.2 NOT SUPPORTED")
            self.verbose("Error: No TLS 1.2 cipher suites supported")

        # Check if TLS 1.3 is supported and check cipher suites
        secure_tls_1_3_ciphers, insecure_tls_1_3_ciphers = [], []
        if len(scan_result.tls_1_3_cipher_suites.result.accepted_cipher_suites) > 0:
            output_data["found_algorithms"]["PROTOCOLS"].append("TLS 1.3")
            self.verbose(f"TLS 1.3 is supported")
            secure_tls_1_3_ciphers, insecure_tls_1_3_ciphers = self.check_tls_1_3_cipher_suites(scan_result.tls_1_3_cipher_suites.result.accepted_cipher_suites)
            output_data["found_algorithms"]["TLS_1_3_CIPHERS"].append(secure_tls_1_3_ciphers + insecure_tls_1_3_ciphers)
            output_data["invalid_algorithms"]["TLS_1_3_CIPHERS"].append(insecure_tls_1_3_ciphers)
        else:
            output_data["invalid_algorithms"]["PROTOCOLS"].append("TLS 1.3 NOT SUPPORTED")
            self.verbose("No TLS 1.3 cipher suites supported")
            
        # Check if the server is vulnerable to heartbleed
        if scan_result.heartbleed.result.is_vulnerable_to_heartbleed:
            self.info("Server is vulnerable to heartbleed")
            vulnerability_event = self.make_event( 
                {"severity": "CRITICAL",
                 "host": str(event.host),
                 "url": "https://" + str(event.host) + ":" + str(event.port),
                 "description": "Heartbleed vulnerability detected on the server."},
                "VULNERABILITY",
                event,
                tags=["tls", "bsi_compliance"]
            )
            await self.emit_event(vulnerability_event)
            output_data["invalid_algorithms"]["EXTENSIONS"].append({
                "name": "heartbeat", 
                "reason": "Heartbleed Verwundbarkeit erkannt TR-02102-2 | 3.3.4.6"
                })
        
        # Check if the server supports TLS compression (CRIME attack)
        if scan_result.tls_compression.result.supports_compression:
            self.verbose("Server supports TLS compression")
            output_data["invalid_algorithms"]["EXTENSIONS"].append({
                "name": "tls-compression", 
                "reason": "TLS Compression wird unterstützt TR-02102-2 | 3.3.4.3"
                })
        
        # Check if the server is vulnerable to LUCKY13
        if lucky13_vulnerable:
            self.info("Server is potentially vulnerable to LUCKY13")
            await self.emit_event(
                    {"description": "Server is potentially vulnerable to LUCKY13.",
                     "host": str(event.host),
                     "url": event.data},
                    "FINDING",
                    tags=["TLS", "LUCKY13"],
                    source=event,
                )
            output_data["invalid_algorithms"]["EXTENSIONS"].append({
                "name": "encrypt-then-mac", 
                "reason": "CBC Cipher suites werden verwendet und encrypt-then-mac nicht unterstützt TR-02102-2 | 3.3.4.4 und 3.3.4.5"
                })
        
        if self.check_extended_master_secret_supported(event):
            output_data["found_algorithms"]["EXTENSIONS"].append({
                "name": "extended-master-secret",
                "reason": "Server unterstützt die extended-master-secret Erweiterung TR-02102-2 | 3.3.4.7"
                })
        else:
            output_data["invalid_algorithms"]["EXTENSIONS"].append({
                "name": "extended-master-secret",
                "reason": "Server unterstützt die extended-master-secret Erweiterung nicht TR-02102-2 | 3.3.4.6"
                })
        
        self.info("BSI Compliance check complete")
        compliance_event = self.make_event(output_data, "BSI_COMPLIANCE_RESULT", source=event, tags=["TLS"])
        await self.emit_event(compliance_event)

    
    def check_encrypt_then_mac_supported(self, event):
        """
        Check if the server supports encrypt-then-mac
        
        Parameters:
        ----------
            event (Dict): Event object

        Returns:
        ----------
            supported (Bool): True if the server supports encrypt-then-mac, False otherwise
        """
        supported = False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect( (event.host, int(event.port)) )
        
        # Create a TLS connection
        connection = TLSConnection(sock)
        
        # Only specify cipher suites where encrypt then mac extensions should be supported
        handshakeSettings = HandshakeSettings()
        handshakeSettings.cipherNames = ["aes256", "aes128"]
        
        # Send ClientHello message
        try:
            connection.handshakeClientCert(settings=handshakeSettings)
        except:
            # This is probably because the server has a self-signed certificate
            # Try again without the client certificate
            self.info("Handshake failed. Server probably has a self-signed certificate. Retrying without client certificate.")
            try:
                connection.handshakeClientAnonymous(settings=handshakeSettings)
            except:
                self.warning("Handshake failed. Could not establish a tls connection. Assuming encrypt-then-mac is not supported.")
                return False
        
        # Check if the server supports the encrypt-then-mac extension
        if connection.session.encryptThenMAC:
            supported = True
            self.verbose("Server supports the encrypt-then-mac extension")
        else:
            self.verbose("Server does not support the encrypt-then-mac extension")
            
        connection.close()
        return supported
    
    def check_extended_master_secret_supported(self, event):
        """
        Check if the server supports extended master secret
        
        Parameters:
        ----------
            event (Dict): Event object
        
        Returns:
        ----------
            supported (Bool): True if the server supports extended master secret, False otherwise
        """
        supported = False
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect( (event.host, int(event.port)) )
        
        # Create a TLS connection
        connection = TLSConnection(sock)
        # Send ClientHello message
        try:
            connection.handshakeClientCert()
        except:
            # This is probably because the server has a self-signed certificate
            # Try again without the client certificate
            self.info("Handshake failed. Server probably has a self-signed certificate. Retrying without client certificate.")
            try:
                connection.handshakeClientAnonymous()
            except:
                self.warning("Handshake failed. Could not establish a tls connection. Assuming extended master secret is not supported.")
                return False
        
        # Check if the server supports the extended master secret extension
        if connection.session.extendedMasterSecret:
            supported = True
            self.verbose("Server supports the extended master secret extension")
        else:
            self.verbose("Server does not support the extended master secret extension")

        connection.close()
        return supported
    
    def check_tls_1_2_cipher_suites(self, cipher_suites):
        """
        Check if the tls 1.3 cipher suites are compliant with BSI KRITIS standards
        
        Parameters:
        ----------
            cipher_suites (Array): Array of cipher suites to check
        
        Returns:
        ----------
            secure_ciphers (Array): Array of secure cipher suites
            insecure_ciphers (Array): Array of insecure cipher suites
        """
        secure_ciphers = []
        insecure_ciphers = []
        
        secure_then_mac_supported = self.check_encrypt_then_mac_supported(self.event)
        lucky13_vulnerable = False
        
        for cipher_suite_accepted_by_server in cipher_suites:
            cipher_suite_name = cipher_suite_accepted_by_server.cipher_suite.name
            if cipher_suite_name not in CIPHER_SUITES_TLS_1_2:
                insecure_ciphers.append({
                    "name": cipher_suite_name,
                    "reason": "Nicht empfohlen in TR-02102-2",
                    "valid_until": -1,
                })
                continue
            cipher_suite = CIPHER_SUITES_TLS_1_2[cipher_suite_name]
            if cipher_suite["valid_until"] < self.compliant_until:
                cipher_suite["reason"] = "Nicht empfohlen in TR-02102-2 | Gültigkeitsdauer abgelaufen"
                insecure_ciphers.append(cipher_suite)
                continue
            # Check if any of the cipher suites are using cbc since they are only recommended if encrypt-then-mac is supported
            if "CBC" in cipher_suite_name:
                if not secure_then_mac_supported:
                    cipher_suite["reason"] = "Nicht empfohlen in TR-02102-2 | encrypt-then-mac Erweiterung nicht unterstützt 3.3.4.5"
                    insecure_ciphers.append(cipher_suite)
                    lucky13_vulnerable = True
                    continue
            secure_ciphers.append(cipher_suite)
        return secure_ciphers, insecure_ciphers, lucky13_vulnerable
        
    
    def check_tls_1_3_cipher_suites(self, cipher_suites):
        """
        Check if the tls 1.2 cipher suites are compliant with BSI KRITIS standards

        Parameters:
        ----------
            cipher_suites (Array): Array of cipher suites to check
            
        Returns:
        ----------
            secure_ciphers (Array): Array of secure cipher suites
            insecure_ciphers (Array): Array of insecure cipher suites
        """
        secure_ciphers = []
        insecure_ciphers = []

        for cipher_suite_accepted_by_server in cipher_suites:
            cipher_suite_name = cipher_suite_accepted_by_server.cipher_suite.name
            if cipher_suite_name not in CIPHER_SUITES_TLS_1_3:
                insecure_ciphers.append({
                    "name": cipher_suite_name,
                    "reason": "Nicht empfohlen in TR-02102-2",
                    "valid_until": -1,
                })
                continue
            cipher_suite = CIPHER_SUITES_TLS_1_3[cipher_suite_name]
            if cipher_suite["valid_until"] < self.compliant_until:
                cipher_suite["reason"] = "Nicht empfohlen in TR-02102-2 | Gültigkeitsdauer abgelaufen"
                insecure_ciphers.append(cipher_suite)
                continue
            secure_ciphers.append(cipher_suite)
        return secure_ciphers, insecure_ciphers
