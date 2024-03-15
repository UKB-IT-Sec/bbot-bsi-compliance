from bbot.modules.base import BaseModule
from datetime import datetime
import subprocess

CURRENT_YEAR = datetime.now().year


class bsi_compliance_ipsec(BaseModule):
    watched_events = ["PROTOCOL"]
    produced_events = ["BSI_COMPLIANCE_RESULT", "FINDING"]
    flags = [
        "active",
        "safe",
        "report",
    ]  # active = Makes active connections to target systems, safe = Non-intrusive, safe to run, report = Generates a report at the end of the scan,
    meta = {"description": "Checks Algorithms used by the Target - IPSEC"}
    options = {"version": "1.0"}
    options_desc = {"version": "Version based of last fundamental Change"}
    _max_event_handlers = 2
    _type = "check"

    async def handle_event(self, event):
        if "IPSEC" in event.data.get("protocol"):  # Tests if the protocol matches
            target_ip = event.data.get("host")  # gets IP_Address of Target
            target_port = event.data.get("port")  # gets Port of Target
            version_check = self.version(target_ip)
            compliance_data = {"host": target_ip, "port": target_port, "protocol": "IPSEC", "version": version_check}
            await self.emit_event(compliance_data, "BSI_COMPLIANCE_RESULT")

        pass

    def version(target):
        cmd = ["ike-scan", target]
        try:
            # Run ike-scan with the target IP address
            p = subprocess.check_output(cmd)
            # Print the output to stdout
            if b"0000000000000000" in p:
                return "Ausschließlich IKEv2"
            else:
                return "IKEv1 wird unterstützt"
        except subprocess.CalledProcessError as e:
            # If there's an error, print the error message
            print("Error executing ike-scan:", e)
