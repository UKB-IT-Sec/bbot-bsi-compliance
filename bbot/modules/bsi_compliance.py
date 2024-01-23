from bbot.modules.base import BaseModule

class bsi_compliance(BaseModule):
    """
    Check discovered services for compliance with BSI KRITIS standards
    Applies to SSH, IPSec and TLS
    """
    watched_events = ["IP_ADDRESS"]
    produced_events = [] # TODO: implement
    flags = ["active"] # TODO: check what kind of flags are needed

    async def handle_event(self, event):
        # TODO: implement
        pass
