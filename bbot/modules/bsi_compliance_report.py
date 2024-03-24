from bbot.core.event.base import BaseEvent
from bbot.modules.base import BaseModule


class bsi_compliance_report(BaseModule):
    """
    Generate report based on BSI compliance module results
    """
    watched_events = ["BSI_COMPLIANCE_RESULT", "FINDING", "VULNERABILITY"]
    produced_events = []
    flags = ["passive", "safe"]
    _type = "report"

    async def handle_event(self, event: BaseEvent):
        self.hugeinfo(f"GOT EVENT: {event.type}")
        self.debug(f"{event.data_human}")
