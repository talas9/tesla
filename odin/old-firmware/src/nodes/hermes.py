# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/hermes.py
import logging
from architect import Node, Input, output, Output, Signal, slot
from odin.core.engine.hermes import messagebox
from odin.core.utils.dispatch import Dispatch
log = logging.getLogger(__name__)

class ListenTopic(Node):
    topic = Input("String")
    message = Output("Dict")
    done = Signal()

    @slot()
    async def wait_for(self):
        topic = await self.topic()
        log.debug("Listening for topic: {}".format(topic))
        event = messagebox.topic_event_queue.get(topic, None)
        if event is None:
            event = Dispatch()
            messagebox.topic_event_queue[topic] = event
        log.debug("Awaiting dispatch.")
        message = await event.wait()
        log.debug("Message on topic {} received.".format(topic))
        self.message.value = message
        await self.done()


class GenerateDeviceTopic(Node):
    channel = Input("String")

    @output("String")
    async def topic(self):
        ctxt = self._root()._context()
        response_topic = ctxt.get("execution_options", {}).get("topic", "")
        if not response_topic:
            raise RuntimeError("GenerateDeviceTopic node did not have a network context response topic. The network containing this node must be run from hermes.")
        topic_parts = response_topic.split(".")
        topic_parts[-1] = await self.channel()
        return ".".join(topic_parts)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/hermes.pyc
