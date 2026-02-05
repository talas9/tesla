# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/messages.py
import asyncio, logging
from architect import Node, Input, Output, Signal, slot
from hermes_client_wrapper.client import HermesProxy
from odin.core.engine import messagebox
from odin_server import messages
from odin_server.hermes import CommandType
log = logging.getLogger(__name__)

class Broadcast(Node):
    message_type = Input("String")
    message = Input("Dict")
    hermes_topic = Input("String")
    done = Signal()

    @slot()
    async def send(self):
        ctxt = self._root()._context()
        run_id = ctxt["run_id"]
        execution_options = ctxt.get("execution_options")
        response_topic = execution_options.get("response_topic")
        req_txid = execution_options.get("req_txid")
        message_type, hermes_topic, message = await asyncio.gather(self.message_type(), self.hermes_topic(), self.message())
        message["message_type"] = message_type
        message["request_id"] = run_id
        outgoing = {'message':message, 
         'hermes_topic':hermes_topic or response_topic, 
         'command_type':ctxt["execution_options"].get("command_type", 0), 
         'req_txid':req_txid}
        await messagebox.outbox.put(outgoing)
        await self.done()


class Listen(Node):
    message_type = Input("String")
    message = Output("Dict")
    timeout = Input("Float")
    while_listening = Signal()
    done = Signal()
    timed_out = Signal()

    @slot()
    async def receive(self):
        message_type, timeout = await asyncio.gather(self.message_type(), self.timeout())
        log.debug("Listening for %s", message_type)
        try:
            async with messagebox.inbox.listening(message_type) as event:
                while_listening_future = asyncio.ensure_future(self.while_listening())
                try:
                    if timeout:
                        message = await asyncio.wait_for((event.wait()), timeout=timeout)
                    else:
                        message = await event.wait()
                finally:
                    while_listening_future.cancel()

        except asyncio.TimeoutError:
            await self.timed_out()
            return
        else:
            self.message.value = message
            await self.done()


class Send(Node):
    payload = Input("String")
    message_topic = Input("String")
    command_type = Input("String")
    txid = Input("String")
    sender_id = Input("String")
    response_topic = Input("String")
    req_txid = Input("String")
    done = Signal()

    @slot()
    async def send(self):
        ctxt = self._root()._context()
        payload, message_topic, command_type, txid, sender_id, response_topic, req_txid = await asyncio.gather(self.payload(), self.message_topic(), self.command_type(), self.txid(), self.sender_id(), self.response_topic(), self.req_txid())
        sender_id = sender_id or ""
        response_topic = response_topic or ctxt.get("execution_options", {}).get("response_topic", "")
        txid = txid or ctxt.get("run_id", "")
        req_txid = req_txid or ctxt.get("execution_options", {}).get("req_txid", "")
        log.debug(("Directly sending message:\n\tsender_id = {sender_id}\n\tpayload = {payload}\n\tmessage_topic = {message_topic}\n\tcommand_type = {command_type}\n\ttxid = {txid}\n\tresponse_topic= {response_topic}\n\treq_txid = {req_txid}".format)(**))
        try:
            message = HermesProxy.build_message((bytes(payload, "utf-8")),
              (bytes(message_topic, "utf-8")),
              (bytes(txid, "utf-8")),
              (bytes(sender_id, "utf-8")),
              command_type=(int(command_type)),
              response_topic=(bytes(response_topic, "utf-8")),
              req_txid=(bytes(req_txid, "utf-8")))
        except:
            log.exception("Error packaging message for hermes")
        else:
            message_handler = ctxt["execution_options"].get("message_handler")
            if message_handler:
                log.debug("sending: %s", message)
                hermes = message_handler.app["hermes.proxy"]
                response = await hermes.send(message)
                log.debug("response: %s", response)
            else:
                log.error("No message handler to send message")
            await self.done()


class StatusUpdate(Node):
    status = Input("String")
    hermes_topic = Input("String")
    done = Signal()

    @slot()
    async def send(self):
        ctxt = self._root()._context()
        run_id = ctxt.get("run_id", "")
        execution_options = ctxt.get("execution_options")
        response_topic = execution_options.get("response_topic")
        req_txid = execution_options.get("req_txid")
        status, hermes_topic = await asyncio.gather(self.status(), self.hermes_topic())
        message = messages.StatusUpdate(run_id, status)
        outgoing = {'message':message, 
         'hermes_topic':hermes_topic or response_topic, 
         'command_type':ctxt["execution_options"].get("command_type", 0), 
         'hermes_req_txid':req_txid}
        await messagebox.outbox.put(outgoing)
        await self.done()


class ProgressUpdate(Node):
    value = Input("Int")
    hermes_topic = Input("String")
    done = Signal()

    @slot()
    async def send(self):
        ctxt = self._root()._context()
        run_id = ctxt.get("run_id", "")
        execution_options = ctxt.get("execution_options")
        response_topic = execution_options.get("response_topic")
        req_txid = execution_options.get("req_txid")
        value, hermes_topic = await asyncio.gather(self.value(), self.hermes_topic())
        message = messages.ProgressUpdate(run_id, value)
        outgoing = {'message':message, 
         'hermes_topic':hermes_topic or response_topic, 
         'command_type':ctxt["execution_options"].get("command_type", 0), 
         'hermes_req_txid':req_txid}
        await messagebox.outbox.put(outgoing)
        await self.done()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/messages.pyc
