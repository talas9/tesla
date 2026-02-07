# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/misc.py
import asyncio, datetime, uuid, string
from re import fullmatch
from architect import Node, Input, output, Output, Signal, slot
from architect.nodes import ReferencedSubnetwork
from odin.core.utils import payload

class Uuid(Node):

    @output("String")
    async def uuid(self):
        return str(uuid.uuid4())


class DateTime(Node):

    @output("String")
    async def now(self):
        return datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]


class ReferencedValidationSubnetwork(ReferencedSubnetwork):
    _register_with_name = "misc.ReferencedValidationSubnetwork"


class IsAlphaNumeric(Node):
    input_text = Input("String")
    allowed_chars = string.ascii_letters + string.digits

    @output("Bool")
    async def alphanumeric(self):
        try:
            payload.validate_safe_string(await self.input_text(), self.allowed_chars)
        except ValueError:
            return False
        else:
            return True


class SanitizeString(Node):
    input_text = Input("String")
    ascii_letters = Input("Bool", default=True)
    digits = Input("Bool", default=True)
    whitespace = Input("Bool", default=False)
    allowed_chars = Input("String", default="")
    value_error_message = Input("String", default="")

    @output("String")
    async def sanitize(self):
        input_text, ascii_letters, digits, whitespace, allowed_chars = await asyncio.gather(self.input_text(), self.ascii_letters(), self.digits(), self.whitespace(), self.allowed_chars())
        if ascii_letters:
            allowed_chars += string.ascii_letters
        if digits:
            allowed_chars += string.digits
        if whitespace:
            allowed_chars += string.whitespace
        for c in input_text:
            if c not in allowed_chars:
                raise ValueError(await self.value_error_message())

        return input_text


class WhitelistList(Node):
    input_data = Input()
    whitelist = Input("List")
    exit_status = Output("Int")
    message = Output("String")
    done = Signal()

    @slot()
    async def run(self):
        input_data, whitelist = await asyncio.gather(self.input_data(), self.whitelist())
        self.exit_status.value = 1
        if not whitelist:
            self.exit_status.value = 0
            msg = "Whitelist is empty"
        elif input_data in whitelist:
            msg = f"Input {input_data} is allowed"
            self.exit_status.value = 0
        else:
            msg = f'Input {input_data} is not allowed, must be one of: {", ".join(whitelist)}'
        self.message.value = msg
        await self.done()


class WhitelistDict(Node):
    input_data = Input("Dict")
    whitelist = Input("Dict")
    exit_status = Output("Int")
    message = Output("String")
    done = Signal()

    @slot()
    async def run(self):
        input_data, whitelist = await asyncio.gather(self.input_data(), self.whitelist())
        msg = []
        self.exit_status.value = 0
        if not whitelist:
            msg.append("Whitelist is empty")
        else:
            for k, v in input_data.items():
                if k in whitelist:
                    if v in whitelist[k]:
                        msg.append(f"Inputs {k} and {v} are allowed")
                    else:
                        msg.append(f'Input {v} is not allowed for {k}, must be one of: {", ".join(whitelist[k])}')
                        self.exit_status.value = 1
                else:
                    msg.append(f'Input {k} is not allowed, must be one of: {", ".join(whitelist.keys())}')
                    self.exit_status.value = 1

        self.message.value = ", ".join(msg)
        await self.done()


class WhitelistRegex(Node):
    input_data = Input("String")
    pattern = Input("String")
    exit_status = Output("Int")
    message = Output("String")
    done = Signal()

    @slot()
    async def run(self):
        input_data, pattern = await asyncio.gather(self.input_data(), self.pattern())
        self.exit_status.value = 1
        if not pattern:
            self.exit_status.value = 0
            msg = "Pattern is empty"
        elif fullmatch(pattern, input_data):
            msg = f"Input {input_data} is allowed"
            self.exit_status.value = 0
        else:
            msg = f"Input {input_data} is not allowed, must match {pattern}"
        self.message.value = msg
        await self.done()


class WhitelistRange(Node):
    input_data = Input("Number")
    low = Input("Number")
    high = Input("Number")
    inclusive = Input("Bool", default=False)
    exit_status = Output("Int")
    message = Output("String")
    done = Signal()

    @slot()
    async def run(self):
        input_data, low, high, inclusive = await asyncio.gather(self.input_data(), self.low(), self.high(), self.inclusive())
        self.exit_status.value = 1
        if not low:
            if not high:
                self.exit_status.value = 0
                msg = "Range is empty"
        if low >= high:
            raise ValueError("low limit must not be greater than or equal to high limit")
        elif inclusive:
            expr = low <= input_data <= high
            msg = f"must be between {low} and {high} (inclusive)"
        else:
            expr = low < input_data < high
            msg = f"must be between {low} and {high}"
        if expr:
            msg = f"Input {input_data} is allowed"
            self.exit_status.value = 0
        else:
            msg = ", ".join([f"Input {input_data} is not allowed", msg])
        self.message.value = msg
        await self.done()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/misc.pyc
