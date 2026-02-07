# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/http.py
import aiofiles, asyncio, os, logging, urllib.parse
from typing import Any, Union
import aiohttp, odin
from architect.core.node import Node
from architect.core.ops.input import Input
from architect.core.ops.output import Output, output
from architect.core.ops.signal import Signal
from architect.core.ops.slot import slot
from odin.core.utils import security
from odin.core.cid import firmware_server
log = logging.getLogger(__name__)
REQUEST_METHODS = [
 ('GET', 'GET'), 
 ('POST', 'POST'), 
 ('PUT', 'PUT'), 
 ('PATCH', 'PATCH'), 
 ('DELETE', 'DELETE')]

class GenerateURL(Node):
    scheme = Input("String", default="http")
    netloc = Input("String", default="")
    path = Input("String", default="")
    parameters = Input("String", default="")
    query = Input("String", default="")
    fragment = Input("String", default="")

    @output("String")
    async def url(self):
        url = await asyncio.gather(self.scheme(), self.netloc(), self.path(), self.parameters(), self.query(), self.fragment())
        return urllib.parse.urlunparse(url)


class Upload(Node):
    url = Input("String")
    headers = Input("Dict")
    params = Input("Dict")
    filename = Input("String")
    timeout = Input("Int", default=10)
    response = Output()
    done = Signal()

    @slot()
    async def upload(self):
        url, headers, params, filename, timeout = await asyncio.gather(self.url(), self.headers(), self.params(), self.filename(), self.timeout())
        session = await odin.get_http_session()
        if security.file_blacklisted(filename):
            raise PermissionError("Not allowed to access file {}".format(filename))
        async with aiofiles.open(filename, "r") as f:
            resp = await session.post(url,
              data=(await f.read()),
              headers=headers,
              params=params,
              timeout=timeout)
            resp.raise_for_status()
            try:
                response = await resp.json()
            except aiohttp.client_exceptions.ClientResponseError:
                response = await resp.text()

            self.response.value = response
            await self.done()


class Request(Node):
    url = Input("String")
    headers = Input("Dict")
    params = Input()
    data = Input()
    method = Input("String", default="GET", enum=REQUEST_METHODS)
    unix_connector = Input("String", default="")
    timeout = Input("Int", default=10)
    raise_error = Input("Bool", default=False)
    attempts = Input("Int", default=1)
    sleep = Input("Float", default=0)
    response = Output()
    status_code = Output("Int")
    done = Signal()

    @slot()
    async def run(self):
        url, headers, params, data, method, unix_connector, timeout, raise_error, attempts, sleep = await asyncio.gather(self.url(), self.headers(), self.params(), self.data(), self.method(), self.unix_connector(), self.timeout(), self.raise_error(), self.attempts(), self.sleep())
        while attempts > 0:
            try:
                attempts -= 1
                status_code, response = await self.request_from_odin_session(method, unix_connector, url, headers, data, params, timeout, raise_error)
                self.status_code.value = status_code
                self.response.value = response
            except (aiohttp.client_exceptions.ClientError, aiohttp.ServerTimeoutError) as e:
                if attempts == 0:
                    raise e
                await asyncio.sleep(sleep)
            else:
                if status_code < 400:
                    break
                await asyncio.sleep(sleep)

        await self.done()

    async def request_from_odin_session(self, method: str, unix_connector: str, url: str, headers: dict, data: Any, params: Union[(str, dict)], timeout: int, raise_error: bool) -> (int, Union[(str, dict)]):
        if unix_connector:
            session = await odin.get_unix_http_session(unix_connector)
        else:
            session = await odin.get_http_session()
        resp = await session.request(method, url, headers=headers, data=data, params=params, timeout=timeout)
        if raise_error:
            resp.raise_for_status()
        if resp.headers:
            if resp.headers.get("Content-Type") == "application/gzip":
                response = await resp.read()
        try:
            response = await resp.json()
        except aiohttp.client_exceptions.ClientResponseError:
            response = await resp.text()

        return (resp.status, response)


class AuthenticatedRequest(Request):

    @slot()
    async def run(self):
        url, headers, params, data, method, unix_connector, timeout, raise_error = await asyncio.gather(self.url(), self.headers(), self.params(), self.data(), self.method(), self.unix_connector(), self.timeout(), self.raise_error())
        ctxt = self._root()._context()
        token = ctxt.get("execution_options", {}).get("token")
        headers = headers or {}
        headers["Authorization"] = "Bearer " + token
        status_code, response = await self.request_from_odin_session(method, unix_connector, url, headers, data, params, timeout, raise_error)
        self.status_code.value = status_code
        self.response.value = response
        await self.done()


class Download(Node):
    url = Input("String")
    headers = Input("Dict")
    params = Input()
    data = Input()
    filepath = Input("String")
    chunk_size = Input("Int", default=1024)
    timeout = Input("Int", default=10)
    raise_error = Input("Bool", default=False)
    status_code = Output("Int")
    done = Signal()

    @slot()
    async def run(self):
        url, headers, params, data, filepath, chunk_size, timeout, raise_error = await asyncio.gather(self.url(), self.headers(), self.params(), self.data(), self.filepath(), self.chunk_size(), self.timeout(), self.raise_error())
        path = os.path.dirname(filepath)
        if not os.path.exists(path):
            try:
                os.makedirs(path)
            except OSError:
                pass

        session = await odin.get_http_session()
        resp = await session.get(url, headers=headers, data=data, params=params, timeout=timeout)
        self.status_code.value = resp.status
        if raise_error:
            resp.raise_for_status()
        if security.file_blacklisted(filepath):
            raise PermissionError("Not allowed to access file {}".format(filepath))
        async with aiofiles.open(filepath, "wb") as fp:
            while True:
                chunk = await resp.content.read(chunk_size)
                if not chunk:
                    break
                await fp.write(chunk)

        await self.done()


class BearerTokenHeader(Node):

    @output("Dict")
    async def header(self):
        ctxt = self._root()._context()
        token = ctxt.get("execution_options", {}).get("token")
        return {"Authorization": ("Bearer " + token)}


class OdinTokens(Node):

    @output("Dict")
    async def tokens(self):
        ctxt = self._root()._context()
        token = ctxt.get("execution_options", {}).get("token")
        token_v2 = ctxt.get("execution_options", {}).get("tokenv2_raw", {})
        return {'token':token,  'tokenv2':token_v2}


class AvailableOdinPatch(Node):

    @output("Dict")
    async def firmware_server_response(self):
        return await firmware_server.available_patch_sig()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/http.pyc
