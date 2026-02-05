# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/plugins/editor.py
import aiofiles, apis, base64, odin, logging
from architect.adapters.aiohttp import AioHttpServeAdapter
from architect.adapters.module_storage import ModuleStorageAdapter, ModulePathResolver
from architect.workflows.path_resolver import RootRelativePathResolver
from architect.adapters.simple_fs_storage import SimpleFSStorage
from aiohttp import web
from aiohttp.web import WebSocketResponse
from odin.config import options
from odin.core.cid import settings
from odin.core.engine.token import validate_and_decode_message
log = logging.getLogger(__name__)
html = ""
ODIN_TOKEN_KEY = "odinToken"
OPTIONS_METHOD = "OPTIONS"

@apis.route("/editor")
async def get_editor(request):
    global html
    if not html:
        filepath = odin.get_resource_path("core/engine/assets/editor.html.templ")
        async with aiofiles.open(filepath, "r") as f:
            html_templ = await f.read()
        conf = request.app["apis.config"]
        odin_token = options["editor"]["odin_token"]
        host = settings.IP
        html = html_templ.format(architect_version=1,
          version=(odin.__version__),
          platform=(odin.__platform__),
          editor_api=(conf.get("editor.api", "http://{host}:8080/api/v1/architect".format(host=host))),
          odin_token=odin_token)
    return web.Response(text=html,
      content_type="text/html")


def includeme(app):
    network_module = odin.get_network_module()
    if network_module:
        storage_root = network_module
        storage_class = ModuleStorageAdapter
        path_resolver_class = ModulePathResolver
    else:
        storage_root = odin.get_network_path()
        storage_class = SimpleFSStorage
        path_resolver_class = RootRelativePathResolver
    port = AioHttpServeAdapter.create_port(static_path=(odin.get_resource_path("core/engine/assets")),
      storage_class=storage_class,
      storage_root=storage_root,
      path_resolver_class=path_resolver_class,
      web_middlewares=[
     auth_middleware_factory],
      ws_message_filters=[
     auth_message_filter])
    app.add_subapp("/api/v1/architect", port.make_app())


async def auth_middleware_factory(app, handler):

    async def auth_middleware(request):
        if should_validate_token(request):
            headers = get_tokenv2_headers(request)
            await validate_and_decode_message(headers)
        return await handler(request)

    return auth_middleware


def should_validate_token(request):
    return not (is_options_request(request) or is_websocket_request(request))


def get_tokenv2_headers(request):
    cert_data = ensure_padding(request.headers.get("X-HTTP-ODIN-INTERMEDIATE-CERTIFICATE", ""))
    token_data = ensure_padding(request.headers.get("X-HTTP-ODIN-TOKEN", ""))
    return {"tokenv2": {'intermediate_certificate':base64.urlsafe_b64decode(cert_data).decode("utf-8"), 
                 'token':base64.urlsafe_b64decode(token_data).decode("utf-8")}}


def ensure_padding(data):
    return data + missing_padding(data)


def missing_padding(data):
    return "=" * (4 - len(data) % 4)


def is_websocket_request(request):
    return WebSocketResponse().can_prepare(request).ok


def is_options_request(request):
    return request.method == OPTIONS_METHOD


async def auth_message_filter(message):
    return await validate_and_decode_message(message)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/plugins/editor.pyc
