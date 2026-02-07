# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/cli.py
import aiohttp_cors, apis, asyncio, click, logging, sys
from os import path
from ... import cli
from ..cid.interface import filesystem, is_fused, is_manufacturing_car
from .unix_socket_server import UnixSocketServer
from odin.core.engine import tasks
from odin.core.utils import arch
from odin.services.data_upload import data_upload
from odin.services.hrl import hrl_upload
log = logging.getLogger(__name__)
EXC = (SystemExit, asyncio.CancelledError)
PORT = 8080

@click.command()
@click.option("--addons", default="", help="Comma-separated list of plugin modules to include")
def engine(addons):
    import odin.nodes, architect.nodes
    all_plugins = [
     'odin.core.engine.plugins.server', 
     'odin.core.engine.plugins.signals', 
     'odin.core.engine.plugins.seceth', 
     'odin.core.engine.plugins.history', 
     'odin.core.engine.plugins.manufacturing', 
     'odin.core.engine.plugins.service']
    editor_module = "odin.core.engine.plugins.editor"
    if should_install_editor(editor_module):
        all_plugins.append(editor_module)
    if addons:
        all_plugins += addons.split(",")
    all_plugins.append("odin.core.engine.plugins.ui")
    filesystem.remove_odin_tmp()
    server = create_unix_server_for_data_upload()
    if not arch.is_tegra():
        asyncio.ensure_future(tasks.get_task_data(boot=True))
    try:
        sys.exit(apis.serve(port=PORT, cors_enabled=True,
          cors_policy=(get_cors_policy()),
          plugins=(",".join(all_plugins))))
    except EXC as e:
        if server:
            server.close()
        raise e


def get_cors_policy():
    allowed_origins = [
     'https://toolbox.tesla.com', 
     'https://toolbox-shanghai.tesla.cn', 
     'https://toolbox.teslamotors.com', 
     'https://toolbox-stg.teslamotors.com', 
     'https://toolbox-external-stg.teslamotors.com', 
     'https://toolbox-mfg.teslamotors.com', 
     'https://toolbox-beta.teslamotors.com', 
     'https://toolbox-beta.tesla.com', 
     'http://127.0.0.1', 
     'http://cid:8080', 
     'http://localhost:8080', 
     'http://192.168.90.100:8080', 
     'http://cid:3000', 
     'http://localhost:3000', 
     'http://192.168.90.100:3000', 
     '-']
    policy_template = aiohttp_cors.ResourceOptions(allow_credentials=True,
      expose_headers="*",
      allow_headers="*",
      allow_methods="*")
    cors_policy = {}
    for item in allowed_origins:
        cors_policy[item] = policy_template

    return cors_policy


def create_unix_server_for_data_upload() -> asyncio.base_events.Server:
    import odin
    from odin.platforms import get_platform_info
    info = get_platform_info()
    if odin.options["core"]["onboard"]:
        if info.get("unix_socket_server_enabled", False):
            if not vehicle_in_manufacturing():
                server = asyncio.get_event_loop().run_until_complete(UnixSocketServer.start())
                asyncio.ensure_future(data_upload.start_service(boot=True))
                asyncio.ensure_future(hrl_upload.start_service(hrl_type="hrl_game_mode", boot=True))
                return server


def vehicle_in_manufacturing() -> bool:
    try:
        return asyncio.get_event_loop().run_until_complete(is_manufacturing_car())
    except asyncio.TimeoutError:
        return False


def should_install_editor(editor_module: str) -> bool:
    car_is_fused = asyncio.get_event_loop().run_until_complete(is_fused())
    if car_is_fused:
        return False
    else:
        import importlib
        editor_exists = importlib.util.find_spec(editor_module) is not None
        if editor_exists:
            return True
        log.debug("Editor not available")
        return False


cli.start.add_command(engine)

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/engine/cli.pyc
