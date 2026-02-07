# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/cli.py
from __future__ import print_function
import click, logging, sys
log = logging.getLogger(__name__)

@click.group()
@click.option("--platform", default=None,
  help="vehicle platform name, e.g. model_x. Overrides env var and config file")
@click.option("--fw-version", default=None,
  help="vehicle firmware version, e.g. 17.12.4. Overrides env var and config file")
@click.option("--log-level", default=None,
  help="set log level, e.g. DEBUG. Overrides config file")
@click.option("--metadata", default=None,
  help="set the path to the metadata required for ODIN per Firmware")
@click.option("--networks", default=None,
  help="set the path to the networks required for ODIN per Firmware")
@click.option("--network-module", default=None,
  help="set the network module when loading compiled networks")
@click.option("--config-file", default=None,
  help="file that defines the configuration for Odin, e.g. configurations/config.yaml")
def main(platform, fw_version, log_level, metadata, networks, network_module, config_file):
    import odin
    from odin.config import options
    from odin.platforms.common import detect_platform
    from odin.core.patch.loader import load_ssq_on_boot
    if config_file:
        odin.config.import_yaml_config(config_file)
    logging.config.dictConfig(options["logging"])
    if log_level:
        logging.getLogger().setLevel(logging.getLevelName(log_level))
    if platform:
        options["core"]["platform"] = platform
    if not options["core"]["platform"]:
        loop = asyncio.get_event_loop()
        options["core"]["platform"] = loop.run_until_complete(detect_platform())
    if fw_version:
        options["core"]["fw_version"] = fw_version
    if metadata:
        options["core"]["metadata_path"] = metadata
    if networks:
        options["core"]["network_path"] = networks
    if network_module:
        options["core"]["network_module"] = network_module
    if options["core"]["onboard"]:
        asyncio.get_event_loop().run_until_complete(load_ssq_on_boot())
    odin.configure_as(options["core"]["platform"], options["core"]["fw_version"])
    if not odin.__platform__:
        print("odin has not been configured.  please either set the ODIN_PLATFORM environment variable or provide by --platform")
        sys.exit(1)
    log.debug("Platform configured - {}".format(odin.__platform__))
    if options["testing"]["gateway_testing_enabled"]:
        print("Gateway Testing Enabled.")


@click.group()
def start():
    return


@click.group()
def listen():
    return


@click.command()
def version():
    import odin
    print(odin.__version__)


main.add_command(start)
main.add_command(version)
main.add_command(listen)
from .core.engine.cli import *

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/cli.pyc
