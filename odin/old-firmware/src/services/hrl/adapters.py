# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/services/hrl/adapters.py
import asyncio, logging
from abc import abstractmethod, ABC
from datetime import datetime
from typing import AsyncGenerator, Optional
from odin import options
from odin.core.cid import hrl
from odin.core.cid.interface import get_data_value, is_development_car, is_manufacturing_car, gwxfer, load_data, request_do_not_sleep, save_data
log = logging.getLogger(__name__)
CRITICAL_TRIGGERS = {
 'HRL_ID_RCM2_alertID_is_RCM2_a000_crashDetected': 81, 
 'HRL_ID_RCM2_alertID_is_RCM2_a001_nearDeploy': 82, 
 'HRL_ID_RCM_alertID_is_RCM_alertID_RCM_a000_crashDetected': 29, 
 'HRL_ID_RCM_alertID_is_RCM_alertID_RCM_a001_nearDeploy': 30}

class AbstractHrl(ABC):

    def __init__(self):
        super().__init__()
        self._daily_allowed_bytes = None

    def name(self) -> str:
        return self.__class__.__name__

    async def daily_allowed_bytes(self) -> int:
        if self._daily_allowed_bytes is None:
            self._daily_allowed_bytes = await self._query_daily_allowed_bytes()
        return self._daily_allowed_bytes

    @abstractmethod
    async def available_files(self) -> Optional[AsyncGenerator[(int, str)]]:
        return

    @abstractmethod
    async def transfer(self, gtw_file: str, size: int) -> Optional[str]:
        return

    @abstractmethod
    async def _query_daily_allowed_bytes(self) -> int:
        return 0

    @abstractmethod
    async def upload_ice_keep_alive(self) -> int:
        return


class HrlEcu(AbstractHrl):

    def __init__(self):
        super().__init__()
        self.bytes_uploaded_file = "/home/odin/HRL/bytes_uploaded"
        self.ice_dir = "/home/odin/HRL/ecu_hrl"
        self.data_value = "FEATURE_odinHrlDailyMb"
        self.gwxfer_ice_keep_alive = 3
        self._upload_ice_keep_alive = 5
        self.upload_timeout = 300
        self.gtw_dir = "/hrl"
        self.cutoff_file = "/home/odin/HRL/cut_off_time"
        self.cutoff_time = None
        self.max_mb = 512
        self.critical_triggers = set(CRITICAL_TRIGGERS.values())

    async def available_files(self) -> Optional[AsyncGenerator[(int, str)]]:
        async for size, file_name in gwxfer.list_dir(self.gtw_dir):
            yield (
             size, file_name)

    async def _query_daily_allowed_bytes(self) -> int:
        mb = 1048576
        daily_limit = options.get("services", {}).get("hrl_ecu", {}).get("daily_upload_limit_mb")
        if daily_limit is None:
            try:
                value = await get_data_value(self.data_value)
                daily_limit = 0 if value == "<invalid>" else int(value)
            except (asyncio.TimeoutError, RuntimeError, FileNotFoundError) as err:
                log.error("Failed getting value of {}: {}".format(self.data_value, repr(err)))
                return 0

        if daily_limit <= 0:
            return 0
        else:
            if daily_limit > self.max_mb:
                daily_limit = self.max_mb
            return daily_limit * mb

    async def upload_ice_keep_alive(self) -> int:
        return self._upload_ice_keep_alive

    async def transfer(self, file_name: str, size: int) -> Optional[str]:
        cutoff = await self._get_hrl_cut_off_time()
        time_from_file_name = self._parse_timestamp_from_file_name(file_name)
        utc_created_at = datetime.utcfromtimestamp(time_from_file_name).strftime(hrl.HRL_DATE_FORMAT)
        if time_from_file_name < cutoff:
            log.info("Ignored {} created before cutoff at utc: {}".format(file_name, utc_created_at))
            return ""
        await request_do_not_sleep((self.gwxfer_ice_keep_alive), silent=True)
        gtw_file_path = "{}/{}".format(self.gtw_dir, file_name)
        try:
            file = await hrl.transfer_hrl((self.ice_dir),
              "hrl_ecu", gtw_file_path, utc_created_at, size, critical_triggers=(self.critical_triggers))
        except hrl.TransferError as err:
            log.error("Failure occured during transfer {}".format(err))
            return ""
        else:
            await gwxfer.delete(gtw_file_path)
            log.info("Success transferring gateway file  {} -> {}".format(gtw_file_path, file))
            return file

    @staticmethod
    def _parse_timestamp_from_file_name(file_name: str) -> int:
        try:
            d = int(file_name.lower().strip(".hrl"), 16)
        except (TypeError, AttributeError, ValueError):
            d = datetime.now().timestamp()

        return int(d)

    async def _get_hrl_cut_off_time(self) -> int:
        if self.cutoff_time is None:
            try:
                self.cutoff_time = await load_data(self.cutoff_file)
            except FileNotFoundError:
                self.cutoff_time = int(datetime.timestamp(datetime.utcnow()))
                await save_data(self.cutoff_file, self.cutoff_time)

            log.info("UTC cutoff time is {} -> utc: {}".format(self.cutoff_time, datetime.utcfromtimestamp(self.cutoff_time).strftime(hrl.HRL_DATE_FORMAT)))
        return self.cutoff_time

    async def _transfer_hrl_and_delete_from_gateway(self, file_name, size, cutoff):
        return

    async def upload_ice_keep_alive(self) -> int:
        return self._upload_ice_keep_alive


class HrlGameMode(AbstractHrl):

    def __init__(self):
        super().__init__()
        self.data_value = "FEATURE_earlyWaveCellNetworkingOk"
        self.ice_dir = "/home/odin/HRL/game_mode_hrl"
        self.bytes_uploaded_file = "/home/odin/HRL/bytes_uploaded_game_mode"
        self.gwxfer_ice_keep_alive = 4
        self._upload_ice_keep_alive = 10
        self.upload_timeout = 600
        self.gtw_file_path = "/gamemode.hrl"

    async def available_files(self) -> Optional[AsyncGenerator[(int, str)]]:
        resp = await gwxfer.get_size(self.gtw_file_path)
        try:
            size = int(resp["stdout"].strip())
        except ValueError:
            size = 0

        if size:
            yield (
             size, self.gtw_file_path)

    async def transfer(self, file_name: str, size: int) -> Optional[str]:
        await request_do_not_sleep((self.gwxfer_ice_keep_alive), silent=True)
        try:
            file = await hrl.transfer_hrl((self.ice_dir), "hrl_game_mode", (self.gtw_file_path), gateway_file_size=size)
        except hrl.TransferError as err:
            log.error("Failure occured during transfer {}".format(err))
            return
        else:
            await gwxfer.delete(self.gtw_file_path)
            log.info("Success transferring gateway file  {} -> {}".format(self.gtw_file_path, file))
            return file

    async def _query_daily_allowed_bytes(self) -> int:
        mb = 1048576
        daily_limit = options.get("services", {}).get("hrl_game_mode", {}).get("daily_upload_limit_mb")
        if not daily_limit:
            return 0
        else:
            if not await self._is_enabled():
                return 0
            return daily_limit * mb

    async def _is_enabled(self):
        is_first_wave = False
        is_dev_car = False
        try:
            first_wave = await get_data_value(self.data_value)
            is_first_wave = first_wave == "true"
        except (asyncio.TimeoutError, RuntimeError) as err:
            log.error("Failed getting value of {}: {}".format(self.data_value, repr(err)))

        try:
            is_dev_car = await is_development_car()
        except (asyncio.TimeoutError, RuntimeError) as err:
            log.error("Failed is_development_car: {}".format(repr(err)))

        return is_first_wave or is_dev_car

    async def upload_ice_keep_alive(self) -> int:
        return self._upload_ice_keep_alive


class HrlUdp(AbstractHrl):

    def __init__(self):
        super().__init__()
        self.ice_dir = hrl.TARGET_ICE_DIR_FOR_UDP_HRL
        self.bytes_uploaded_file = "/home/odin/HRL/bytes_uploaded_udp_hrl"
        self._gwxfer_ice_keep_alive_prod = 3
        self._gwxfer_ice_keep_alive_mfg = 0
        self._upload_ice_keep_alive_prod = 5
        self._upload_ice_keep_alive_mfg = 0
        self.upload_timeout = 600
        self.gwxfer_timeout = 120
        self.gtw_file_path = hrl.UDP_HRL_PATH

    async def available_files(self) -> Optional[AsyncGenerator[(int, str)]]:
        resp = await gwxfer.get_size(self.gtw_file_path)
        try:
            size = int(resp["stdout"].strip())
        except ValueError:
            size = 0

        if size:
            yield (
             size, self.gtw_file_path)

    async def transfer(self, file_name: str, size: int) -> Optional[str]:
        await request_do_not_sleep((await self.gwxfer_ice_keep_alive()), silent=True)
        try:
            file = await hrl.transfer_udp_url(file_name="hrl_udp", timeout=(self.gwxfer_timeout))
        except hrl.TransferError as err:
            log.error("Failure occured during transfer {}".format(err))
            return
        else:
            await gwxfer.delete(self.gtw_file_path)
            log.info("Success transferring gateway file  {} -> {}".format(self.gtw_file_path, file))
            return file

    async def _query_daily_allowed_bytes(self) -> int:
        return hrl.MAX_HRL_SIZE

    async def gwxfer_ice_keep_alive(self) -> int:
        if await is_manufacturing_car():
            return self._gwxfer_ice_keep_alive_mfg
        else:
            return self._gwxfer_ice_keep_alive_prod

    async def upload_ice_keep_alive(self) -> int:
        if await is_manufacturing_car():
            return self._upload_ice_keep_alive_mfg
        else:
            return self._upload_ice_keep_alive_prod

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/services/hrl/adapters.pyc
