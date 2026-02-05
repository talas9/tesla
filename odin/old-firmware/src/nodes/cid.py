# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/cid.py
import aiofiles, asyncio, binascii, logging, operator, os, re, shutil, string, time, tempfile, hashlib, json, async_timeout
from collections import Counter
from fnmatch import fnmatch
from gzip import open as gzopen
from architect.core.node import Node
from architect.core.ops.input import Input
from architect.core.ops.output import Output, output
from architect.core.ops.signal import Signal
from architect.core.ops.slot import slot
from typing import Tuple
from odin.core import cid
from odin.core.utils.async_logging import async_syslog
from odin.core.utils.desync import desync
from odin.core.utils import arch, payload, security
from odin.core.cid import hrl
from odin.core.cid.interface import hermes_file_upload
from odin.services.hrl import hrl_upload
from odin.core.cid.interface import gwxfer, filesystem
from odin.core.cid.interface import LDVS_WHITELIST
REQUEST_METHODS = [
 ('get', 'get'), 
 ('post', 'post'), 
 ('put', 'put'), 
 ('patch', 'patch'), 
 ('delete', 'delete')]
MOUNTS = [
 ('/home', '/home'),
 ('/var', '/var')]
SERVERS = [(s, s) for s in cid.settings.PORTS.keys()]
log = logging.getLogger(__name__)

class IsFused(Node):
    force_recheck = Input("Bool", default=True)

    @output("Bool")
    async def is_fused(self):
        force_recheck = await self.force_recheck()
        return await cid.interface.is_fused(force_recheck=force_recheck)


class CheckProcess(Node):
    process_name = Input("String")
    start_command = Input("String")
    timeout = Input("Int", default=5)
    done = Signal()

    def __init__(self):
        super().__init__()
        self._error = ""
        self._is_active = False

    @output("String")
    async def error(self):
        return self._error

    @output("Bool")
    async def is_active(self):
        return self._is_active

    def validate_inputs(self, process_name, start_command):
        payload.validate_safe_string(process_name, string.ascii_letters + string.digits + "_-")
        payload.validate_safe_string(start_command, string.ascii_letters + string.digits + "_-")

    async def sv_service_list(self, timeout):
        ls_sv_command = [
         "/bin/ls", "-1", "/etc/sv/"]
        result = await cid.interface.exec_command(ls_sv_command, user="root", timeout=timeout)
        if result.get("stderr") or not result.get("stdout"):
            raise RuntimeError("Could not get the list of sv services.")
        return result.get("stdout").split("\n")[:-1]

    async def start_process_if_down(self, process_name, start_command, timeout):
        check_command = [
         "/bin/pidof", "-x", process_name]
        result = await cid.interface.exec_command(check_command, user="root", timeout=timeout)
        if result.get("stderr"):
            raise RuntimeError("Could not get pid for {}. error: {}".format(process_name, result.get("stderr")))
        if result.get("stdout") or arch.is_tegra():
            if start_command not in await self.sv_service_list(timeout):
                start_command = [
                 "/sbin/start", start_command]
            else:
                start_command = [
                 "/sbin/sv", "start", start_command]
            result = await cid.interface.exec_command(start_command, user="root", timeout=timeout)
            if result.get("stderr"):
                raise RuntimeError("Could not start service for {}. error: {}".format(process_name, result.get("stderr")))
        else:
            await asyncio.sleep(2)
            result = await cid.interface.exec_command(check_command, user="root", timeout=timeout)
        if result.get("stderr") or not result.get("stdout"):
            raise RuntimeError("Could not start service for {}. error: {}".format(process_name, result.get("stderr")))

    @slot()
    async def run(self):
        process_name, start_command, timeout = await asyncio.gather(self.process_name(), self.start_command(), self.timeout())
        self.validate_inputs(process_name, start_command)
        try:
            await self.start_process_if_down(process_name, start_command, timeout)
        except (asyncio.TimeoutError, RuntimeError) as err:
            self._error = err
            self._is_active = False
        else:
            self._is_active = True
        await self.done()


class GetDataValue(Node):
    data_name = Input("String")
    timeout = Input("Int", default=(cid.settings.DEFAULT_TIMEOUT))

    @output("String")
    async def value(self):
        data_name, timeout = await asyncio.gather(self.data_name(), self.timeout())
        value = await cid.interface.get_data_value(data_name, timeout=timeout)
        return value


class GetDataValueUntil(Node):
    data_name = Input("String")
    pass_value = Input()
    operator = Input("Int", default=0, enum=[
     (0, '=='), 
     (1, '!='), 
     (2, '>'), 
     (3, '<'), 
     (4, '>='), 
     (5, '<=')])
    request_timeout = Input("Float", default=(float(cid.settings.DEFAULT_TIMEOUT)))
    sleep = Input("Float")
    timeout = Input("Float")
    passed = Signal()
    timed_out = Signal()

    @slot()
    async def run(self):
        operators = {0:operator.eq,  1:operator.ne, 
         2:operator.gt, 
         3:operator.lt, 
         4:operator.ge, 
         5:operator.le}
        data_name, pass_value, operator_, request_timeout, sleep, timeout = await asyncio.gather(self.data_name(), self.pass_value(), self.operator(), self.request_timeout(), self.sleep(), self.timeout())
        start = time.time()
        while 1:
            now = time.time()
            if timeout:
                if now - start > timeout:
                    await self.timed_out()
                    break
                value = await cid.interface.get_data_value(data_name, timeout=request_timeout)
                if operators[operator_](value, pass_value):
                    await self.passed()
                    break
                if sleep:
                    await asyncio.sleep(sleep)


class GetVin(Node):
    in_hex = Input("Bool", default=False)

    @output("String")
    async def vin(self):
        vin = await cid.interface.get_vin()
        if await self.in_hex():
            vin = "0x" + "".join(hex(ord(x))[2:] for x in vin)
        return vin


class GetVitals(Node):

    @output("Dict")
    async def vitals(self):
        return await cid.interface.get_vitals()


class SaveData(Node):
    filename = Input("String")
    data = Input()
    done = Signal()

    @slot()
    async def save(self):
        filename, data = await asyncio.gather(self.filename(), self.data())
        await cid.interface.save_data(filename, data)
        await self.done()


class LoadData(Node):
    filename = Input("String")

    @output()
    async def data(self):
        filename = await self.filename()
        if security.file_blacklisted(filename):
            raise PermissionError("Not allowed to access file {}".format(filename))
        return await cid.interface.load_data(filename)


class SetDataValue(Node):
    data_name = Input("String")
    value = Input()
    timeout = Input("Int", default=(cid.settings.DEFAULT_TIMEOUT))
    done = Signal()

    @slot()
    async def run(self):
        data_name, value, timeout = await asyncio.gather(self.data_name(), self.value(), self.timeout())
        await cid.interface.set_data_value(data_name, value, timeout=timeout)
        await self.done()


class CarServerRequest(Node):
    server = Input("String", enum=SERVERS)
    command = Input("String")
    params = Input("Dict")
    secure = Input("Bool", default=False)
    method = Input("String", default="get", enum=REQUEST_METHODS)
    timeout = Input("Int", default=(cid.settings.DEFAULT_TIMEOUT))
    host = Input("String", default=(cid.settings.IP))
    response = Output()
    done = Signal()

    @slot()
    async def run(self):
        server, command, params, secure, method, timeout, host = await asyncio.gather(self.server(), self.command(), self.params(), self.secure(), self.method(), self.timeout(), self.host())
        url = cid.interface.get_url(server, command=command, secure=secure, host=host)
        headers = None
        if server == "carserver":
            headers = await cid.interface.generate_security_header()
        else:
            data = await cid.interface.json_api_request((method.upper()),
              url, params=params, headers=headers, timeout=timeout)
            if data.pop("_rval_", None) is False:
                raise RuntimeError("Failed to run car server request")
            else:
                self.response.value = data
            await self.done()


class CidCommand(Node):
    command = Input("String")
    timeout = Input("Int", default=3)
    run_elevated = Input("Bool", default=False)
    force_ssh = Input("Bool", default=False)
    exit_status = Output("Int")
    stdout = Output("String")
    stderr = Output("String")
    done = Signal()

    @slot()
    async def run(self):
        command, timeout, run_elevated, force_ssh = await asyncio.gather(self.command(), self.timeout(), self.run_elevated(), self.force_ssh())
        try:
            if force_ssh:
                result = await cid.interface.run_via_ssh(command, timeout=timeout)
            else:
                result = await cid.interface.run_command(command, run_elevated,
                  timeout=timeout)
        except asyncio.TimeoutError:
            raise RuntimeError("CID command timed out")
        else:
            self.exit_status.value = result["exit_status"]
            self.stdout.value = result["stdout"]
            self.stderr.value = result["stderr"]
            await self.done()


class ExecuteApplication(Node):
    path = Input("String")
    user = Input("String", default="odin_script")
    whitelist_chars = Input("String", default="")
    current_working_dir = Input("String")
    args = Input("List")
    timeout = Input("Int", default=3)
    stdout = Output("String")
    stderr = Output("String")
    exit_status = Output("Int")
    done = Signal()

    def validateArgs(self, args, wlc):
        allowed_chars = string.ascii_letters + string.digits + wlc
        for v in args:
            payload.validate_safe_string(v, allowed_chars)

    @slot()
    async def run(self):
        path, user, wlc, args, timeout, current_working_dir = await asyncio.gather(self.path(), self.user(), self.whitelist_chars(), self.args(), self.timeout(), self.current_working_dir())
        cmd = [
         path]
        if args is not None:
            self.validateArgs(args, wlc)
            cmd.extend(args)
        result = await cid.interface.exec_command(cmd,
          user=user, timeout=timeout, current_working_dir=current_working_dir)
        self.exit_status.value = result["exit_status"]
        self.stdout.value = result["stdout"]
        self.stderr.value = result["stderr"]
        await self.done()


class ExecuteScript(Node):
    lang = Input("String", default="bash", enum=[
     ('bash', 'bash'),
     ('sh', 'sh'),
     ('perl', 'perl')])
    path = Input("String")
    user = Input("String", default="odin_script")
    whitelist_chars = Input("String", default="")
    current_working_dir = Input("String")
    args = Input("List")
    timeout = Input("Int", default=None)
    stdout = Output("String")
    stderr = Output("String")
    exit_status = Output("Int")
    done = Signal()

    def validateArgs(self, args, wlc):
        allowed_chars = string.ascii_letters + string.digits + wlc
        for v in args:
            payload.validate_safe_string(v, allowed_chars)

    @slot()
    async def run(self):
        lang, path, user, wlc, args, timeout, current_working_dir = await asyncio.gather(self.lang(), self.path(), self.user(), self.whitelist_chars(), self.args(), self.timeout(), self.current_working_dir())
        if lang == "bash":
            interpreter = "/bin/bash"
        elif lang == "sh":
            interpreter = "/bin/sh"
        else:
            if lang == "perl":
                interpreter = "/usr/bin/perl"
        cmd = [
         interpreter, path]
        if args is not None:
            self.validateArgs(args, wlc)
            cmd.extend(args)
        result = await cid.interface.exec_command(cmd,
          user=user, timeout=timeout, current_working_dir=current_working_dir)
        self.exit_status.value = result["exit_status"]
        self.stdout.value = result["stdout"]
        self.stderr.value = result["stderr"]
        await self.done()


class ExpectedPOS(Node):
    eu_vehicle = Input("Bool")
    country = Input("String")
    audiotype = Input("String")

    @output("List")
    async def expected(self):
        eu_vehicle, country = await asyncio.gather(self.eu_vehicle(), self.country())
        country = binascii.unhexlify("{:04x}".format(int(country)))
        if eu_vehicle:
            point_of_sale = {'JP':[3],  'CN':[
              5], 
             'TW':[
              5], 
             'KR':[
              17], 
             'NZ':[
              17], 
             'AU':{'Premium':[
               6], 
              'Base':[7]}}
            try:
                expected_pos = point_of_sale[country.upper()]
            except KeyError:
                expected_pos = {'Premium':[
                  16], 
                 'Base':[16, 17]}

        else:
            expected_pos = {'Premium':[
              0], 
             'Base':[1]}
        if isinstance(expected_pos, dict):
            audiotype = await self.audiotype()
            expected_pos = expected_pos[audiotype]
        return expected_pos


class HashFile(Node):
    algorithm = Input("String", default="SHA256", enum=[
     ('SHA256', 'SHA256'),
     ('SHA512', 'SHA512'),
     ('SHA1', 'SHA1'),
     ('MD5', 'MD5')])
    filepath = Input("String")
    timeout = Input("Int", default=60)

    @output("String")
    async def filehash(self):
        algorithm, filepath, timeout = await asyncio.gather(self.algorithm(), self.filepath(), self.timeout())
        if not os.path.isfile(filepath):
            raise ValueError("Given filepath input not a file.")
        hash_algo = {'SHA256':hashlib.sha256, 
         'SHA512':hashlib.sha512, 
         'SHA1':hashlib.sha1, 
         'MD5':hashlib.md5}
        m = hash_algo[algorithm]()
        with async_timeout.timeout(timeout):
            async with aiofiles.open(filepath, "rb") as f:
                while True:
                    chunk = await f.read(4096)
                    if chunk == b'':
                        break
                    m.update(chunk)

            return m.hexdigest()


class PutGatewayFile(Node):
    data = Input("Bytes")
    destination = Input("String")
    timeout = Input("Int", default=60)
    exit_status = Output("Int")
    stderr = Output("String")
    done = Signal()

    @slot()
    async def run(self):
        destination, data, timeout = await asyncio.gather(self.destination(), self.data(), self.timeout())
        validate_path_input(destination)
        try:
            tmp_fd, tmp_p = tempfile.mkstemp(prefix="odin_")
            async with aiofiles.open(tmp_fd, mode="wb") as fp:
                await fp.write(data)
            result = await gwxfer.put_file(tmp_p,
              destination, timeout=timeout)
        finally:
            try:
                os.close(tmp_fd)
            except OSError:
                pass

            try:
                os.remove(tmp_p)
            except OSError:
                pass

        self.exit_status.value = result["exit_status"]
        self.stderr.value = result["stderr"]
        await self.done()


class GetGatewayLogMetadata(Node):
    error = Output("String")
    latest_file_id = Output("Int")
    number_of_log_files = Output("Int")
    done = Signal()

    @slot()
    async def run(self):
        try:
            latest_file_id, number_of_log_files = await gwxfer.get_metadata()
            self.latest_file_id.value = latest_file_id
            self.number_of_log_files.value = number_of_log_files
        except gwxfer.GwxferException as e:
            self.error.value = str(e)

        await self.done()


class GetGatewayFileTimeBounds(Node):
    source = Input("String")
    sample_size = Input("Int", default=16000)
    error = Output("String")
    time_range = Output("Tuple")
    offsets = Output("Tuple")
    done = Signal()

    @slot()
    async def run(self):
        source, sample_size = await asyncio.gather(self.source(), self.sample_size())
        try:
            result = await gwxfer.get_file_bounds(source, sample_size)
            self.time_range.value = result["time_range"]
            self.offsets.value = result["offsets"]
        except gwxfer.GwxferException as e:
            self.error.value = str(e)

        await self.done()


class ExtractTimestampFromGatewayLog(Node):
    sample = Input("Bytes")
    return_first_occurence = Input("Bool", default=True)
    error = Output("String")
    timestamp = Output("Int")
    record_start_offset = Output("Int")
    done = Signal()

    @slot()
    async def run(self):
        sample, return_first_occurence = await asyncio.gather(self.sample(), self.return_first_occurence())
        try:
            timestamp, record_start_offset = await gwxfer.extract_timestamp(sample, return_first_occurence)
            self.timestamp.value = timestamp
            self.record_start_offset.value = record_start_offset
        except gwxfer.GwxferException as e:
            self.error.value = str(e)

        await self.done()


class GetGatewayFile(Node):
    source = Input("String")
    timeout = Input("Int", default=60)
    offset = Input("Int", default=0)
    length = Input("Int", default=0)
    exit_status = Output("Int")
    stderr = Output("String")
    data = Output("Bytes")
    done = Signal()

    @slot()
    async def run(self):
        source, timeout, offset, length = await asyncio.gather(self.source(), self.timeout(), self.offset(), self.length())
        validate_path_input(source)
        content, gwxfer_result = await gwxfer.get_file_content(source,
          timeout=timeout, offset=offset, length=length)
        self.exit_status.value = gwxfer_result["exit_status"]
        self.stderr.value = gwxfer_result["stderr"]
        self.data.value = content
        await self.done()


class GetDirectoryContents(Node):
    directory = Input("String")
    user = Input("String", default="tesla")
    show_hidden = Input("Bool", default=False)
    details = Input("Bool", default=True)
    human_readable = Input("Bool", default=True)
    result = Output("List")
    error = Output("Bool")
    stderr = Output("String")
    done = Signal()

    def blacklisted_directory(self, path):
        blacklist = [
         "/proc"]
        for parent in blacklist:
            return os.path.commonpath([
             os.path.realpath(path), parent]) == parent

    @slot()
    async def run(self):
        directory, user, show_hidden, details, human_readable = await asyncio.gather(self.directory(), self.user(), self.show_hidden(), self.details(), self.human_readable())
        if self.blacklisted_directory(directory):
            raise PermissionError
        cmd = ["/bin/ls"]
        if show_hidden:
            cmd.append("-a")
        if details:
            cmd.append("-l")
        if human_readable:
            cmd.append("-h")
        cmd.append(directory)
        r = await cid.interface.exec_command(cmd, timeout=5, user=user)
        self.result.value = []
        for line in r["stdout"].splitlines():
            if not line:
                pass
            else:
                self.result.value.append(line)

        self.error.value = r["exit_status"] != 0
        self.stderr.value = r["stderr"]
        await self.done()


class GetDiskFree(Node):
    mountpoint = Input("String")
    total_bytes = Output("Int")
    used_bytes = Output("Int")
    free_bytes = Output("Int")
    done = Signal()

    @slot()
    async def run(self):
        result = shutil.disk_usage(await self.mountpoint())
        self.total_bytes.value = result.total
        self.used_bytes.value = result.used
        self.free_bytes.value = result.free
        await self.done()


class Grep(Node):
    args = Input("List", default=[])
    file_location = Input("String")
    pattern = Input("String")
    variant = Input("String", default="grep", enum=[
     ('grep', 'grep'), 
     ('zgrep', 'zgrep'), 
     ('zegrep', 'zegrep'), 
     ('egrep', 'egrep'), 
     ('pgrep', 'pgrep'), 
     ('fgrep', 'fgrep'), 
     ('zfgrep', 'zfgrep'), 
     ('bzgrep', 'bzgrep'), 
     ('bzegrep', 'bzegrep'), 
     ('bzfgrep', 'bzfrep'), 
     ('pcregrep', 'pzegrep'), 
     ('ptargrep', 'ptargrep')])
    exit_status = Output("Int")
    stderr = Output("List")
    stdout = Output("List")
    done = Signal()

    def checkEmpty(self, s):
        for i in s:
            if i.isspace() or len(i) < 1:
                raise ValueError("Given file location or pattern undefined.")

    @slot()
    async def grep(self):
        args, file_location, pattern, variant = await asyncio.gather(self.args(), self.file_location(), self.pattern(), self.variant())
        if security.file_blacklisted(file_location):
            raise PermissionError("Not allowed to access file {}".format(file_location))
        else:
            self.checkEmpty([file_location, pattern])
            if os.path.isfile("/usr/bin/{}".format(variant)):
                cmd = [
                 "/usr/bin/{}".format(variant)]
            else:
                cmd = [
                 "/bin/{}".format(variant)]
        if args is not None:
            cmd.extend(args)
        cmd.extend([pattern, file_location])
        r = await cid.interface.exec_command(cmd, user="root")
        self.exit_status.value = r["exit_status"]
        self.stdout.value = []
        self.stderr.value = []
        for line in r["stdout"].splitlines():
            if not line:
                pass
            else:
                self.stdout.value.append(line)

        for line in r["stderr"].splitlines():
            if not line:
                pass
            else:
                self.stderr.value.append(line)

        await self.done()


class RebootCid(Node):
    delay = Input("Int", default=5)
    done = Signal()

    @slot()
    async def reboot(self):
        delay = await self.delay()
        await async_syslog("Rebooting system in {} seconds".format(delay))
        cmd = ["/bin/sh", "-c", "sleep {}; /sbin/reboot".format(delay)]
        await cid.interface.exec_command(cmd, user="root", detached=True)
        await self.done()


class EmitRebootGateway(Node):
    gateway_only = Input("Bool", default=False)
    delay = Input("Int", default=0)
    exit_status = Output("Int")
    stderr = Output("String")
    stdout = Output("String")
    done = Signal()

    @slot()
    async def run(self):
        delay = await self.delay()
        await async_syslog("Rebooting gateway in {} seconds".format(delay))
        reboot_cmd = "sleep {}; /usr/local/bin/emit-reboot-gateway".format(delay)
        if await self.gateway_only():
            reboot_cmd = " ".join([reboot_cmd, "--gw-only"])
        full_cmd = [
         "/bin/sh", "-c", reboot_cmd]
        result = await cid.interface.exec_command(full_cmd, user="tesla", detached=True)
        self.exit_status.value = result["exit_status"]
        self.stderr.value = result["stderr"]
        self.stdout.value = result["stdout"]
        await self.done()


class EmitRestartUpdater(Node):
    exit_status = Output("Int")
    stderr = Output("String")
    stdout = Output("String")
    done = Signal()

    @slot()
    async def run(self):
        result = await cid.interface.exec_command([
         "/usr/local/bin/emit-restart-updater"],
          user="tesla")
        self.exit_status.value = result["exit_status"]
        self.stderr.value = result["stderr"]
        self.stdout.value = result["stdout"]
        await self.done()


class SetCellAPN(Node):
    apn = Input("String")
    timeout = Input("Int", default=(cid.settings.DEFAULT_TIMEOUT))
    api_response = Output("String")
    done = Signal()

    def validateApn(self, apn):
        if len(apn) > 255:
            raise ValueError("Length of given apn string > 255 characters.")
        payload.validate_safe_string(apn, string.ascii_letters + string.digits + "._-")

    @slot()
    async def setApn(self):
        apn, timeout = await asyncio.gather(self.apn(), self.timeout())
        self.validateApn(apn)
        command = "setCellApn?apn={}".format(apn)
        url = cid.interface.get_url("netmanager",
          command=command, host="localhost")
        apnloc = "/home/tesla/.Tesla/car/cell_apn"
        self.api_response = await cid.interface.json_api_request("GET", url, timeout=timeout)
        await cid.interface.save_data(apnloc, apn)
        shutil.chown(apnloc, user="tesla", group="tesla")
        await self.done()


class SaveAuthoredPopup(Node):
    identifier = Input("String")
    data = Input("Dict")
    success = Output("Bool")
    done = Signal()

    @slot()
    async def save(self):
        ident, data = await asyncio.gather(self.identifier(), self.data())
        security.validate_authored_popup_id(ident)
        path = "/home/tesla/.Tesla/data/{}.json".format(ident)
        await cid.interface.save_data(path, json.dumps(data))
        shutil.chown(path, user="tesla", group="tesla")
        await self.done()


class SearchLogs(Node):
    search_term = Input("String")
    file_glob = Input("String")
    start_utime = Input("Int")
    end_utime = Input("Int")
    allowed_directories = Input("List", default=(cid.settings.DEFAULT_LOG_SEARCH_ALLOWED_DIRS))

    def search_file(self, f: list, term: str, path: str, size: int, matches: list) -> Tuple[(int, bool)]:
        MAX_MESSAGE_SIZE = 153600
        for line in f:
            if re.search(term, line):
                result = "{}:{}".format(path, line)
                if size + len(result) > MAX_MESSAGE_SIZE:
                    return (
                     size, True)
                matches.append(result)
                size += len(result)

        return (
         size, False)

    def search_gzip_file(self, path: str, search_term: str, size: int, matches: list) -> Tuple[(int, bool)]:
        with gzopen(path, mode="rt", encoding="utf-8", errors="surrogateescape") as w:
            contents = w.readlines()
        return self.search_file(contents, search_term, path, size, matches)

    @output("List")
    async def search(self):
        search_term, file_glob, start_utime, end_utime, allowed_directories = await asyncio.gather(self.search_term(), self.file_glob(), self.start_utime(), self.end_utime(), self.allowed_directories())
        try:
            re.compile(search_term)
        except re.error:
            raise ValueError("Bad search_term: {}", search_term)

        search_files = []
        for f in await filesystem.globpath(path="", pattern=file_glob, recurse=True):
            if not await filesystem.is_file(f):
                pass
            else:
                path = os.path.realpath(f)
                if not any([path.startswith(ad) for ad in allowed_directories]):
                    raise PermissionError("Path {} is not permitted for log searching", path)
            if ".err" in path:
                pass
            else:
                mt = int(await filesystem.mtime(path))
                if start_utime:
                    if mt < start_utime:
                        continue
                    if end_utime and mt > end_utime:
                        continue
                    search_files.append({'path':path,  'mtime':mt})

        search_files.sort(key=(lambda i: i["mtime"]))
        matches = []
        size = 0
        MAX_MESSAGE_WARN = "Max result size hit. Please choose more specific terms or a tighter date range for better results."
        for f in search_files:
            path = f.get("path")
            if await filesystem.is_gz(path):
                size, over = await desync(self.search_gzip_file, path, search_term, size, matches)
            else:
                async with aiofiles.open(path, mode="r", encoding="utf-8", errors="surrogateescape") as w:
                    contents = await w.readlines()
                size, over = self.search_file(contents, search_term, path, size, matches)
            if over:
                matches.insert(0, MAX_MESSAGE_WARN)
                break

        return matches


class ShowAuthoredPopup(Node):
    identifier = Input("String")
    success = Output("Bool")
    done = Signal()

    @slot()
    async def run(self):
        ident = await self.identifier()
        security.validate_authored_popup_id(ident)
        cmd = "show_authored_popup?id={}".format(ident)
        url = cid.interface.get_url("center_display", command=cmd)
        await cid.interface.json_api_request("GET", url)
        await self.done()


class SvCommand(Node):
    service = Input("String")
    v_flag = Input("Bool", default=False)
    w_flag = Input("Int")
    action = Input("String", enum=[
     ('status', 'status'), 
     ('up', 'up'), 
     ('down', 'down'), 
     ('once', 'once'), 
     ('sig', 'sig'), 
     ('exit', 'exit'), 
     ('start', 'start'), 
     ('stop', 'stop'), 
     ('restart', 'restart'), 
     ('shutdown', 'shutdown'), 
     ('force-stop', 'force-stop'), 
     ('force-reload', 'force-reload'), 
     ('force-restart', 'force-restart'), 
     ('force-shutdown', 'force-shutdown'), 
     ('try-restart', 'try-restart')])
    sig = Input("String", enum=[
     ('pause', 'pause'), 
     ('cont', 'cont'), 
     ('hup', 'hup'), 
     ('alarm', 'alarm'), 
     ('interrupt', 'interrupt'), 
     ('quit', 'quit'), 
     ('1', '1'), 
     ('2', '2'), 
     ('term', 'term'), 
     ('kill', 'kill')])
    exit_status = Output("Int")
    stderr = Output("String")
    stdout = Output("String")
    done = Signal()

    @slot()
    async def run(self):
        service, action, v_flag, w_flag = await asyncio.gather(self.service(), self.action(), self.v_flag(), self.w_flag())
        payload.validate_safe_string(service, string.ascii_letters + string.digits + "_-")
        cmd = [
         "/sbin/sv"]
        if w_flag:
            cmd.append("w", w_flag)
        else:
            if v_flag:
                cmd.append("v")
            if action == "sig":
                cmd.append(await self.sig())
            else:
                cmd.append(action)
        cmd.append(service)
        result = await cid.interface.exec_command(cmd, user="root")
        self.exit_status.value = result["exit_status"]
        self.stderr.value = result["stderr"]
        self.stdout.value = result["stdout"]
        await self.done()


class ListInodeUsers(Node):
    max_output = Input("Int", default=10)
    mount_point = Input("String", enum=MOUNTS, default="/home")
    result = Output("Dict")
    error = Output("Bool")
    stderr = Output("String")
    done = Signal()

    @slot()
    async def run(self):
        mount_point, max_output = await asyncio.gather(self.mount_point(), self.max_output())
        cmd = [
         "/usr/bin/find"]
        cmd.append(mount_point)
        cmd.append("-xdev")
        r = await cid.interface.exec_command(cmd, timeout=5, user="root")
        raw_list = [s for s in r["stdout"].splitlines() if s]
        self.result.value = await {a: b for a, b in Counter(raw_list).most_common(max_output) if not await security.file_blacklisted(a)}
        self.error.value = r["exit_status"] != 0
        self.stderr.value = r["stderr"]
        await self.done()


class ListDataValues(Node):
    dv = Input("String", default="")
    max_size = Input("Int", default=500)

    @output("Dict")
    async def run(self):
        dv_pattern, max_size = await asyncio.gather(self.dv(), self.max_size())
        if dv_pattern in ('', None):
            raise ValueError("No search pattern was provided.")
        self.whitelist = self.get_whitelist()
        if "*" not in dv_pattern:
            if not self.is_key_whitelisted(dv_pattern):
                raise ValueError("Search pattern not allowed.")
            return {dv_pattern: (await cid.interface.get_data_value(dv_pattern, timeout=3))}
        else:
            r = await cid.interface.exec_command(["ldvs"], timeout=3)
            if r["exit_status"] != 0:
                raise ValueError("Failed ldvs: {}".format(r["stderr"]))
            matching_data_values = {}
            for line in r["stdout"].splitlines():
                key, value = line.split(",", maxsplit=1)
                if self.is_key_whitelisted(key) and fnmatch(key.lower(), dv_pattern.lower()):
                    matching_data_values[key] = value

            if not self.valid_len(matching_data_values, max_size):
                raise ValueError("Search patterns too broad. Result limit reached.")
            return matching_data_values

    @staticmethod
    def valid_len(data_values: dict, max_length: int) -> bool:
        return len(data_values) <= max_length

    @staticmethod
    def get_whitelist() -> list:
        from odin import get_resource_path
        WHITELIST_PATH = get_resource_path(LDVS_WHITELIST)
        log.info("Using list datavalues whitelist: {}".format(WHITELIST_PATH))
        with open(WHITELIST_PATH) as whitelist:
            return [dv.strip() for dv in whitelist]

    def is_key_whitelisted(self, key: str):
        return any([whitelisted_key for whitelisted_key in self.whitelist if whitelisted_key.lower() == key.lower()])


class ClearCache(Node):
    successful = Output("Bool")
    error = Output("String")
    done = Signal()

    @slot()
    async def run(self):
        directories = [
         '/home/tesla/.Tesla/cache', 
         '/home/tesla/.Tesla/tmp', 
         '/home/tesla/.cache', 
         '/home/tesla/.Tesla/car/DABCache', 
         '/home/mediaserver/.Tesla/cache']
        result = await cid.interface.exec_command(([
         "/bin/rm", "-rf"].extend(directories)),
          user="root")
        if result["exit_status"] == 0:
            self.successful.value = True
        else:
            self.successful.value = False
            self.error.value = result["stderr"]
        await self.done()


class StartHRL(Node):
    timeout = Input("Int", default=300)
    result = Output("Dict")
    done = Signal()

    @slot()
    async def run(self):
        timeout = await self.timeout()
        self.result = await hrl.start_hrl(timeout)
        await self.done()


class StopHRL(Node):
    result = Output("Dict")
    done = Signal()

    @slot()
    async def run(self):
        self.result = await hrl.stop_hrl()
        await self.done()


class UploadFile(Node):
    file_path = Input("String")
    keep_alive_min = Input("Int", default=0)
    timeout = Input("Int", default=10)
    response = Output("String", default="")
    exit_status = Output("Int")
    done = Signal()
    WHITELIST_DIRS = [
     "/home/odin/HRL/udp_hrl",
     "/home/odin/HRL/ecu_hrl",
     "/home/odin/HRL/game_mode_hrl"]

    @slot()
    async def run(self):
        file_path, keep_alive_min, timeout = await asyncio.gather(self.file_path(), self.keep_alive_min(), self.timeout())
        file_path = os.path.realpath(file_path)
        payload.validate_safe_string(file_path, string.ascii_letters + string.digits + "._-/:")
        if os.path.dirname(file_path) not in self.WHITELIST_DIRS:
            raise ValueError("Specified file_path not in whitelist directories.")
        response = await hermes_file_upload.upload_file(file_path=file_path, remove_on_success=False,
          wifi_only=True,
          keep_alive_min=keep_alive_min,
          timeout=timeout)
        self.response.value = response
        self.exit_status.value = response.get("exit_status", 1)
        await self.done()


class StartHrlUploadService(Node):
    hrl_type = Input("String", default="hrl_udp")
    done = Signal()

    @slot()
    async def run(self):
        hrl_type = await self.hrl_type()
        payload.validate_safe_string(hrl_type, string.ascii_letters + string.digits + "_")
        asyncio.ensure_future(hrl_upload.start_service(hrl_type=hrl_type))
        await self.done()


def validate_path_input(path_name: str):
    if len(path_name) > 255:
        raise ValueError("Length of given path > 255 characters.")
    payload.validate_safe_string(path_name, string.ascii_letters + string.digits + "._-/")

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/cid.pyc
