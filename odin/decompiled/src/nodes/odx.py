# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/odx.py
__authors__ = [
 "Ines Swenson"]
__author__ = ",".join(__authors__)
__email__ = "inkoch@teslamotors.com"
__copyright__ = "Copyright Tesla Motors Inc. 2017"
import asyncio, logging, async_timeout
from architect import Node, Input, Output, Signal, slot
from odin.core import odx, uds
from odin.core.isotp.error import ISOTPError
from odin.core.utils import payload
from odin.core.utils.context import optional_context
from .uds import NODE_NAMES_FUNC, UDS_ROUTINE_TYPES, UDS_SESSION_TYPES, UDS_CONTROL_TYPES
log = logging.getLogger(__name__)

class OdxGetParsedValue(Node):
    node_name = Input("String", default="", enum_func=NODE_NAMES_FUNC)
    param_name = Input("String")
    param_type = Input("String", default="output", enum=[(n, n) for n in ('input',
                                                                          'output')])
    param_value = Input("Hex")
    routine_control_type = Input("String", default=(uds.RoutineControl.REQUEST_ROUTINE_RESULTS.name),
      enum=UDS_ROUTINE_TYPES)
    routine_name = Input("String")
    output_value = Output()
    done = Signal()

    @slot()
    async def run(self) -> None:
        param_value, node_name, param_name, param_type, routine_name, routine_control_type = await asyncio.gather(self.param_value(), self.node_name(), self.param_name(), self.param_type(), self.routine_name(), self.routine_control_type())
        uds_node = uds.nodes[node_name]
        odx_routine_spec = uds_node.get_odx_routine_spec(routine_name)
        routine_control_type_key = {'START_ROUTINE':"start", 
         'STOP_ROUTINE':"stop", 
         'REQUEST_ROUTINE_RESULTS':"results"}[routine_control_type]
        param_def = odx_routine_spec[routine_control_type_key][param_type][param_name]
        mapper = param_def.get("map")
        if mapper:
            calculator_name = "{0}_calculator".format(mapper["calculator"])
            calculator = getattr(payload, calculator_name)
            if not calculator:
                raise NotImplementedError(calculator_name)
            else:
                kw = {k: v for k, v in mapper.items() if k != "calculator"}
                self.output_value.value = calculator(param_value, **kw)
        else:
            self.output_value.value = param_value
        await self.done()


class OdxGetRawValue(Node):
    node_name = Input("String", default="", enum_func=NODE_NAMES_FUNC)
    param_name = Input("String")
    param_type = Input("String", default="output", enum=[(n, n) for n in ('input',
                                                                          'output')])
    param_value = Input()
    routine_control_type = Input("String", default=(uds.RoutineControl.REQUEST_ROUTINE_RESULTS.name),
      enum=UDS_ROUTINE_TYPES)
    routine_name = Input("String")
    output_value = Output("Bytes")
    done = Signal()

    @slot()
    async def run(self) -> None:
        param_value, node_name, param_name, param_type, routine_name, routine_control_type = await asyncio.gather(self.param_value(), self.node_name(), self.param_name(), self.param_type(), self.routine_name(), self.routine_control_type())
        uds_node = uds.nodes[node_name]
        odx_routine_spec = uds_node.get_odx_routine_spec(routine_name)
        routine_control_type_key = {'START_ROUTINE':"start", 
         'STOP_ROUTINE':"stop", 
         'REQUEST_ROUTINE_RESULTS':"results"}[routine_control_type]
        param_def = odx_routine_spec[routine_control_type_key][param_type][param_name]
        mapper = param_def.get("map")
        if mapper:
            generator_name = "{0}_generator".format(mapper["calculator"])
            generator = getattr(payload, generator_name)
            if not generator:
                raise NotImplementedError(generator_name)
            else:
                kw = {k: v for k, v in mapper.items() if k != "calculator"}
                self.output_value.value = generator(param_value, **kw)
        else:
            self.output_value.value = param_value
        await self.done()


class OdxIoControl(Node):
    control_type = Input("String", default="RETURN_TO_ECU", enum=UDS_CONTROL_TYPES)
    diagnostic_session = Input("String", default="NO_SESSION", enum=UDS_SESSION_TYPES)
    node_name = Input("String", default="", enum_func=NODE_NAMES_FUNC)
    control_name = Input("String")
    params = Input("Dict")
    results = Output("Dict")
    raw_results = Output("Bytes")
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, control_name, control_type, params, diagnostic_session = await asyncio.gather(self.node_name(), self.control_name(), self.control_type(), self.params(), self.diagnostic_session())
        uds_node = uds.nodes[node_name]
        odx_control_spec = uds_node.get_odx_iocontrol_spec(control_name)
        control_type = uds.IoControl[control_type]
        diagnostic_session = uds.SessionType[diagnostic_session]
        await uds.diagnostic_session(uds_node, diagnostic_session)
        await odx.security_access(uds_node, odx_control_spec)
        results, raw = await (odx.io_control)(control_type, odx_control_spec, **params or {})
        self.results.value = dict(results)
        self.raw_results.value = raw
        await self.done()


class OdxReadData(Node):
    data_name = Input("String")
    diagnostic_session = Input("String", default="EXTENDED_DIAGNOSTIC_SESSION", enum=UDS_SESSION_TYPES)
    node_name = Input("String", default="", enum_func=NODE_NAMES_FUNC)
    response_required = Input("Bool", default=True)
    data = Output("Dict")
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, data_name, diagnostic_session, response_required = await asyncio.gather(self.node_name(), self.data_name(), self.diagnostic_session(), self.response_required())
        uds_node = uds.nodes[node_name]
        odx_data_spec = uds_node.get_odx_data_spec(data_name)
        diagnostic_session = uds.SessionType[diagnostic_session]
        await uds.diagnostic_session(uds_node, diagnostic_session)
        await odx.security_access(uds_node, odx_data_spec["read"])
        results = await odx.read_data(odx_data_spec)
        self.data.value = dict(results)
        await self.done()


class OdxRequestResults(Node):
    diagnostic_session = Input("String", default="NO_SESSION", enum=UDS_SESSION_TYPES)
    node_name = Input("String", default="", enum_func=NODE_NAMES_FUNC)
    routine_name = Input("String")
    params = Input("Dict")
    results = Output("Dict")
    raw_results = Output("Bytes")
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, routine_name, params, diagnostic_session = await asyncio.gather(self.node_name(), self.routine_name(), self.params(), self.diagnostic_session())
        uds_node = uds.nodes[node_name]
        odx_routine_spec = uds_node.get_odx_routine_spec(routine_name)
        diagnostic_session = uds.SessionType[diagnostic_session]
        await uds.diagnostic_session(uds_node, diagnostic_session)
        await odx.security_access(uds_node, odx_routine_spec["results"])
        results, raw = await (odx.request_results)(odx_routine_spec, **params or {})
        self.results.value = dict(results)
        self.raw_results.value = raw
        await self.done()


class OdxStartAndWaitResults(Node):
    diagnostic_session = Input("String", default="EXTENDED_DIAGNOSTIC_SESSION", enum=UDS_SESSION_TYPES)
    node_name = Input("String", default="", enum_func=NODE_NAMES_FUNC)
    routine_name = Input("String")
    input_parameters = Input("Dict", default={})
    request_parameters = Input("Dict", default={})
    max_retries = Input("Int", default=100)
    tester_present = Input("Bool")
    tester_present_interval = Input("Float", default=0.1)
    timeout = Input("Number", default=0.5)
    stop_routine = Input("Bool", default=True)
    status_parameter = Input("String", default="STATUS")
    in_progress_statuses = Input("List", default=["ROUTINE_IN_PROGRESS", "RUNNING"])
    handle_brr = Input("Bool", default=False)
    start_status_parameter = Input("String", default="START_RESULT")
    successful_start_statuses = Input("List", default=["SUCCESSFUL"])
    uds_resilience = Input("Int", default=2)
    results_control_type = Output("String", default="REQUEST_ROUTINE_RESULTS")
    raw_data = Output("Bytes")
    results = Output("Dict")
    run_body = Signal()
    done = Signal()

    @slot()
    async def run(self) -> None:
        log.debug("Running: {}".format(__name__))
        node_name, routine_name, input_parameters, request_parameters, max_retries, status_parameter, timeout, tester_present, in_progress_statuses, diagnostic_session, tester_present_interval, stop_routine, handle_brr, start_status_parameter, successful_start_statuses, uds_resilience = await asyncio.gather(self.node_name(), self.routine_name(), self.input_parameters(), self.request_parameters(), self.max_retries(), self.status_parameter(), self.timeout(), self.tester_present(), self.in_progress_statuses(), self.diagnostic_session(), self.tester_present_interval(), self.stop_routine(), self.handle_brr(), self.start_status_parameter(), self.successful_start_statuses(), self.uds_resilience())
        uds_node = uds.nodes[node_name]
        odx_routine_spec = uds_node.get_odx_routine_spec(routine_name)
        async with optional_context(tester_present, (uds.tester_present_context),
          kw={'uds_node_name':node_name, 
         'interval':tester_present_interval}):
            await asyncio.sleep(tester_present_interval * 2)
            try:
                timeout_count = 0
                while True:
                    try:
                        await uds.diagnostic_session(uds_node, uds.SessionType[diagnostic_session])
                        await odx.security_access(uds_node, odx_routine_spec["start"])
                    except ISOTPError:
                        timeout_count += 1
                        if timeout_count <= uds_resilience:
                            continue
                        raise
                    else:
                        break

                start_results, start_raw = await (odx.start_routine)(odx_routine_spec, **input_parameters)
            except (uds.UdsException, KeyError) as e:
                log.error("Could not start routine: {}\n{}".format(odx_routine_spec, str(e)))
                raise

            start_results = dict(start_results)
            default_start_result = successful_start_statuses[0] if not odx_routine_spec["start"].get("output", {}) else None
            if start_results.get(start_status_parameter, default_start_result) not in successful_start_statuses:
                log.error("Failed to start UDS routine {}.{}({}) = {}".format(node_name, routine_name, input_parameters, start_results))
                self.results_control_type.value = "START_ROUTINE"
                self.results.value = start_results
                self.raw_data.value = start_raw
            else:
                timeout_count = 0
                for i in range(max_retries + 1):
                    if timeout:
                        log.debug("sleep: {}".format(timeout))
                        await asyncio.sleep(timeout)
                    try:
                        parsed, raw = await (odx.request_results)(odx_routine_spec, **request_parameters)
                    except ISOTPError:
                        timeout_count += 1
                        if timeout_count <= uds_resilience:
                            continue
                        raise
                    except uds.exceptions.BusyRepeatRequest:
                        if handle_brr:
                            continue
                        raise

                    timeout_count = 0
                    results = dict(parsed)
                    log.debug("results: {}, {}".format(results, raw))
                    self.results_control_type = "REQUEST_ROUTINE_RESULTS"
                    self.results.value = results
                    self.raw_data.value = raw
                    await self.run_body()
                    curr_status = results.get(status_parameter)
                    if curr_status not in in_progress_statuses:
                        break
                else:
                    raise RuntimeError("Failed to finish running routine")

            if stop_routine:
                try:
                    log.debug("Stopping: {}".format(__name__))
                    await odx.stop_routine(odx_routine_spec)
                except (uds.UdsException, KeyError) as e:
                    log.warning("Could not stop routine: {}\n{}".format(odx_routine_spec, str(e)))

        await self.done()


class OdxStartAndWaitResults_V2(Node):
    diagnostic_session = Input("String", default="EXTENDED_DIAGNOSTIC_SESSION", enum=UDS_SESSION_TYPES)
    node_name = Input("String", default="", enum_func=NODE_NAMES_FUNC)
    routine_name = Input("String")
    input_parameters = Input("Dict", default={})
    request_parameters = Input("Dict", default={})
    should_stop = Input("Bool", default=True)
    max_runtime = Input("Float")
    poll_interval = Input("Float", default=0.5)
    status_parameter = Input("String", default="STATUS")
    in_progress_statuses = Input("List", default=["ROUTINE_IN_PROGRESS", "RUNNING"])
    handle_brr = Input("Bool", default=False)
    start_status_parameter = Input("String", default="STATUS")
    successful_start_statuses = Input("List", default=["SUCCESSFUL"])
    uds_resilience = Input("Int", default=2)
    raw_results = Output("Bytes")
    results = Output("Dict")
    error = Output("String")
    success = Signal()
    failed = Signal()

    @slot()
    async def run(self) -> None:
        log.debug("Running: {}".format(__name__))
        diagnostic_session, in_progress_statuses, input_parameters, max_runtime, node_name, poll_interval, routine_name, request_parameters, should_stop, status_parameter, handle_brr, start_status_parameter, successful_start_statuses, uds_resilience = await asyncio.gather(self.diagnostic_session(), self.in_progress_statuses(), self.input_parameters(), self.max_runtime(), self.node_name(), self.poll_interval(), self.routine_name(), self.request_parameters(), self.should_stop(), self.status_parameter(), self.handle_brr(), self.start_status_parameter(), self.successful_start_statuses(), self.uds_resilience())
        uds_node = uds.nodes[node_name]
        odx_routine_spec = uds_node.get_odx_routine_spec(routine_name)
        try:
            timeout_count = 0
            while True:
                try:
                    await uds.diagnostic_session(uds_node, uds.SessionType[diagnostic_session])
                    await odx.security_access(uds_node, odx_routine_spec["start"])
                except ISOTPError:
                    timeout_count += 1
                    if timeout_count <= uds_resilience:
                        continue
                    raise
                else:
                    break

            start_results, start_raw = await (odx.start_routine)(odx_routine_spec, **input_parameters)
        except (uds.UdsException, ISOTPError) as e:
            error_str = "Exception raised while starting UDS routine {}.{}({}): {}".format(node_name, routine_name, input_parameters, e)
            log.exception(error_str)
            self.error.value = error_str
            success = False
        else:
            start_results = dict(start_results)
            if start_results.get(start_status_parameter, "SUCCESSFUL") not in successful_start_statuses:
                error_str = "Failed to start UDS routine {}.{}({}) = {}".format(node_name, routine_name, input_parameters, start_results)
                log.error(error_str)
                self.error.value = error_str
                success = False
            else:
                error_str = None
                success = False
                try:
                    timeout_count = 0
                    async with async_timeout.timeout(max_runtime):
                        while 1:
                            await asyncio.sleep(poll_interval)
                            try:
                                parsed, raw = await (odx.request_results)(odx_routine_spec, **request_parameters)
                            except ISOTPError:
                                timeout_count += 1
                                if timeout_count <= uds_resilience:
                                    continue
                                raise
                            except uds.exceptions.BusyRepeatRequest:
                                if handle_brr:
                                    continue
                                raise

                            timeout_count = 0
                            results = dict(parsed)
                            log.debug("results: {}, {}".format(results, raw))
                            curr_status = results.get(status_parameter)
                            if curr_status not in in_progress_statuses:
                                self.results.value = results
                                self.raw_results.value = raw
                                success = True
                                break

                except (uds.UdsException, ISOTPError) as e:
                    error_str = "UDS error during requesting results for UDS routine {}.{}({}): {}".format(node_name, routine_name, request_parameters, e)
                except asyncio.TimeoutError as e:
                    error_str = "Timeout waiting for results of UDS routine: {}.{}({}): {}".format(node_name, routine_name, request_parameters, e)

                if error_str:
                    log.exception(error_str)
                    self.error.value = error_str
                if should_stop:
                    try:
                        log.debug("Stopping: {}".format(__name__))
                        await odx.stop_routine(odx_routine_spec)
                    except (uds.UdsException, KeyError) as e:
                        log.exception("Routine does not support stopping {}.{}: {}".format(node_name, routine_name, e))

                    if success:
                        await self.success()
                else:
                    await self.failed()


class OdxStartRoutine(Node):
    diagnostic_session = Input("String", default="EXTENDED_DIAGNOSTIC_SESSION")
    node_name = Input("String", default="", enum_func=NODE_NAMES_FUNC)
    routine_name = Input("String")
    params = Input("Dict", default={})
    results = Output("Dict")
    raw = Output("Bytes")
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, routine_name, params, diagnostic_session = await asyncio.gather(self.node_name(), self.routine_name(), self.params(), self.diagnostic_session())
        uds_node = uds.nodes[node_name]
        odx_routine_spec = uds_node.get_odx_routine_spec(routine_name)
        diagnostic_session = uds.SessionType[diagnostic_session]
        await uds.diagnostic_session(uds_node, diagnostic_session)
        await odx.security_access(uds_node, odx_routine_spec["start"])
        results, raw = await (odx.start_routine)(odx_routine_spec, **params)
        self.results.value = dict(results)
        self.raw.value = raw
        await self.done()


class OdxStopRoutine(Node):
    diagnostic_session = Input("String", default="NO_SESSION")
    node_name = Input("String", default="", enum_func=NODE_NAMES_FUNC)
    routine_name = Input("String")
    params = Input("Dict")
    results = Output("Dict")
    raw = Output("Bytes")
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, routine_name, params, diagnostic_session = await asyncio.gather(self.node_name(), self.routine_name(), self.params(), self.diagnostic_session())
        uds_node = uds.nodes[node_name]
        odx_routine_spec = uds_node.get_odx_routine_spec(routine_name)
        params = params or {}
        diagnostic_session = uds.SessionType[diagnostic_session]
        await uds.diagnostic_session(uds_node, diagnostic_session)
        await odx.security_access(uds_node, odx_routine_spec["stop"])
        results, raw = await (odx.stop_routine)(odx_routine_spec, **params)
        self.results.value = dict(results)
        self.raw.value = raw
        await self.done()


class OdxWriteData(Node):
    diagnostic_session = Input("String", default="EXTENDED_DIAGNOSTIC_SESSION")
    node_name = Input("String", default="", enum_func=NODE_NAMES_FUNC)
    data_name = Input("String")
    data = Input("Dict")
    done = Signal()

    @slot()
    async def run(self) -> None:
        node_name, data_name, data, diagnostic_session = await asyncio.gather(self.node_name(), self.data_name(), self.data(), self.diagnostic_session())
        uds_node = uds.nodes[node_name]
        odx_data_spec = uds_node.get_odx_data_spec(data_name)
        diagnostic_session = uds.SessionType[diagnostic_session]
        await uds.diagnostic_session(uds_node, diagnostic_session)
        await odx.security_access(uds_node, odx_data_spec["write"])
        await odx.write_data(odx_data_spec, data)
        await self.done()

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/nodes/odx.pyc
