# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/utils/profiletools.py
import asyncio, cProfile, contextlib, datetime, logging, io, os, pstats, time
DEFAULT_FORMAT = "elapsed=%(elapsed)s delta=%(since_last)s level=%(levelname)s from=%(name)s.%(funcName)s (line:%(lineno)s) message=%(message)s"

class RelativeFilter(logging.Filter):

    def __init__(self, *args, **kw):
        (super().__init__)(*args, **kw)
        self.first = None
        self.last = None

    def filter(self, record):
        curr = record.relativeCreated
        first = self.first or curr
        last = self.last or curr
        first_time = datetime.datetime.fromtimestamp(first / 1000.0)
        curr_time = datetime.datetime.fromtimestamp(curr / 1000.0)
        last_time = datetime.datetime.fromtimestamp(last / 1000.0)
        delta = curr_time - last_time
        since_last = delta.seconds + delta.microseconds / 1000000.0
        delta = curr_time - first_time
        since_first = delta.seconds + delta.microseconds / 1000000.0
        record.since_last = "{0:.2f}".format(since_last)
        record.elapsed = "{0:.2f}".format(since_first)
        self.last = curr
        self.first = self.first or curr
        return True


class Profiler:

    def __init__(self, *, request_id=None, enabled=False, stats_order=None, stats_restrictions=None, profile_subcalls=False, profile_builtins=False, loggers=None, log_level="INFO", log_format=DEFAULT_FORMAT):
        self.request_id = request_id
        self.enabled = enabled
        self.duration = 0
        self.num_calls = 0
        self.started = 0
        self.log_stream = io.StringIO()
        self.loggers = loggers if loggers is not None else ["root"]
        self.logging_handler = None
        self.log_level = log_level
        self.log_format = log_format
        self.orig_levels = {}
        self.stats_stream = io.StringIO()
        self.stats_order = stats_order or ["cumulative"]
        self.stats_restrictions = stats_restrictions or [25]
        self.profile = None
        self.profile_subcalls = profile_subcalls
        self.profile_builtins = profile_builtins

    def dump(self):
        return {'started':self.started, 
         'duration':self.duration, 
         'num_calls':self.num_calls, 
         'stats':self.stats_stream.getvalue(), 
         'log':self.log_stream.getvalue()}

    @contextlib.contextmanager
    def profile(self):
        self.start()
        yield
        self.stop()

    def start(self):
        if self.enabled:
            os.environ["PYTHONASYNCIODEBUG"] = "1"
            self.logging_handler = logging.StreamHandler(stream=(self.log_stream))
            self.logging_handler.setLevel(self.log_level)
            self.logging_handler.addFilter(RelativeFilter())
            fmt = "request={} {}".format(self.request_id, self.log_format)
            self.logging_handler.setFormatter(logging.Formatter(fmt))
            for name in self.loggers:
                log = logging.getLogger() if name is "root" else logging.getLogger(name)
                self.orig_levels[name] = log.level
                log.addHandler(self.logging_handler)
                log.setLevel(self.log_level)

            self.started = time.time()
            self.profile = cProfile.Profile(subcalls=(self.profile_subcalls),
              builtins=(self.profile_builtins))
            self.profile.enable()

    def stop(self):
        if self.enabled:
            os.environ["PYTHONASYNCIODEBUG"] = "0"
            self.profile.disable()
            stats = pstats.Stats((self.profile), stream=(self.stats_stream))
            (stats.sort_stats)(*self.stats_order)
            (stats.print_stats)(*self.stats_restrictions)
            self.duration = stats.total_tt
            self.num_calls = stats.total_calls
            for name in self.loggers:
                log = logging.getLogger() if name is "root" else logging.getLogger(name)
                log.removeHandler(self.logging_handler)
                log.setLevel(self.orig_levels[name])

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/core/utils/profiletools.pyc
