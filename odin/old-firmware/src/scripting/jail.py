# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/scripting/jail.py
from ast import NodeVisitor
from ast import parse
from logging import getLogger
from types import ModuleType
from ..platforms import architect_scripts_port
log = getLogger(__name__)

class NotAllowed(Exception):
    return


ALLOWED_MODULE_IMPORTS = [
 "math",
 "base64"]
ALLOWED_FUNCTION_IMPORTS = [
 (
  "asyncio", ['sleep', 'wait_for', 'TimeoutError', 'ensure_future', 'Event']),
 (
  "time", ["strftime", "time", "localtime"]),
 (
  "random", ["randint"])]
EXCLUDED_BUILTINS = [
 'eval', 
 'exec', 
 'compile', 
 'execfile', 
 'open', 
 'print', 
 'input', 
 'locals', 
 'globals', 
 'raw_input', 
 'vars', 
 'memoryview', 
 'breakpoint']
EXCLUDED_MSG = "{} is not allowed in scripted self-tests."

def exec_with_scripting_jail(code, name=None):
    return exec_in_jail(code, name=name)


async def import_with_scripting_jail(script_file, name=None):
    port = architect_scripts_port()
    code = await port.adapter.storage.load_string_from_basename_and_version(script_file)
    return exec_in_jail(code, name=name)


def exec_in_jail(code, name=None):
    ast_node = parse(code)
    JailVisitor().visit(ast_node)
    byte_code = compile(ast_node, name or "odin_self_test", "exec")
    module = ModuleType("odin_self_test")
    exec(byte_code, {"__builtins__": (get_safe_builtins())}, module.__dict__)
    return module


class JailVisitor(NodeVisitor):

    def visit_Call(self, node):
        if hasattr(node.func, "id"):
            if node.func.id in EXCLUDED_BUILTINS:
                raise NotAllowed(EXCLUDED_MSG.format(node.func.id))
        return self.generic_visit(node)

    def visit_Name(self, node):
        if node.id in EXCLUDED_BUILTINS or is_dunderbar(node.id):
            raise NotAllowed(EXCLUDED_MSG.format(node.id))
        return self.generic_visit(node)

    def visit_Import(self, node):
        if not ast_import_allowed(node):
            raise NotAllowed

    def visit_ImportFrom(self, node):
        if not ast_from_import_allowed(node):
            raise NotAllowed


def is_dunderbar(name):
    return name.startswith("__") and name.endswith("__")


def get_safe_builtins():
    return ({**{k: sanitize_builtin(k, v) for k, v in globals()["__builtins__"].items()}, **{"__import__": (make_safe_import())}})


def sanitize_builtin(key, value):
    if key in EXCLUDED_BUILTINS:

        def raises(*args, **kw):
            raise NotAllowed("{}() is not allowed in scripted self-tests.".format(key))

        return raises
    else:
        return value


def make_safe_import():
    orig_import = __import__

    def safe_import(name, globals=None, locals=None, fromlist=(), level=0):
        if not import_allowed(name, fromlist):
            log.error(f"{name} import not found in allowed imports: {ALLOWED_MODULE_IMPORTS}")
            raise NotAllowed("Import found that is not allowed in scripted self-tests")
        return orig_import(name, globals=globals, locals=locals, fromlist=fromlist, level=level)

    return safe_import


def ast_from_import_allowed(node):
    return import_function_allowed((node.module), from_list=[n.name for n in node.names])


def ast_import_allowed(node):
    return import_module_allowed(node.names[0].name)


def import_allowed(name, fromlist):
    if fromlist is None:
        return import_module_allowed(name)
    else:
        return import_function_allowed(name, fromlist)


def import_module_allowed(module_name):
    module_names = expand_module_name(module_name)
    for name in module_names:
        if name in ALLOWED_MODULE_IMPORTS:
            return True

    return False


def import_function_allowed(module_name, from_list):
    if import_module_allowed(module_name):
        return True
    else:
        for from_module, allowed_functions in ALLOWED_FUNCTION_IMPORTS:
            if module_name == from_module:
                if set(from_list).issubset(set(allowed_functions)):
                    return True

        return False


def expand_module_name(module_name):
    names = []
    tokens = module_name.split(".")
    for i in range(0, len(tokens)):
        names.append(".".join(tokens[:i + 1]))

    return names


def expand_from_list(base, from_list):
    return [base + "." + f for f in from_list]

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/scripting/jail.pyc
