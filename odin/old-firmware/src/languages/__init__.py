# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/languages/__init__.py
import logging, odin
from odin.core.cid.interface import get_data_value
log = logging.getLogger(__name__)
DEFAULT_LANGUAGE = "English"
AVAILABLE_LANGUAGES = ["English", "ChineseMandarin", "TaiwaneseMandarin", "HongKongCantonese"]
LANGUAGE_MODULE_MAP = {
 'English': '"english"', 
 'ChineseMandarin': '"schinese"', 
 'TaiwaneseMandarin': '"schinese"', 
 'HongKongCantonese': '"schinese"'}
NO_SUCH_STRING_KEY_PREFIX = "[NS]"
NO_TRANSLATION_PREFIX = "[NT]"
UI_READ_TIMEOUT = 2

async def _get_language() -> str:
    language = None
    try:
        if odin.options["core"]["onboard"]:
            language = await get_data_value("GUI_language", UI_READ_TIMEOUT)
        if not language:
            log.warning("Unable to get language from UI! Default to {}".format(DEFAULT_LANGUAGE))
            return DEFAULT_LANGUAGE
        return language
    except Exception as e:
        log.warning("Unable to get language from UI (Exception: {})! Default to {}".format(repr(e), DEFAULT_LANGUAGE))
        return DEFAULT_LANGUAGE


def _load_language_module(module_name: str) -> dict:
    try:
        import importlib
        language_module_fullname = "odin.languages.{}".format(module_name.replace(".", "_"))
        return importlib.import_module(language_module_fullname).strings
    except Exception as ex:
        log.exception("Unable to import language module {}! Returning empty dict.".format(language_module_fullname))
        return {}


def _load_default_language_string_table() -> dict:
    default_language_string_table = _load_language_module(LANGUAGE_MODULE_MAP[DEFAULT_LANGUAGE])
    if not default_language_string_table:
        log.warning("Unable to load default String Table (default language={})".format(DEFAULT_LANGUAGE))
    return default_language_string_table or {}


def _load_string_table(language: str) -> dict:
    actual_language = language
    actual_language = DEFAULT_LANGUAGE if actual_language not in AVAILABLE_LANGUAGES else actual_language
    if actual_language != language:
        log.warning("Language loaded not requested language! Requested = {}, Loaded = {}".format(language, actual_language))
    if actual_language == DEFAULT_LANGUAGE:
        return _load_default_language_string_table()
    language_module = LANGUAGE_MODULE_MAP.get(actual_language)
    if not language_module:
        log.warning("Unable to find language module for {} (evaluated as {})! Default to {}".format(language, actual_language, DEFAULT_LANGUAGE))
        return _load_default_language_string_table()
    else:
        string_table = _load_language_module(language_module)
        if not string_table:
            log.warning("Unable to get String Table for {} (evaluated as {})!".format(language, actual_language))
        return string_table or {}


LANGUAGE = None
STRING_TABLE = {}
DEFAULT_LANGUAGE_STRING_TABLE = {}

async def init_language():
    global DEFAULT_LANGUAGE_STRING_TABLE
    global LANGUAGE
    global STRING_TABLE
    LANGUAGE = await _get_language()
    STRING_TABLE = _load_string_table(LANGUAGE)
    DEFAULT_LANGUAGE_STRING_TABLE = _load_default_language_string_table()


def get_locstring(string_key: str, default: str=None) -> str:
    result = STRING_TABLE.get(string_key)
    if not result:
        result = DEFAULT_LANGUAGE_STRING_TABLE.get(string_key)
        if not result:
            result = "{}{}".format(NO_SUCH_STRING_KEY_PREFIX, string_key) if not default else default
        else:
            result = NO_TRANSLATION_PREFIX + result
    return result

# okay decompiling /root/downloads/old-firmware/opt/odin/odin_extracted/out00-PYZ.pyz_extracted/odin/languages/__init__.pyc
