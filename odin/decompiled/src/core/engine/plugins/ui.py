# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/engine/plugins/ui.py

-- Stacks of completed symbols:
START ::= |- stmts . 
_stmts ::= _stmts . last_stmt
_stmts ::= _stmts . stmt
_stmts ::= stmt . 
and ::= expr . JUMP_IF_FALSE_OR_POP expr COME_FROM
and ::= expr . jmp_false expr
and ::= expr . jmp_false expr COME_FROM
and ::= expr . jmp_false expr jmp_false
assert ::= assert_expr . jmp_true LOAD_ASSERT RAISE_VARARGS_1 COME_FROM
assert2 ::= assert_expr . jmp_true LOAD_ASSERT expr CALL_FUNCTION_1 RAISE_VARARGS_1 COME_FROM
assert_expr ::= expr . 
assert_expr_and ::= assert_expr . jmp_false expr
assert_expr_or ::= assert_expr . jmp_true expr
assign ::= expr . DUP_TOP designList
assign ::= expr . store
assign ::= expr store . 
assign2 ::= expr . expr ROT_TWO store store
assign2 ::= expr expr . ROT_TWO store store
assign3 ::= expr . expr expr ROT_THREE ROT_TWO store store store
assign3 ::= expr expr . expr ROT_THREE ROT_TWO store store store
assign3 ::= expr expr expr . ROT_THREE ROT_TWO store store store
async_call ::= expr . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg expr CALL_FUNCTION_KW_1 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . expr CALL_FUNCTION_KW_1 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg expr . CALL_FUNCTION_KW_1 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg expr CALL_FUNCTION_KW_1 . GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_with_as_stmt ::= expr . async_with_pre store \e_suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_as_stmt ::= expr . async_with_pre store suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_as_stmt ::= expr async_with_pre . store \e_suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_as_stmt ::= expr async_with_pre . store suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_as_stmt ::= expr async_with_pre store . suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_as_stmt ::= expr async_with_pre store \e_suite_stmts_opt . POP_BLOCK LOAD_CONST async_with_post
async_with_as_stmt ::= expr async_with_pre store suite_stmts_opt . POP_BLOCK LOAD_CONST async_with_post
async_with_pre ::= BEFORE_ASYNC_WITH . GET_AWAITABLE LOAD_CONST YIELD_FROM SETUP_ASYNC_WITH
async_with_pre ::= BEFORE_ASYNC_WITH GET_AWAITABLE . LOAD_CONST YIELD_FROM SETUP_ASYNC_WITH
async_with_pre ::= BEFORE_ASYNC_WITH GET_AWAITABLE LOAD_CONST . YIELD_FROM SETUP_ASYNC_WITH
async_with_pre ::= BEFORE_ASYNC_WITH GET_AWAITABLE LOAD_CONST YIELD_FROM . SETUP_ASYNC_WITH
async_with_pre ::= BEFORE_ASYNC_WITH GET_AWAITABLE LOAD_CONST YIELD_FROM SETUP_ASYNC_WITH . 
async_with_stmt ::= expr . POP_TOP \e_suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_stmt ::= expr . POP_TOP \e_suite_stmts_opt async_with_post
async_with_stmt ::= expr . POP_TOP suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_stmt ::= expr . POP_TOP suite_stmts_opt async_with_post
async_with_stmt ::= expr . async_with_pre POP_TOP \e_suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_stmt ::= expr . async_with_pre POP_TOP \e_suite_stmts_opt async_with_post
async_with_stmt ::= expr . async_with_pre POP_TOP suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_stmt ::= expr . async_with_pre POP_TOP suite_stmts_opt async_with_post
async_with_stmt ::= expr async_with_pre . POP_TOP \e_suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_stmt ::= expr async_with_pre . POP_TOP \e_suite_stmts_opt async_with_post
async_with_stmt ::= expr async_with_pre . POP_TOP suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_stmt ::= expr async_with_pre . POP_TOP suite_stmts_opt async_with_post
attribute ::= expr . LOAD_ATTR
attribute ::= expr LOAD_ATTR . 
aug_assign1 ::= expr . expr inplace_op ROT_THREE STORE_SUBSCR
aug_assign1 ::= expr . expr inplace_op store
aug_assign1 ::= expr expr . inplace_op ROT_THREE STORE_SUBSCR
aug_assign1 ::= expr expr . inplace_op store
aug_assign2 ::= expr . DUP_TOP LOAD_ATTR expr inplace_op ROT_TWO STORE_ATTR
await_expr ::= expr . GET_AWAITABLE LOAD_CONST YIELD_FROM
await_expr ::= expr GET_AWAITABLE . LOAD_CONST YIELD_FROM
await_expr ::= expr GET_AWAITABLE LOAD_CONST . YIELD_FROM
await_expr ::= expr GET_AWAITABLE LOAD_CONST YIELD_FROM . 
bin_op ::= expr . expr binary_operator
bin_op ::= expr expr . binary_operator
call ::= expr . CALL_FUNCTION_0
call ::= expr . pos_arg CALL_FUNCTION_1
call ::= expr . pos_arg pos_arg CALL_FUNCTION_2
call ::= expr CALL_FUNCTION_0 . 
call ::= expr pos_arg . CALL_FUNCTION_1
call ::= expr pos_arg . pos_arg CALL_FUNCTION_2
call ::= expr pos_arg CALL_FUNCTION_1 . 
call ::= expr pos_arg pos_arg . CALL_FUNCTION_2
call ::= expr pos_arg pos_arg CALL_FUNCTION_2 . 
call_kw36 ::= expr . expr LOAD_CONST CALL_FUNCTION_KW_1
call_kw36 ::= expr . expr expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr . LOAD_CONST CALL_FUNCTION_KW_1
call_kw36 ::= expr expr . expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr LOAD_CONST . CALL_FUNCTION_KW_1
call_kw36 ::= expr expr LOAD_CONST CALL_FUNCTION_KW_1 . 
call_kw36 ::= expr expr expr . LOAD_CONST CALL_FUNCTION_KW_2
call_stmt ::= expr . POP_TOP
classdefdeco1 ::= expr . classdefdeco1 CALL_FUNCTION_1
classdefdeco1 ::= expr . classdefdeco2 CALL_FUNCTION_1
compare_chained ::= expr . compared_chained_middle ROT_TWO POP_TOP \e__come_froms
compare_chained ::= expr . compared_chained_middle ROT_TWO POP_TOP _come_froms
compare_single ::= expr . expr COMPARE_OP
compare_single ::= expr expr . COMPARE_OP
compared_chained_middle ::= expr . DUP_TOP ROT_THREE COMPARE_OP JUMP_IF_FALSE_OR_POP compare_chained_right COME_FROM
compared_chained_middle ::= expr . DUP_TOP ROT_THREE COMPARE_OP JUMP_IF_FALSE_OR_POP compared_chained_middle COME_FROM
continues ::= _stmts . lastl_stmt continue
dict ::= expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_2
dict ::= expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_2
dict ::= expr expr LOAD_CONST . BUILD_CONST_KEY_MAP_2
expr ::= LOAD_CONST . 
expr ::= LOAD_FAST . 
expr ::= LOAD_GLOBAL . 
expr ::= LOAD_STR . 
expr ::= attribute . 
expr ::= await_expr . 
expr ::= call . 
expr ::= call_kw36 . 
expr_jitop ::= expr . JUMP_IF_TRUE_OR_POP
expr_jt ::= expr . jmp_true
if_exp ::= expr . jmp_false expr jf_cf expr COME_FROM
if_exp ::= expr . jmp_false expr jump_absolute_else expr
if_exp ::= expr . jmp_false expr jump_forward_else expr COME_FROM
if_exp37 ::= expr . expr jf_cfs expr COME_FROM
if_exp37 ::= expr expr . jf_cfs expr COME_FROM
if_exp_lambda ::= expr . jmp_false expr return_if_lambda return_stmt_lambda LAMBDA_MARKER
if_exp_not ::= expr . jmp_true expr jump_forward_else expr COME_FROM
if_exp_not_lambda ::= expr . jmp_true expr return_if_lambda return_stmt_lambda LAMBDA_MARKER
if_exp_true ::= expr . JUMP_FORWARD expr COME_FROM
lambda_body ::= expr . LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_4
mkfunc ::= expr . LOAD_CODE LOAD_STR MAKE_FUNCTION_4
mkfuncdeco ::= expr . mkfuncdeco CALL_FUNCTION_1
mkfuncdeco ::= expr . mkfuncdeco0 CALL_FUNCTION_1
pos_arg ::= expr . 
ret_and ::= expr . JUMP_IF_FALSE_OR_POP return_expr_or_cond COME_FROM
ret_or ::= expr . JUMP_IF_TRUE_OR_POP return_expr_or_cond COME_FROM
return ::= return_expr . RETURN_END_IF
return ::= return_expr . RETURN_VALUE
return ::= return_expr . RETURN_VALUE COME_FROM
return ::= return_expr RETURN_VALUE . 
return ::= return_expr RETURN_VALUE . COME_FROM
return_expr ::= expr . 
return_expr_lambda ::= return_expr . RETURN_VALUE_LAMBDA
return_expr_lambda ::= return_expr . RETURN_VALUE_LAMBDA LAMBDA_MARKER
returns ::= _stmts . return
returns ::= _stmts . return_if_stmt
returns ::= return . 
sstmt ::= sstmt . RETURN_LAST
sstmt ::= stmt . 
stmt ::= assign . 
stmt ::= return . 
stmts ::= sstmt . 
stmts ::= stmts . sstmt
store ::= STORE_FAST . 
store ::= expr . STORE_ATTR
store_subscript ::= expr . expr STORE_SUBSCR
store_subscript ::= expr expr . STORE_SUBSCR
subscript ::= expr . expr BINARY_SUBSCR
subscript ::= expr expr . BINARY_SUBSCR
subscript2 ::= expr . expr DUP_TOP_TWO BINARY_SUBSCR
subscript2 ::= expr expr . DUP_TOP_TWO BINARY_SUBSCR
suite_stmts ::= _stmts . 
suite_stmts ::= returns . 
suite_stmts_opt ::= suite_stmts . 
testfalse ::= expr . jmp_false
testtrue ::= expr . jmp_true
unary_not ::= expr . UNARY_NOT
unary_op ::= expr . unary_operator
with ::= expr . SETUP_WITH POP_TOP \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with ::= expr . SETUP_WITH POP_TOP suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
yield ::= expr . YIELD_VALUE
yield_from ::= expr . GET_YIELD_FROM_ITER LOAD_CONST YIELD_FROM
Instruction context:
-> 
 L.  44         0  LOAD_STR                 '/tmp/odin/image.png'
                   2  STORE_FAST               'imgpath'
import aiofiles, base64, logging, apis
from aiohttp import web
import odin
from odin import get_resource_path
from odin.languages import get_locstring
from odin.platforms import get_ui_portal
log = logging.getLogger(__name__)
STRING_FILE_CONTENT = None
STRING_KEYS_FOR_UI = [
 'STRKEY.ONBOARDUI.TPMS_AUTOLEARN_BTN', 
 'STRKEY.ONBOARDUI.DRIVE_BTN', 
 'STRKEY.ONBOARDUI.STOP_DRIVE_BTN', 
 'STRKEY.ONBOARDUI.BRAKE_BTN', 
 'STRKEY.ONBOARDUI.CHARGE_PORT_BTN', 
 'STRKEY.ONBOARDUI.DAS_BTN', 
 'STRKEY.ONBOARDUI.RADC_BTN', 
 'STRKEY.ONBOARDUI.WINDOW-BTN', 
 'STRKEY.ONBOARDUI.SMALL_BANNER_TEXT', 
 'STRKEY.ONBOARDUI.PASSCODE_ENTER_H1', 
 'STRKEY.ONBOARDUI.PASSCODE_ENTER_H2', 
 'STRKEY.ONBOARDUI.NO-CONNECTORS-TEXT', 
 'STRKEY.ONBOARDUI.TEST_RESULT_TH_TEST_NAME', 
 'STRKEY.ONBOARDUI.TEST_RESULT_TH_DATE', 
 'STRKEY.ONBOARDUI.TEST_RESULT_TH_START_TIME', 
 'STRKEY.ONBOARDUI.TEST_RESULT_TH_FINISH_TIME', 
 'STRKEY.ONBOARDUI.TEST_RESULT_TH_STATUS']

@apis.route("/api/v1/image", method="GET")
async def das_imageParse error at or near `LOAD_STR' instruction at offset 0


@apis.route("/resource/strings", method="GET")
async def string_resource(request):
    global STRING_FILE_CONTENT
    if not STRING_FILE_CONTENT:
        template_path = get_resource_path("core/engine/assets/onboard/static/js/strings.js.template")
        async with aiofiles.opentemplate_path"r" as template:
            STRING_FILE_CONTENT = await template.read
        for key in STRING_KEYS_FOR_UI:
            STRING_FILE_CONTENT = STRING_FILE_CONTENT.replace"{{{{{}}}}}".format(key)get_locstring(key)

    return web.Response(body=STRING_FILE_CONTENT)


@apis.route("/{tail:.*}", method="GET")
async def index(request):
    html_file = get_ui_portal or "index.html"
    return web.FileResponse(get_resource_path("core/engine/assets/onboard/" + html_file))


def includeme(app):
    app.router.add_static"/static"get_resource_path("core/engine/assets/onboard/static")
    app.router.add_static"/js"get_resource_path("core/engine/assets/js")
    app.router.add_static"/img"get_resource_path("core/engine/assets/img")
