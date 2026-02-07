# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/ic/updater.py

-- Stacks of completed symbols:
START ::= |- stmts . 
_stmts ::= _stmts . last_stmt
_stmts ::= _stmts . stmt
_stmts ::= _stmts stmt . 
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
async_call ::= expr . pos_arg pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg . expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg expr . CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_3 . GET_AWAITABLE LOAD_CONST YIELD_FROM
async_with_as_stmt ::= expr . async_with_pre store \e_suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_as_stmt ::= expr . async_with_pre store suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_as_stmt ::= expr async_with_pre . store \e_suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_as_stmt ::= expr async_with_pre . store suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_as_stmt ::= expr async_with_pre store . suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_as_stmt ::= expr async_with_pre store \e_suite_stmts_opt . POP_BLOCK LOAD_CONST async_with_post
async_with_as_stmt ::= expr async_with_pre store suite_stmts_opt . POP_BLOCK LOAD_CONST async_with_post
async_with_post ::= COME_FROM_ASYNC_WITH . WITH_CLEANUP_START GET_AWAITABLE LOAD_CONST YIELD_FROM WITH_CLEANUP_FINISH END_FINALLY
async_with_post ::= COME_FROM_ASYNC_WITH WITH_CLEANUP_START . GET_AWAITABLE LOAD_CONST YIELD_FROM WITH_CLEANUP_FINISH END_FINALLY
async_with_post ::= COME_FROM_ASYNC_WITH WITH_CLEANUP_START GET_AWAITABLE . LOAD_CONST YIELD_FROM WITH_CLEANUP_FINISH END_FINALLY
async_with_post ::= COME_FROM_ASYNC_WITH WITH_CLEANUP_START GET_AWAITABLE LOAD_CONST . YIELD_FROM WITH_CLEANUP_FINISH END_FINALLY
async_with_post ::= COME_FROM_ASYNC_WITH WITH_CLEANUP_START GET_AWAITABLE LOAD_CONST YIELD_FROM . WITH_CLEANUP_FINISH END_FINALLY
async_with_post ::= COME_FROM_ASYNC_WITH WITH_CLEANUP_START GET_AWAITABLE LOAD_CONST YIELD_FROM WITH_CLEANUP_FINISH . END_FINALLY
async_with_post ::= COME_FROM_ASYNC_WITH WITH_CLEANUP_START GET_AWAITABLE LOAD_CONST YIELD_FROM WITH_CLEANUP_FINISH END_FINALLY . 
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
async_with_stmt ::= expr POP_TOP . suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_stmt ::= expr POP_TOP . suite_stmts_opt async_with_post
async_with_stmt ::= expr POP_TOP \e_suite_stmts_opt . POP_BLOCK LOAD_CONST async_with_post
async_with_stmt ::= expr POP_TOP \e_suite_stmts_opt . async_with_post
async_with_stmt ::= expr POP_TOP suite_stmts_opt . POP_BLOCK LOAD_CONST async_with_post
async_with_stmt ::= expr POP_TOP suite_stmts_opt . async_with_post
async_with_stmt ::= expr POP_TOP suite_stmts_opt async_with_post . 
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
await_stmt ::= await_expr . POP_TOP
bin_op ::= expr . expr binary_operator
bin_op ::= expr expr . binary_operator
call ::= expr . CALL_FUNCTION_0
call ::= expr . pos_arg CALL_FUNCTION_1
call ::= expr . pos_arg pos_arg pos_arg CALL_FUNCTION_3
call ::= expr CALL_FUNCTION_0 . 
call ::= expr pos_arg . CALL_FUNCTION_1
call ::= expr pos_arg . pos_arg pos_arg CALL_FUNCTION_3
call ::= expr pos_arg CALL_FUNCTION_1 . 
call ::= expr pos_arg pos_arg . pos_arg CALL_FUNCTION_3
call ::= expr pos_arg pos_arg pos_arg . CALL_FUNCTION_3
call_kw36 ::= expr . expr expr expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr . expr expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr . expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr expr . LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr expr LOAD_CONST . CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr expr LOAD_CONST CALL_FUNCTION_KW_3 . 
call_stmt ::= expr . POP_TOP
call_stmt ::= expr POP_TOP . 
classdefdeco1 ::= expr . classdefdeco1 CALL_FUNCTION_1
classdefdeco1 ::= expr . classdefdeco2 CALL_FUNCTION_1
compare_chained ::= expr . compared_chained_middle ROT_TWO POP_TOP \e__come_froms
compare_chained ::= expr . compared_chained_middle ROT_TWO POP_TOP _come_froms
compare_single ::= expr . expr COMPARE_OP
compare_single ::= expr expr . COMPARE_OP
compared_chained_middle ::= expr . DUP_TOP ROT_THREE COMPARE_OP JUMP_IF_FALSE_OR_POP compare_chained_right COME_FROM
compared_chained_middle ::= expr . DUP_TOP ROT_THREE COMPARE_OP JUMP_IF_FALSE_OR_POP compared_chained_middle COME_FROM
continues ::= _stmts . lastl_stmt continue
dict ::= expr . LOAD_CONST BUILD_CONST_KEY_MAP_1
dict ::= expr . expr expr LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr LOAD_CONST . BUILD_CONST_KEY_MAP_1
dict ::= expr expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr expr expr LOAD_CONST . BUILD_CONST_KEY_MAP_3
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
genexpr_func ::= LOAD_FAST . FOR_ITER store comp_iter JUMP_BACK
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
lambda_body ::= expr . expr LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_5
lambda_body ::= expr expr . LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_5
mkfunc ::= expr . LOAD_CODE LOAD_STR MAKE_FUNCTION_4
mkfunc ::= expr . expr LOAD_CODE LOAD_STR MAKE_FUNCTION_5
mkfunc ::= expr expr . LOAD_CODE LOAD_STR MAKE_FUNCTION_5
mkfuncdeco ::= expr . mkfuncdeco CALL_FUNCTION_1
mkfuncdeco ::= expr . mkfuncdeco0 CALL_FUNCTION_1
pos_arg ::= expr . 
raise_stmt1 ::= expr . RAISE_VARARGS_1
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
return_if_stmt ::= return_expr . RETURN_END_IF
return_if_stmt ::= return_expr . RETURN_END_IF POP_BLOCK
returns ::= _stmts . return
returns ::= _stmts . return_if_stmt
returns ::= _stmts return . 
returns ::= return . 
sstmt ::= sstmt . RETURN_LAST
sstmt ::= stmt . 
stmt ::= assign . 
stmt ::= async_with_stmt . 
stmt ::= call_stmt . 
stmt ::= return . 
stmts ::= sstmt . 
stmts ::= stmts . sstmt
stmts ::= stmts sstmt . 
store ::= STORE_FAST . 
store ::= expr . STORE_ATTR
store_locals ::= LOAD_FAST . STORE_LOCALS
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
 L.  29         0  LOAD_GLOBAL              odin
                   2  LOAD_ATTR                get_http_session
                   4  CALL_FUNCTION_0       0  '0 positional arguments'
                   6  GET_AWAITABLE    
                   8  LOAD_CONST               None
                  10  YIELD_FROM       
                  12  STORE_FAST               'session'
import logging, odin
from . import settings
from odin import platforms
log = logging.getLogger(__name__)
watching = False

async def run_command(command: str, params=None, timeout: int=10) -> str:
    if odin.__platform__ != "tegra":
        raise NotImplementedError("ic updater only supported on tegra")
    url = "http://{}:{}/{}".format(settings.IC_IP, settings.PORTS["ic_updater"], command)
    return await http_get_request(url, params=params, timeout=timeout)


async def http_get_requestParse error at or near `LOAD_GLOBAL' instruction at offset 0


async def read_signature() -> dict:
    results = await run_command("readsig")
    return dict([line.split(": ") for line in results.splitlines])
