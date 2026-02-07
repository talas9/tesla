# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/cid/interface/filesystem.py

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
assign2 ::= expr . expr ROT_TWO store store
assign2 ::= expr expr . ROT_TWO store store
assign3 ::= expr . expr expr ROT_THREE ROT_TWO store store store
assign3 ::= expr expr . expr ROT_THREE ROT_TWO store store store
assign3 ::= expr expr expr . ROT_THREE ROT_TWO store store store
async_call ::= expr . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
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
call ::= expr . pos_arg pos_arg pos_arg CALL_FUNCTION_3
call ::= expr . pos_arg pos_arg pos_arg pos_arg CALL_FUNCTION_4
call ::= expr pos_arg . CALL_FUNCTION_1
call ::= expr pos_arg . pos_arg CALL_FUNCTION_2
call ::= expr pos_arg . pos_arg pos_arg CALL_FUNCTION_3
call ::= expr pos_arg . pos_arg pos_arg pos_arg CALL_FUNCTION_4
call ::= expr pos_arg CALL_FUNCTION_1 . 
call ::= expr pos_arg pos_arg . CALL_FUNCTION_2
call ::= expr pos_arg pos_arg . pos_arg CALL_FUNCTION_3
call ::= expr pos_arg pos_arg . pos_arg pos_arg CALL_FUNCTION_4
call ::= expr pos_arg pos_arg CALL_FUNCTION_2 . 
call_kw36 ::= expr . expr expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr . expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr expr . LOAD_CONST CALL_FUNCTION_KW_2
call_stmt ::= expr . POP_TOP
classdefdeco1 ::= expr . classdefdeco1 CALL_FUNCTION_1
classdefdeco1 ::= expr . classdefdeco2 CALL_FUNCTION_1
compare ::= compare_single . 
compare_chained ::= expr . compared_chained_middle ROT_TWO POP_TOP \e__come_froms
compare_chained ::= expr . compared_chained_middle ROT_TWO POP_TOP _come_froms
compare_single ::= expr . expr COMPARE_OP
compare_single ::= expr expr . COMPARE_OP
compare_single ::= expr expr COMPARE_OP . 
compared_chained_middle ::= expr . DUP_TOP ROT_THREE COMPARE_OP JUMP_IF_FALSE_OR_POP compare_chained_right COME_FROM
compared_chained_middle ::= expr . DUP_TOP ROT_THREE COMPARE_OP JUMP_IF_FALSE_OR_POP compared_chained_middle COME_FROM
continues ::= _stmts . lastl_stmt continue
dict ::= expr . LOAD_CONST BUILD_CONST_KEY_MAP_1
dict ::= expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_2
dict ::= expr . expr expr LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr . expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr LOAD_CONST . BUILD_CONST_KEY_MAP_1
dict ::= expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_2
dict ::= expr expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr expr . expr expr LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr expr LOAD_CONST . BUILD_CONST_KEY_MAP_2
dict ::= expr expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr expr expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_4
expr ::= LOAD_CONST . 
expr ::= LOAD_FAST . 
expr ::= LOAD_GLOBAL . 
expr ::= LOAD_STR . 
expr ::= attribute . 
expr ::= await_expr . 
expr ::= call . 
expr ::= compare . 
expr_jitop ::= expr . JUMP_IF_TRUE_OR_POP
expr_jt ::= expr . jmp_true
get_iter ::= expr . GET_ITER
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
returns ::= _stmts . return
returns ::= _stmts . return_if_stmt
returns ::= return . 
stmt ::= return . 
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
tuple ::= expr . expr expr BUILD_TUPLE_3
tuple ::= expr expr . expr BUILD_TUPLE_3
tuple ::= expr expr expr . BUILD_TUPLE_3
unary_not ::= expr . UNARY_NOT
unary_op ::= expr . unary_operator
with ::= expr . SETUP_WITH POP_TOP \e_suite_stmts_opt COME_FROM_WITH with_suffix
with ::= expr . SETUP_WITH POP_TOP \e_suite_stmts_opt POP_BLOCK BEGIN_FINALLY COME_FROM_WITH with_suffix
with ::= expr . SETUP_WITH POP_TOP \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with ::= expr . SETUP_WITH POP_TOP suite_stmts_opt COME_FROM_WITH with_suffix
with ::= expr . SETUP_WITH POP_TOP suite_stmts_opt POP_BLOCK BEGIN_FINALLY COME_FROM_WITH with_suffix
with ::= expr . SETUP_WITH POP_TOP suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store \e_suite_stmts_opt COME_FROM_WITH with_suffix
with_as ::= expr . SETUP_WITH store \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store suite_stmts_opt COME_FROM_WITH with_suffix
with_as ::= expr . SETUP_WITH store suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
yield ::= expr . YIELD_VALUE
yield_from ::= expr . GET_YIELD_FROM_ITER LOAD_CONST YIELD_FROM
Instruction context:
-> 
 L. 147         0  LOAD_GLOBAL              aiofiles
                   2  LOAD_ATTR                open
                   4  LOAD_FAST                'path'
                   6  LOAD_STR                 'rb'
                   8  CALL_FUNCTION_2       2  '2 positional arguments'
                  10  BEFORE_ASYNC_WITH
                  12  GET_AWAITABLE    
                  14  LOAD_CONST               None
                  16  YIELD_FROM       
                  18  SETUP_ASYNC_WITH     46  'to 46'
                  20  STORE_FAST               'f'

-- Stacks of completed symbols:
START ::= |- stmts . 
_come_froms ::= \e__come_froms . COME_FROM
_come_froms ::= \e__come_froms COME_FROM . 
_come_froms ::= _come_froms . COME_FROM
_iflaststmts_jump ::= stmts . last_stmt
_ifstmts_jump ::= \e_c_stmts_opt . ELSE
_ifstmts_jump ::= \e_c_stmts_opt . JUMP_ABSOLUTE JUMP_FORWARD COME_FROM
_ifstmts_jump ::= \e_c_stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jump ::= \e_c_stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jump ::= \e_c_stmts_opt . come_froms
_ifstmts_jump ::= \e_stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jump ::= \e_stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jump ::= c_stmts_opt . ELSE
_ifstmts_jump ::= c_stmts_opt . JUMP_ABSOLUTE JUMP_FORWARD COME_FROM
_ifstmts_jump ::= c_stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jump ::= c_stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jump ::= c_stmts_opt . come_froms
_ifstmts_jump ::= c_stmts_opt come_froms . 
_ifstmts_jump ::= return_if_stmts . 
_ifstmts_jump ::= stmts . _come_froms
_ifstmts_jump ::= stmts \e__come_froms . 
_ifstmts_jump ::= stmts _come_froms . 
_ifstmts_jump ::= stmts_opt . 
_ifstmts_jump ::= stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jump ::= stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jumpl ::= \e_c_stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jumpl ::= \e_c_stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jumpl ::= \e_c_stmts_opt . come_froms
_ifstmts_jumpl ::= c_stmts . JUMP_BACK
_ifstmts_jumpl ::= c_stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jumpl ::= c_stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jumpl ::= c_stmts_opt . come_froms
_ifstmts_jumpl ::= c_stmts_opt come_froms . 
_stmts ::= _stmts . last_stmt
_stmts ::= _stmts . stmt
_stmts ::= _stmts stmt . 
_stmts ::= stmt . 
and ::= expr . JUMP_IF_FALSE_OR_POP expr COME_FROM
and ::= expr . jmp_false expr
and ::= expr . jmp_false expr COME_FROM
and ::= expr . jmp_false expr jmp_false
and ::= expr jmp_false . expr
and ::= expr jmp_false . expr COME_FROM
and ::= expr jmp_false . expr jmp_false
and ::= expr jmp_false expr . 
and ::= expr jmp_false expr . COME_FROM
and ::= expr jmp_false expr . jmp_false
assert ::= assert_expr . jmp_true LOAD_ASSERT RAISE_VARARGS_1 COME_FROM
assert2 ::= assert_expr . jmp_true LOAD_ASSERT expr CALL_FUNCTION_1 RAISE_VARARGS_1 COME_FROM
assert_expr ::= assert_expr_and . 
assert_expr ::= expr . 
assert_expr_and ::= assert_expr . jmp_false expr
assert_expr_and ::= assert_expr jmp_false . expr
assert_expr_and ::= assert_expr jmp_false expr . 
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
async_call ::= expr . pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
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
await_stmt ::= await_expr . POP_TOP
bin_op ::= expr . expr binary_operator
bin_op ::= expr expr . binary_operator
c_stmts ::= _stmts . 
c_stmts ::= _stmts . lastc_stmt
c_stmts ::= lastc_stmt . 
c_stmts_opt ::= c_stmts . 
call ::= expr . CALL_FUNCTION_0
call ::= expr . pos_arg CALL_FUNCTION_1
call ::= expr . pos_arg pos_arg CALL_FUNCTION_2
call ::= expr . pos_arg pos_arg pos_arg CALL_FUNCTION_3
call ::= expr . pos_arg pos_arg pos_arg pos_arg CALL_FUNCTION_4
call ::= expr CALL_FUNCTION_0 . 
call ::= expr pos_arg . CALL_FUNCTION_1
call ::= expr pos_arg . pos_arg CALL_FUNCTION_2
call ::= expr pos_arg . pos_arg pos_arg CALL_FUNCTION_3
call ::= expr pos_arg . pos_arg pos_arg pos_arg CALL_FUNCTION_4
call ::= expr pos_arg CALL_FUNCTION_1 . 
call ::= expr pos_arg pos_arg . CALL_FUNCTION_2
call ::= expr pos_arg pos_arg . pos_arg CALL_FUNCTION_3
call ::= expr pos_arg pos_arg . pos_arg pos_arg CALL_FUNCTION_4
call ::= expr pos_arg pos_arg CALL_FUNCTION_2 . 
call ::= expr pos_arg pos_arg pos_arg . CALL_FUNCTION_3
call ::= expr pos_arg pos_arg pos_arg . pos_arg CALL_FUNCTION_4
call_kw36 ::= expr . expr expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr . expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr expr . LOAD_CONST CALL_FUNCTION_KW_2
call_stmt ::= expr . POP_TOP
cf_jf_else ::= come_froms . JUMP_FORWARD ELSE
cf_jump_back ::= COME_FROM . JUMP_BACK
classdefdeco1 ::= expr . classdefdeco1 CALL_FUNCTION_1
classdefdeco1 ::= expr . classdefdeco2 CALL_FUNCTION_1
come_from_opt ::= COME_FROM . 
come_froms ::= COME_FROM . 
come_froms ::= come_froms . COME_FROM
compare_chained ::= expr . compared_chained_middle ROT_TWO POP_TOP \e__come_froms
compare_chained ::= expr . compared_chained_middle ROT_TWO POP_TOP _come_froms
compare_single ::= expr . expr COMPARE_OP
compare_single ::= expr expr . COMPARE_OP
compared_chained_middle ::= expr . DUP_TOP ROT_THREE COMPARE_OP JUMP_IF_FALSE_OR_POP compare_chained_right COME_FROM
compared_chained_middle ::= expr . DUP_TOP ROT_THREE COMPARE_OP JUMP_IF_FALSE_OR_POP compared_chained_middle COME_FROM
continues ::= _stmts . lastl_stmt continue
continues ::= lastl_stmt . continue
dict ::= expr . LOAD_CONST BUILD_CONST_KEY_MAP_1
dict ::= expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_2
dict ::= expr . expr expr LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr . expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_2
dict ::= expr expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr expr . expr expr LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr expr expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr expr expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_4
else_suite ::= stmts . 
else_suite ::= suite_stmts . 
except_cond1 ::= DUP_TOP . expr COMPARE_OP jmp_false POP_TOP POP_TOP POP_TOP
except_cond1 ::= DUP_TOP expr . COMPARE_OP jmp_false POP_TOP POP_TOP POP_TOP
except_cond1 ::= DUP_TOP expr COMPARE_OP . jmp_false POP_TOP POP_TOP POP_TOP
except_cond1 ::= DUP_TOP expr COMPARE_OP jmp_false . POP_TOP POP_TOP POP_TOP
except_cond1 ::= DUP_TOP expr COMPARE_OP jmp_false POP_TOP . POP_TOP POP_TOP
except_cond1 ::= DUP_TOP expr COMPARE_OP jmp_false POP_TOP POP_TOP . POP_TOP
except_cond1 ::= DUP_TOP expr COMPARE_OP jmp_false POP_TOP POP_TOP POP_TOP . 
except_cond2 ::= DUP_TOP . expr COMPARE_OP jmp_false POP_TOP store POP_TOP
except_cond2 ::= DUP_TOP expr . COMPARE_OP jmp_false POP_TOP store POP_TOP
except_cond2 ::= DUP_TOP expr COMPARE_OP . jmp_false POP_TOP store POP_TOP
except_cond2 ::= DUP_TOP expr COMPARE_OP jmp_false . POP_TOP store POP_TOP
except_cond2 ::= DUP_TOP expr COMPARE_OP jmp_false POP_TOP . store POP_TOP
except_handler36 ::= COME_FROM_EXCEPT . except_stmts
except_handler36 ::= COME_FROM_EXCEPT . except_stmts END_FINALLY
except_handler36 ::= COME_FROM_EXCEPT except_stmts . 
except_handler36 ::= COME_FROM_EXCEPT except_stmts . END_FINALLY
except_handler36 ::= COME_FROM_EXCEPT except_stmts END_FINALLY . 
except_stmt ::= except_cond1 . except_suite
except_stmt ::= except_cond1 except_suite . 
except_stmts ::= except_stmt . 
except_stmts ::= except_stmts . except_stmt
except_suite ::= \e_c_stmts_opt . COME_FROM POP_EXCEPT jump_except COME_FROM
except_suite ::= \e_c_stmts_opt . POP_EXCEPT jump_except
except_suite ::= \e_c_stmts_opt . POP_EXCEPT jump_except ELSE
except_suite ::= c_stmts_opt . COME_FROM POP_EXCEPT jump_except COME_FROM
except_suite ::= c_stmts_opt . POP_EXCEPT jump_except
except_suite ::= c_stmts_opt . POP_EXCEPT jump_except ELSE
except_suite ::= c_stmts_opt COME_FROM . POP_EXCEPT jump_except COME_FROM
except_suite ::= c_stmts_opt POP_EXCEPT . jump_except
except_suite ::= c_stmts_opt POP_EXCEPT . jump_except ELSE
except_suite ::= c_stmts_opt POP_EXCEPT jump_except . 
except_suite ::= c_stmts_opt POP_EXCEPT jump_except . ELSE
expr ::= LOAD_FAST . 
expr ::= LOAD_GLOBAL . 
expr ::= LOAD_STR . 
expr ::= attribute . 
expr ::= await_expr . 
expr ::= call . 
expr ::= list . 
expr_jitop ::= expr . JUMP_IF_TRUE_OR_POP
expr_jt ::= expr . jmp_true
genexpr_func ::= LOAD_FAST . FOR_ITER store comp_iter JUMP_BACK
get_iter ::= expr . GET_ITER
if_exp ::= expr . jmp_false expr jf_cf expr COME_FROM
if_exp ::= expr . jmp_false expr jump_absolute_else expr
if_exp ::= expr . jmp_false expr jump_forward_else expr COME_FROM
if_exp ::= expr jmp_false . expr jf_cf expr COME_FROM
if_exp ::= expr jmp_false . expr jump_absolute_else expr
if_exp ::= expr jmp_false . expr jump_forward_else expr COME_FROM
if_exp ::= expr jmp_false expr . jf_cf expr COME_FROM
if_exp ::= expr jmp_false expr . jump_absolute_else expr
if_exp ::= expr jmp_false expr . jump_forward_else expr COME_FROM
if_exp37 ::= expr . expr jf_cfs expr COME_FROM
if_exp37 ::= expr expr . jf_cfs expr COME_FROM
if_exp_lambda ::= expr . jmp_false expr return_if_lambda return_stmt_lambda LAMBDA_MARKER
if_exp_lambda ::= expr jmp_false . expr return_if_lambda return_stmt_lambda LAMBDA_MARKER
if_exp_lambda ::= expr jmp_false expr . return_if_lambda return_stmt_lambda LAMBDA_MARKER
if_exp_not ::= expr . jmp_true expr jump_forward_else expr COME_FROM
if_exp_not_lambda ::= expr . jmp_true expr return_if_lambda return_stmt_lambda LAMBDA_MARKER
if_exp_true ::= expr . JUMP_FORWARD expr COME_FROM
ifelsestmt ::= testexpr . c_stmts come_froms else_suite come_froms
ifelsestmt ::= testexpr . c_stmts_opt JUMP_FORWARD else_suite \e__come_froms
ifelsestmt ::= testexpr . c_stmts_opt JUMP_FORWARD else_suite _come_froms
ifelsestmt ::= testexpr . c_stmts_opt cf_jf_else else_suite \e__come_froms
ifelsestmt ::= testexpr . c_stmts_opt cf_jf_else else_suite _come_froms
ifelsestmt ::= testexpr . c_stmts_opt jf_cfs else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr . c_stmts_opt jf_cfs else_suite opt_come_from_except
ifelsestmt ::= testexpr . c_stmts_opt jump_forward_else else_suite \e__come_froms
ifelsestmt ::= testexpr . c_stmts_opt jump_forward_else else_suite _come_froms
ifelsestmt ::= testexpr . stmts_opt JUMP_FORWARD else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr . stmts_opt JUMP_FORWARD else_suite opt_come_from_except
ifelsestmt ::= testexpr . stmts_opt jump_absolute_else else_suite
ifelsestmt ::= testexpr . stmts_opt jump_forward_else else_suite \e__come_froms
ifelsestmt ::= testexpr . stmts_opt jump_forward_else else_suite _come_froms
ifelsestmt ::= testexpr \e_c_stmts_opt . JUMP_FORWARD else_suite \e__come_froms
ifelsestmt ::= testexpr \e_c_stmts_opt . JUMP_FORWARD else_suite _come_froms
ifelsestmt ::= testexpr \e_c_stmts_opt . cf_jf_else else_suite \e__come_froms
ifelsestmt ::= testexpr \e_c_stmts_opt . cf_jf_else else_suite _come_froms
ifelsestmt ::= testexpr \e_c_stmts_opt . jf_cfs else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr \e_c_stmts_opt . jf_cfs else_suite opt_come_from_except
ifelsestmt ::= testexpr \e_c_stmts_opt . jump_forward_else else_suite \e__come_froms
ifelsestmt ::= testexpr \e_c_stmts_opt . jump_forward_else else_suite _come_froms
ifelsestmt ::= testexpr \e_stmts_opt . JUMP_FORWARD else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr \e_stmts_opt . JUMP_FORWARD else_suite opt_come_from_except
ifelsestmt ::= testexpr \e_stmts_opt . jump_absolute_else else_suite
ifelsestmt ::= testexpr \e_stmts_opt . jump_forward_else else_suite \e__come_froms
ifelsestmt ::= testexpr \e_stmts_opt . jump_forward_else else_suite _come_froms
ifelsestmt ::= testexpr c_stmts . come_froms else_suite come_froms
ifelsestmt ::= testexpr c_stmts come_froms . else_suite come_froms
ifelsestmt ::= testexpr c_stmts come_froms else_suite . come_froms
ifelsestmt ::= testexpr c_stmts_opt . JUMP_FORWARD else_suite \e__come_froms
ifelsestmt ::= testexpr c_stmts_opt . JUMP_FORWARD else_suite _come_froms
ifelsestmt ::= testexpr c_stmts_opt . cf_jf_else else_suite \e__come_froms
ifelsestmt ::= testexpr c_stmts_opt . cf_jf_else else_suite _come_froms
ifelsestmt ::= testexpr c_stmts_opt . jf_cfs else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr c_stmts_opt . jf_cfs else_suite opt_come_from_except
ifelsestmt ::= testexpr c_stmts_opt . jump_forward_else else_suite \e__come_froms
ifelsestmt ::= testexpr c_stmts_opt . jump_forward_else else_suite _come_froms
ifelsestmt ::= testexpr stmts_opt . JUMP_FORWARD else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr stmts_opt . JUMP_FORWARD else_suite opt_come_from_except
ifelsestmt ::= testexpr stmts_opt . jump_absolute_else else_suite
ifelsestmt ::= testexpr stmts_opt . jump_forward_else else_suite \e__come_froms
ifelsestmt ::= testexpr stmts_opt . jump_forward_else else_suite _come_froms
ifelsestmtc ::= testexpr . c_stmts_opt JUMP_ABSOLUTE else_suitec
ifelsestmtc ::= testexpr . c_stmts_opt JUMP_FORWARD else_suitec
ifelsestmtc ::= testexpr . c_stmts_opt jump_absolute_else else_suitec
ifelsestmtc ::= testexpr . c_stmts_opt jump_forward_else else_suitec \e__come_froms
ifelsestmtc ::= testexpr . c_stmts_opt jump_forward_else else_suitec _come_froms
ifelsestmtc ::= testexpr \e_c_stmts_opt . JUMP_ABSOLUTE else_suitec
ifelsestmtc ::= testexpr \e_c_stmts_opt . JUMP_FORWARD else_suitec
ifelsestmtc ::= testexpr \e_c_stmts_opt . jump_absolute_else else_suitec
ifelsestmtc ::= testexpr \e_c_stmts_opt . jump_forward_else else_suitec \e__come_froms
ifelsestmtc ::= testexpr \e_c_stmts_opt . jump_forward_else else_suitec _come_froms
ifelsestmtc ::= testexpr c_stmts_opt . JUMP_ABSOLUTE else_suitec
ifelsestmtc ::= testexpr c_stmts_opt . JUMP_FORWARD else_suitec
ifelsestmtc ::= testexpr c_stmts_opt . jump_absolute_else else_suitec
ifelsestmtc ::= testexpr c_stmts_opt . jump_forward_else else_suitec \e__come_froms
ifelsestmtc ::= testexpr c_stmts_opt . jump_forward_else else_suitec _come_froms
ifelsestmtl ::= testexpr . c_stmts_opt JUMP_BACK else_suitel
ifelsestmtl ::= testexpr . c_stmts_opt cf_jf_else else_suitel
ifelsestmtl ::= testexpr . c_stmts_opt cf_jump_back else_suitel
ifelsestmtl ::= testexpr . c_stmts_opt continue else_suitel
ifelsestmtl ::= testexpr . c_stmts_opt jb_cfs else_suitel
ifelsestmtl ::= testexpr . c_stmts_opt jb_else else_suitel
ifelsestmtl ::= testexpr \e_c_stmts_opt . JUMP_BACK else_suitel
ifelsestmtl ::= testexpr \e_c_stmts_opt . cf_jf_else else_suitel
ifelsestmtl ::= testexpr \e_c_stmts_opt . cf_jump_back else_suitel
ifelsestmtl ::= testexpr \e_c_stmts_opt . continue else_suitel
ifelsestmtl ::= testexpr \e_c_stmts_opt . jb_cfs else_suitel
ifelsestmtl ::= testexpr \e_c_stmts_opt . jb_else else_suitel
ifelsestmtl ::= testexpr c_stmts_opt . JUMP_BACK else_suitel
ifelsestmtl ::= testexpr c_stmts_opt . cf_jf_else else_suitel
ifelsestmtl ::= testexpr c_stmts_opt . cf_jump_back else_suitel
ifelsestmtl ::= testexpr c_stmts_opt . continue else_suitel
ifelsestmtl ::= testexpr c_stmts_opt . jb_cfs else_suitel
ifelsestmtl ::= testexpr c_stmts_opt . jb_else else_suitel
ifelsestmtr ::= testexpr . return_if_stmts returns
ifelsestmtr ::= testexpr return_if_stmts . returns
iflaststmt ::= testexpr . _iflaststmts_jump
iflaststmt ::= testexpr . _ifstmts_jumpl
iflaststmt ::= testexpr . c_stmts_opt JUMP_FORWARD
iflaststmt ::= testexpr . last_stmt JUMP_ABSOLUTE
iflaststmt ::= testexpr . stmts JUMP_ABSOLUTE
iflaststmt ::= testexpr . stmts_opt JUMP_ABSOLUTE
iflaststmt ::= testexpr \e_c_stmts_opt . JUMP_FORWARD
iflaststmt ::= testexpr \e_stmts_opt . JUMP_ABSOLUTE
iflaststmt ::= testexpr _ifstmts_jumpl . 
iflaststmt ::= testexpr c_stmts_opt . JUMP_FORWARD
iflaststmt ::= testexpr stmts . JUMP_ABSOLUTE
iflaststmt ::= testexpr stmts_opt . JUMP_ABSOLUTE
iflaststmtl ::= testexpr . _ifstmts_jumpl
iflaststmtl ::= testexpr . c_stmts_opt
iflaststmtl ::= testexpr . c_stmts_opt JUMP_BACK
iflaststmtl ::= testexpr \e_c_stmts_opt . 
iflaststmtl ::= testexpr \e_c_stmts_opt . JUMP_BACK
iflaststmtl ::= testexpr _ifstmts_jumpl . 
iflaststmtl ::= testexpr c_stmts_opt . 
iflaststmtl ::= testexpr c_stmts_opt . JUMP_BACK
ifstmt ::= testexpr . _ifstmts_jump
ifstmt ::= testexpr \e__ifstmts_jump . 
ifstmt ::= testexpr _ifstmts_jump . 
ifstmtl ::= testexpr . _ifstmts_jumpl
ifstmtl ::= testexpr _ifstmts_jumpl . 
jmp_false ::= POP_JUMP_IF_FALSE . 
jump_except ::= JUMP_FORWARD . 
lambda_body ::= expr . LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_4
lambda_body ::= expr . expr LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_5
lambda_body ::= expr expr . LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_5
lastc_stmt ::= iflaststmt . 
lastc_stmt ::= iflaststmtl . 
lastl_stmt ::= iflaststmtl . 
list ::= BUILD_LIST_0 . 
list_comp ::= BUILD_LIST_0 . list_iter
mkfunc ::= expr . LOAD_CODE LOAD_STR MAKE_FUNCTION_4
mkfunc ::= expr . expr LOAD_CODE LOAD_STR MAKE_FUNCTION_5
mkfunc ::= expr expr . LOAD_CODE LOAD_STR MAKE_FUNCTION_5
mkfuncdeco ::= expr . mkfuncdeco CALL_FUNCTION_1
mkfuncdeco ::= expr . mkfuncdeco0 CALL_FUNCTION_1
opt_come_from_except ::= _come_froms . 
pos_arg ::= expr . 
raise_stmt0 ::= RAISE_VARARGS_0 . 
raise_stmt1 ::= expr . RAISE_VARARGS_1
ret_and ::= expr . JUMP_IF_FALSE_OR_POP return_expr_or_cond COME_FROM
ret_or ::= expr . JUMP_IF_TRUE_OR_POP return_expr_or_cond COME_FROM
return ::= return_expr . RETURN_END_IF
return ::= return_expr . RETURN_VALUE
return ::= return_expr . RETURN_VALUE COME_FROM
return ::= return_expr RETURN_END_IF . 
return ::= return_expr RETURN_VALUE . 
return ::= return_expr RETURN_VALUE . COME_FROM
return_expr ::= expr . 
return_expr_lambda ::= return_expr . RETURN_VALUE_LAMBDA
return_expr_lambda ::= return_expr . RETURN_VALUE_LAMBDA LAMBDA_MARKER
return_if_stmt ::= return_expr . RETURN_END_IF
return_if_stmt ::= return_expr . RETURN_END_IF POP_BLOCK
return_if_stmt ::= return_expr RETURN_END_IF . 
return_if_stmt ::= return_expr RETURN_END_IF . POP_BLOCK
return_if_stmts ::= _stmts . return_if_stmt \e__come_froms
return_if_stmts ::= _stmts . return_if_stmt _come_froms
return_if_stmts ::= return_if_stmt . come_from_opt
return_if_stmts ::= return_if_stmt \e_come_from_opt . 
return_if_stmts ::= return_if_stmt come_from_opt . 
returns ::= _stmts . return
returns ::= _stmts . return_if_stmt
returns ::= _stmts return . 
returns ::= return . 
sstmt ::= return . RETURN_LAST
sstmt ::= sstmt . RETURN_LAST
sstmt ::= stmt . 
stmt ::= assign . 
stmt ::= ifstmt . 
stmt ::= ifstmtl . 
stmt ::= raise_stmt0 . 
stmt ::= return . 
stmt ::= try_except36 . 
stmts ::= sstmt . 
stmts ::= stmts . sstmt
stmts_opt ::= _stmts . 
stmts_opt ::= stmts . 
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
testexpr ::= testfalse . 
testfalse ::= expr . jmp_false
testfalse ::= expr jmp_false . 
testtrue ::= expr . jmp_true
try_except ::= SETUP_EXCEPT . suite_stmts_opt POP_BLOCK except_handler \e_opt_come_from_except
try_except ::= SETUP_EXCEPT . suite_stmts_opt POP_BLOCK except_handler jump_excepts come_from_except_clauses
try_except ::= SETUP_EXCEPT . suite_stmts_opt POP_BLOCK except_handler opt_come_from_except
try_except ::= SETUP_EXCEPT \e_suite_stmts_opt . POP_BLOCK except_handler \e_opt_come_from_except
try_except ::= SETUP_EXCEPT \e_suite_stmts_opt . POP_BLOCK except_handler jump_excepts come_from_except_clauses
try_except ::= SETUP_EXCEPT \e_suite_stmts_opt . POP_BLOCK except_handler opt_come_from_except
try_except ::= SETUP_EXCEPT suite_stmts_opt . POP_BLOCK except_handler \e_opt_come_from_except
try_except ::= SETUP_EXCEPT suite_stmts_opt . POP_BLOCK except_handler jump_excepts come_from_except_clauses
try_except ::= SETUP_EXCEPT suite_stmts_opt . POP_BLOCK except_handler opt_come_from_except
try_except36 ::= SETUP_EXCEPT . returns except_handler36 \e_opt_come_from_except
try_except36 ::= SETUP_EXCEPT . returns except_handler36 opt_come_from_except
try_except36 ::= SETUP_EXCEPT . suite_stmts
try_except36 ::= SETUP_EXCEPT . suite_stmts_opt POP_BLOCK except_handler36 \e_opt_come_from_except
try_except36 ::= SETUP_EXCEPT . suite_stmts_opt POP_BLOCK except_handler36 opt_come_from_except
try_except36 ::= SETUP_EXCEPT \e_suite_stmts_opt . POP_BLOCK except_handler36 \e_opt_come_from_except
try_except36 ::= SETUP_EXCEPT \e_suite_stmts_opt . POP_BLOCK except_handler36 opt_come_from_except
try_except36 ::= SETUP_EXCEPT returns . except_handler36 \e_opt_come_from_except
try_except36 ::= SETUP_EXCEPT returns . except_handler36 opt_come_from_except
try_except36 ::= SETUP_EXCEPT returns except_handler36 . opt_come_from_except
try_except36 ::= SETUP_EXCEPT returns except_handler36 \e_opt_come_from_except . 
try_except36 ::= SETUP_EXCEPT returns except_handler36 opt_come_from_except . 
try_except36 ::= SETUP_EXCEPT suite_stmts . 
try_except36 ::= SETUP_EXCEPT suite_stmts_opt . POP_BLOCK except_handler36 \e_opt_come_from_except
try_except36 ::= SETUP_EXCEPT suite_stmts_opt . POP_BLOCK except_handler36 opt_come_from_except
tryelsestmt ::= SETUP_EXCEPT . suite_stmts_opt POP_BLOCK except_handler else_suite jump_excepts come_from_except_clauses
tryelsestmt ::= SETUP_EXCEPT . suite_stmts_opt POP_BLOCK except_handler_else else_suite come_froms
tryelsestmt ::= SETUP_EXCEPT \e_suite_stmts_opt . POP_BLOCK except_handler else_suite jump_excepts come_from_except_clauses
tryelsestmt ::= SETUP_EXCEPT \e_suite_stmts_opt . POP_BLOCK except_handler_else else_suite come_froms
tryelsestmt ::= SETUP_EXCEPT suite_stmts_opt . POP_BLOCK except_handler else_suite jump_excepts come_from_except_clauses
tryelsestmt ::= SETUP_EXCEPT suite_stmts_opt . POP_BLOCK except_handler_else else_suite come_froms
tryelsestmtl3 ::= SETUP_EXCEPT . suite_stmts_opt POP_BLOCK except_handler_else COME_FROM else_suitel \e_opt_come_from_except
tryelsestmtl3 ::= SETUP_EXCEPT . suite_stmts_opt POP_BLOCK except_handler_else COME_FROM else_suitel opt_come_from_except
tryelsestmtl3 ::= SETUP_EXCEPT \e_suite_stmts_opt . POP_BLOCK except_handler_else COME_FROM else_suitel \e_opt_come_from_except
tryelsestmtl3 ::= SETUP_EXCEPT \e_suite_stmts_opt . POP_BLOCK except_handler_else COME_FROM else_suitel opt_come_from_except
tryelsestmtl3 ::= SETUP_EXCEPT suite_stmts_opt . POP_BLOCK except_handler_else COME_FROM else_suitel \e_opt_come_from_except
tryelsestmtl3 ::= SETUP_EXCEPT suite_stmts_opt . POP_BLOCK except_handler_else COME_FROM else_suitel opt_come_from_except
tuple ::= expr . expr expr BUILD_TUPLE_3
tuple ::= expr expr . expr BUILD_TUPLE_3
tuple ::= expr expr expr . BUILD_TUPLE_3
unary_not ::= expr . UNARY_NOT
unary_op ::= expr . unary_operator
with ::= expr . SETUP_WITH POP_TOP \e_suite_stmts_opt COME_FROM_WITH with_suffix
with ::= expr . SETUP_WITH POP_TOP \e_suite_stmts_opt POP_BLOCK BEGIN_FINALLY COME_FROM_WITH with_suffix
with ::= expr . SETUP_WITH POP_TOP \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with ::= expr . SETUP_WITH POP_TOP suite_stmts_opt COME_FROM_WITH with_suffix
with ::= expr . SETUP_WITH POP_TOP suite_stmts_opt POP_BLOCK BEGIN_FINALLY COME_FROM_WITH with_suffix
with ::= expr . SETUP_WITH POP_TOP suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store \e_suite_stmts_opt COME_FROM_WITH with_suffix
with_as ::= expr . SETUP_WITH store \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store suite_stmts_opt COME_FROM_WITH with_suffix
with_as ::= expr . SETUP_WITH store suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
yield ::= expr . YIELD_VALUE
yield_from ::= expr . GET_YIELD_FROM_ITER LOAD_CONST YIELD_FROM
Instruction context:
-> 
 L. 167         0  LOAD_GLOBAL              str
                   2  LOAD_GLOBAL              _get_relative_path
                   4  LOAD_FAST                'path'
                   6  CALL_FUNCTION_1       1  '1 positional argument'
                   8  CALL_FUNCTION_1       1  '1 positional argument'
                  10  STORE_FAST               'full_path'

-- Stacks of completed symbols:
START ::= |- stmts . 
_come_froms ::= \e__come_froms . COME_FROM
_come_froms ::= \e__come_froms COME_FROM . 
_come_froms ::= _come_froms . COME_FROM
_iflaststmts_jump ::= stmts . last_stmt
_ifstmts_jump ::= \e_c_stmts_opt . ELSE
_ifstmts_jump ::= \e_c_stmts_opt . JUMP_ABSOLUTE JUMP_FORWARD COME_FROM
_ifstmts_jump ::= \e_c_stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jump ::= \e_c_stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jump ::= \e_c_stmts_opt . come_froms
_ifstmts_jump ::= \e_stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jump ::= \e_stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jump ::= c_stmts_opt . ELSE
_ifstmts_jump ::= c_stmts_opt . JUMP_ABSOLUTE JUMP_FORWARD COME_FROM
_ifstmts_jump ::= c_stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jump ::= c_stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jump ::= c_stmts_opt . come_froms
_ifstmts_jump ::= c_stmts_opt come_froms . 
_ifstmts_jump ::= stmts . _come_froms
_ifstmts_jump ::= stmts \e__come_froms . 
_ifstmts_jump ::= stmts _come_froms . 
_ifstmts_jump ::= stmts_opt . 
_ifstmts_jump ::= stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jump ::= stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jumpl ::= \e_c_stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jumpl ::= \e_c_stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jumpl ::= \e_c_stmts_opt . come_froms
_ifstmts_jumpl ::= c_stmts . JUMP_BACK
_ifstmts_jumpl ::= c_stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jumpl ::= c_stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jumpl ::= c_stmts_opt . come_froms
_ifstmts_jumpl ::= c_stmts_opt come_froms . 
_stmts ::= _stmts . last_stmt
_stmts ::= _stmts . stmt
_stmts ::= stmt . 
and ::= expr . JUMP_IF_FALSE_OR_POP expr COME_FROM
and ::= expr . jmp_false expr
and ::= expr . jmp_false expr COME_FROM
and ::= expr . jmp_false expr jmp_false
assert ::= assert_expr . jmp_true LOAD_ASSERT RAISE_VARARGS_1 COME_FROM
assert ::= assert_expr jmp_true . LOAD_ASSERT RAISE_VARARGS_1 COME_FROM
assert2 ::= assert_expr . jmp_true LOAD_ASSERT expr CALL_FUNCTION_1 RAISE_VARARGS_1 COME_FROM
assert2 ::= assert_expr jmp_true . LOAD_ASSERT expr CALL_FUNCTION_1 RAISE_VARARGS_1 COME_FROM
assert_expr ::= assert_expr_or . 
assert_expr ::= expr . 
assert_expr_and ::= assert_expr . jmp_false expr
assert_expr_or ::= assert_expr . jmp_true expr
assert_expr_or ::= assert_expr jmp_true . expr
assert_expr_or ::= assert_expr jmp_true expr . 
assign ::= expr . DUP_TOP designList
assign ::= expr . store
assign2 ::= expr . expr ROT_TWO store store
assign2 ::= expr expr . ROT_TWO store store
assign3 ::= expr . expr expr ROT_THREE ROT_TWO store store store
assign3 ::= expr expr . expr ROT_THREE ROT_TWO store store store
assign3 ::= expr expr expr . ROT_THREE ROT_TWO store store store
async_call ::= expr . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg expr CALL_FUNCTION_KW_2 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg expr CALL_FUNCTION_KW_2 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . expr CALL_FUNCTION_KW_2 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg expr . CALL_FUNCTION_KW_2 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg expr CALL_FUNCTION_KW_2 . GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg . expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
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
await_stmt ::= await_expr . POP_TOP
bin_op ::= expr . expr binary_operator
bin_op ::= expr expr . binary_operator
c_stmts ::= _stmts . 
c_stmts ::= _stmts . lastc_stmt
c_stmts_opt ::= c_stmts . 
call ::= expr . CALL_FUNCTION_0
call ::= expr . pos_arg CALL_FUNCTION_1
call ::= expr . pos_arg pos_arg CALL_FUNCTION_2
call ::= expr . pos_arg pos_arg pos_arg CALL_FUNCTION_3
call ::= expr . pos_arg pos_arg pos_arg pos_arg CALL_FUNCTION_4
call ::= expr CALL_FUNCTION_0 . 
call ::= expr pos_arg . CALL_FUNCTION_1
call ::= expr pos_arg . pos_arg CALL_FUNCTION_2
call ::= expr pos_arg . pos_arg pos_arg CALL_FUNCTION_3
call ::= expr pos_arg . pos_arg pos_arg pos_arg CALL_FUNCTION_4
call ::= expr pos_arg CALL_FUNCTION_1 . 
call ::= expr pos_arg pos_arg . CALL_FUNCTION_2
call ::= expr pos_arg pos_arg . pos_arg CALL_FUNCTION_3
call ::= expr pos_arg pos_arg . pos_arg pos_arg CALL_FUNCTION_4
call ::= expr pos_arg pos_arg pos_arg . CALL_FUNCTION_3
call ::= expr pos_arg pos_arg pos_arg . pos_arg CALL_FUNCTION_4
call_kw36 ::= expr . expr expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr . expr expr expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr . expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr . expr expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr . LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr expr . expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr LOAD_CONST . CALL_FUNCTION_KW_2
call_kw36 ::= expr expr expr LOAD_CONST CALL_FUNCTION_KW_2 . 
call_kw36 ::= expr expr expr expr . LOAD_CONST CALL_FUNCTION_KW_3
call_stmt ::= expr . POP_TOP
cf_jf_else ::= come_froms . JUMP_FORWARD ELSE
classdefdeco1 ::= expr . classdefdeco1 CALL_FUNCTION_1
classdefdeco1 ::= expr . classdefdeco2 CALL_FUNCTION_1
come_froms ::= COME_FROM . 
come_froms ::= come_froms . COME_FROM
compare_chained ::= expr . compared_chained_middle ROT_TWO POP_TOP \e__come_froms
compare_chained ::= expr . compared_chained_middle ROT_TWO POP_TOP _come_froms
compare_single ::= expr . expr COMPARE_OP
compare_single ::= expr expr . COMPARE_OP
compared_chained_middle ::= expr . DUP_TOP ROT_THREE COMPARE_OP JUMP_IF_FALSE_OR_POP compare_chained_right COME_FROM
compared_chained_middle ::= expr . DUP_TOP ROT_THREE COMPARE_OP JUMP_IF_FALSE_OR_POP compared_chained_middle COME_FROM
continues ::= _stmts . lastl_stmt continue
dict ::= expr . LOAD_CONST BUILD_CONST_KEY_MAP_1
dict ::= expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_2
dict ::= expr . expr expr LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr . expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr LOAD_CONST . BUILD_CONST_KEY_MAP_1
dict ::= expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_2
dict ::= expr expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr expr . expr expr LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr expr LOAD_CONST . BUILD_CONST_KEY_MAP_2
dict ::= expr expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr expr expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr expr expr LOAD_CONST . BUILD_CONST_KEY_MAP_3
dict ::= expr expr expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_4
expr ::= LOAD_CONST . 
expr ::= LOAD_FAST . 
expr ::= LOAD_GLOBAL . 
expr ::= LOAD_STR . 
expr ::= attribute . 
expr ::= await_expr . 
expr ::= call . 
expr ::= call_kw36 . 
expr ::= or . 
expr_jitop ::= expr . JUMP_IF_TRUE_OR_POP
expr_jt ::= expr . jmp_true
expr_jt ::= expr jmp_true . 
genexpr_func ::= LOAD_FAST . FOR_ITER store comp_iter JUMP_BACK
get_iter ::= expr . GET_ITER
if_exp ::= expr . jmp_false expr jf_cf expr COME_FROM
if_exp ::= expr . jmp_false expr jump_absolute_else expr
if_exp ::= expr . jmp_false expr jump_forward_else expr COME_FROM
if_exp37 ::= expr . expr jf_cfs expr COME_FROM
if_exp37 ::= expr expr . jf_cfs expr COME_FROM
if_exp_lambda ::= expr . jmp_false expr return_if_lambda return_stmt_lambda LAMBDA_MARKER
if_exp_not ::= expr . jmp_true expr jump_forward_else expr COME_FROM
if_exp_not ::= expr jmp_true . expr jump_forward_else expr COME_FROM
if_exp_not ::= expr jmp_true expr . jump_forward_else expr COME_FROM
if_exp_not_lambda ::= expr . jmp_true expr return_if_lambda return_stmt_lambda LAMBDA_MARKER
if_exp_not_lambda ::= expr jmp_true . expr return_if_lambda return_stmt_lambda LAMBDA_MARKER
if_exp_not_lambda ::= expr jmp_true expr . return_if_lambda return_stmt_lambda LAMBDA_MARKER
if_exp_true ::= expr . JUMP_FORWARD expr COME_FROM
ifelsestmt ::= testexpr . c_stmts come_froms else_suite come_froms
ifelsestmt ::= testexpr . c_stmts_opt JUMP_FORWARD else_suite \e__come_froms
ifelsestmt ::= testexpr . c_stmts_opt JUMP_FORWARD else_suite _come_froms
ifelsestmt ::= testexpr . c_stmts_opt cf_jf_else else_suite \e__come_froms
ifelsestmt ::= testexpr . c_stmts_opt cf_jf_else else_suite _come_froms
ifelsestmt ::= testexpr . c_stmts_opt jf_cfs else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr . c_stmts_opt jf_cfs else_suite opt_come_from_except
ifelsestmt ::= testexpr . c_stmts_opt jump_forward_else else_suite \e__come_froms
ifelsestmt ::= testexpr . c_stmts_opt jump_forward_else else_suite _come_froms
ifelsestmt ::= testexpr . stmts_opt JUMP_FORWARD else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr . stmts_opt JUMP_FORWARD else_suite opt_come_from_except
ifelsestmt ::= testexpr . stmts_opt jump_absolute_else else_suite
ifelsestmt ::= testexpr . stmts_opt jump_forward_else else_suite \e__come_froms
ifelsestmt ::= testexpr . stmts_opt jump_forward_else else_suite _come_froms
ifelsestmt ::= testexpr \e_c_stmts_opt . JUMP_FORWARD else_suite \e__come_froms
ifelsestmt ::= testexpr \e_c_stmts_opt . JUMP_FORWARD else_suite _come_froms
ifelsestmt ::= testexpr \e_c_stmts_opt . cf_jf_else else_suite \e__come_froms
ifelsestmt ::= testexpr \e_c_stmts_opt . cf_jf_else else_suite _come_froms
ifelsestmt ::= testexpr \e_c_stmts_opt . jf_cfs else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr \e_c_stmts_opt . jf_cfs else_suite opt_come_from_except
ifelsestmt ::= testexpr \e_c_stmts_opt . jump_forward_else else_suite \e__come_froms
ifelsestmt ::= testexpr \e_c_stmts_opt . jump_forward_else else_suite _come_froms
ifelsestmt ::= testexpr \e_stmts_opt . JUMP_FORWARD else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr \e_stmts_opt . JUMP_FORWARD else_suite opt_come_from_except
ifelsestmt ::= testexpr \e_stmts_opt . jump_absolute_else else_suite
ifelsestmt ::= testexpr \e_stmts_opt . jump_forward_else else_suite \e__come_froms
ifelsestmt ::= testexpr \e_stmts_opt . jump_forward_else else_suite _come_froms
ifelsestmt ::= testexpr c_stmts . come_froms else_suite come_froms
ifelsestmt ::= testexpr c_stmts come_froms . else_suite come_froms
ifelsestmt ::= testexpr c_stmts_opt . JUMP_FORWARD else_suite \e__come_froms
ifelsestmt ::= testexpr c_stmts_opt . JUMP_FORWARD else_suite _come_froms
ifelsestmt ::= testexpr c_stmts_opt . cf_jf_else else_suite \e__come_froms
ifelsestmt ::= testexpr c_stmts_opt . cf_jf_else else_suite _come_froms
ifelsestmt ::= testexpr c_stmts_opt . jf_cfs else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr c_stmts_opt . jf_cfs else_suite opt_come_from_except
ifelsestmt ::= testexpr c_stmts_opt . jump_forward_else else_suite \e__come_froms
ifelsestmt ::= testexpr c_stmts_opt . jump_forward_else else_suite _come_froms
ifelsestmt ::= testexpr stmts_opt . JUMP_FORWARD else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr stmts_opt . JUMP_FORWARD else_suite opt_come_from_except
ifelsestmt ::= testexpr stmts_opt . jump_absolute_else else_suite
ifelsestmt ::= testexpr stmts_opt . jump_forward_else else_suite \e__come_froms
ifelsestmt ::= testexpr stmts_opt . jump_forward_else else_suite _come_froms
ifelsestmtc ::= testexpr . c_stmts_opt JUMP_ABSOLUTE else_suitec
ifelsestmtc ::= testexpr . c_stmts_opt JUMP_FORWARD else_suitec
ifelsestmtc ::= testexpr . c_stmts_opt jump_absolute_else else_suitec
ifelsestmtc ::= testexpr . c_stmts_opt jump_forward_else else_suitec \e__come_froms
ifelsestmtc ::= testexpr . c_stmts_opt jump_forward_else else_suitec _come_froms
ifelsestmtc ::= testexpr \e_c_stmts_opt . JUMP_ABSOLUTE else_suitec
ifelsestmtc ::= testexpr \e_c_stmts_opt . JUMP_FORWARD else_suitec
ifelsestmtc ::= testexpr \e_c_stmts_opt . jump_absolute_else else_suitec
ifelsestmtc ::= testexpr \e_c_stmts_opt . jump_forward_else else_suitec \e__come_froms
ifelsestmtc ::= testexpr \e_c_stmts_opt . jump_forward_else else_suitec _come_froms
ifelsestmtc ::= testexpr c_stmts_opt . JUMP_ABSOLUTE else_suitec
ifelsestmtc ::= testexpr c_stmts_opt . JUMP_FORWARD else_suitec
ifelsestmtc ::= testexpr c_stmts_opt . jump_absolute_else else_suitec
ifelsestmtc ::= testexpr c_stmts_opt . jump_forward_else else_suitec \e__come_froms
ifelsestmtc ::= testexpr c_stmts_opt . jump_forward_else else_suitec _come_froms
ifelsestmtr ::= testexpr . return_if_stmts returns
iflaststmt ::= testexpr . _iflaststmts_jump
iflaststmt ::= testexpr . _ifstmts_jumpl
iflaststmt ::= testexpr . c_stmts_opt JUMP_FORWARD
iflaststmt ::= testexpr . last_stmt JUMP_ABSOLUTE
iflaststmt ::= testexpr . stmts JUMP_ABSOLUTE
iflaststmt ::= testexpr . stmts_opt JUMP_ABSOLUTE
iflaststmt ::= testexpr \e_c_stmts_opt . JUMP_FORWARD
iflaststmt ::= testexpr \e_stmts_opt . JUMP_ABSOLUTE
iflaststmt ::= testexpr _ifstmts_jumpl . 
iflaststmt ::= testexpr c_stmts_opt . JUMP_FORWARD
iflaststmt ::= testexpr stmts . JUMP_ABSOLUTE
iflaststmt ::= testexpr stmts_opt . JUMP_ABSOLUTE
ifstmt ::= testexpr . _ifstmts_jump
ifstmt ::= testexpr \e__ifstmts_jump . 
ifstmt ::= testexpr _ifstmts_jump . 
ifstmtl ::= testexpr . _ifstmts_jumpl
ifstmtl ::= testexpr _ifstmts_jumpl . 
jmp_true ::= POP_JUMP_IF_TRUE . 
lambda_body ::= expr . LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_4
lambda_body ::= expr . expr LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_5
lambda_body ::= expr expr . LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_5
last_stmt ::= iflaststmt . 
mkfunc ::= expr . LOAD_CODE LOAD_STR MAKE_FUNCTION_4
mkfunc ::= expr . expr LOAD_CODE LOAD_STR MAKE_FUNCTION_5
mkfunc ::= expr expr . LOAD_CODE LOAD_STR MAKE_FUNCTION_5
mkfuncdeco ::= expr . mkfuncdeco CALL_FUNCTION_1
mkfuncdeco ::= expr . mkfuncdeco0 CALL_FUNCTION_1
or ::= expr_jt . expr
or ::= expr_jt . expr COME_FROM
or ::= expr_jt expr . 
or ::= expr_jt expr . COME_FROM
pos_arg ::= expr . 
raise_stmt1 ::= expr . RAISE_VARARGS_1
raise_stmt1 ::= expr RAISE_VARARGS_1 . 
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
return_if_stmts ::= _stmts . return_if_stmt \e__come_froms
return_if_stmts ::= _stmts . return_if_stmt _come_froms
returns ::= _stmts . return
returns ::= _stmts . return_if_stmt
returns ::= return . 
sstmt ::= sstmt . RETURN_LAST
sstmt ::= stmt . 
stmt ::= ifstmt . 
stmt ::= ifstmtl . 
stmt ::= raise_stmt1 . 
stmt ::= return . 
stmts ::= last_stmt . 
stmts ::= sstmt . 
stmts ::= stmts . sstmt
stmts_opt ::= _stmts . 
stmts_opt ::= stmts . 
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
testexpr ::= testtrue . 
testfalse ::= expr . jmp_false
testtrue ::= expr . jmp_true
testtrue ::= expr jmp_true . 
tuple ::= expr . expr expr BUILD_TUPLE_3
tuple ::= expr expr . expr BUILD_TUPLE_3
tuple ::= expr expr expr . BUILD_TUPLE_3
unary_not ::= expr . UNARY_NOT
unary_op ::= expr . unary_operator
with ::= expr . SETUP_WITH POP_TOP \e_suite_stmts_opt COME_FROM_WITH with_suffix
with ::= expr . SETUP_WITH POP_TOP \e_suite_stmts_opt POP_BLOCK BEGIN_FINALLY COME_FROM_WITH with_suffix
with ::= expr . SETUP_WITH POP_TOP \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with ::= expr . SETUP_WITH POP_TOP suite_stmts_opt COME_FROM_WITH with_suffix
with ::= expr . SETUP_WITH POP_TOP suite_stmts_opt POP_BLOCK BEGIN_FINALLY COME_FROM_WITH with_suffix
with ::= expr . SETUP_WITH POP_TOP suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store \e_suite_stmts_opt COME_FROM_WITH with_suffix
with_as ::= expr . SETUP_WITH store \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store suite_stmts_opt COME_FROM_WITH with_suffix
with_as ::= expr . SETUP_WITH store suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
yield ::= expr . YIELD_VALUE
yield_from ::= expr . GET_YIELD_FROM_ITER LOAD_CONST YIELD_FROM
Instruction context:
-> 
 L. 213         0  LOAD_GLOBAL              is_file
                   2  LOAD_FAST                'path'
                   4  CALL_FUNCTION_1       1  '1 positional argument'
                   6  GET_AWAITABLE    
                   8  LOAD_CONST               None
                  10  YIELD_FROM       
                  12  POP_JUMP_IF_TRUE     28  'to 28'
import json, os, logging, glob, gzip, shutil
from binascii import hexlify
from pathlib import Path
from typing import List, Optional
import aiofiles
from odin.core.utils.desync import desync
_ROOT_PATH = Path("/home/odin/")
log = logging.getLogger(__name__)

class IsSymlink(Exception):
    return


def _get_relative_path(path: str) -> Path:
    return Path(_ROOT_PATH, Path(path))


async def exists(path: str) -> bool:
    return await desync(_get_relative_path(path).exists)


async def is_mount_point(path: str) -> bool:
    path = str(_get_relative_path(path))
    return await desync(os.path.ismount, path)


async def dir_size(path: str) -> int:
    if not await is_dir(path):
        raise NotADirectoryError("{} is not a directory".format(path))
    return await desync(_dir_size, path)


def _dir_size(path: str) -> int:
    size = 0
    for dirpath, dirnames, filenames in os.walk(path):
        size += sum(Path(os.path.join(dirpath, f)).stat().st_size for f in filenames)

    return size


async def disk_usage(path: str) -> tuple:
    total, used, free = await desync(shutil.disk_usage, path)
    return (total, used, free)


async def file_size(path: str) -> int:
    if not await is_file(path):
        raise FileNotFoundError("{} is not a file".format(path))
    stat = await desync(_get_relative_path(path).stat)
    return stat.st_size


async def gzip_file(path, target_path='', delete_src_file=True):
    return await desync(_gzip_file, path, target_path, delete_src_file)


def _gzip_file(path, target_path='', delete_src_file=True):
    with open(path, "rb") as f_in:
        if not target_path:
            target_path = "{}.gz".format(path)
        with gzip.open(target_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
    if delete_src_file:
        os.remove(path)
    return target_path


async def globpath(path, pattern, recurse=False):
    path = os.path.join(path, pattern)
    if recurse:
        return await desync(_recursive_globpath, path)
    else:
        return await desync(glob.glob, path)


def _recursive_globpath(pattern: str) -> list:
    return glob.glob(pattern, recursive=True)


async def is_dir(path: str) -> bool:
    return await desync(_get_relative_path(path).is_dir)


async def is_file(path: str) -> bool:
    return await desync(_get_relative_path(path).is_file)


async def is_symlink(path: str) -> bool:
    return await desync(_get_relative_path(path).is_symlink)


async def is_gzParse error at or near `LOAD_GLOBAL' instruction at offset 0


async def list_dir(path: str, doesnt_exist_ok: bool=False) -> List[Path]:
    try:
        return await desync(list, _get_relative_path(path).iterdir())
    except FileNotFoundError:
        if doesnt_exist_ok:
            return []
        raise


async def load_jsonParse error at or near `LOAD_GLOBAL' instruction at offset 0


async def mkdir(path, mode=511, parents=False, exist_ok=False):
    await desync(_get_relative_path(path).mkdir, mode, parents, exist_ok)


async def mkdir_odin_tmp() -> str:
    odin_tmp_dir = odin_tmp()
    await mkdir(odin_tmp_dir, parents=True, exist_ok=True)
    return odin_tmp_dir


async def mtime(path: str) -> float:
    return (await desync(os.stat, path)).st_mtime


def odin_tmp() -> str:
    return str(_get_relative_path("tmp"))


async def read_text(path: str, encoding: Optional[str]=None, errors: Optional[str]=None) -> str:
    return await desync(_get_relative_path(path).read_text, encoding, errors)


async def read_file_bytesParse error at or near `LOAD_GLOBAL' instruction at offset 0


async def remove_dir(path: str, recursive: bool=False, doesnt_exist_ok: bool=False):
    full_path = _get_relative_path(path)
    try:
        if recursive:
            await desync(shutil.rmtree, str(full_path))
        else:
            await desync(full_path.rmdir)
    except FileNotFoundError:
        if not doesnt_exist_ok:
            raise


async def remove_file(path: str, doesnt_exist_ok: bool=False, symlink_ok=False):
    if not symlink_ok:
        if await is_symlink(path):
            raise IsSymlink("{} is a symlink".format(path))
    try:
        await desync(_get_relative_path(path).unlink)
    except FileNotFoundError:
        if not doesnt_exist_ok:
            raise


async def remove_real_file(path: str):
    try:
        await remove_file(path, doesnt_exist_ok=True, symlink_ok=False)
    except IsSymlink:
        log.warning("Did not remove symlink: {}".format(path))


def remove_odin_tmp():
    try:
        shutil.rmtree(path=(odin_tmp()), ignore_errors=True)
    except OSError:
        pass


async def rename_file(path: str, target: str):
    await desync(_get_relative_path(path).rename, target)


async def sync():
    await desync(os.sync)


async def touch(path: str, mode=438, exist_ok=True):
    await desync(_get_relative_path(path).touch, mode, exist_ok)


async def write_text(path: str, data: str, encoding: Optional[str]=None, errors: Optional[str]=None):
    return await desync(_get_relative_path(path).write_text, data, encoding, errors)


async def write_json(path: str, obj, **json_dumps_kwargs):
    full_path = str(_get_relative_path(path))
    async with aiofiles.open(full_path, "w") as f:
        await f.write((json.dumps)(obj, **json_dumps_kwargs))
