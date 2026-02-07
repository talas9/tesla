# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/nodes/can.py

-- Stacks of completed symbols:
START ::= |- stmts . 
_come_froms ::= \e__come_froms . COME_FROM
_come_froms ::= \e__come_froms COME_FROM . 
_come_froms ::= _come_froms . COME_FROM
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
_ifstmts_jump ::= c_stmts_opt JUMP_FORWARD . _come_froms
_ifstmts_jump ::= c_stmts_opt JUMP_FORWARD \e__come_froms . 
_ifstmts_jump ::= c_stmts_opt come_froms . 
_ifstmts_jump ::= stmts . _come_froms
_ifstmts_jump ::= stmts \e__come_froms . 
_ifstmts_jump ::= stmts _come_froms . 
_ifstmts_jump ::= stmts_opt . 
_ifstmts_jump ::= stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jump ::= stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jump ::= stmts_opt JUMP_FORWARD . _come_froms
_ifstmts_jump ::= stmts_opt JUMP_FORWARD \e__come_froms . 
_ifstmts_jumpl ::= \e_c_stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jumpl ::= \e_c_stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jumpl ::= \e_c_stmts_opt . come_froms
_ifstmts_jumpl ::= c_stmts . JUMP_BACK
_ifstmts_jumpl ::= c_stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jumpl ::= c_stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jumpl ::= c_stmts_opt . come_froms
_ifstmts_jumpl ::= c_stmts_opt JUMP_FORWARD . _come_froms
_ifstmts_jumpl ::= c_stmts_opt JUMP_FORWARD \e__come_froms . 
_ifstmts_jumpl ::= c_stmts_opt come_froms . 
_stmts ::= _stmts . last_stmt
_stmts ::= _stmts . stmt
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
async_call ::= expr . pos_arg pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
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
call ::= expr . pos_arg pos_arg pos_arg CALL_FUNCTION_3
call ::= expr CALL_FUNCTION_0 . 
call ::= expr pos_arg . CALL_FUNCTION_1
call ::= expr pos_arg . pos_arg pos_arg CALL_FUNCTION_3
call ::= expr pos_arg CALL_FUNCTION_1 . 
call ::= expr pos_arg pos_arg . pos_arg CALL_FUNCTION_3
call ::= expr pos_arg pos_arg pos_arg . CALL_FUNCTION_3
call ::= expr pos_arg pos_arg pos_arg CALL_FUNCTION_3 . 
call_kw36 ::= expr . expr expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr . expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr expr . LOAD_CONST CALL_FUNCTION_KW_2
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
dict_comp ::= LOAD_DICTCOMP . LOAD_STR MAKE_FUNCTION_0 expr GET_ITER CALL_FUNCTION_1
dict_comp ::= LOAD_DICTCOMP LOAD_STR . MAKE_FUNCTION_0 expr GET_ITER CALL_FUNCTION_1
dict_comp ::= LOAD_DICTCOMP LOAD_STR MAKE_FUNCTION_0 . expr GET_ITER CALL_FUNCTION_1
dict_comp ::= LOAD_DICTCOMP LOAD_STR MAKE_FUNCTION_0 expr . GET_ITER CALL_FUNCTION_1
else_suite ::= stmts . 
else_suite ::= suite_stmts . 
else_suitec ::= c_stmts . 
expr ::= LOAD_CONST . 
expr ::= LOAD_FAST . 
expr ::= LOAD_GLOBAL . 
expr ::= attribute . 
expr ::= await_expr . 
expr ::= call . 
expr ::= subscript . 
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
ifelsestmt ::= testexpr c_stmts_opt . JUMP_FORWARD else_suite \e__come_froms
ifelsestmt ::= testexpr c_stmts_opt . JUMP_FORWARD else_suite _come_froms
ifelsestmt ::= testexpr c_stmts_opt . cf_jf_else else_suite \e__come_froms
ifelsestmt ::= testexpr c_stmts_opt . cf_jf_else else_suite _come_froms
ifelsestmt ::= testexpr c_stmts_opt . jf_cfs else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr c_stmts_opt . jf_cfs else_suite opt_come_from_except
ifelsestmt ::= testexpr c_stmts_opt . jump_forward_else else_suite \e__come_froms
ifelsestmt ::= testexpr c_stmts_opt . jump_forward_else else_suite _come_froms
ifelsestmt ::= testexpr c_stmts_opt JUMP_FORWARD . else_suite \e__come_froms
ifelsestmt ::= testexpr c_stmts_opt JUMP_FORWARD . else_suite _come_froms
ifelsestmt ::= testexpr c_stmts_opt jf_cfs . else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr c_stmts_opt jf_cfs . else_suite opt_come_from_except
ifelsestmt ::= testexpr c_stmts_opt jump_forward_else . else_suite \e__come_froms
ifelsestmt ::= testexpr c_stmts_opt jump_forward_else . else_suite _come_froms
ifelsestmt ::= testexpr c_stmts_opt jump_forward_else else_suite . _come_froms
ifelsestmt ::= testexpr c_stmts_opt jump_forward_else else_suite \e__come_froms . 
ifelsestmt ::= testexpr c_stmts_opt jump_forward_else else_suite _come_froms . 
ifelsestmt ::= testexpr stmts_opt . JUMP_FORWARD else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr stmts_opt . JUMP_FORWARD else_suite opt_come_from_except
ifelsestmt ::= testexpr stmts_opt . jump_absolute_else else_suite
ifelsestmt ::= testexpr stmts_opt . jump_forward_else else_suite \e__come_froms
ifelsestmt ::= testexpr stmts_opt . jump_forward_else else_suite _come_froms
ifelsestmt ::= testexpr stmts_opt JUMP_FORWARD . else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr stmts_opt JUMP_FORWARD . else_suite opt_come_from_except
ifelsestmt ::= testexpr stmts_opt jump_forward_else . else_suite \e__come_froms
ifelsestmt ::= testexpr stmts_opt jump_forward_else . else_suite _come_froms
ifelsestmt ::= testexpr stmts_opt jump_forward_else else_suite . _come_froms
ifelsestmt ::= testexpr stmts_opt jump_forward_else else_suite \e__come_froms . 
ifelsestmt ::= testexpr stmts_opt jump_forward_else else_suite _come_froms . 
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
ifelsestmtc ::= testexpr c_stmts_opt JUMP_FORWARD . else_suitec
ifelsestmtc ::= testexpr c_stmts_opt jump_forward_else . else_suitec \e__come_froms
ifelsestmtc ::= testexpr c_stmts_opt jump_forward_else . else_suitec _come_froms
ifelsestmtc ::= testexpr c_stmts_opt jump_forward_else else_suitec . _come_froms
ifelsestmtc ::= testexpr c_stmts_opt jump_forward_else else_suitec \e__come_froms . 
ifelsestmtc ::= testexpr c_stmts_opt jump_forward_else else_suitec _come_froms . 
ifelsestmtr ::= testexpr . return_if_stmts returns
ifstmt ::= testexpr . _ifstmts_jump
ifstmt ::= testexpr \e__ifstmts_jump . 
ifstmt ::= testexpr _ifstmts_jump . 
ifstmtl ::= testexpr . _ifstmts_jumpl
ifstmtl ::= testexpr _ifstmts_jumpl . 
import ::= LOAD_CONST . LOAD_CONST alias
import_from ::= LOAD_CONST . LOAD_CONST IMPORT_NAME importlist POP_TOP
import_from_star ::= LOAD_CONST . LOAD_CONST IMPORT_NAME IMPORT_STAR
importmultiple ::= LOAD_CONST . LOAD_CONST alias imports_cont
jf_cfs ::= JUMP_FORWARD . _come_froms
jf_cfs ::= JUMP_FORWARD \e__come_froms . 
jmp_false ::= POP_JUMP_IF_FALSE . 
jump_forward_else ::= JUMP_FORWARD . ELSE
jump_forward_else ::= JUMP_FORWARD ELSE . 
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
return_expr ::= expr . 
return_expr_lambda ::= return_expr . RETURN_VALUE_LAMBDA
return_expr_lambda ::= return_expr . RETURN_VALUE_LAMBDA LAMBDA_MARKER
return_if_stmt ::= return_expr . RETURN_END_IF
return_if_stmt ::= return_expr . RETURN_END_IF POP_BLOCK
return_if_stmts ::= _stmts . return_if_stmt \e__come_froms
return_if_stmts ::= _stmts . return_if_stmt _come_froms
returns ::= _stmts . return
returns ::= _stmts . return_if_stmt
sstmt ::= sstmt . RETURN_LAST
sstmt ::= stmt . 
stmt ::= assign . 
stmt ::= ifelsestmt . 
stmt ::= ifelsestmtc . 
stmt ::= ifstmt . 
stmt ::= ifstmtl . 
stmts ::= sstmt . 
stmts ::= stmts . sstmt
stmts ::= stmts sstmt . 
stmts_opt ::= _stmts . 
stmts_opt ::= stmts . 
store ::= STORE_FAST . 
store ::= expr . STORE_ATTR
store ::= unpack . 
store_locals ::= LOAD_FAST . STORE_LOCALS
store_subscript ::= expr . expr STORE_SUBSCR
store_subscript ::= expr expr . STORE_SUBSCR
subscript ::= expr . expr BINARY_SUBSCR
subscript ::= expr expr . BINARY_SUBSCR
subscript ::= expr expr BINARY_SUBSCR . 
subscript2 ::= expr . expr DUP_TOP_TWO BINARY_SUBSCR
subscript2 ::= expr expr . DUP_TOP_TWO BINARY_SUBSCR
suite_stmts ::= _stmts . 
testexpr ::= testfalse . 
testfalse ::= expr . jmp_false
testfalse ::= expr jmp_false . 
testtrue ::= expr . jmp_true
tuple ::= expr . expr BUILD_TUPLE_2
tuple ::= expr expr . BUILD_TUPLE_2
unary_not ::= expr . UNARY_NOT
unary_op ::= expr . unary_operator
unpack ::= UNPACK_SEQUENCE_3 . store store store
unpack ::= UNPACK_SEQUENCE_3 store . store store
unpack ::= UNPACK_SEQUENCE_3 store store . store
unpack ::= UNPACK_SEQUENCE_3 store store store . 
with ::= expr . SETUP_WITH POP_TOP \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with ::= expr . SETUP_WITH POP_TOP suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
yield ::= expr . YIELD_VALUE
yield_from ::= expr . GET_YIELD_FROM_ITER LOAD_CONST YIELD_FROM
Instruction context:
-> 
 L.  43         0  LOAD_GLOBAL              asyncio
                   2  LOAD_ATTR                gather
                   4  LOAD_FAST                'self'
                   6  LOAD_ATTR                audience
                   8  CALL_FUNCTION_0       0  '0 positional arguments'
                  10  LOAD_FAST                'self'
                  12  LOAD_ATTR                bus_name
                  14  CALL_FUNCTION_0       0  '0 positional arguments'
                  16  LOAD_FAST                'self'
                  18  LOAD_ATTR                prefix
                  20  CALL_FUNCTION_0       0  '0 positional arguments'
                  22  CALL_FUNCTION_3       3  '3 positional arguments'
                  24  GET_AWAITABLE    
                  26  LOAD_CONST               None
                  28  YIELD_FROM       
                  30  UNPACK_SEQUENCE_3     3 
                  32  STORE_FAST               'audience'
                  34  STORE_FAST               'bus_name'
                  36  STORE_FAST               'prefix'

-- Stacks of completed symbols:
START ::= |- stmts . 
_come_froms ::= \e__come_froms . COME_FROM
_come_froms ::= \e__come_froms COME_FROM . 
_come_froms ::= _come_froms . COME_FROM
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
_ifstmts_jump ::= c_stmts_opt JUMP_FORWARD . _come_froms
_ifstmts_jump ::= c_stmts_opt JUMP_FORWARD \e__come_froms . 
_ifstmts_jump ::= stmts . _come_froms
_ifstmts_jump ::= stmts \e__come_froms . 
_ifstmts_jump ::= stmts_opt . 
_ifstmts_jump ::= stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jump ::= stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jump ::= stmts_opt JUMP_FORWARD . _come_froms
_ifstmts_jump ::= stmts_opt JUMP_FORWARD \e__come_froms . 
_ifstmts_jumpl ::= \e_c_stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jumpl ::= \e_c_stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jumpl ::= \e_c_stmts_opt . come_froms
_ifstmts_jumpl ::= c_stmts . JUMP_BACK
_ifstmts_jumpl ::= c_stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jumpl ::= c_stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jumpl ::= c_stmts_opt . come_froms
_ifstmts_jumpl ::= c_stmts_opt JUMP_FORWARD . _come_froms
_ifstmts_jumpl ::= c_stmts_opt JUMP_FORWARD \e__come_froms . 
_stmts ::= _stmts . last_stmt
_stmts ::= _stmts . stmt
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
async_call ::= expr . pos_arg pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg . expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg expr . CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_3 . GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_for_stmt ::= SETUP_LOOP . expr GET_AITER LOAD_CONST YIELD_FROM SETUP_EXCEPT GET_ANEXT LOAD_CONST YIELD_FROM store POP_BLOCK JUMP_FORWARD COME_FROM_EXCEPT DUP_TOP LOAD_GLOBAL COMPARE_OP POP_JUMP_IF_FALSE POP_TOP POP_TOP POP_TOP POP_EXCEPT POP_BLOCK JUMP_ABSOLUTE END_FINALLY COME_FROM for_block POP_BLOCK COME_FROM_LOOP
async_for_stmt ::= SETUP_LOOP . expr GET_AITER LOAD_CONST YIELD_FROM SETUP_EXCEPT GET_ANEXT LOAD_CONST YIELD_FROM store POP_BLOCK jump_except COME_FROM_EXCEPT DUP_TOP LOAD_GLOBAL COMPARE_OP POP_JUMP_IF_FALSE POP_TOP POP_TOP POP_TOP POP_EXCEPT POP_BLOCK JUMP_ABSOLUTE END_FINALLY JUMP_BACK \e_pass POP_BLOCK JUMP_ABSOLUTE COME_FROM_LOOP
async_for_stmt ::= SETUP_LOOP . expr GET_AITER LOAD_CONST YIELD_FROM SETUP_EXCEPT GET_ANEXT LOAD_CONST YIELD_FROM store POP_BLOCK jump_except COME_FROM_EXCEPT DUP_TOP LOAD_GLOBAL COMPARE_OP POP_JUMP_IF_FALSE POP_TOP POP_TOP POP_TOP POP_EXCEPT POP_BLOCK JUMP_ABSOLUTE END_FINALLY JUMP_BACK pass POP_BLOCK JUMP_ABSOLUTE COME_FROM_LOOP
async_for_stmt ::= SETUP_LOOP expr . GET_AITER LOAD_CONST YIELD_FROM SETUP_EXCEPT GET_ANEXT LOAD_CONST YIELD_FROM store POP_BLOCK JUMP_FORWARD COME_FROM_EXCEPT DUP_TOP LOAD_GLOBAL COMPARE_OP POP_JUMP_IF_FALSE POP_TOP POP_TOP POP_TOP POP_EXCEPT POP_BLOCK JUMP_ABSOLUTE END_FINALLY COME_FROM for_block POP_BLOCK COME_FROM_LOOP
async_for_stmt ::= SETUP_LOOP expr . GET_AITER LOAD_CONST YIELD_FROM SETUP_EXCEPT GET_ANEXT LOAD_CONST YIELD_FROM store POP_BLOCK jump_except COME_FROM_EXCEPT DUP_TOP LOAD_GLOBAL COMPARE_OP POP_JUMP_IF_FALSE POP_TOP POP_TOP POP_TOP POP_EXCEPT POP_BLOCK JUMP_ABSOLUTE END_FINALLY JUMP_BACK \e_pass POP_BLOCK JUMP_ABSOLUTE COME_FROM_LOOP
async_for_stmt ::= SETUP_LOOP expr . GET_AITER LOAD_CONST YIELD_FROM SETUP_EXCEPT GET_ANEXT LOAD_CONST YIELD_FROM store POP_BLOCK jump_except COME_FROM_EXCEPT DUP_TOP LOAD_GLOBAL COMPARE_OP POP_JUMP_IF_FALSE POP_TOP POP_TOP POP_TOP POP_EXCEPT POP_BLOCK JUMP_ABSOLUTE END_FINALLY JUMP_BACK pass POP_BLOCK JUMP_ABSOLUTE COME_FROM_LOOP
async_for_stmt36 ::= SETUP_LOOP . expr GET_AITER LOAD_CONST YIELD_FROM SETUP_EXCEPT GET_ANEXT LOAD_CONST YIELD_FROM store POP_BLOCK JUMP_BACK COME_FROM_EXCEPT DUP_TOP LOAD_GLOBAL COMPARE_OP POP_JUMP_IF_TRUE END_FINALLY for_block COME_FROM POP_TOP POP_TOP POP_TOP POP_EXCEPT POP_TOP POP_BLOCK COME_FROM_LOOP
async_for_stmt36 ::= SETUP_LOOP . expr GET_AITER LOAD_CONST YIELD_FROM SETUP_EXCEPT GET_ANEXT LOAD_CONST YIELD_FROM store POP_BLOCK JUMP_FORWARD COME_FROM_EXCEPT DUP_TOP LOAD_GLOBAL COMPARE_OP POP_JUMP_IF_TRUE END_FINALLY COME_FROM for_block COME_FROM POP_TOP POP_TOP POP_TOP POP_EXCEPT POP_TOP POP_BLOCK COME_FROM_LOOP
async_for_stmt36 ::= SETUP_LOOP expr . GET_AITER LOAD_CONST YIELD_FROM SETUP_EXCEPT GET_ANEXT LOAD_CONST YIELD_FROM store POP_BLOCK JUMP_BACK COME_FROM_EXCEPT DUP_TOP LOAD_GLOBAL COMPARE_OP POP_JUMP_IF_TRUE END_FINALLY for_block COME_FROM POP_TOP POP_TOP POP_TOP POP_EXCEPT POP_TOP POP_BLOCK COME_FROM_LOOP
async_for_stmt36 ::= SETUP_LOOP expr . GET_AITER LOAD_CONST YIELD_FROM SETUP_EXCEPT GET_ANEXT LOAD_CONST YIELD_FROM store POP_BLOCK JUMP_FORWARD COME_FROM_EXCEPT DUP_TOP LOAD_GLOBAL COMPARE_OP POP_JUMP_IF_TRUE END_FINALLY COME_FROM for_block COME_FROM POP_TOP POP_TOP POP_TOP POP_EXCEPT POP_TOP POP_BLOCK COME_FROM_LOOP
async_forelse_stmt ::= SETUP_LOOP . expr GET_AITER LOAD_CONST YIELD_FROM SETUP_EXCEPT GET_ANEXT LOAD_CONST YIELD_FROM store POP_BLOCK JUMP_FORWARD COME_FROM_EXCEPT DUP_TOP LOAD_GLOBAL COMPARE_OP POP_JUMP_IF_FALSE POP_TOP POP_TOP POP_TOP POP_EXCEPT POP_BLOCK JUMP_ABSOLUTE END_FINALLY COME_FROM for_block POP_BLOCK else_suite COME_FROM_LOOP
async_forelse_stmt ::= SETUP_LOOP expr . GET_AITER LOAD_CONST YIELD_FROM SETUP_EXCEPT GET_ANEXT LOAD_CONST YIELD_FROM store POP_BLOCK JUMP_FORWARD COME_FROM_EXCEPT DUP_TOP LOAD_GLOBAL COMPARE_OP POP_JUMP_IF_FALSE POP_TOP POP_TOP POP_TOP POP_EXCEPT POP_BLOCK JUMP_ABSOLUTE END_FINALLY COME_FROM for_block POP_BLOCK else_suite COME_FROM_LOOP
async_forelse_stmt36 ::= SETUP_LOOP . expr GET_AITER LOAD_CONST YIELD_FROM SETUP_EXCEPT GET_ANEXT LOAD_CONST YIELD_FROM store POP_BLOCK JUMP_FORWARD COME_FROM_EXCEPT DUP_TOP LOAD_GLOBAL COMPARE_OP POP_JUMP_IF_TRUE END_FINALLY COME_FROM for_block \e__come_froms POP_TOP POP_TOP POP_TOP POP_EXCEPT POP_TOP POP_BLOCK else_suite COME_FROM_LOOP
async_forelse_stmt36 ::= SETUP_LOOP . expr GET_AITER LOAD_CONST YIELD_FROM SETUP_EXCEPT GET_ANEXT LOAD_CONST YIELD_FROM store POP_BLOCK JUMP_FORWARD COME_FROM_EXCEPT DUP_TOP LOAD_GLOBAL COMPARE_OP POP_JUMP_IF_TRUE END_FINALLY COME_FROM for_block _come_froms POP_TOP POP_TOP POP_TOP POP_EXCEPT POP_TOP POP_BLOCK else_suite COME_FROM_LOOP
async_forelse_stmt36 ::= SETUP_LOOP expr . GET_AITER LOAD_CONST YIELD_FROM SETUP_EXCEPT GET_ANEXT LOAD_CONST YIELD_FROM store POP_BLOCK JUMP_FORWARD COME_FROM_EXCEPT DUP_TOP LOAD_GLOBAL COMPARE_OP POP_JUMP_IF_TRUE END_FINALLY COME_FROM for_block \e__come_froms POP_TOP POP_TOP POP_TOP POP_EXCEPT POP_TOP POP_BLOCK else_suite COME_FROM_LOOP
async_forelse_stmt36 ::= SETUP_LOOP expr . GET_AITER LOAD_CONST YIELD_FROM SETUP_EXCEPT GET_ANEXT LOAD_CONST YIELD_FROM store POP_BLOCK JUMP_FORWARD COME_FROM_EXCEPT DUP_TOP LOAD_GLOBAL COMPARE_OP POP_JUMP_IF_TRUE END_FINALLY COME_FROM for_block _come_froms POP_TOP POP_TOP POP_TOP POP_EXCEPT POP_TOP POP_BLOCK else_suite COME_FROM_LOOP
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
call ::= expr . pos_arg pos_arg pos_arg CALL_FUNCTION_3
call ::= expr . pos_arg pos_arg pos_arg pos_arg CALL_FUNCTION_4
call ::= expr CALL_FUNCTION_0 . 
call ::= expr pos_arg . CALL_FUNCTION_1
call ::= expr pos_arg . pos_arg pos_arg CALL_FUNCTION_3
call ::= expr pos_arg . pos_arg pos_arg pos_arg CALL_FUNCTION_4
call ::= expr pos_arg CALL_FUNCTION_1 . 
call ::= expr pos_arg pos_arg . pos_arg CALL_FUNCTION_3
call ::= expr pos_arg pos_arg . pos_arg pos_arg CALL_FUNCTION_4
call ::= expr pos_arg pos_arg pos_arg . CALL_FUNCTION_3
call ::= expr pos_arg pos_arg pos_arg . pos_arg CALL_FUNCTION_4
call ::= expr pos_arg pos_arg pos_arg pos_arg . CALL_FUNCTION_4
call ::= expr pos_arg pos_arg pos_arg pos_arg CALL_FUNCTION_4 . 
call_kw36 ::= expr . expr expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr . expr expr expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr . expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr . expr expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr . LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr expr . expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr LOAD_CONST . CALL_FUNCTION_KW_2
call_kw36 ::= expr expr expr expr . LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr expr LOAD_CONST . CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr expr LOAD_CONST CALL_FUNCTION_KW_3 . 
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
continues ::= lastl_stmt . continue
dict ::= expr . LOAD_CONST BUILD_CONST_KEY_MAP_1
dict ::= expr LOAD_CONST . BUILD_CONST_KEY_MAP_1
dict_comp ::= LOAD_DICTCOMP . LOAD_STR MAKE_FUNCTION_0 expr GET_ITER CALL_FUNCTION_1
dict_comp ::= LOAD_DICTCOMP LOAD_STR . MAKE_FUNCTION_0 expr GET_ITER CALL_FUNCTION_1
dict_comp ::= LOAD_DICTCOMP LOAD_STR MAKE_FUNCTION_0 . expr GET_ITER CALL_FUNCTION_1
dict_comp ::= LOAD_DICTCOMP LOAD_STR MAKE_FUNCTION_0 expr . GET_ITER CALL_FUNCTION_1
else_suite ::= stmts . 
else_suite ::= suite_stmts . 
else_suitec ::= c_stmts . 
expr ::= LOAD_CONST . 
expr ::= LOAD_FAST . 
expr ::= LOAD_GLOBAL . 
expr ::= LOAD_STR . 
expr ::= attribute . 
expr ::= await_expr . 
expr ::= call . 
expr ::= call_kw36 . 
expr ::= if_exp . 
expr ::= set . 
expr ::= subscript . 
expr_jitop ::= expr . JUMP_IF_TRUE_OR_POP
expr_jt ::= expr . jmp_true
for ::= SETUP_LOOP . expr for_iter store for_block POP_BLOCK COME_FROM_LOOP
for ::= SETUP_LOOP . expr for_iter store for_block POP_BLOCK NOP COME_FROM_LOOP
for ::= SETUP_LOOP expr . for_iter store for_block POP_BLOCK COME_FROM_LOOP
for ::= SETUP_LOOP expr . for_iter store for_block POP_BLOCK NOP COME_FROM_LOOP
forelsestmt ::= SETUP_LOOP . expr for_iter store for_block POP_BLOCK else_suite COME_FROM_LOOP
forelsestmt ::= SETUP_LOOP . expr for_iter store for_block POP_BLOCK else_suite \e__come_froms
forelsestmt ::= SETUP_LOOP . expr for_iter store for_block POP_BLOCK else_suite _come_froms
forelsestmt ::= SETUP_LOOP expr . for_iter store for_block POP_BLOCK else_suite COME_FROM_LOOP
forelsestmt ::= SETUP_LOOP expr . for_iter store for_block POP_BLOCK else_suite \e__come_froms
forelsestmt ::= SETUP_LOOP expr . for_iter store for_block POP_BLOCK else_suite _come_froms
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
if_exp ::= expr jmp_false expr jump_forward_else . expr COME_FROM
if_exp ::= expr jmp_false expr jump_forward_else expr . COME_FROM
if_exp ::= expr jmp_false expr jump_forward_else expr COME_FROM . 
if_exp37 ::= expr . expr jf_cfs expr COME_FROM
if_exp37 ::= expr expr . jf_cfs expr COME_FROM
if_exp_lambda ::= expr . jmp_false expr return_if_lambda return_stmt_lambda LAMBDA_MARKER
if_exp_lambda ::= expr jmp_false . expr return_if_lambda return_stmt_lambda LAMBDA_MARKER
if_exp_lambda ::= expr jmp_false expr . return_if_lambda return_stmt_lambda LAMBDA_MARKER
if_exp_not ::= expr . jmp_true expr jump_forward_else expr COME_FROM
if_exp_not_lambda ::= expr . jmp_true expr return_if_lambda return_stmt_lambda LAMBDA_MARKER
if_exp_true ::= expr . JUMP_FORWARD expr COME_FROM
if_exp_true ::= expr JUMP_FORWARD . expr COME_FROM
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
ifelsestmt ::= testexpr c_stmts_opt . JUMP_FORWARD else_suite \e__come_froms
ifelsestmt ::= testexpr c_stmts_opt . JUMP_FORWARD else_suite _come_froms
ifelsestmt ::= testexpr c_stmts_opt . cf_jf_else else_suite \e__come_froms
ifelsestmt ::= testexpr c_stmts_opt . cf_jf_else else_suite _come_froms
ifelsestmt ::= testexpr c_stmts_opt . jf_cfs else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr c_stmts_opt . jf_cfs else_suite opt_come_from_except
ifelsestmt ::= testexpr c_stmts_opt . jump_forward_else else_suite \e__come_froms
ifelsestmt ::= testexpr c_stmts_opt . jump_forward_else else_suite _come_froms
ifelsestmt ::= testexpr c_stmts_opt JUMP_FORWARD . else_suite \e__come_froms
ifelsestmt ::= testexpr c_stmts_opt JUMP_FORWARD . else_suite _come_froms
ifelsestmt ::= testexpr c_stmts_opt jf_cfs . else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr c_stmts_opt jf_cfs . else_suite opt_come_from_except
ifelsestmt ::= testexpr c_stmts_opt jump_forward_else . else_suite \e__come_froms
ifelsestmt ::= testexpr c_stmts_opt jump_forward_else . else_suite _come_froms
ifelsestmt ::= testexpr c_stmts_opt jump_forward_else else_suite . _come_froms
ifelsestmt ::= testexpr c_stmts_opt jump_forward_else else_suite \e__come_froms . 
ifelsestmt ::= testexpr c_stmts_opt jump_forward_else else_suite _come_froms . 
ifelsestmt ::= testexpr stmts_opt . JUMP_FORWARD else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr stmts_opt . JUMP_FORWARD else_suite opt_come_from_except
ifelsestmt ::= testexpr stmts_opt . jump_absolute_else else_suite
ifelsestmt ::= testexpr stmts_opt . jump_forward_else else_suite \e__come_froms
ifelsestmt ::= testexpr stmts_opt . jump_forward_else else_suite _come_froms
ifelsestmt ::= testexpr stmts_opt JUMP_FORWARD . else_suite \e_opt_come_from_except
ifelsestmt ::= testexpr stmts_opt JUMP_FORWARD . else_suite opt_come_from_except
ifelsestmt ::= testexpr stmts_opt jump_forward_else . else_suite \e__come_froms
ifelsestmt ::= testexpr stmts_opt jump_forward_else . else_suite _come_froms
ifelsestmt ::= testexpr stmts_opt jump_forward_else else_suite . _come_froms
ifelsestmt ::= testexpr stmts_opt jump_forward_else else_suite \e__come_froms . 
ifelsestmt ::= testexpr stmts_opt jump_forward_else else_suite _come_froms . 
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
ifelsestmtc ::= testexpr c_stmts_opt JUMP_FORWARD . else_suitec
ifelsestmtc ::= testexpr c_stmts_opt jump_forward_else . else_suitec \e__come_froms
ifelsestmtc ::= testexpr c_stmts_opt jump_forward_else . else_suitec _come_froms
ifelsestmtc ::= testexpr c_stmts_opt jump_forward_else else_suitec . _come_froms
ifelsestmtc ::= testexpr c_stmts_opt jump_forward_else else_suitec \e__come_froms . 
ifelsestmtc ::= testexpr c_stmts_opt jump_forward_else else_suitec _come_froms . 
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
ifelsestmtr ::= testexpr . return_if_stmts returns
iflaststmtl ::= testexpr . _ifstmts_jumpl
iflaststmtl ::= testexpr . c_stmts_opt
iflaststmtl ::= testexpr . c_stmts_opt JUMP_BACK
iflaststmtl ::= testexpr \e_c_stmts_opt . 
iflaststmtl ::= testexpr \e_c_stmts_opt . JUMP_BACK
ifstmt ::= testexpr . _ifstmts_jump
ifstmt ::= testexpr \e__ifstmts_jump . 
ifstmt ::= testexpr _ifstmts_jump . 
ifstmtl ::= testexpr . _ifstmts_jumpl
ifstmtl ::= testexpr _ifstmts_jumpl . 
import ::= LOAD_CONST . LOAD_CONST alias
import_from ::= LOAD_CONST . LOAD_CONST IMPORT_NAME importlist POP_TOP
import_from_star ::= LOAD_CONST . LOAD_CONST IMPORT_NAME IMPORT_STAR
importmultiple ::= LOAD_CONST . LOAD_CONST alias imports_cont
jf_cf ::= JUMP_FORWARD . COME_FROM
jf_cfs ::= JUMP_FORWARD . _come_froms
jf_cfs ::= JUMP_FORWARD \e__come_froms . 
jmp_false ::= POP_JUMP_IF_FALSE . 
jump_forward_else ::= JUMP_FORWARD . ELSE
jump_forward_else ::= JUMP_FORWARD ELSE . 
l_stmts ::= l_stmts . lstmt
l_stmts ::= lastl_stmt . 
l_stmts ::= lastl_stmt . come_froms l_stmts
l_stmts_opt ::= l_stmts . 
lambda_body ::= expr . LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_4
lastl_stmt ::= iflaststmtl . 
mkfunc ::= expr . LOAD_CODE LOAD_STR MAKE_FUNCTION_4
mkfuncdeco ::= expr . mkfuncdeco CALL_FUNCTION_1
mkfuncdeco ::= expr . mkfuncdeco0 CALL_FUNCTION_1
pos_arg ::= expr . 
ret_and ::= expr . JUMP_IF_FALSE_OR_POP return_expr_or_cond COME_FROM
ret_or ::= expr . JUMP_IF_TRUE_OR_POP return_expr_or_cond COME_FROM
return ::= return_expr . RETURN_END_IF
return ::= return_expr . RETURN_VALUE
return ::= return_expr . RETURN_VALUE COME_FROM
return_expr ::= expr . 
return_expr_lambda ::= return_expr . RETURN_VALUE_LAMBDA
return_expr_lambda ::= return_expr . RETURN_VALUE_LAMBDA LAMBDA_MARKER
return_if_stmt ::= return_expr . RETURN_END_IF
return_if_stmt ::= return_expr . RETURN_END_IF POP_BLOCK
return_if_stmts ::= _stmts . return_if_stmt \e__come_froms
return_if_stmts ::= _stmts . return_if_stmt _come_froms
returns ::= _stmts . return
returns ::= _stmts . return_if_stmt
set ::= expr . BUILD_SET_1
set ::= expr BUILD_SET_1 . 
sstmt ::= sstmt . RETURN_LAST
sstmt ::= stmt . 
stmt ::= assign . 
stmt ::= ifelsestmt . 
stmt ::= ifelsestmtc . 
stmt ::= ifstmt . 
stmt ::= ifstmtl . 
stmts ::= sstmt . 
stmts ::= stmts . sstmt
stmts ::= stmts sstmt . 
stmts_opt ::= _stmts . 
stmts_opt ::= stmts . 
store ::= STORE_FAST . 
store ::= expr . STORE_ATTR
store ::= unpack . 
store_locals ::= LOAD_FAST . STORE_LOCALS
store_subscript ::= expr . expr STORE_SUBSCR
store_subscript ::= expr expr . STORE_SUBSCR
subscript ::= expr . expr BINARY_SUBSCR
subscript ::= expr expr . BINARY_SUBSCR
subscript ::= expr expr BINARY_SUBSCR . 
subscript2 ::= expr . expr DUP_TOP_TWO BINARY_SUBSCR
subscript2 ::= expr expr . DUP_TOP_TWO BINARY_SUBSCR
suite_stmts ::= _stmts . 
testexpr ::= testfalse . 
testfalse ::= expr . jmp_false
testfalse ::= expr jmp_false . 
testtrue ::= expr . jmp_true
tuple ::= expr . expr BUILD_TUPLE_2
tuple ::= expr expr . BUILD_TUPLE_2
unary_not ::= expr . UNARY_NOT
unary_op ::= expr . unary_operator
unpack ::= UNPACK_SEQUENCE_4 . store store store store
unpack ::= UNPACK_SEQUENCE_4 store . store store store
unpack ::= UNPACK_SEQUENCE_4 store store . store store
unpack ::= UNPACK_SEQUENCE_4 store store store . store
unpack ::= UNPACK_SEQUENCE_4 store store store store . 
while1elsestmt ::= SETUP_LOOP . l_stmts JUMP_BACK POP_BLOCK else_suite COME_FROM_LOOP
while1elsestmt ::= SETUP_LOOP . l_stmts JUMP_BACK \e__come_froms POP_BLOCK else_suitel COME_FROM_LOOP
while1elsestmt ::= SETUP_LOOP . l_stmts JUMP_BACK _come_froms POP_BLOCK else_suitel COME_FROM_LOOP
while1elsestmt ::= SETUP_LOOP . l_stmts JUMP_BACK else_suite COME_FROM_LOOP
while1elsestmt ::= SETUP_LOOP . l_stmts JUMP_BACK else_suitel
while1elsestmt ::= SETUP_LOOP l_stmts . JUMP_BACK POP_BLOCK else_suite COME_FROM_LOOP
while1elsestmt ::= SETUP_LOOP l_stmts . JUMP_BACK \e__come_froms POP_BLOCK else_suitel COME_FROM_LOOP
while1elsestmt ::= SETUP_LOOP l_stmts . JUMP_BACK _come_froms POP_BLOCK else_suitel COME_FROM_LOOP
while1elsestmt ::= SETUP_LOOP l_stmts . JUMP_BACK else_suite COME_FROM_LOOP
while1elsestmt ::= SETUP_LOOP l_stmts . JUMP_BACK else_suitel
while1stmt ::= SETUP_LOOP . l_stmts COME_FROM JUMP_BACK COME_FROM_LOOP
while1stmt ::= SETUP_LOOP . l_stmts COME_FROM JUMP_BACK POP_BLOCK COME_FROM_LOOP
while1stmt ::= SETUP_LOOP . l_stmts COME_FROM_LOOP
while1stmt ::= SETUP_LOOP . l_stmts POP_BLOCK COME_FROM_LOOP
while1stmt ::= SETUP_LOOP l_stmts . COME_FROM JUMP_BACK COME_FROM_LOOP
while1stmt ::= SETUP_LOOP l_stmts . COME_FROM JUMP_BACK POP_BLOCK COME_FROM_LOOP
while1stmt ::= SETUP_LOOP l_stmts . COME_FROM_LOOP
while1stmt ::= SETUP_LOOP l_stmts . POP_BLOCK COME_FROM_LOOP
whileTruestmt ::= SETUP_LOOP . l_stmts_opt JUMP_BACK COME_FROM_LOOP
whileTruestmt ::= SETUP_LOOP . l_stmts_opt JUMP_BACK POP_BLOCK COME_FROM_LOOP
whileTruestmt ::= SETUP_LOOP \e_l_stmts_opt . JUMP_BACK COME_FROM_LOOP
whileTruestmt ::= SETUP_LOOP \e_l_stmts_opt . JUMP_BACK POP_BLOCK COME_FROM_LOOP
whileTruestmt ::= SETUP_LOOP l_stmts_opt . JUMP_BACK COME_FROM_LOOP
whileTruestmt ::= SETUP_LOOP l_stmts_opt . JUMP_BACK POP_BLOCK COME_FROM_LOOP
whileelsestmt ::= SETUP_LOOP . testexpr \e_l_stmts_opt JUMP_BACK POP_BLOCK else_suitel COME_FROM
whileelsestmt ::= SETUP_LOOP . testexpr \e_l_stmts_opt jb_cfs POP_BLOCK else_suitel COME_FROM_LOOP
whileelsestmt ::= SETUP_LOOP . testexpr l_stmts_opt JUMP_BACK POP_BLOCK else_suitel COME_FROM
whileelsestmt ::= SETUP_LOOP . testexpr l_stmts_opt jb_cfs POP_BLOCK else_suitel COME_FROM_LOOP
whileelsestmt ::= SETUP_LOOP testexpr . l_stmts_opt JUMP_BACK POP_BLOCK else_suitel COME_FROM
whileelsestmt ::= SETUP_LOOP testexpr . l_stmts_opt jb_cfs POP_BLOCK else_suitel COME_FROM_LOOP
whileelsestmt ::= SETUP_LOOP testexpr \e_l_stmts_opt . JUMP_BACK POP_BLOCK else_suitel COME_FROM
whileelsestmt ::= SETUP_LOOP testexpr \e_l_stmts_opt . jb_cfs POP_BLOCK else_suitel COME_FROM_LOOP
whileelsestmt2 ::= SETUP_LOOP . testexpr \e_l_stmts_opt JUMP_BACK POP_BLOCK else_suitel JUMP_BACK COME_FROM_LOOP
whileelsestmt2 ::= SETUP_LOOP . testexpr l_stmts_opt JUMP_BACK POP_BLOCK else_suitel JUMP_BACK COME_FROM_LOOP
whileelsestmt2 ::= SETUP_LOOP testexpr . l_stmts_opt JUMP_BACK POP_BLOCK else_suitel JUMP_BACK COME_FROM_LOOP
whileelsestmt2 ::= SETUP_LOOP testexpr \e_l_stmts_opt . JUMP_BACK POP_BLOCK else_suitel JUMP_BACK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP . testexpr \e_l_stmts_opt COME_FROM JUMP_BACK POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP . testexpr \e_l_stmts_opt JUMP_BACK POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP . testexpr \e_l_stmts_opt JUMP_BACK POP_BLOCK JUMP_BACK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP . testexpr \e_l_stmts_opt JUMP_BACK come_froms POP_BLOCK
whilestmt ::= SETUP_LOOP . testexpr \e_l_stmts_opt JUMP_BACK come_froms POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP . testexpr \e_l_stmts_opt come_froms JUMP_BACK come_froms POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP . testexpr l_stmts_opt COME_FROM JUMP_BACK POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP . testexpr l_stmts_opt JUMP_BACK POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP . testexpr l_stmts_opt JUMP_BACK POP_BLOCK JUMP_BACK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP . testexpr l_stmts_opt JUMP_BACK come_froms POP_BLOCK
whilestmt ::= SETUP_LOOP . testexpr l_stmts_opt JUMP_BACK come_froms POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP . testexpr l_stmts_opt come_froms JUMP_BACK come_froms POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP . testexpr returns POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP . testexpr returns come_froms POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr . l_stmts_opt COME_FROM JUMP_BACK POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr . l_stmts_opt JUMP_BACK POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr . l_stmts_opt JUMP_BACK POP_BLOCK JUMP_BACK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr . l_stmts_opt JUMP_BACK come_froms POP_BLOCK
whilestmt ::= SETUP_LOOP testexpr . l_stmts_opt JUMP_BACK come_froms POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr . l_stmts_opt come_froms JUMP_BACK come_froms POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr . returns POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr . returns come_froms POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr \e_l_stmts_opt . COME_FROM JUMP_BACK POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr \e_l_stmts_opt . JUMP_BACK POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr \e_l_stmts_opt . JUMP_BACK POP_BLOCK JUMP_BACK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr \e_l_stmts_opt . JUMP_BACK come_froms POP_BLOCK
whilestmt ::= SETUP_LOOP testexpr \e_l_stmts_opt . JUMP_BACK come_froms POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr \e_l_stmts_opt . come_froms JUMP_BACK come_froms POP_BLOCK COME_FROM_LOOP
with ::= expr . SETUP_WITH POP_TOP \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with ::= expr . SETUP_WITH POP_TOP suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
yield ::= expr . YIELD_VALUE
yield_from ::= expr . GET_YIELD_FROM_ITER LOAD_CONST YIELD_FROM
Instruction context:
-> 
 L.  88         0  LOAD_GLOBAL              asyncio
                   2  LOAD_ATTR                gather
                   4  LOAD_FAST                'self'
                   6  LOAD_ATTR                audience
                   8  CALL_FUNCTION_0       0  '0 positional arguments'
                  10  LOAD_FAST                'self'
                  12  LOAD_ATTR                bus_name
                  14  CALL_FUNCTION_0       0  '0 positional arguments'
                  16  LOAD_FAST                'self'
                  18  LOAD_ATTR                prefix
                  20  CALL_FUNCTION_0       0  '0 positional arguments'
                  22  LOAD_FAST                'self'
                  24  LOAD_ATTR                whitelist
                  26  CALL_FUNCTION_0       0  '0 positional arguments'
                  28  CALL_FUNCTION_4       4  '4 positional arguments'
                  30  GET_AWAITABLE    
                  32  LOAD_CONST               None
                  34  YIELD_FROM       
                  36  UNPACK_SEQUENCE_4     4 
                  38  STORE_FAST               'audience'
                  40  STORE_FAST               'bus_name'
                  42  STORE_FAST               'prefix'
                  44  STORE_FAST               'whitelist'
import asyncio, logging, operator
from typing import Any, Dict, Optional
from architect.core.node import Node
from architect.core.ops.input import Input
from architect.core.ops.output import Output, output
from architect.core.ops.signal import Signal
from architect.core.ops.slot import slot
from odin.core import can, cid
log = logging.getLogger(__name__)
BUS_ENUM_FUNC = lambda: [

class ActiveAlerts(Node):
    audience = Input("List")
    prefix = Input("String")
    bus_name = Input("String", enum_func=BUS_ENUM_FUNC)

    @output("Dict")
    async def alertsParse error at or near `LOAD_GLOBAL' instruction at offset 0


class MonitorAlerts(Node):
    audience = Input("List")
    prefix = Input("String")
    bus_name = Input("String", enum_func=BUS_ENUM_FUNC)
    whitelist = Input("List", default=[])
    enabled = Input("Bool", default=True)
    alerts = Output
    triggered = Signal

    @slot
    async def monitorParse error at or near `LOAD_GLOBAL' instruction at offset 0


class BytesToInt(Node):
    bytes = Input("Bytes")

    @output("Int")
    async def integer(self):
        _bytes = await self.bytes
        return int(_bytes.hex, 16)


class CANMessageRead(Node):
    message_name = Input("String")
    bus_name = Input("String", enum_func=BUS_ENUM_FUNC)

    @output
    async def values(self):
        message_name, bus_name = await asyncio.gather(self.message_name, self.bus_name)
        bus = can.Bus[bus_name] if bus_name else None
        message_info, bus = can.message.find(message_name, bus=bus)
        return await can.message.read(message_info, bus)


class CANSignalRead(Node):
    signal_name = Input("String")
    bus_name = Input("String", enum_func=BUS_ENUM_FUNC)

    @output
    async def value(self):
        signal_name, bus_name = await asyncio.gather(self.signal_name, self.bus_name)
        bus = can.Bus[bus_name] if bus_name else None
        _, bus = can.signal.find(signal_name, bus=bus)
        bus_name = bus.name
        return await can.signal.read_by_name(signal_name, bus_name)


class CANMessageMonitor(Node):
    message_name = Input("String")
    bus_name = Input("String", enum_func=BUS_ENUM_FUNC)
    timeout = Input("Float", default=0)
    enabled = Input("Bool", default=True)
    current = Output
    values = Output("List")
    value_changed = Signal
    timed_out = Signal
    done = Signal

    def _init(self):
        return

    @slot
    async def start(self):
        message_name, bus_name = await asyncio.gather(self.message_name, self.bus_name)
        bus = can.Bus[bus_name] if bus_name else None
        message_info, bus = can.message.find(message_name, bus=bus)
        bus_name = bus.name
        async with can.message.monitor(message_info, bus) as session_id:
            try:
                try:
                    await asyncio.wait_for((self.monitor_message(message_name, bus_name, message_info, bus, session_id)), timeout=(await self.timeout))
                except asyncio.TimeoutError:
                    await self.timed_out

            finally:
                self._init

        await self.done

    async def monitor_message(self, message_name: str, bus_name: str, message_info: Dict, bus: can.Bus, session_id: Optional[int]):
        last_value = None
        seen_values = []
        while await self.enabled:
            try:
                value = await can.message.read(message_info, bus, session_id=session_id)
            except asyncio.TimeoutError:
                log.info("Timeout reading CAN message {}:{}".format(bus_name, message_name))
            else:
                self.current.value = value
            if value != last_value:
                last_value = value
                seen_values.append(value)
                self.values.value = seen_values
                await self.value_changed


class CANSignalMonitor(Node):
    signal_name = Input("String")
    bus_name = Input("String", enum_func=BUS_ENUM_FUNC)
    timeout = Input("Float", default=0)
    enabled = Input("Bool", default=True)
    current = Output
    values = Output("List")
    value_changed = Signal
    timed_out = Signal
    done = Signal

    def _init(self):
        return

    @slot
    async def start(self):
        signal_name, bus_name = await asyncio.gather(self.signal_name, self.bus_name)
        bus = can.Bus[bus_name] if bus_name else None
        signal, bus = can.signal.find(signal_name, bus=bus)
        bus_name = bus.name
        async with can.signal.monitor(signal, bus) as session_id:
            try:
                try:
                    await asyncio.wait_for((self.monitor_signal(signal_name, bus_name, signal, bus, session_id)), timeout=(await self.timeout))
                except asyncio.TimeoutError:
                    await self.timed_out

            finally:
                self._init

        await self.done

    async def monitor_signal(self, signal_name: str, bus_name: str, signal: Dict, bus: can.Bus, session_id: Optional[int]):
        from odin.config import options
        from odin.platforms import get_gateway_interface
        read_from_cid = options["core"]["read_can_from_cid"] and get_gateway_interface == "Gen3"
        last_value = None
        seen_values = []
        while await self.enabled:
            try:
                if read_from_cid:
                    value = await can.signal.read_from_cid_simplified(signal_name, signal)
                else:
                    value = await can.signal.read(signal, bus, session_id=session_id)
            except asyncio.TimeoutError:
                log.info("Timeout reading CAN signal {}:{}".format(bus_name, signal_name))
            else:
                self.current.value = value
            if value != last_value:
                last_value = value
                seen_values.append(value)
                self.values.value = seen_values
                await self.value_changed


class CANSignalValueComparison(Node):
    signal_name = Input("String")
    bus_name = Input("String", enum_func=BUS_ENUM_FUNC)
    timeout = Input("Float", default=0)
    comparator = Input("Int", default=0, enum=[
     (0, '=='), 
     (1, '!='), 
     (2, '>'), 
     (3, '<'), 
     (4, '>='), 
     (5, '<=')])
    target = Input
    current = Output
    true = Signal
    false = Signal

    @slot
    async def start(self):
        signal_name, bus_name = await asyncio.gather(self.signal_name, self.bus_name)
        timeout = await self.timeout
        bus = can.Bus[bus_name] if bus_name else None
        signal, bus = can.signal.find(signal_name, bus=bus)
        bus_name = bus.name
        async with can.signal.monitor(signal, bus) as session_id:
            try:
                if timeout:
                    result = await asyncio.wait_for(self.evaluate_signal(signal_name, bus_name, signal, bus, session_id, loop=True),
                      timeout=timeout)
                else:
                    result = await self.evaluate_signal(signal_name, bus_name, signal, bus, session_id, loop=False)
            except asyncio.TimeoutError:
                await self.false
            else:
                if result:
                    await self.true
                else:
                    await self.false

    async def evaluate_signal(self, signal_name: str, bus_name: str, signal: Dict, bus: can.Bus, session_id: Optional[int], loop: bool):
        from odin.config import options
        from odin.platforms import get_gateway_interface
        operators = {0:operator.eq, 
         1:operator.ne, 
         2:operator.gt, 
         3:operator.lt, 
         4:operator.ge, 
         5:operator.le}
        comparator, target = await asyncio.gather(self.comparator, self.target)
        comparator = operators[comparator]
        read_from_cid = options["core"]["read_can_from_cid"] and get_gateway_interface == "Gen3"
        last_value = None
        while 1:
            try:
                if read_from_cid:
                    value = await can.signal.read_from_cid_simplified(signal_name, signal)
                else:
                    value = await can.signal.read(signal, bus, session_id=session_id)
                log.debug("CAN signal value comparison value: {}".format(value))
            except RuntimeError:
                log.exception("No data read.")
            except asyncio.TimeoutError:
                log.info("Timeout reading CAN signal {}:{}".format(bus_name, signal_name))
            else:
                self.current.value = value
                if value != last_value:
                    last_value = value
                    self.current.value = value
                    if comparator(value, target):
                        return True
                    elif not loop:
                        break

        return False
