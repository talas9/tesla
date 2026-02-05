# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/can/message.py

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
async_call ::= expr . pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_5 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_5 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_5 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg . expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg . pos_arg pos_arg expr CALL_FUNCTION_KW_5 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg expr . CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_3 . GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg pos_arg . pos_arg expr CALL_FUNCTION_KW_5 GET_AWAITABLE LOAD_CONST YIELD_FROM
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
call ::= expr CALL_FUNCTION_0 . 
call ::= expr pos_arg . CALL_FUNCTION_1
call ::= expr pos_arg . pos_arg CALL_FUNCTION_2
call ::= expr pos_arg CALL_FUNCTION_1 . 
call ::= expr pos_arg pos_arg . CALL_FUNCTION_2
call_kw36 ::= expr . expr expr expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr . expr expr expr expr expr LOAD_CONST CALL_FUNCTION_KW_5
call_kw36 ::= expr expr . expr expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr . expr expr expr expr LOAD_CONST CALL_FUNCTION_KW_5
call_kw36 ::= expr expr expr . expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr . expr expr expr LOAD_CONST CALL_FUNCTION_KW_5
call_kw36 ::= expr expr expr expr . LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr expr . expr expr LOAD_CONST CALL_FUNCTION_KW_5
call_kw36 ::= expr expr expr expr LOAD_CONST . CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr expr LOAD_CONST CALL_FUNCTION_KW_3 . 
call_kw36 ::= expr expr expr expr expr . expr LOAD_CONST CALL_FUNCTION_KW_5
call_stmt ::= expr . POP_TOP
cf_jf_else ::= come_froms . JUMP_FORWARD ELSE
cf_jump_back ::= COME_FROM . JUMP_BACK
classdefdeco1 ::= expr . classdefdeco1 CALL_FUNCTION_1
classdefdeco1 ::= expr . classdefdeco2 CALL_FUNCTION_1
come_from_opt ::= COME_FROM . 
come_froms ::= COME_FROM . 
come_froms ::= come_froms . COME_FROM
compare ::= compare_single . 
compare_chained ::= expr . compared_chained_middle ROT_TWO POP_TOP \e__come_froms
compare_chained ::= expr . compared_chained_middle ROT_TWO POP_TOP _come_froms
compare_single ::= expr . expr COMPARE_OP
compare_single ::= expr expr . COMPARE_OP
compare_single ::= expr expr COMPARE_OP . 
compared_chained_middle ::= expr . DUP_TOP ROT_THREE COMPARE_OP JUMP_IF_FALSE_OR_POP compare_chained_right COME_FROM
compared_chained_middle ::= expr . DUP_TOP ROT_THREE COMPARE_OP JUMP_IF_FALSE_OR_POP compared_chained_middle COME_FROM
continues ::= _stmts . lastl_stmt continue
continues ::= lastl_stmt . continue
dict ::= expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_2
dict ::= expr . expr expr LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr . expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr . expr expr expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_6
dict ::= expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_2
dict ::= expr expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr expr . expr expr LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr expr . expr expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_6
dict ::= expr expr LOAD_CONST . BUILD_CONST_KEY_MAP_2
dict ::= expr expr LOAD_CONST BUILD_CONST_KEY_MAP_2 . 
dict ::= expr expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr expr expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr expr expr . expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_6
dict ::= expr expr expr LOAD_CONST . BUILD_CONST_KEY_MAP_3
dict ::= expr expr expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr expr expr expr . expr expr LOAD_CONST BUILD_CONST_KEY_MAP_6
dict ::= expr expr expr expr LOAD_CONST . BUILD_CONST_KEY_MAP_4
dict ::= expr expr expr expr expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_6
dict_comp ::= load_closure . LOAD_DICTCOMP LOAD_STR MAKE_FUNCTION_CLOSURE expr GET_ITER CALL_FUNCTION_1
else_suite ::= stmts . 
else_suite ::= suite_stmts . 
expr ::= LOAD_CONST . 
expr ::= LOAD_DEREF . 
expr ::= LOAD_FAST . 
expr ::= LOAD_GLOBAL . 
expr ::= LOAD_STR . 
expr ::= attribute . 
expr ::= await_expr . 
expr ::= call . 
expr ::= call_kw36 . 
expr ::= compare . 
expr ::= dict . 
expr ::= if_exp . 
expr ::= subscript . 
expr ::= tuple . 
expr_jitop ::= expr . JUMP_IF_TRUE_OR_POP
expr_jt ::= expr . jmp_true
function_def ::= mkfunc . store
function_def ::= mkfunc store . 
generator_exp ::= load_closure . load_genexpr LOAD_STR MAKE_FUNCTION_0 expr GET_ITER CALL_FUNCTION_1
generator_exp ::= load_closure . load_genexpr LOAD_STR MAKE_FUNCTION_CLOSURE expr GET_ITER CALL_FUNCTION_1
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
ifelsestmt ::= testexpr c_stmts come_froms . else_suite come_froms
ifelsestmt ::= testexpr c_stmts come_froms else_suite . come_froms
ifelsestmt ::= testexpr c_stmts come_froms else_suite come_froms . 
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
import ::= LOAD_CONST . LOAD_CONST alias
import_from ::= LOAD_CONST . LOAD_CONST IMPORT_NAME importlist POP_TOP
import_from_star ::= LOAD_CONST . LOAD_CONST IMPORT_NAME IMPORT_STAR
importmultiple ::= LOAD_CONST . LOAD_CONST alias imports_cont
jf_cf ::= JUMP_FORWARD . COME_FROM
jmp_false ::= POP_JUMP_IF_FALSE . 
jump_forward_else ::= JUMP_FORWARD . ELSE
jump_forward_else ::= JUMP_FORWARD ELSE . 
lambda_body ::= expr . LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_4
lambda_body ::= expr . expr LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_5
lambda_body ::= expr . expr load_closure BUILD_TUPLE_1 LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_13
lambda_body ::= expr expr . LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_5
lambda_body ::= expr expr . load_closure BUILD_TUPLE_1 LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_13
lambda_body ::= expr expr load_closure . BUILD_TUPLE_1 LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_13
lambda_body ::= load_closure . LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_CLOSURE
last_stmt ::= iflaststmt . 
lastl_stmt ::= iflaststmtl . 
list_comp ::= load_closure . LOAD_LISTCOMP LOAD_STR MAKE_FUNCTION_0 expr GET_ITER CALL_FUNCTION_1
load_closure ::= LOAD_CLOSURE . 
load_closure ::= LOAD_CLOSURE . BUILD_TUPLE_1
load_closure ::= LOAD_CLOSURE . LOAD_CLOSURE LOAD_CLOSURE LOAD_CLOSURE BUILD_TUPLE_4
load_closure ::= LOAD_CLOSURE LOAD_CLOSURE . LOAD_CLOSURE LOAD_CLOSURE BUILD_TUPLE_4
load_closure ::= LOAD_CLOSURE LOAD_CLOSURE LOAD_CLOSURE . LOAD_CLOSURE BUILD_TUPLE_4
load_closure ::= LOAD_CLOSURE LOAD_CLOSURE LOAD_CLOSURE LOAD_CLOSURE . BUILD_TUPLE_4
load_closure ::= LOAD_CLOSURE LOAD_CLOSURE LOAD_CLOSURE LOAD_CLOSURE BUILD_TUPLE_4 . 
load_closure ::= load_closure . LOAD_CLOSURE
load_closure ::= load_closure LOAD_CLOSURE . 
mkfunc ::= expr . LOAD_CODE LOAD_STR MAKE_FUNCTION_4
mkfunc ::= expr . expr LOAD_CODE LOAD_STR MAKE_FUNCTION_5
mkfunc ::= expr . expr load_closure LOAD_CODE LOAD_STR MAKE_FUNCTION_13
mkfunc ::= expr expr . LOAD_CODE LOAD_STR MAKE_FUNCTION_5
mkfunc ::= expr expr . load_closure LOAD_CODE LOAD_STR MAKE_FUNCTION_13
mkfunc ::= expr expr load_closure . LOAD_CODE LOAD_STR MAKE_FUNCTION_13
mkfunc ::= expr expr load_closure LOAD_CODE . LOAD_STR MAKE_FUNCTION_13
mkfunc ::= expr expr load_closure LOAD_CODE LOAD_STR . MAKE_FUNCTION_13
mkfunc ::= expr expr load_closure LOAD_CODE LOAD_STR MAKE_FUNCTION_13 . 
mkfunc ::= load_closure . LOAD_CODE LOAD_STR MAKE_FUNCTION_CLOSURE
mkfunc ::= load_closure LOAD_CODE . LOAD_STR MAKE_FUNCTION_CLOSURE
mkfunc ::= load_closure LOAD_CODE LOAD_STR . MAKE_FUNCTION_CLOSURE
mkfuncdeco ::= expr . mkfuncdeco CALL_FUNCTION_1
mkfuncdeco ::= expr . mkfuncdeco0 CALL_FUNCTION_1
pos_arg ::= expr . 
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
returns ::= return . 
sstmt ::= return . RETURN_LAST
sstmt ::= sstmt . RETURN_LAST
sstmt ::= stmt . 
stmt ::= assign . 
stmt ::= function_def . 
stmt ::= ifelsestmt . 
stmt ::= ifstmt . 
stmt ::= ifstmtl . 
stmt ::= return . 
stmts ::= last_stmt . 
stmts ::= sstmt . 
stmts ::= stmts . sstmt
stmts ::= stmts sstmt . 
stmts_opt ::= _stmts . 
stmts_opt ::= stmts . 
store ::= STORE_DEREF . 
store ::= STORE_FAST . 
store ::= expr . STORE_ATTR
store_locals ::= LOAD_FAST . STORE_LOCALS
store_subscript ::= expr . expr STORE_SUBSCR
store_subscript ::= expr expr . STORE_SUBSCR
subscript ::= expr . expr BINARY_SUBSCR
subscript ::= expr expr . BINARY_SUBSCR
subscript ::= expr expr BINARY_SUBSCR . 
subscript2 ::= expr . expr DUP_TOP_TWO BINARY_SUBSCR
subscript2 ::= expr expr . DUP_TOP_TWO BINARY_SUBSCR
suite_stmts ::= _stmts . 
suite_stmts ::= returns . 
suite_stmts_opt ::= suite_stmts . 
testexpr ::= testfalse . 
testfalse ::= expr . jmp_false
testfalse ::= expr jmp_false . 
testtrue ::= expr . jmp_true
tuple ::= expr . expr BUILD_TUPLE_2
tuple ::= expr expr . BUILD_TUPLE_2
tuple ::= expr expr BUILD_TUPLE_2 . 
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
 L. 117         0  LOAD_CONST               (None,)
                   2  LOAD_GLOBAL              Optional
                   4  LOAD_GLOBAL              int
                   6  BINARY_SUBSCR    
                   8  LOAD_GLOBAL              Dict
                  10  LOAD_GLOBAL              str
                  12  LOAD_GLOBAL              signal
                  14  LOAD_ATTR                CanSignalValue
                  16  BUILD_TUPLE_2         2 
                  18  BINARY_SUBSCR    
                  20  LOAD_CONST               ('uid', 'return')
                  22  BUILD_CONST_KEY_MAP_2     2 
                  24  LOAD_CLOSURE             'bus'
                  26  LOAD_CLOSURE             'is_uds_message'
                  28  LOAD_CLOSURE             'message'
                  30  LOAD_CLOSURE             'timeout'
                  32  BUILD_TUPLE_4         4 
                  34  LOAD_CODE                <code_object _read_wrapper>
                  36  LOAD_STR                 'read.<locals>._read_wrapper'
                  38  MAKE_FUNCTION_13         'default, annotation, closure'
                  40  STORE_FAST               '_read_wrapper'
import asyncio, asyncio_extras, logging, re
from typing import Any, AsyncGenerator, Dict, Generator, Optional, Set, Tuple
from odin.core import can
from odin.platforms import get_gateway_interface
from . import signal
from . import utils
from .. import gateway
log = logging.getLogger(__name__)

def decode(message: Dict, data: bytes) -> Dict[(str, signal.CanSignalValue)]:
    return {signal_name: signal.decode(sig, data) for signal_name, sig in message["signals"].items() if not sig.get("not_in_whitelist", False)}


def find(message_name: str, bus: can.Bus=None) -> Tuple[(Dict, can.Bus)]:
    try:
        message = can.library.messages[message_name]
    except KeyError:
        raise RuntimeError("could not find message {0}".format(message_name))

    if bus is not None:
        try:
            info = (
             message[bus.name.lower()], bus)
            utils.whitelist_check(message_name, info)
            return info
        except KeyError:
            raise RuntimeError("could not find bus {0} for message {1}".format(bus.name, message_name))

    else:
        bus = utils.best_bus(message)
        if bus is None:
            raise RuntimeError("could not find info for message {}".format(message_name))
        else:
            info = (
             message[bus.name.lower()], bus)
            utils.whitelist_check(message_name, info)
            return info


@asyncio_extras.async_contextmanager
async def monitor(message: Dict, bus: can.Bus, is_uds_message: bool=False) -> AsyncGenerator[(int, None)]:
    slots = max(1, len(multiplexer_values(message))) if message.get("muxer") else 1
    if not gateway.interface.uds_over_tcp():
        async with gateway.interface.ensure_connections():
            session_id = await gateway.interface.monitor_message(bus, (message["message_id"]), is_uds_message=is_uds_message,
              slots=slots,
              enabled=True)
            try:
                yield session_id
            finally:
                await gateway.interface.monitor_message(bus, (message["message_id"]), enabled=False)

    else:
        session_id = await gateway.interface.monitor_message(bus, (message["message_id"]), is_uds_message=is_uds_message,
          slots=slots,
          enabled=True)
        try:
            yield session_id
        finally:
            await gateway.interface.monitor_message(bus, (message["message_id"]), enabled=False)


def multiplexer_values(message: Dict) -> Set[int]:
    muxer_name = message.get("muxer")
    muxer = message.get("signals", {}).get(muxer_name)
    if isinstance(muxer, dict):
        if muxer.get("mux_ids"):
            return set(muxer.get("mux_ids"))
    signals = message.get("signals")
    return set([sig.get("mux_id") for sig in signals.values() if isinstance(sig.get("mux_id"), int)])


async def readParse error at or near `LOAD_CONST' instruction at offset 0


async def read_multiplexed(message_info: Dict, muxer: str, bus: can.Bus) -> Dict[(str, signal.CanSignalValue)]:
    signals = message_info.get("signals")
    mux_values = multiplexer_values(message_info)
    cycle_time = (message_info["cycle_time"] or signal.DEFAULT_CYCLE_TIME) / 1000.0
    max_message_delay = cycle_time * 2
    final_timeout = max(1, len(mux_values)) * cycle_time * 2
    if get_gateway_interface() == "Gen2":
        max_message_delay += signal.GEN2_UDP_SLOTTED_PERIOD
        final_timeout += signal.GEN2_UDP_SLOTTED_PERIOD
    value_buffer = {}

    async def read_until_all_matched():
        while len(mux_values):
            data = await gateway.interface.read_message(bus, (message_info["message_id"]), timeout=max_message_delay)
            if not data:
                raise RuntimeError("no data found for 0x{:x} bus: {}".format(message_info["message_id"], bus.name))
            message_values = decode(message_info, data)
            active_mux_id = utils.get_active_mux_id(message_values, message_info, muxer)
            mux_values.discard(active_mux_id)
            value_buffer.update({name: value for name, value in message_values.items() if not signals[name].get("is_muxer", False)})

    try:
        await asyncio.wait_for(read_until_all_matched(), final_timeout)
    except asyncio.TimeoutError:
        value_buffer.update({name: None for name in signals.keys() if signals[name].get("mux_id") in mux_values})
        log.error("missing mux ids: {} of message: 0x{:x} bus: {}".format(mux_values, message_info["message_id"], bus))

    return value_buffer
