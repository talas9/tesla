# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/can/signal.py

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
async_call ::= expr . pos_arg pos_arg expr CALL_FUNCTION_KW_2 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_5 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg expr CALL_FUNCTION_KW_2 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_5 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . expr CALL_FUNCTION_KW_2 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_5 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg expr . CALL_FUNCTION_KW_2 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg expr CALL_FUNCTION_KW_2 . GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg . expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg . pos_arg pos_arg expr CALL_FUNCTION_KW_5 GET_AWAITABLE LOAD_CONST YIELD_FROM
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
async_with_stmt ::= expr POP_TOP . suite_stmts_opt POP_BLOCK LOAD_CONST async_with_post
async_with_stmt ::= expr POP_TOP . suite_stmts_opt async_with_post
async_with_stmt ::= expr POP_TOP \e_suite_stmts_opt . POP_BLOCK LOAD_CONST async_with_post
async_with_stmt ::= expr POP_TOP \e_suite_stmts_opt . async_with_post
async_with_stmt ::= expr POP_TOP suite_stmts_opt . POP_BLOCK LOAD_CONST async_with_post
async_with_stmt ::= expr POP_TOP suite_stmts_opt . async_with_post
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
call ::= expr pos_arg pos_arg CALL_FUNCTION_2 . 
call_kw36 ::= expr . expr LOAD_CONST CALL_FUNCTION_KW_1
call_kw36 ::= expr . expr expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr . expr expr expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr . expr expr expr expr expr LOAD_CONST CALL_FUNCTION_KW_5
call_kw36 ::= expr expr . LOAD_CONST CALL_FUNCTION_KW_1
call_kw36 ::= expr expr . expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr . expr expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr . expr expr expr expr LOAD_CONST CALL_FUNCTION_KW_5
call_kw36 ::= expr expr LOAD_CONST . CALL_FUNCTION_KW_1
call_kw36 ::= expr expr expr . LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr expr . expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr . expr expr expr LOAD_CONST CALL_FUNCTION_KW_5
call_kw36 ::= expr expr expr LOAD_CONST . CALL_FUNCTION_KW_2
call_kw36 ::= expr expr expr LOAD_CONST CALL_FUNCTION_KW_2 . 
call_kw36 ::= expr expr expr expr . LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr expr . expr expr LOAD_CONST CALL_FUNCTION_KW_5
call_stmt ::= expr . POP_TOP
call_stmt ::= expr POP_TOP . 
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
dict ::= expr . LOAD_CONST BUILD_CONST_KEY_MAP_1
dict ::= expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_2
dict ::= expr . expr expr LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr . expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr . expr expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_5
dict ::= expr LOAD_CONST . BUILD_CONST_KEY_MAP_1
dict ::= expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_2
dict ::= expr expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr expr . expr expr LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr expr . expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_5
dict ::= expr expr LOAD_CONST . BUILD_CONST_KEY_MAP_2
dict ::= expr expr LOAD_CONST BUILD_CONST_KEY_MAP_2 . 
dict ::= expr expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr expr expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr expr expr . expr expr LOAD_CONST BUILD_CONST_KEY_MAP_5
dict ::= expr expr expr LOAD_CONST . BUILD_CONST_KEY_MAP_3
dict ::= expr expr expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_4
dict ::= expr expr expr expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_5
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
expr ::= subscript . 
expr_jitop ::= expr . JUMP_IF_TRUE_OR_POP
expr_jt ::= expr . jmp_true
function_def ::= mkfunc . store
function_def ::= mkfunc store . 
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
jmp_false ::= POP_JUMP_IF_FALSE . 
kvlist_1 ::= expr . expr BUILD_MAP_1
kvlist_1 ::= expr expr . BUILD_MAP_1
lambda_body ::= expr . LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_4
lambda_body ::= expr . expr LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_5
lambda_body ::= expr . expr load_closure BUILD_TUPLE_1 LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_13
lambda_body ::= expr expr . LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_5
lambda_body ::= expr expr . load_closure BUILD_TUPLE_1 LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_13
lambda_body ::= expr expr load_closure . BUILD_TUPLE_1 LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_13
lambda_body ::= load_closure . LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_CLOSURE
last_stmt ::= iflaststmt . 
lastl_stmt ::= iflaststmtl . 
list ::= expr . BUILD_LIST_1
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
raise_stmt2 ::= expr . expr RAISE_VARARGS_2
raise_stmt2 ::= expr expr . RAISE_VARARGS_2
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
return_if_stmts ::= _stmts return_if_stmt . _come_froms
return_if_stmts ::= _stmts return_if_stmt \e__come_froms . 
return_if_stmts ::= _stmts return_if_stmt _come_froms . 
return_if_stmts ::= return_if_stmt . come_from_opt
return_if_stmts ::= return_if_stmt \e_come_from_opt . 
return_if_stmts ::= return_if_stmt come_from_opt . 
returns ::= _stmts . return
returns ::= _stmts . return_if_stmt
returns ::= _stmts return . 
returns ::= _stmts return_if_stmt . 
returns ::= return . 
sstmt ::= return . RETURN_LAST
sstmt ::= sstmt . RETURN_LAST
sstmt ::= stmt . 
stmt ::= assign . 
stmt ::= call_stmt . 
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
suite_stmts ::= returns . 
suite_stmts_opt ::= suite_stmts . 
testexpr ::= testfalse . 
testfalse ::= expr . jmp_false
testfalse ::= expr jmp_false . 
testtrue ::= expr . jmp_true
tuple ::= expr . BUILD_TUPLE_1
tuple ::= expr . expr BUILD_TUPLE_2
tuple ::= expr . expr expr expr expr BUILD_TUPLE_5
tuple ::= expr expr . BUILD_TUPLE_2
tuple ::= expr expr . expr expr expr BUILD_TUPLE_5
tuple ::= expr expr expr . expr expr BUILD_TUPLE_5
tuple ::= expr expr expr expr . expr BUILD_TUPLE_5
unary_not ::= expr . UNARY_NOT
unary_op ::= expr . unary_operator
unpack ::= UNPACK_SEQUENCE_2 . store store
unpack ::= UNPACK_SEQUENCE_2 store . store
unpack ::= UNPACK_SEQUENCE_2 store store . 
with ::= expr . SETUP_WITH POP_TOP \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with ::= expr . SETUP_WITH POP_TOP suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
yield ::= expr . YIELD_VALUE
yield_from ::= expr . GET_YIELD_FROM_ITER LOAD_CONST YIELD_FROM
Instruction context:
-> 
 L. 231         0  LOAD_CONST               (None,)
                   2  LOAD_GLOBAL              Optional
                   4  LOAD_GLOBAL              int
                   6  BINARY_SUBSCR    
                   8  LOAD_GLOBAL              CanSignalValue
                  10  LOAD_CONST               ('uid', 'return')
                  12  BUILD_CONST_KEY_MAP_2     2 
                  14  LOAD_CLOSURE             'bus'
                  16  LOAD_CLOSURE             'message_info'
                  18  LOAD_CLOSURE             'signal'
                  20  LOAD_CLOSURE             'timeout'
                  22  BUILD_TUPLE_4         4 
                  24  LOAD_CODE                <code_object _read_wrapper>
                  26  LOAD_STR                 'read.<locals>._read_wrapper'
                  28  MAKE_FUNCTION_13         'default, annotation, closure'
                  30  STORE_FAST               '_read_wrapper'
import asyncio, asyncio_extras, hashlib, logging
from typing import Any, AsyncGenerator, Dict, Generator, Iterable, Optional, Set, Tuple, Union
from odin.core import can
from odin.core import cid
from odin.core import gateway
from odin.platforms import get_gateway_interface
from . import utils
log = logging.getLogger(__name__)
ACTIVE_ALERT_VALUES = ('DTC_FAIL', 'FAILED_DTC')
CanSignalValue = Union[(bool, float, int, str, None)]
DEFAULT_CYCLE_TIME = 500
GEN2_UDP_SLOTTED_PERIOD = 0.5

async def active_alerts(prefix: Optional[str]=None, bus: Optional[can.Bus]=None, audience: Optional[Set[str]]=None) -> AsyncGenerator[(Tuple[(str, Dict[(str, Any)])], None)]:
    async for name, value in cid.interface.active_alerts(audience=audience):
        if not prefix or name.startswith(prefix):
            if is_alert_in_bus(name, bus):
                yield (
                 name, value)


def generate_hash_key(salt: str, value: str) -> str:
    bytes_data = "{}{}".format(value, salt).encode()
    return hashlib.sha256(bytes_data).hexdigest()


def is_alert_in_bus(alert_name: str, bus: Optional[can.Bus]=None) -> bool:
    if bus is None:
        return True
    else:
        if not isinstance(can.library.get("hashed"), dict) or not isinstance(can.library.get("hashed").get("bus_alerts_map"), dict):
            log.warning("No BUS filtering available as BUS-to-alerts mapping is unavailable")
            return True
        salt = can.library.hashed.bus_alerts_map.salt
        hashed_bus_name = generate_hash_key(salt, bus.name.upper())
        hashed_alert_name = generate_hash_key(salt, alert_name)
        return hashed_bus_name in can.library.hashed.bus_alerts_map.hashed_map and hashed_alert_name in can.library.hashed.bus_alerts_map.hashed_map[hashed_bus_name]


def available_signals(buses: list=[
 "eth"]) -> list:
    signals = []
    for signal_name, signal_info in can.library.signals.items():
        relevant_signal_info = {bus: info for bus, info in signal_info.items() if bus in buses}
        if relevant_signal_info:
            signals.append({signal_name: relevant_signal_info})

    return signals


def decode(signal: dict, data: bytes) -> CanSignalValue:
    raw = utils.decode(data,
      start_position=(signal["start_position"]),
      width=(signal["width"]),
      signed=(signal["signedness"] == "SIGNED"),
      big_endian=(signal["endianness"] == "BIG"))
    return process(signal, raw)


def find(signal_name: str, bus: Optional[can.Bus]=None) -> Tuple[(Dict, can.Bus)]:
    try:
        signal = can.library["signals"][signal_name]
    except KeyError:
        raise RuntimeError("could not find signal {0}".format(signal_name)) from None

    if bus is not None:
        try:
            info = (
             signal[bus.name.lower()], bus)
            utils.whitelist_check(signal_name, info)
            return info
        except KeyError:
            raise RuntimeError("could not find bus {0} for signal {1}".format(bus.name, signal_name))

    else:
        bus = utils.best_bus(signal)
        if bus is None:
            raise RuntimeError("could not find info for signal {}".format(signal_name))
        else:
            info = (
             signal[bus.name.lower()], bus)
            utils.whitelist_check(signal_name, info)
            return info


def is_muxed(signal: Dict):
    return signal.get("mux_id") is not None


@asyncio_extras.async_contextmanager
async def monitor(signal: Dict, bus: can.Bus) -> AsyncGenerator[(int, None)]:
    if get_gateway_interface() == "Gen3":
        log.debug("Overriding bus to ETH for Gen3")
        bus = can.Bus.ETH
    message_info, bus = can.message.find((signal["message_name"]), bus=bus)
    slots = max(1, len(can.message.multiplexer_values(message_info))) if is_muxed(signal) else 1
    async with gateway.interface.ensure_connections():
        session_id = await gateway.interface.monitor_message(bus, (message_info["message_id"]), is_uds_message=False,
          slots=slots,
          enabled=True)
        try:
            yield session_id
        finally:
            await gateway.interface.monitor_message(bus, (message_info["message_id"]), enabled=False)


def process(signal: dict, raw_value: int) -> CanSignalValue:
    try:
        desc = signal["value_description"]
    except KeyError:
        pass
    else:
        if raw_value in desc:
            return raw_value
        neg_raw = (~raw_value + 1 & 2 ** signal["width"] - 1) * -1
        if neg_raw in desc:
            return neg_raw
        for k, v in desc.items():
            if v == raw_value:
                return k

    if signal["width"] == 1:
        return bool(raw_value)
    else:
        if int(signal["scale"]) == signal["scale"]:
            if int(signal["offset"]) == signal["offset"]:
                return raw_value * int(signal["scale"]) + int(signal["offset"])
        return raw_value * signal["scale"] + signal["offset"]


def process_from_string(signal: dict, parsed_value: str) -> Optional[CanSignalValue]:
    if parsed_value == "**":
        return
    else:
        try:
            desc = signal["value_description"]
        except KeyError:
            pass
        else:
            if parsed_value in desc:
                return parsed_value
            try:
                numerical_value = float(parsed_value)
            except ValueError:
                return parsed_value

            if signal["width"] == 1:
                return bool(numerical_value)
            if int(numerical_value) == numerical_value:
                return int(numerical_value)
        return numerical_value


async def readParse error at or near `LOAD_CONST' instruction at offset 0


async def read_by_name(signal_name: str, bus_name: Optional[str]=None, session_id: Optional[int]=None) -> CanSignalValue:
    from odin.config import options
    if options["core"]["read_can_from_cid"]:
        if get_gateway_interface() == "Gen3":
            return await read_from_cid(signal_name, bus_name)
    return await read_from_can(signal_name, bus_name, session_id=session_id)


async def read_by_names(signal_names, bus_name: Optional[str]=None, session_id: Optional[int]=None) -> Dict[(str, CanSignalValue)]:
    from odin.config import options
    if options["core"]["read_can_from_cid"]:
        if get_gateway_interface() == "Gen3":
            return await read_multi_from_cid(signal_names, bus_name)
    signals = {}

    async def populate_signal(signal_name, bus_name):
        try:
            signals[signal_name] = await can.signal.read_by_name(signal_name, bus_name, session_id=session_id)
        except asyncio.TimeoutError:
            signals[signal_name] = None

    await (asyncio.gather)(*[populate_signal(s, bus_name) for s in signal_names])
    return signals


async def read_from_can(signal_name: str, bus_name: Optional[str]=None, session_id: Optional[int]=None) -> CanSignalValue:
    if bus_name:
        bus = can.Bus[bus_name]
    else:
        bus = None
    signal, bus = find(signal_name, bus=bus)
    return await read(signal, bus, session_id=session_id)


async def read_from_cid(signal_name: str, bus_name: Optional[str]=None) -> CanSignalValue:
    signals = await read_multi_from_cid([signal_name], bus_name)
    return signals.get(signal_name)


async def read_from_cid_simplified(signal_name: str, signal: Dict) -> CanSignalValue:
    values = await cid.interface.get_eth_signals([signal_name])
    return process_from_string(signal, values[signal_name])


async def read_multi_from_cid(signal_names: Iterable[str], bus_name: Optional[str]=None) -> Dict[(str, CanSignalValue)]:
    if bus_name is None or bus_name.upper() == can.Bus.ETH.name:
        values = await cid.interface.get_eth_signals(signal_names)
        bus = can.Bus[bus_name] if bus_name else None
        return {signal_name: process_from_string(find(signal_name, bus=bus)[0], values[signal_name]) for signal_name in signal_names}
    raise NotImplementedError("Reading of CAN signals is only supportedfor ETH bus. Bus requested: {}".format(bus_name))


async def read_multiplexed(signal: Dict, message_info: Dict, bus: can.Bus) -> CanSignalValue:
    mux_values = can.message.multiplexer_values(message_info)
    cycle_time = (message_info["cycle_time"] or DEFAULT_CYCLE_TIME) / 1000.0
    max_message_delay = cycle_time * 2
    final_timeout = max(1, len(mux_values)) * cycle_time * 2
    if get_gateway_interface() == "Gen2":
        max_message_delay += GEN2_UDP_SLOTTED_PERIOD
        final_timeout += GEN2_UDP_SLOTTED_PERIOD
    muxer = message_info.get("muxer")
    mux_id = signal.get("mux_id")

    async def read_until_match(mux_id, muxer):
        message_id = message_info["message_id"]
        while 1:
            data = await gateway.interface.read_message(bus, message_id, timeout=max_message_delay)
            if data:
                message_values = can.message.decode(message_info, data)
                if mux_id == utils.get_active_mux_id(message_values, message_info, muxer):
                    msg = "decoding can frame for message: {} bus: {}: {}"
                    log.debug(msg.format(signal["message_name"], bus.name, data))
                    return decode(signal, data)

    return await asyncio.wait_for(read_until_match(mux_id, muxer), final_timeout)
