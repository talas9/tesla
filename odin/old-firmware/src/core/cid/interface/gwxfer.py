# uncompyle6 version 3.9.3
# Python bytecode version base 3.6 (3379)
# Decompiled from: Python 3.12.3 (main, Jan  8 2026, 11:30:50) [GCC 13.3.0]
# Embedded file name: /firmware/components/odin/src/odin/core/cid/interface/gwxfer.py

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
_ifstmts_jumpl ::= c_stmts JUMP_BACK . 
_ifstmts_jumpl ::= c_stmts_opt . JUMP_FORWARD \e__come_froms
_ifstmts_jumpl ::= c_stmts_opt . JUMP_FORWARD _come_froms
_ifstmts_jumpl ::= c_stmts_opt . come_froms
_ifstmts_jumpl ::= c_stmts_opt come_froms . 
_stmts ::= _stmts . last_stmt
_stmts ::= _stmts . stmt
_stmts ::= _stmts last_stmt . 
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
and ::= expr jmp_false expr COME_FROM . 
assert ::= assert_expr . jmp_true LOAD_ASSERT RAISE_VARARGS_1 COME_FROM
assert ::= assert_expr jmp_true . LOAD_ASSERT RAISE_VARARGS_1 COME_FROM
assert2 ::= assert_expr . jmp_true LOAD_ASSERT expr CALL_FUNCTION_1 RAISE_VARARGS_1 COME_FROM
assert2 ::= assert_expr jmp_true . LOAD_ASSERT expr CALL_FUNCTION_1 RAISE_VARARGS_1 COME_FROM
assert_expr ::= assert_expr_and . 
assert_expr ::= assert_expr_or . 
assert_expr ::= expr . 
assert_expr_and ::= assert_expr . jmp_false expr
assert_expr_and ::= assert_expr jmp_false . expr
assert_expr_and ::= assert_expr jmp_false expr . 
assert_expr_or ::= assert_expr . jmp_true expr
assert_expr_or ::= assert_expr jmp_true . expr
assert_expr_or ::= assert_expr jmp_true expr . 
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
async_call ::= expr . pos_arg pos_arg expr CALL_FUNCTION_KW_2 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg pos_arg pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr . pos_arg pos_arg pos_arg pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_6 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . expr CALL_FUNCTION_KW_1 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg expr CALL_FUNCTION_KW_2 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg . pos_arg pos_arg pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_6 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg expr . CALL_FUNCTION_KW_1 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . expr CALL_FUNCTION_KW_2 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg . pos_arg pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_6 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg expr . CALL_FUNCTION_KW_2 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg expr CALL_FUNCTION_KW_2 . GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg . expr CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg . pos_arg pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg . pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_6 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg expr . CALL_FUNCTION_KW_3 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg pos_arg . pos_arg CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg pos_arg . pos_arg pos_arg expr CALL_FUNCTION_KW_6 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg pos_arg pos_arg . CALL_FUNCTION GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg pos_arg pos_arg . pos_arg expr CALL_FUNCTION_KW_6 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg pos_arg pos_arg pos_arg . expr CALL_FUNCTION_KW_6 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg pos_arg pos_arg pos_arg expr . CALL_FUNCTION_KW_6 GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_6 . GET_AWAITABLE LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_6 GET_AWAITABLE . LOAD_CONST YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_6 GET_AWAITABLE LOAD_CONST . YIELD_FROM
async_call ::= expr pos_arg pos_arg pos_arg pos_arg pos_arg pos_arg expr CALL_FUNCTION_KW_6 GET_AWAITABLE LOAD_CONST YIELD_FROM . 
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
await_stmt ::= await_expr POP_TOP . 
bin_op ::= expr . expr binary_operator
bin_op ::= expr expr . binary_operator
bin_op ::= expr expr binary_operator . 
binary_operator ::= BINARY_ADD . 
binary_operator ::= BINARY_FLOOR_DIVIDE . 
binary_operator ::= BINARY_MODULO . 
binary_operator ::= BINARY_SUBTRACT . 
break ::= BREAK_LOOP . 
c_stmts ::= _stmts . 
c_stmts ::= _stmts . lastc_stmt
c_stmts ::= lastc_stmt . 
c_stmts_opt ::= c_stmts . 
call ::= expr . CALL_FUNCTION_0
call ::= expr . pos_arg CALL_FUNCTION_1
call ::= expr . pos_arg pos_arg CALL_FUNCTION_2
call ::= expr . pos_arg pos_arg pos_arg CALL_FUNCTION_3
call ::= expr . pos_arg pos_arg pos_arg pos_arg pos_arg CALL_FUNCTION_5
call ::= expr CALL_FUNCTION_0 . 
call ::= expr pos_arg . CALL_FUNCTION_1
call ::= expr pos_arg . pos_arg CALL_FUNCTION_2
call ::= expr pos_arg . pos_arg pos_arg CALL_FUNCTION_3
call ::= expr pos_arg . pos_arg pos_arg pos_arg pos_arg CALL_FUNCTION_5
call ::= expr pos_arg CALL_FUNCTION_1 . 
call ::= expr pos_arg pos_arg . CALL_FUNCTION_2
call ::= expr pos_arg pos_arg . pos_arg CALL_FUNCTION_3
call ::= expr pos_arg pos_arg . pos_arg pos_arg pos_arg CALL_FUNCTION_5
call ::= expr pos_arg pos_arg CALL_FUNCTION_2 . 
call ::= expr pos_arg pos_arg pos_arg . CALL_FUNCTION_3
call ::= expr pos_arg pos_arg pos_arg . pos_arg pos_arg CALL_FUNCTION_5
call ::= expr pos_arg pos_arg pos_arg pos_arg . pos_arg CALL_FUNCTION_5
call ::= expr pos_arg pos_arg pos_arg pos_arg pos_arg . CALL_FUNCTION_5
call ::= expr pos_arg pos_arg pos_arg pos_arg pos_arg CALL_FUNCTION_5 . 
call_kw36 ::= expr . expr LOAD_CONST CALL_FUNCTION_KW_1
call_kw36 ::= expr . expr expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr . expr expr expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr . expr expr expr expr expr expr LOAD_CONST CALL_FUNCTION_KW_6
call_kw36 ::= expr expr . LOAD_CONST CALL_FUNCTION_KW_1
call_kw36 ::= expr expr . expr LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr . expr expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr . expr expr expr expr expr LOAD_CONST CALL_FUNCTION_KW_6
call_kw36 ::= expr expr LOAD_CONST . CALL_FUNCTION_KW_1
call_kw36 ::= expr expr expr . LOAD_CONST CALL_FUNCTION_KW_2
call_kw36 ::= expr expr expr . expr LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr . expr expr expr expr LOAD_CONST CALL_FUNCTION_KW_6
call_kw36 ::= expr expr expr LOAD_CONST . CALL_FUNCTION_KW_2
call_kw36 ::= expr expr expr LOAD_CONST CALL_FUNCTION_KW_2 . 
call_kw36 ::= expr expr expr expr . LOAD_CONST CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr expr . expr expr expr LOAD_CONST CALL_FUNCTION_KW_6
call_kw36 ::= expr expr expr expr LOAD_CONST . CALL_FUNCTION_KW_3
call_kw36 ::= expr expr expr expr expr . expr expr LOAD_CONST CALL_FUNCTION_KW_6
call_kw36 ::= expr expr expr expr expr expr . expr LOAD_CONST CALL_FUNCTION_KW_6
call_kw36 ::= expr expr expr expr expr expr expr . LOAD_CONST CALL_FUNCTION_KW_6
call_kw36 ::= expr expr expr expr expr expr expr LOAD_CONST . CALL_FUNCTION_KW_6
call_kw36 ::= expr expr expr expr expr expr expr LOAD_CONST CALL_FUNCTION_KW_6 . 
call_stmt ::= expr . POP_TOP
call_stmt ::= expr POP_TOP . 
cf_jf_else ::= come_froms . JUMP_FORWARD ELSE
cf_jump_back ::= COME_FROM . JUMP_BACK
classdefdeco1 ::= expr . classdefdeco1 CALL_FUNCTION_1
classdefdeco1 ::= expr . classdefdeco2 CALL_FUNCTION_1
come_from_loops ::= \e_come_from_loops . COME_FROM_LOOP
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
continues ::= _stmts lastl_stmt . continue
continues ::= lastl_stmt . continue
dict ::= expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_2
dict ::= expr . expr expr LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr . expr expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_5
dict ::= expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_2
dict ::= expr expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr expr . expr expr expr LOAD_CONST BUILD_CONST_KEY_MAP_5
dict ::= expr expr LOAD_CONST . BUILD_CONST_KEY_MAP_2
dict ::= expr expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_3
dict ::= expr expr expr . expr expr LOAD_CONST BUILD_CONST_KEY_MAP_5
dict ::= expr expr expr LOAD_CONST . BUILD_CONST_KEY_MAP_3
dict ::= expr expr expr expr . expr LOAD_CONST BUILD_CONST_KEY_MAP_5
dict ::= expr expr expr expr expr . LOAD_CONST BUILD_CONST_KEY_MAP_5
dict ::= expr expr expr expr expr LOAD_CONST . BUILD_CONST_KEY_MAP_5
else_suite ::= stmts . 
else_suite ::= suite_stmts . 
else_suitec ::= c_stmts . 
else_suitel ::= l_stmts . 
else_suitel ::= stmts . 
expr ::= LOAD_CONST . 
expr ::= LOAD_FAST . 
expr ::= LOAD_GLOBAL . 
expr ::= LOAD_STR . 
expr ::= async_call . 
expr ::= attribute . 
expr ::= await_expr . 
expr ::= bin_op . 
expr ::= call . 
expr ::= call_kw36 . 
expr ::= compare . 
expr ::= get_iter . 
expr ::= or . 
expr ::= subscript . 
expr_jitop ::= expr . JUMP_IF_TRUE_OR_POP
expr_jitop ::= expr JUMP_IF_TRUE_OR_POP . 
expr_jt ::= expr . jmp_true
expr_jt ::= expr jmp_true . 
for ::= SETUP_LOOP . expr for_iter store for_block POP_BLOCK COME_FROM_LOOP
for ::= SETUP_LOOP . expr for_iter store for_block POP_BLOCK NOP COME_FROM_LOOP
for ::= SETUP_LOOP expr . for_iter store for_block POP_BLOCK COME_FROM_LOOP
for ::= SETUP_LOOP expr . for_iter store for_block POP_BLOCK NOP COME_FROM_LOOP
for ::= SETUP_LOOP expr for_iter . store for_block POP_BLOCK COME_FROM_LOOP
for ::= SETUP_LOOP expr for_iter . store for_block POP_BLOCK NOP COME_FROM_LOOP
for ::= SETUP_LOOP expr for_iter store . for_block POP_BLOCK COME_FROM_LOOP
for ::= SETUP_LOOP expr for_iter store . for_block POP_BLOCK NOP COME_FROM_LOOP
for ::= SETUP_LOOP expr for_iter store for_block . POP_BLOCK COME_FROM_LOOP
for ::= SETUP_LOOP expr for_iter store for_block . POP_BLOCK NOP COME_FROM_LOOP
for ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK . COME_FROM_LOOP
for ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK . NOP COME_FROM_LOOP
for_block ::= \e_l_stmts_opt . COME_FROM_LOOP JUMP_BACK
for_block ::= \e_l_stmts_opt . _come_froms JUMP_BACK
for_block ::= \e_l_stmts_opt . come_from_loops JUMP_BACK
for_block ::= \e_l_stmts_opt \e__come_froms . JUMP_BACK
for_block ::= \e_l_stmts_opt \e_come_from_loops . JUMP_BACK
for_block ::= l_stmts . 
for_block ::= l_stmts_opt . COME_FROM_LOOP JUMP_BACK
for_block ::= l_stmts_opt . _come_froms JUMP_BACK
for_block ::= l_stmts_opt . come_from_loops JUMP_BACK
for_block ::= l_stmts_opt \e__come_froms . JUMP_BACK
for_block ::= l_stmts_opt \e__come_froms JUMP_BACK . 
for_block ::= l_stmts_opt \e_come_from_loops . JUMP_BACK
for_block ::= l_stmts_opt \e_come_from_loops JUMP_BACK . 
for_block ::= l_stmts_opt _come_froms . JUMP_BACK
for_iter ::= GET_ITER . FOR_ITER
for_iter ::= GET_ITER FOR_ITER . 
forelselaststmt ::= SETUP_LOOP . expr for_iter store for_block POP_BLOCK else_suitec COME_FROM_LOOP
forelselaststmt ::= SETUP_LOOP . expr for_iter store for_block POP_BLOCK else_suitec \e__come_froms
forelselaststmt ::= SETUP_LOOP . expr for_iter store for_block POP_BLOCK else_suitec _come_froms
forelselaststmt ::= SETUP_LOOP expr . for_iter store for_block POP_BLOCK else_suitec COME_FROM_LOOP
forelselaststmt ::= SETUP_LOOP expr . for_iter store for_block POP_BLOCK else_suitec \e__come_froms
forelselaststmt ::= SETUP_LOOP expr . for_iter store for_block POP_BLOCK else_suitec _come_froms
forelselaststmt ::= SETUP_LOOP expr for_iter . store for_block POP_BLOCK else_suitec COME_FROM_LOOP
forelselaststmt ::= SETUP_LOOP expr for_iter . store for_block POP_BLOCK else_suitec \e__come_froms
forelselaststmt ::= SETUP_LOOP expr for_iter . store for_block POP_BLOCK else_suitec _come_froms
forelselaststmt ::= SETUP_LOOP expr for_iter store . for_block POP_BLOCK else_suitec COME_FROM_LOOP
forelselaststmt ::= SETUP_LOOP expr for_iter store . for_block POP_BLOCK else_suitec \e__come_froms
forelselaststmt ::= SETUP_LOOP expr for_iter store . for_block POP_BLOCK else_suitec _come_froms
forelselaststmt ::= SETUP_LOOP expr for_iter store for_block . POP_BLOCK else_suitec COME_FROM_LOOP
forelselaststmt ::= SETUP_LOOP expr for_iter store for_block . POP_BLOCK else_suitec \e__come_froms
forelselaststmt ::= SETUP_LOOP expr for_iter store for_block . POP_BLOCK else_suitec _come_froms
forelselaststmt ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK . else_suitec COME_FROM_LOOP
forelselaststmt ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK . else_suitec \e__come_froms
forelselaststmt ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK . else_suitec _come_froms
forelselaststmt ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK else_suitec . COME_FROM_LOOP
forelselaststmt ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK else_suitec . _come_froms
forelselaststmt ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK else_suitec COME_FROM_LOOP . 
forelselaststmt ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK else_suitec \e__come_froms . 
forelselaststmtl ::= SETUP_LOOP . expr for_iter store for_block POP_BLOCK else_suitel COME_FROM_LOOP
forelselaststmtl ::= SETUP_LOOP . expr for_iter store for_block POP_BLOCK else_suitel \e__come_froms
forelselaststmtl ::= SETUP_LOOP . expr for_iter store for_block POP_BLOCK else_suitel _come_froms
forelselaststmtl ::= SETUP_LOOP expr . for_iter store for_block POP_BLOCK else_suitel COME_FROM_LOOP
forelselaststmtl ::= SETUP_LOOP expr . for_iter store for_block POP_BLOCK else_suitel \e__come_froms
forelselaststmtl ::= SETUP_LOOP expr . for_iter store for_block POP_BLOCK else_suitel _come_froms
forelselaststmtl ::= SETUP_LOOP expr for_iter . store for_block POP_BLOCK else_suitel COME_FROM_LOOP
forelselaststmtl ::= SETUP_LOOP expr for_iter . store for_block POP_BLOCK else_suitel \e__come_froms
forelselaststmtl ::= SETUP_LOOP expr for_iter . store for_block POP_BLOCK else_suitel _come_froms
forelselaststmtl ::= SETUP_LOOP expr for_iter store . for_block POP_BLOCK else_suitel COME_FROM_LOOP
forelselaststmtl ::= SETUP_LOOP expr for_iter store . for_block POP_BLOCK else_suitel \e__come_froms
forelselaststmtl ::= SETUP_LOOP expr for_iter store . for_block POP_BLOCK else_suitel _come_froms
forelselaststmtl ::= SETUP_LOOP expr for_iter store for_block . POP_BLOCK else_suitel COME_FROM_LOOP
forelselaststmtl ::= SETUP_LOOP expr for_iter store for_block . POP_BLOCK else_suitel \e__come_froms
forelselaststmtl ::= SETUP_LOOP expr for_iter store for_block . POP_BLOCK else_suitel _come_froms
forelselaststmtl ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK . else_suitel COME_FROM_LOOP
forelselaststmtl ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK . else_suitel \e__come_froms
forelselaststmtl ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK . else_suitel _come_froms
forelselaststmtl ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK else_suitel . COME_FROM_LOOP
forelselaststmtl ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK else_suitel . _come_froms
forelselaststmtl ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK else_suitel COME_FROM_LOOP . 
forelselaststmtl ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK else_suitel \e__come_froms . 
forelsestmt ::= SETUP_LOOP . expr for_iter store for_block POP_BLOCK else_suite COME_FROM_LOOP
forelsestmt ::= SETUP_LOOP . expr for_iter store for_block POP_BLOCK else_suite \e__come_froms
forelsestmt ::= SETUP_LOOP . expr for_iter store for_block POP_BLOCK else_suite _come_froms
forelsestmt ::= SETUP_LOOP expr . for_iter store for_block POP_BLOCK else_suite COME_FROM_LOOP
forelsestmt ::= SETUP_LOOP expr . for_iter store for_block POP_BLOCK else_suite \e__come_froms
forelsestmt ::= SETUP_LOOP expr . for_iter store for_block POP_BLOCK else_suite _come_froms
forelsestmt ::= SETUP_LOOP expr for_iter . store for_block POP_BLOCK else_suite COME_FROM_LOOP
forelsestmt ::= SETUP_LOOP expr for_iter . store for_block POP_BLOCK else_suite \e__come_froms
forelsestmt ::= SETUP_LOOP expr for_iter . store for_block POP_BLOCK else_suite _come_froms
forelsestmt ::= SETUP_LOOP expr for_iter store . for_block POP_BLOCK else_suite COME_FROM_LOOP
forelsestmt ::= SETUP_LOOP expr for_iter store . for_block POP_BLOCK else_suite \e__come_froms
forelsestmt ::= SETUP_LOOP expr for_iter store . for_block POP_BLOCK else_suite _come_froms
forelsestmt ::= SETUP_LOOP expr for_iter store for_block . POP_BLOCK else_suite COME_FROM_LOOP
forelsestmt ::= SETUP_LOOP expr for_iter store for_block . POP_BLOCK else_suite \e__come_froms
forelsestmt ::= SETUP_LOOP expr for_iter store for_block . POP_BLOCK else_suite _come_froms
forelsestmt ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK . else_suite COME_FROM_LOOP
forelsestmt ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK . else_suite \e__come_froms
forelsestmt ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK . else_suite _come_froms
forelsestmt ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK else_suite . COME_FROM_LOOP
forelsestmt ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK else_suite . _come_froms
forelsestmt ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK else_suite COME_FROM_LOOP . 
forelsestmt ::= SETUP_LOOP expr for_iter store for_block POP_BLOCK else_suite \e__come_froms . 
formatted_value1 ::= expr . FORMAT_VALUE
genexpr_func ::= LOAD_FAST . FOR_ITER store comp_iter JUMP_BACK
get_iter ::= expr . GET_ITER
get_iter ::= expr GET_ITER . 
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
ifelsestmt ::= testexpr stmts_opt jump_absolute_else . else_suite
ifelsestmt ::= testexpr stmts_opt jump_absolute_else else_suite . 
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
ifelsestmtc ::= testexpr c_stmts_opt jump_absolute_else . else_suitec
ifelsestmtc ::= testexpr c_stmts_opt jump_absolute_else else_suitec . 
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
ifelsestmtl ::= testexpr c_stmts_opt JUMP_BACK . else_suitel
ifelsestmtl ::= testexpr c_stmts_opt jb_cfs . else_suitel
ifelsestmtl ::= testexpr c_stmts_opt jb_else . else_suitel
ifelsestmtl ::= testexpr c_stmts_opt jb_else else_suitel . 
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
iflaststmtl ::= testexpr . _ifstmts_jumpl
iflaststmtl ::= testexpr . c_stmts_opt
iflaststmtl ::= testexpr . c_stmts_opt JUMP_BACK
iflaststmtl ::= testexpr \e_c_stmts_opt . 
iflaststmtl ::= testexpr \e_c_stmts_opt . JUMP_BACK
iflaststmtl ::= testexpr _ifstmts_jumpl . 
iflaststmtl ::= testexpr c_stmts_opt . 
iflaststmtl ::= testexpr c_stmts_opt . JUMP_BACK
iflaststmtl ::= testexpr c_stmts_opt JUMP_BACK . 
ifstmt ::= testexpr . _ifstmts_jump
ifstmt ::= testexpr \e__ifstmts_jump . 
ifstmt ::= testexpr _ifstmts_jump . 
ifstmtl ::= testexpr . _ifstmts_jumpl
ifstmtl ::= testexpr _ifstmts_jumpl . 
import ::= LOAD_CONST . LOAD_CONST alias
import_from ::= LOAD_CONST . LOAD_CONST IMPORT_NAME importlist POP_TOP
import_from_star ::= LOAD_CONST . LOAD_CONST IMPORT_NAME IMPORT_STAR
importmultiple ::= LOAD_CONST . LOAD_CONST alias imports_cont
jb_cfs ::= JUMP_BACK . _come_froms
jb_cfs ::= JUMP_BACK . come_froms
jb_cfs ::= JUMP_BACK \e__come_froms . 
jb_else ::= JUMP_BACK . ELSE
jb_else ::= JUMP_BACK ELSE . 
jmp_false ::= POP_JUMP_IF_FALSE . 
jmp_true ::= POP_JUMP_IF_TRUE . 
jump_absolute_else ::= jb_else . 
l_stmts ::= _stmts . 
l_stmts ::= _stmts . lastl_stmt
l_stmts ::= _stmts lastl_stmt . 
l_stmts ::= l_stmts . lstmt
l_stmts ::= l_stmts lstmt . 
l_stmts ::= lastl_stmt . 
l_stmts ::= lastl_stmt . come_froms l_stmts
l_stmts ::= lastl_stmt come_froms . l_stmts
l_stmts ::= lastl_stmt come_froms l_stmts . 
l_stmts ::= lstmt . 
l_stmts_opt ::= l_stmts . 
lambda_body ::= expr . LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_4
lambda_body ::= expr . expr LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_5
lambda_body ::= expr expr . LOAD_LAMBDA LOAD_STR MAKE_FUNCTION_5
last_stmt ::= forelselaststmt . 
last_stmt ::= iflaststmt . 
lastc_stmt ::= iflaststmtl . 
lastl_stmt ::= forelselaststmtl . 
lastl_stmt ::= ifelsestmtl . 
lastl_stmt ::= iflaststmtl . 
list ::= expr . BUILD_LIST_1
list ::= expr . expr BUILD_LIST_2
list ::= expr . expr expr BUILD_LIST_3
list ::= expr . expr expr expr expr BUILD_LIST_5
list ::= expr expr . BUILD_LIST_2
list ::= expr expr . expr BUILD_LIST_3
list ::= expr expr . expr expr expr BUILD_LIST_5
list ::= expr expr expr . BUILD_LIST_3
list ::= expr expr expr . expr expr BUILD_LIST_5
list ::= expr expr expr expr . expr BUILD_LIST_5
list ::= expr expr expr expr expr . BUILD_LIST_5
lstmt ::= stmt . 
mkfunc ::= expr . LOAD_CODE LOAD_STR MAKE_FUNCTION_4
mkfunc ::= expr . expr LOAD_CODE LOAD_STR MAKE_FUNCTION_5
mkfunc ::= expr expr . LOAD_CODE LOAD_STR MAKE_FUNCTION_5
mkfuncdeco ::= expr . mkfuncdeco CALL_FUNCTION_1
mkfuncdeco ::= expr . mkfuncdeco0 CALL_FUNCTION_1
or ::= expr_jitop . expr COME_FROM
or ::= expr_jitop expr . COME_FROM
or ::= expr_jitop expr COME_FROM . 
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
stmt ::= await_stmt . 
stmt ::= break . 
stmt ::= call_stmt . 
stmt ::= forelsestmt . 
stmt ::= ifelsestmt . 
stmt ::= ifelsestmtc . 
stmt ::= ifstmt . 
stmt ::= ifstmtl . 
stmt ::= raise_stmt1 . 
stmts ::= last_stmt . 
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
testexpr ::= testtrue . 
testfalse ::= expr . jmp_false
testfalse ::= expr jmp_false . 
testtrue ::= expr . jmp_true
testtrue ::= expr jmp_true . 
tuple ::= expr . expr BUILD_TUPLE_2
tuple ::= expr expr . BUILD_TUPLE_2
unary_not ::= expr . UNARY_NOT
unary_op ::= expr . unary_operator
unpack ::= UNPACK_SEQUENCE_2 . store store
unpack ::= UNPACK_SEQUENCE_2 store . store
unpack ::= UNPACK_SEQUENCE_2 store store . 
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
while1stmt ::= SETUP_LOOP l_stmts COME_FROM . JUMP_BACK COME_FROM_LOOP
while1stmt ::= SETUP_LOOP l_stmts COME_FROM . JUMP_BACK POP_BLOCK COME_FROM_LOOP
while1stmt ::= SETUP_LOOP l_stmts COME_FROM_LOOP . 
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
whileelsestmt ::= SETUP_LOOP testexpr l_stmts_opt . JUMP_BACK POP_BLOCK else_suitel COME_FROM
whileelsestmt ::= SETUP_LOOP testexpr l_stmts_opt . jb_cfs POP_BLOCK else_suitel COME_FROM_LOOP
whileelsestmt2 ::= SETUP_LOOP . testexpr \e_l_stmts_opt JUMP_BACK POP_BLOCK else_suitel JUMP_BACK COME_FROM_LOOP
whileelsestmt2 ::= SETUP_LOOP . testexpr l_stmts_opt JUMP_BACK POP_BLOCK else_suitel JUMP_BACK COME_FROM_LOOP
whileelsestmt2 ::= SETUP_LOOP testexpr . l_stmts_opt JUMP_BACK POP_BLOCK else_suitel JUMP_BACK COME_FROM_LOOP
whileelsestmt2 ::= SETUP_LOOP testexpr \e_l_stmts_opt . JUMP_BACK POP_BLOCK else_suitel JUMP_BACK COME_FROM_LOOP
whileelsestmt2 ::= SETUP_LOOP testexpr l_stmts_opt . JUMP_BACK POP_BLOCK else_suitel JUMP_BACK COME_FROM_LOOP
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
whilestmt ::= SETUP_LOOP testexpr l_stmts_opt . COME_FROM JUMP_BACK POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr l_stmts_opt . JUMP_BACK POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr l_stmts_opt . JUMP_BACK POP_BLOCK JUMP_BACK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr l_stmts_opt . JUMP_BACK come_froms POP_BLOCK
whilestmt ::= SETUP_LOOP testexpr l_stmts_opt . JUMP_BACK come_froms POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr l_stmts_opt . come_froms JUMP_BACK come_froms POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr l_stmts_opt COME_FROM . JUMP_BACK POP_BLOCK COME_FROM_LOOP
whilestmt ::= SETUP_LOOP testexpr l_stmts_opt come_froms . JUMP_BACK come_froms POP_BLOCK COME_FROM_LOOP
with ::= expr . SETUP_WITH POP_TOP \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with ::= expr . SETUP_WITH POP_TOP suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store \e_suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
with_as ::= expr . SETUP_WITH store suite_stmts_opt POP_BLOCK LOAD_CONST COME_FROM_WITH WITH_CLEANUP_START WITH_CLEANUP_FINISH END_FINALLY
yield ::= expr . YIELD_VALUE
yield_from ::= expr . GET_YIELD_FROM_ITER LOAD_CONST YIELD_FROM
Instruction context:
-> 
 L. 105         0  LOAD_FAST                'offset'
                   2  LOAD_CONST               0
                   4  COMPARE_OP               <
                   6  POP_JUMP_IF_FALSE    16  'to 16'
import asyncio, logging, string, tempfile, re, os, aiofiles, struct
from typing import AsyncGenerator, Union, Tuple, Dict, Optional
from odin.core.utils import payload
from . import exec_command
from . import run_command
from . import filesystem
MAX_GWXFER_PAYLOAD_BYTES = 1000000
GWXFER_CHUNK_WAIT_TIME_S = 10
MAX_GWXFER_TRANSFER_ATTEMPTS = 3
EXCLUDE_GTW_FILE = "CUR"
ENUMIDS = {'VIRT_GTW_logHeader':3489662942L,  'VIRT_GTW_timeStamp':3489662941L}
RECORD_START = 170
COMMON_SIZE = 6
MIN_SAMPLE_SIZE = COMMON_SIZE + 8
log = logging.getLogger(__name__)

class GwxferException(Exception):
    return


async def delete(gtw_file: str) -> dict:
    if not gtw_file:
        raise ValueError("gtw_file required.")
    log.debug("Delete hrl from gateway {}".format(gtw_file))
    return await exec_command(["/usr/local/bin/gwxfer", "-delete", "gw:{}".format(gtw_file)], timeout=2, user="odin")


async def get_size(gtw_file: str) -> dict:
    if not gtw_file:
        raise ValueError("gtw_file required.")
    return await exec_command(["/usr/local/bin/gwxfer", "-getsize", "gw:{}".format(gtw_file)], timeout=2, user="odin")


async def list_dir(path: str, timeout: int=5) -> AsyncGenerator[(int, str)]:
    try:
        rtn = await exec_command(["/usr/local/bin/gwxfer",
         "-filter", "[!{}]*".format(EXCLUDE_GTW_FILE),
         "-listdir", "gw:{}".format(path)],
          timeout=timeout, user="odin")
    except asyncio.TimeoutError:
        log.error("Gwxfer listdir of {} timed out".format(path))
        return
    else:
        if rtn["exit_status"] == 0:
            files = rtn["stdout"].splitlines()
            files.sort(key=(lambda x: x.split()[-1]))
            for line in files:
                try:
                    size, file_name = line.split()
                except ValueError:
                    return
                else:
                    yield (
                     int(size), file_name)


async def transfer(src, dst, timeout=60, offset=0, length=0, append=False):
    args = [
     "/usr/local/bin/gwxfer"]
    if append:
        args += ["-append"]
    if offset:
        args += ["-offset", (f"{offset}")]
    if length:
        args += ["-length", (f"{length}")]
    args += ["gw:{}".format(src), dst]
    return await exec_command(args=args, timeout=timeout, user="root")


async def put_file(src, gtw_dst, timeout=60):
    args = [
     "/usr/local/bin/gwxfer", src, "gw:{}".format(gtw_dst)]
    return await exec_command(args=args, timeout=timeout, user="root")


async def get_file_contentParse error at or near `LOAD_FAST' instruction at offset 0


def handle_gwxfer_response(gwxfer_response: dict, file_path: str):
    if gwxfer_response["exit_status"] != 0:
        raise GwxferException("Couldnt access {} from gateway. gwxfer: {}".formatfile_pathgwxfer_response["stderr"])


async def gw_file_size(gw_file: str) -> int:
    response = await get_size(gw_file)
    handle_gwxfer_responseresponsegw_file
    return int(response["stdout"])


async def read_gw_file(src, timeout=60, offset=0, length=0):
    content, response = await get_file_content(src, timeout, offset, length)
    handle_gwxfer_responseresponsesrc
    return content


async def get_metadata(timeout: int=60) -> Tuple[(int, int)]:
    offset_data = await read_gw_file("log/offsets.txt")
    offset_data = offset_data.decode()
    latest_file_idx = int(re.search"(offset\\s\\d+\\s)(\\d)"offset_data.group(2))
    num_log_files = 0
    async for _, file in list_dir"log"timeout:
        if re.search("\\.LOG", file, re.IGNORECASE):
            num_log_files += 1

    return (
     latest_file_idx, num_log_files)


async def get_file_bounds(log_file: str, sample_size: int) -> Dict[(str, Tuple[(int, int)])]:
    if sample_size < MIN_SAMPLE_SIZE:
        raise ValueError("sample_size must be > {}.".format(MIN_SAMPLE_SIZE))
    file_size = await gw_file_size(log_file)
    lower_offset = 0
    while 1:
        sample = await read_gw_file(log_file, offset=lower_offset, length=(minsample_sizefile_size - lower_offset + 1))
        lower_timestamp, last_record_offset = await extract_timestampsampleTrue
        if last_record_offset > 0:
            lower_offset += last_record_offset
        else:
            lower_offset += sample_size
        if lower_timestamp is not None:
            break
        else:
            if lower_offset >= file_size:
                raise EOFError("Unable to find valid timestamp in {}.".format(log_file))

    upper_offset = file_size - sample_size
    while 1:
        sample = await read_gw_file(log_file, offset=(max0upper_offset), length=(minsample_sizefile_size - upper_offset + 1))
        upper_timestamp, last_record_offset = await extract_timestampsampleFalse
        upper_offset -= sample_size + last_record_offset
        if upper_timestamp is not None:
            break

    return {'time_range':(lower_timestamp,
      upper_timestamp), 
     'offsets':(
      lower_offset,
      upper_offset)}


async def extract_timestamp(sample: bytes, return_first_occurrence: bool=True) -> Tuple[(Optional[int], int)]:
    sequence_length = len(sample)
    current_offset = current_record_offset = record_start_offset = 0 if return_first_occurrence else sequence_length - 1
    while 0 <= current_offset < sequence_length:
        if struct.unpack"B"sample[current_offset:current_offset + 1][0] == RECORD_START:
            record_start_offset = current_record_offset = current_offset
            common_end = current_record_offset + COMMON_SIZE
            if common_end <= sequence_length - COMMON_SIZE:
                common = sample[current_record_offset:common_end]
                size = struct.unpack"!2xH2x"common[0]
                current_record_offset = common_end
                if size >= COMMON_SIZE + 8:
                    record_end = current_record_offset + size - COMMON_SIZE + 1
                    if record_end <= sequence_length:
                        record = sample[current_record_offset:record_end]
                        current_record_offset = record_end
                        if struct.unpack"!L"record[:4][0] in ENUMIDS.values():
                            return (struct.unpack"!L"record[4:8][0], record_start_offset)
            if return_first_occurrence:
                current_offset = maxcurrent_offset + 1current_record_offset + 1
        else:
            current_offset -= 1

    return (
     None, record_start_offset)
