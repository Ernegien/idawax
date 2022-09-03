#pragma once

#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <entry.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>

#pragma region Instructions

/// <summary>
/// Determines if the specified instruction jumps.
/// </summary>
/// <param name="ins">The instruction.</param>
/// <returns>Returns true if it jumps.</returns>
bool is_jxx_insn(const insn_t& ins);

/// <summary>
/// Determines if the instruction at the specified address jumps.
/// </summary>
/// <param name="ea">The instruction address.</param>
/// <returns>Returns true if it jumps.</returns>
bool is_jxx_insn(const ea_t ea);

/// <summary>
/// Determines if the specified instruction is a conditional jump.
/// </summary>
/// <param name="ins">The instruction.</param>
/// <returns>Returns true if it's a conditional jump.</returns>
bool is_jcc_insn(const insn_t& instruction);

/// <summary>
/// Determines if the instruction at the specified address is a conditional jump.
/// </summary>
/// <param name="ea">The instruction address.</param>
/// <returns>Returns true if it's a conditional jump.</returns>
bool is_jcc_insn(const ea_t ea);

/// <summary>
/// Determines if the specified instruction is a jmp.
/// </summary>
/// <param name="ins">The instruction.</param>
/// <returns>Returns true if it's a jmp.</returns>
bool is_jmp_insn(const insn_t& ins);

/// <summary>
/// Determines if the instruction at the specified address is a jmp.
/// </summary>
/// <param name="ins">The instruction address.</param>
/// <returns>Returns true if it's a jmp.</returns>
bool is_jmp_insn(const ea_t ea);

/// <summary>
/// Determines if the specified address contains a jump/indirect table used for switch statements.
/// </summary>
/// <param name="ea">The address.</param>
/// <returns>Returns true if the address contains a jump/indirect table.</returns>
bool is_jmp_table(const ea_t ea);

/// <summary>
/// Determines if the specified instruction is a return.
/// NOTE: do not use is_ret_insn as it appears to be buggy!
/// </summary>
/// <param name="ins">The instruction.</param>
/// <returns>Returns true if the instruction is a return.</returns>
bool is_ret_insn_ex(const insn_t& ins);

/// <summary>
/// Determines if the instruction at the specified address is a return.
/// NOTE: do not use is_ret_insn as it appears to be buggy!
/// </summary>
/// <param name="ea"></param>
/// <returns></returns>
bool is_ret_insn_ex(const ea_t ea);

/// <summary>
/// Determines if the specified instruction is an int 3.
/// </summary>
/// <param name="ins">The instruction.</param>
/// <returns>Returns true if the instruction is an int 3.</returns>
bool is_int3_insn(const insn_t& ins);

/// <summary>
/// Determines if the instruction at the specified address is an int 3.
/// </summary>
/// <param name="ea">The instruction address.</param>
/// <returns>Returns true if the instruction is an int 3.</returns>
bool is_int3_insn(const ea_t ea);

/// <summary>
/// Return true if it's an instruction functions commonly end with.
/// </summary>
/// <param name="ins">The instruction.</param>
/// <returns>Return true for a ret, jmp, or int 3 instruction.</returns>
bool is_func_end_insn(const insn_t& ins);

/// <summary>
/// Return true if the address contains an instruction functions commonly end with.
/// </summary>
/// <param name="ea">The instruction address.</param>
/// <returns>Return true for a ret, jmp, or int 3 instruction.</returns>
bool is_func_end_insn(const ea_t ea);

/// <summary>
/// Attempts to create an instruction, undefining existing items if necessary. 
/// </summary>
/// <param name="ea">The address.</param>
/// <returns>Returns true if an instruction has been successfully created.</returns>
bool create_insn_ex(const ea_t ea);

#pragma endregion

#pragma region Functions

/// <summary>
/// Retrieves the last instruction in the specified function.
/// </summary>
/// <param name="func">The function.</param>
/// <param name="out">The returned instruction.</param>
void get_func_end_insn(const func_t& func, insn_t& out);

/// <summary>
/// Detects functions that don't end on a retn, jmp, or int 3.
/// </summary>
/// <param name="func">The function.</param>
/// <returns>Returns true if the function ends.</returns>
bool func_does_end(const func_t& func);

#pragma endregion

#pragma region Segments

/// <summary>
/// Retrieves the list of segments.
/// </summary>
/// <param name="out">The returned list of segments.</param>
void get_segments(qvector<segment_t>& out);

#pragma endregion

#pragma region XRefs

/// <summary>
/// Deletes the specified dref and sets the referring data type to numerical.
/// </summary>
/// <param name="from">The source reference address.</param>
/// <param name="to">The address referenced.</param>
void del_dref_ex(const ea_t from, const ea_t to);

/// <summary>
/// Deletes all drefs to the specified address and sets the referring data types to numerical.
/// </summary>
/// <param name="ea">The address referenced.</param>
void del_all_drefs_to(const ea_t ea);

/// <summary>
/// Deletes all drefs to the specified address range and sets the referring data types to numerical.
/// </summary>
/// <param name="start">The start address referenced.</param>
/// <param name="end">The end address referenced.</param>
void del_all_drefs_to(const ea_t start, const ea_t end);

#pragma endregion

#pragma region Code Analysis

/// <summary>
/// Determines if the specified address is the start of a 16-byte function alignment directive.
/// </summary>
/// <param name="ea">The address.</param>
/// <returns>Returns true if alignment detected.</returns>
bool is_func_align(const ea_t ea);

/// <summary>
/// Makes a 16-byte alignment directive if detected at the specified address.
/// </summary>
/// <param name="ea">The address.</param>
/// <returns>Returns true if alignment was detected and successfully created.</returns>
bool try_make_func_align(const ea_t ea);

/// <summary>
/// Removes bad xrefs to code.
/// </summary>
/// <param name="ea">The instruction address.</param>
void remove_bad_code_xrefs(const ea_t ea);

/// <summary>
/// Identifies and converts constant string tag arguments in function calls.
///     Old: push    6F626A65h
///     New: push    'obje'
/// </summary>
/// <param name="instruction"></param>
void detect_and_make_op_tag(const insn_t& instruction);

#pragma endregion

#pragma region Data Analysis

#pragma endregion

#pragma region Display

/// <summary>
/// Prints a range of disassembly to the console.
/// </summary>
/// <param name="start">The range start address.</param>
/// <param name="end">The range end address.</param>
/// <param name="indent">Indents the output.</param>
/// <param name="no_addresses">Removes address and xref info.</param>
/// <param name="only_instructions">Only shows lines with instructions.</param>
/// <param name="no_comments">Removes comments.</param>
/// <param name="no_empty">Removes empty lines.</param>
void msg_disasm_range(ea_t start, ea_t end, bool indent = true, bool no_addresses = false, bool only_instructions = false, bool no_comments = false, bool no_empty = false);

#pragma endregion