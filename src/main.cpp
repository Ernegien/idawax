/*
 *  This plugin is intended to cleanup x86 executables (particularly XBEs for now) immediately after auto-analysis.
 *
 */

#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <entry.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <chrono>
#include "ida_extensions.h"

void detect_function(const ea_t ea)
{ 
    func_t* func = get_func(ea);

    // skip alignment and data (for now)
    flags_t flags = get_flags(ea);
    if (func != nullptr || is_align(flags) || is_data(flags))
        return;

    msg("Creating function at 0x%X\r\n", ea);
    //auto_make_proc(ea);
    if (add_func(ea))
    {
        // TODO: fixups
    }
}

// TODO: run this per-function rather than per-place!
// attempts to fix functions that incorrectly end on a call due to an early exit
void extend_bad_function_end(const idaplace_t& place, const func_t* func, const insn_t& instruction)
{
    if (place.ea != (func->end_ea - instruction.size) || !is_call_insn(instruction))
        return;

    int lookahead = 100;
    idaplace_t p = idaplace_t(place);
    insn_t i;

    do
    {
        decode_insn(&i, p.ea);
        p.next(NULL);
        lookahead--;
    } while (!is_retn_insn(i) && !is_align_insn(p.ea) && get_func(p.ea) == nullptr && lookahead > 0);

    if (lookahead > 0)
    {
        msg("Extending function end from 0x%X to 0x%X\r\n", func->end_ea, p.ea);
        msg_disasm_range(place.ea, p.ea + 1);
        set_func_end(func->start_ea, p.ea);
    }
}

// TODO: removes bad xrefs to data
void clear_bad_data_xrefs(const idaplace_t& place)
{
    // TODO: skip when dref points to a mid-instruction in a code segment (if possible)
}

void process_data(const idaplace_t& place)
{
    // TODO: undefined data gets turned into aligned dwords to be checked for xrefs
}

void process_code(const idaplace_t& place)
{
    // skip jump tables
    if (is_jmp_table(place.ea))
        return;

    if (!get_func(place.ea))
    {
        detect_and_make_align(place.ea);
        detect_function(place.ea);
    }

    func_t* func = get_func(place.ea);
    if (func != nullptr)
    {
        insn_t instruction;
        decode_insn(&instruction, place.ea);
        remove_bad_code_xrefs(place.ea);
        extend_bad_function_end(place, func, instruction);
        detect_and_make_op_tag(instruction);
    }
}

void process_segment(const segment_t& segment)
{
    // get segment info
    qstring name;
    get_segm_name(&name, &segment);
    const char* c_name = name.c_str();

    // TODO: dyamic detection from a first-pass scan
    bool has_code = segment.type == SEG_CODE || (strstr(c_name, "BINK") && !strstr(c_name, "DATA"));
    bool has_data = segment.type == SEG_DATA || strstr(c_name, "D3D") || strstr(c_name, "DSOUND") ||
        strstr(c_name, "XNET") || strstr(c_name, "XPP") || strstr(c_name, "DOLBY") || 
        strstr(c_name, "DATA") || strstr(c_name, "$$X");

    // loop through functions checking for partials
    func_t* func = get_next_func(segment.start_ea);
    while (func != nullptr)
    {
        if (is_func_truncated(*func))
        {
            msg("Partial function found at 0x%X\r\n", func->start_ea);
            // TODO: apply necessary fix-ups
        }

        func = get_next_func(func->end_ea);
    }

    // loop through each place address
    idaplace_t place = idaplace_t(segment.start_ea, 0);
    while (place.ea <= segment.end_ea)
    {
        if (has_code)
        {
            process_code(place);
        }
        if (has_data)
        {
            process_data(place);
        }
        place.next(NULL);
    }
}

bool idaapi run(size_t)
{
  if ( !auto_is_ok()
    && ask_yn(ASKBTN_NO,
              "HIDECANCEL\n"
              "The autoanalysis has not finished yet.\n"
              "The result might be incomplete.\n"
              "Do you want to continue?") < ASKBTN_YES )
  {
    return true;
  }

  auto start = std::chrono::high_resolution_clock::now();

  qvector<segment_t> segments;
  get_segments(segments);
  for (auto const& segment : segments)
  {
      process_segment(segment);
  }
 
  auto stop = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
  msg("Cleanup finished in %d milliseconds\r\n", duration);

  return true;
}

//--------------------------------------------------------------------------
int idaapi init(void)
{
    return PLUGIN_OK;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,                    // plugin flags
  init,                 // initialize
  NULL,                 // terminate. this pointer may be NULL.
  run,                  // invoke plugin
  NULL,                 // long comment about the plugin
  NULL,                 // multiline help about the plugin
  "IDA Wax",            // the preferred short name of the plugin
  "Ctrl-F11",           // the preferred hotkey to run the plugin
};
