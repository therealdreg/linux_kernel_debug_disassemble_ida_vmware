# https://github.com/therealdreg/linux_kernel_debug_disassemble_ida_vmware
# -
# linux_kernel_symloader
# MIT LICENSE Copyright <2020>
# David Reguera Garcia aka Dreg
# Dreg@fr33project.org - http://www.fr33project.org/ - https://github.com/therealdreg
# twitter: @therealdreg
# -
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
# associated documentation files (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial
# portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
# LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
# OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# -
# WARNING!! bullshit code
# -
# Refs:
# https://www.hex-rays.com/wp-content/uploads/2019/12/debugging_gdb_linux_vmware.pdf


import idaapi
import ida_kernwin
import time
import ida_dbg
import ida_idd
import ida_ua


class UICancel(Exception):
    pass


def parse_symbol_line(symbol_line):
    try:
        address_string, type_string, *others_string = symbol_line.split()
        name_string = " ".join(map(str, others_string))
        name_string = "".join(name_string.split())
        if len(name_string) < 1:
            raise Exception("name_string is empty")
        address_number = int(address_string, 16)
        if len(address_string) > 10:
            is_arch64 = True
        else:
            is_arch64 = False
        return address_number, type_string, name_string, is_arch64
    except BaseException as error:
        print("bad symbol line format: " + symbol_line)
        print("An exception occurred: {}".format(error))
        raise


def open_symbols_file():
    ida_kernwin.warning(
        "linux_kernel_symloader by Dreg, press button to select the symbol file https://github.com/therealdreg/linux_kernel_debug_disassemble_ida_vmware"
    )
    symbols_file_path = ida_kernwin.ask_file(
        0,
        "*",
        "Load system map or nm output or kallsyms output or pattern-finder-ring0-LKM output",
    )
    if symbols_file_path:
        symbols_file = open(symbols_file_path)
    return symbols_file


def check_arch64(symbols_file):
    sym_arch_size = ida_kernwin.ask_buttons(
        "x64", "x32", "Auto detect", -1, "Select symbol arch"
    )
    if sym_arch_size == 1:
        return True
    elif sym_arch_size == 0:
        return False
    symbol_line = symbols_file.readline()
    address_number, type_string, name, is_arch64 = parse_symbol_line(symbol_line)
    return is_arch64


def check_memory_region(is_arch64):
    if ida_dbg.is_debugger_on():
        if (
            ida_kernwin.ask_buttons(
                "Yes",
                "No",
                "Cancel",
                -1,
                "Add auto memory region (without memory region go to EIP/RIP can fail)",
            )
            == -1
        ):
            raise UICancel
        ida_dbg.enable_manual_regions(1)
        infos = ida_idd.meminfo_vec_t()
        info = ida_idd.memory_info_t()
        info.perm = 7
        if is_arch64:
            info.end_ea = 18446744073709551614
            info.bitness = 2
        else:
            info.end_ea = 4294967294
            info.bitness = 1
        info.sbase = 0
        info.sclass = "UNK"
        info.name = "MEMORY"
        info.start_ea = 0
        infos.push_back(info)
        ida_dbg.set_manual_regions(infos)
        # enable manual regions workarr:
        ida_dbg.enable_manual_regions(0)
        ida_dbg.refresh_debugger_memory()
        ida_dbg.enable_manual_regions(1)
        ida_dbg.refresh_debugger_memory()
        ida_dbg.edit_manual_regions()
        if idaapi.get_process_state() == -1:
            if is_arch64:
                cipreg = idaapi.get_reg_val("RIP")
            else:
                cipreg = idaapi.get_reg_val("EIP")
            ida_ua.create_insn(cipreg)
            ida_kernwin.jumpto(cipreg)
            ida_kernwin.refresh_idaview_anyway()


def check_skip_absolute_symbols():
    skip_absolute_symbols = ida_kernwin.ask_buttons(
        "Yes", "No", "Cancel", -1, "Skip Absolute Symbols"
    )
    if skip_absolute_symbols == -1:
        raise UICancel
    elif skip_absolute_symbols == 1:
        return True
    return False


def check_skip_module_symbols():
    skip_module_symbols = ida_kernwin.ask_buttons(
        "Yes", "No", "Cancel", -1, "Skip Module Symbols"
    )
    if skip_module_symbols == -1:
        raise UICancel
    elif skip_module_symbols == 1:
        return True
    return False


def make_symbols(symbols_file, is_arch64, skip_absolute_symbols, skip_module_symbols):
    arch_warn = True
    for symbol_line in symbols_file:
        symbol_line = symbol_line.strip()
        print(symbol_line)
        address_number, type_string, name, line_is_arch64 = parse_symbol_line(
            symbol_line
        )
        if arch_warn and is_arch64 != line_is_arch64:
            ignore_arch_warn = ida_kernwin.ask_buttons(
                "Yes",
                "No",
                "Cancel",
                -1,
                "Detected line arch is different from arch selected, maybe symbols file is corrupted, do you want ignore this kind of warning? Cancel to exit",
            )
            if ignore_arch_warn == -1:
                raise UICancel
            elif ignore_arch_warn == 1:
                arch_warn = False
        if skip_absolute_symbols and type_string == "A":
            continue
        if skip_module_symbols and name[-1] == "]":
            continue
        idaapi.set_debug_name(address_number, name)
        idaapi.set_name(
            address_number,
            name,
            idaapi.SN_NOWARN | idaapi.SN_NOCHECK | idaapi.SN_PUBLIC,
        )
    ida_kernwin.open_names_window(0)
    


def linux_kernel_symloader():
    idaapi.msg(
        "\nlinux_kernel_symloader making symbols, please be patient, ida can stay blocked, dont worry https://github.com/therealdreg/linux_kernel_debug_disassemble_ida_vmware\n\n"
    )
    symbols_file = open_symbols_file()
    is_arch64 = check_arch64(symbols_file)
    check_memory_region(is_arch64)
    skip_absolute_symbols = check_skip_absolute_symbols()
    skip_module_symbols = check_skip_module_symbols()
    start_time = time.time()
    make_symbols(symbols_file, is_arch64, skip_absolute_symbols, skip_module_symbols)
    idaapi.msg(
        "\ndone! linux_kernel_symloader finshed - %s seconds\n\n"
        % (round(time.time() - start_time, 1))
    )
    symbols_file.close()


linux_kernel_symloader()
