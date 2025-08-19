#!/usr/bin/env python3
# Copyright (c) 2015-2021 The Bitcoin Core developers
# Copyright (c) 2023 The Dogecoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''
Perform basic security checks on a series of executables.
Exit status will be 0 if successful, and the program will be silent.
Otherwise the exit status will be 1 and it will log which executables failed which checks.
'''
import sys
from typing import List

import lief #type:ignore

def check_ELF_RELRO(binary) -> bool:
    '''
    Check for read-only relocations.
    GNU_RELRO program header must exist
    Dynamic section must have BIND_NOW flag
    '''
    have_gnu_relro = False
    for segment in binary.segments:
        # Note: not checking p_flags == PF_R: here as linkers set the permission differently
        # This does not affect security: the permission flags of the GNU_RELRO program
        # header are ignored, the PT_LOAD header determines the effective permissions.
        # However, the dynamic linker need to write to this area so these are RW.
        # Glibc itself takes care of mprotecting this area R after relocations are finished.
        # See also https://marc.info/?l=binutils&m=1498883354122353
        GNU_RELRO = segment.type.GNU_RELRO if hasattr(segment.type, 'GNU_RELRO') else None
        if segment.type == GNU_RELRO:
            have_gnu_relro = True

    have_bindnow = False
    try:
        # Check FLAGS entry in dynamic section using new lief API
        for entry in binary.dynamic_entries:
            if entry.tag.name == 'FLAGS' and hasattr(entry, 'FLAG'):
                if entry.has(entry.FLAG.BIND_NOW):
                    have_bindnow = True
                    break
    except:
        have_bindnow = False

    return have_gnu_relro and have_bindnow

def check_ELF_Canary(binary) -> bool:
    '''
    Check for use of stack canary
    '''
    return binary.has_symbol('__stack_chk_fail')

def check_ELF_separate_code(binary):
    '''
    Check that sections are appropriately separated in virtual memory,
    based on their permissions. This checks for missing -Wl,-z,separate-code
    and potentially other problems.
    '''
    R = lief.ELF.SEGMENT_FLAGS.R
    W = lief.ELF.SEGMENT_FLAGS.W
    E = lief.ELF.SEGMENT_FLAGS.X
    EXPECTED_FLAGS = {
        # Read + execute
        '.init': R | E,
        '.plt': R | E,
        '.plt.got': R | E,
        '.plt.sec': R | E,
        '.text': R | E,
        '.fini': R | E,
        # Read-only data
        '.interp': R,
        '.note.gnu.property': R,
        '.note.gnu.build-id': R,
        '.note.ABI-tag': R,
        '.gnu.hash': R,
        '.dynsym': R,
        '.dynstr': R,
        '.gnu.version': R,
        '.gnu.version_r': R,
        '.rela.dyn': R,
        '.rela.plt': R,
        '.rodata': R,
        '.eh_frame_hdr': R,
        '.eh_frame': R,
        '.qtmetadata': R,
        '.gcc_except_table': R,
        '.stapsdt.base': R,
        # Writable data
        '.init_array': R | W,
        '.fini_array': R | W,
        '.dynamic': R | W,
        '.got': R | W,
        '.data': R | W,
        '.bss': R | W,
    }
    if binary.header.machine_type == lief.ELF.ARCH.PPC64:
        # .plt is RW on ppc64 even with separate-code
        EXPECTED_FLAGS['.plt'] = R | W
    # For all LOAD program headers get mapping to the list of sections,
    # and for each section, remember the flags of the associated program header.
    flags_per_section = {}
    for segment in binary.segments:
        LOAD = segment.type.LOAD if hasattr(segment.type, 'LOAD') else None
        if segment.type == LOAD:
            for section in segment.sections:
                flags_per_section[section.name] = segment.flags
    # Spot-check ELF LOAD program header flags per section
    # If these sections exist, check them against the expected R/W/E flags
    for (section, flags) in flags_per_section.items():
        if section in EXPECTED_FLAGS:
            if int(EXPECTED_FLAGS[section]) != int(flags):
                return False
    return True

def check_ELF_control_flow(binary) -> bool:
    '''
    Check for control flow instrumentation
    '''
    main = binary.get_function_address('main')
    content = binary.get_content_from_virtual_address(main, 4, lief.Binary.VA_TYPES.AUTO)

    if content == [243, 15, 30, 250]: # endbr64
        return True
    return False

def check_PE_DYNAMIC_BASE(binary) -> bool:
    '''PIE: DllCharacteristics bit 0x40 signifies dynamicbase (ASLR)'''
    characteristics = binary.optional_header.dll_characteristics_lists
    if not characteristics:
        return False
    DYNAMIC_BASE = characteristics[0].DYNAMIC_BASE  # Get constant from any char object
    return DYNAMIC_BASE in characteristics

# Must support high-entropy 64-bit address space layout randomization
# in addition to DYNAMIC_BASE to have secure ASLR.
def check_PE_HIGH_ENTROPY_VA(binary) -> bool:
    '''PIE: DllCharacteristics bit 0x20 signifies high-entropy ASLR'''
    characteristics = binary.optional_header.dll_characteristics_lists
    if not characteristics:
        return False
    HIGH_ENTROPY_VA = characteristics[0].HIGH_ENTROPY_VA  # Get constant from any char object
    return HIGH_ENTROPY_VA in characteristics

def check_PE_RELOC_SECTION(binary) -> bool:
    '''Check for a reloc section. This is required for functional ASLR.'''
    return binary.has_relocations

def check_PE_control_flow(binary) -> bool:
    '''
    Check for control flow instrumentation
    '''
    main = binary.get_symbol('main').value

    section_addr = binary.section_from_rva(main).virtual_address
    virtual_address = binary.optional_header.imagebase + section_addr + main

    content = binary.get_content_from_virtual_address(virtual_address, 4, lief.Binary.VA_TYPES.VA)

    if content == [243, 15, 30, 250]: # endbr64
        return True
    return False

def check_MACHO_NOUNDEFS(binary) -> bool:
    '''
    Check for no undefined references.
    '''
    NOUNDEFS = binary.header.FLAGS.NOUNDEFS if hasattr(binary.header, 'FLAGS') else None
    return NOUNDEFS in binary.header.flags_list if NOUNDEFS is not None else False

def check_MACHO_LAZY_BINDINGS(binary) -> bool:
    '''
    Check for no lazy bindings.
    We don't use or check for MH_BINDATLOAD. See #18295.
    '''
    return binary.dyld_info.lazy_bind == (0,0)

def check_MACHO_Canary(binary) -> bool:
    '''
    Check for use of stack canary
    '''
    return binary.has_symbol('___stack_chk_fail')

def check_PIE(binary) -> bool:
    '''
    Check for position independent executable (PIE),
    allowing for address space randomization.
    '''
    return binary.is_pie

def check_NX(binary) -> bool:
    '''
    Check for no stack execution
    '''
    if isinstance(binary, lief.MachO.Binary):
        # For macOS, check heap and stack NX protection specifically
        return binary.has_nx_heap and binary.has_nx_stack
    else:
        return binary.has_nx

def check_MACHO_control_flow(binary) -> bool:
    '''
    Check for control flow instrumentation
    '''
    content = binary.get_content_from_virtual_address(binary.entrypoint, 4, lief.Binary.VA_TYPES.AUTO)

    if content == [243, 15, 30, 250]: # endbr64
        return True
    return False

BASE_ELF = [
    ('PIE', check_PIE),
    ('NX', check_NX),
    ('RELRO', check_ELF_RELRO),
    ('Canary', check_ELF_Canary),
    #('separate_code', check_ELF_separate_code),
    # Note: separate_code can be enabled once release binaries are
    #       created with binutils 2.31 or explicitly configured on
    #       binutils 2.30 with -z,separate-code,
    # see Bitcoin Core commit 2e9e6377
]

BASE_PE = [
    ('PIE', check_PIE),
    ('DYNAMIC_BASE', check_PE_DYNAMIC_BASE),
    #('HIGH_ENTROPY_VA', check_PE_HIGH_ENTROPY_VA),
    # Note: HIGH_ENTROPY_VA can be enabled when all issues with RELOC_SECTION
    #       are solved.
    ('NX', check_NX),
    #('RELOC_SECTION', check_PE_RELOC_SECTION),
    # Note: RELOC_SECTION is newer than our source and currently doesn't pass
    #       on cli tools and tests, but does work for dogecoind / dogecoin-qt
    #('CONTROL_FLOW', check_PE_control_flow),
    # Note: CONTROL_FLOW can be re-enabled when we build with gcc8 or higher
]

BASE_MACHO = [
    ('NOUNDEFS', check_MACHO_NOUNDEFS),
    ('LAZY_BINDINGS', check_MACHO_LAZY_BINDINGS),
    ('Canary', check_MACHO_Canary),
]

def get_arch_checks(binary):
    """Get security checks based on binary format and architecture"""
    if isinstance(binary, lief.ELF.Binary):
        arch = binary.header.machine_type
        if arch in [lief.ELF.ARCH.I386, lief.ELF.ARCH.X86_64]:
            return BASE_ELF  # Remove CONTROL_FLOW until gcc8+
        elif arch in [lief.ELF.ARCH.ARM, lief.ELF.ARCH.AARCH64, lief.ELF.ARCH.PPC, lief.ELF.ARCH.PPC64]:
            return BASE_ELF
        else:
            return BASE_ELF
    elif isinstance(binary, lief.PE.Binary):
        return BASE_PE
    elif isinstance(binary, lief.MachO.Binary):
        arch = binary.header.cpu_type if hasattr(binary.header, 'cpu_type') else None
        # Get the X86_64 constant from the cpu_type object
        X86_64_TYPE = arch.X86_64 if arch and hasattr(arch, 'X86_64') else None
        if arch == X86_64_TYPE:
            return BASE_MACHO + [('PIE', check_PIE), ('NX', check_NX)]
        else:
            return BASE_MACHO
    else:
        return []

if __name__ == '__main__':
    retval: int = 0
    for filename in sys.argv[1:]:
        try:
            binary = lief.parse(filename)
            if binary is None:
                print(f'{filename}: unable to parse')
                retval = 1
                continue

            # Get appropriate checks for this binary
            checks = get_arch_checks(binary)
            if not checks:
                print(f'{filename}: unknown executable format or architecture')
                retval = 1
                continue

            failed: List[str] = []
            for (name, func) in checks:
                if not func(binary):
                    failed.append(name)
            if failed:
                print(f'{filename}: failed {" ".join(failed)}')
                retval = 1
        except IOError:
            print(f'{filename}: cannot open')
            retval = 1
    sys.exit(retval)
