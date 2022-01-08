"""
GOST - Go binary analysis script (for IDA)
"""
import string

from idaapi import *


# https://github.com/golang/go/blob/b5bfaf410ad4dc329400b92a7818ffec5cd9ebb0/src/cmd/link/internal/ld/pcln.go#L743
# https://github.com/golang/go/blob/b5bfaf410ad4dc329400b92a7818ffec5cd9ebb0/src/runtime/symtab.go#L394
def find_pcln_table():

    print("Find pcln table")
    
    pcln_ea = ida_idaapi.BADADDR
    
    for seg_ea in Segments():
        print("Segment %s @ %08x" % (idc.get_segm_name(seg_ea), seg_ea))
        
        if idc.get_segm_attr(seg_ea, SEGATTR_PERM) & SEGPERM_EXEC:
            print("Segment is executable, skip...")
            continue
            
        seg_end_ea = idc.get_segm_end(seg_ea)
        pcln_magic = '0000FFFFFFFA'
        print("Searching pcln table from %08x to %08x" % (seg_ea, seg_end_ea))
        
        start_ea = seg_ea
        end_ea = seg_end_ea
        while start_ea < end_ea:
            pcln_ea = ida_search.find_binary(start_ea, end_ea, pcln_magic, 16, ida_search.SEARCH_DOWN)
            if pcln_ea == ida_idaapi.BADADDR:
                print("No pcln found, move to next segment...")
                continue
                
            print("Found potential pcln table @ %08x" % (pcln_ea))
            
            ptr_size = Byte(pcln_ea + 0x07)
            print("Ptr size: %x" % (ptr_size))
            
            if ptr_size != 4 and ptr_size != 8:
                print("Wrong ptr size, search next...")
                start_ea = pcln_ea + 0x04
                pcln_ea = ida_idaapi.BADADDR
                continue
                
            break
        
        if pcln_ea != ida_idaapi.BADADDR:
            break
        
    return pcln_ea

def read_str(ea):

    result = ''
    
    for i in range(0, 256):
        ch = Byte(ea + i)
        if ch == 0:
            break
        
        result += chr(ch)

    return result

def process_pcln_info(pcln_ea):

     ptr_size = Byte(pcln_ea + 0x07)
     
     if ptr_size == 4:
        read_ptr = Dword
     elif ptr_size == 8:
        read_ptr = Qword
     else:
        print("Wrong ptr size")
        return
     
     number_of_functions = read_ptr(pcln_ea + 0x08)
     print("number_of_functions: %08x" % (number_of_functions))
     
     number_of_files = read_ptr(pcln_ea + 0x08 + ptr_size * 1)
     print("number_of_files: %08x" % (number_of_files))
     
     funcname_ea = pcln_ea + read_ptr(pcln_ea + 0x08 + ptr_size * 2)
     print("funcname_ea: %08x" % (funcname_ea))
     
     pctable_ea = pcln_ea + read_ptr(pcln_ea + 0x08 + ptr_size * 5)
     print("pctable_ea: %08x" % (pctable_ea))
     
     functable_ea = pcln_ea + read_ptr(pcln_ea + 0x08 + ptr_size * 6)
     print("functable_ea: %08x" % (functable_ea))
     
     for i in range(0, number_of_functions):
        func_addr = read_ptr(functable_ea + i * ptr_size * 2)
        func_table = functable_ea + read_ptr(functable_ea + i * ptr_size * 2 + ptr_size)
        func_name = read_str(funcname_ea + (read_ptr(func_table + ptr_size) & 0xffff))
        print("function @ %08x is %s" % (func_addr, func_name))
        
        if ida_bytes.is_func(func_addr) == False:
            if idc.isCode(func_addr) == False:
                idc.MakeUnkn(func_addr, idc.DOUNK_SIMPLE)
            if idc.MakeFunction(func_addr) == False:
                idc.MakeCode(func_addr)
            
        idc.MakeNameEx(func_addr, func_name, SN_NOCHECK|SN_FORCE)


if __name__ == '__main__':

    pcln_ea = find_pcln_table()
    
    if pcln_ea != ida_idaapi.BADADDR:
        print("Found pcln table @ %08x" % (pcln_ea))
        process_pcln_info(pcln_ea)
    else:
        print("Could not find pcln table")