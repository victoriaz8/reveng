import idautils
import idc
import idaapi
import ida_ua
import ida_segment
from ida_funcs import *

auto_patch = 0
num_cpuid = 0
int3_loc = []
cpuid_addrs = {}
debugger_loc= {}
xor_loc     = {}
timing      = {}
seh_loc         = {}
flags = []
""" 
jumpers rules      
JE, JZ = 74
JNE, JNZ = 75

JB, JNAE, JC = 72
JNB, JAE, JNC = 73

JBE, JNA = 76
JA, JNBE = 77

JL, JNGE = 7C
JGE, JNL = 7D

JLE, JNG = 7E
JG, JNLE = 7F

JP, JPE = 7A
JNP, JPO = 7B

if byte is between 0x72 and 0x7F
if byte is even, add 1
if byte is odd,  sub 1
    
"""    
#https://www.somersetrecon.com/blog/2018/7/6/introduction-to-idapython-for-vulnerability-hunting     
        
### rly dumb flag helper funcs that i need to keep my brain functional

def int3_flags():
    if "-a" in flags or "-i" in flags:
        return True
    else:
        return False

def dbg_flags():
    if "-a" in flags or "-d" in flags:
        return True
    else:
        return False       

def time_flags():
    if "-a" in flags or "-t" in flags:
        return True
    else:
        return False          

def seh_flags():
    if "-a" in flags or "-s" in flags:
        return True
    else:
        return False 

def cpuid_flags():
    if "-a" in flags or "-c" in flags:
        return True
    else:
        return False   

def xor_flags():
    if "-a" in flags or "-x" in flags:
        return True
    else:
        return False           

def term_flags():
    if "-a" in flags or "-f" in flags:
        return True
    else:
        return False           


###### end rly dumb helper funcs that i need to keep my brai nfunctional


def hijack(addr):   
    orig = GetDisasm(addr)
    # print(orig)
    if("j" in print_insn_mnem(addr)):
        # patch to be opposite instruction - see jumper table above
        byte = ida_bytes.get_byte(addr)
        if(byte % 2):
            # is odd
            patch_byte(addr, byte-1)
        else:
            # is even
            patch_byte(addr, byte+1)
        # print(GetDisasm(addr))
    return "nice"

def hijack_int3(addr):   
    patch_byte(addr, 0x90)
    return "nice"
    
def findthejump(head):
    hd = head
    while(print_insn_mnem(hd) not in "retn"):
        if("j" in print_insn_mnem(hd)):
            return hd
        hd = next_head(hd)
    return 0

def trace_reg(start, target):
#tries to find where the target value ends up - ideally where the cmpare is
    head = start
    curr = target
    elsewhere = []
    #print("\nstart addr: " + " " + "0x%08x"%(head))
    while(print_insn_mnem(head) not in "retn"):    
        head = next_head(head)
        #test curr curr,cmp curr x or cmp x curr
        if(print_insn_mnem(head) in "test" or print_insn_mnem(head) in "cmp"):
            if(print_operand(head, 0) in curr or print_operand(head, 1) in curr):
                print("comparing containing register")
                jump = findthejump(head)
                if isinstance(jump, int):
                    print("no jump before return, idk")
                    break
                # else, sucess
                if auto_patch is 1:
                    hijack(jump)
                break

        # case store
        
        # case mov
        elif(print_insn_mnem(head) in "mov"):
            # subcase mov: if target is operand 0, we've lost it. return with info
            if(print_operand(head, 0) in curr and not print_operand(head, 1) in curr):
                break
                
            if(print_operand(head, 1) in curr):
                curr = print_operand(head, 0)     
                continue
                    
        # case push - note as well as act on it
        elif(print_insn_mnem(head) in "push"):
            if(print_operand(head, 0) in curr):
                # target is now on the stack.
                elsewhere.append("stack: esp")
                
        elif(print_operand(head, 0) in curr):        
            #we're lost it again.
            break
    #print("traced to: " + str(curr))
    return (curr, elsewhere)
    
    
def start():
    print("\n\n------------------------")
    print("\nyee let's get this party started")
    print("------------------------\n")
    
def cpuid():
    print("analyzing cpuid anti-analysis")
    # find values in eax if possible to determine which anti-vm strat
    for hd in cpuid_addrs:
        func = cpuid_addrs[hd]
        end = get_func_attr(func, FUNCATTR_END)
        hds = idautils.Heads(func, end)
        first_hd = hds.next()
        ph = prev_head(hd, func)
        eax_val = "None"
        eax = 0         
        while(ph != first_hd): 
            if print_operand(ph, 0) in "eax":
                if(print_insn_mnem(ph) in "xor"):
                    if eax_val is "None":
                        eax_val = "yep"                    
                        eax = 0
                    elif eax_val != "None":
                        eax = eax
                    break
                elif(print_insn_mnem(ph) in "pop"):
                    # find the last push?
                    while(ph != first_hd):
                        ph = prev_head(ph)
                        if print_insn_mnem(ph) in "push":
                            eax = eax + int(print_operand(ph, 0))
                            eax_val = "yep"
                            break
                    break                
                elif(print_insn_mnem(ph) in "mov"):
                    eax_val = "yep"                                            
                    eax = print_operand(ph, 1)
                    #todo?
                    break                
                elif(print_insn_mnem(ph) in "inc"):
                    eax_val = "yep"                
                    eax = eax + 1                                       
            ph = prev_head(ph)

        if(eax_val is "None"):
            eax = "<unknown>"
        # print("cpuid at 0x%08x"%(hd) + ": eax is " + str(eax))

    # TODO : elaborate - output information on which registers are being accessed 
    # TODO : try to find what values are being stored or compared against     
    
    

def find_timing(hd):
    # possible timing checks
    ins = GetDisasm(hd)
    if "rdtsc" in ins:
        if("rdtsc" in timing):
            timing['rdtsc'].append((hd))
        else:
            timing['rdtsc'] = []
            timing['rdtsc'].append((hd))
        
    elif "GetTickCount" in ins:
        if("GetTickCount" in timing):
            timing['GetTickCount'].append((hd))
        else:
            timing['GetTickCount'] = []
            timing['GetTickCount'].append((hd))
            
    elif "TickCountMultiplier" in ins:
        if("TickCountMultiplier" in timing):
            timing['TickCountMultiplier'].append((hd))
        else:
            timing['TickCountMultiplier'] = []
            timing['TickCountMultiplier'].append((hd))
        
    elif "TickCountLow" in ins:
        if("TickCountLow" in timing):
            timing['TickCountLow'].append((hd))
        else:
            timing['TickCountLow'] = []
            timing['TickCountLow'].append((hd))
                        
    elif "QueryPerformanceCounter" in ins:
        if("QueryPerformanceCounter" in timing):
            timing['QueryPerformanceCounter'].append((hd))
        else:
            timing['QueryPerformanceCounter'] = []
            timing['QueryPerformanceCounter'].append((hd))
        

def seh(hd):
    #todo "UnhandledExceptionFilter" in ins
    ins = print_insn_mnem(hd)
    # find where it's installed
    if "SetUnhandledExceptionFilter" in ins:
        if("SetUnhandledExceptionfilter" in seh_loc):
            seh_loc["SetUnhandledExceptionFilter"].append((hd))
        else:
            seh_loc["SetUnhandledExceptionFilter"] = []
            seh_loc["SetUnhandledExceptionFilter"].append((hd))
    elif "UnhandledExceptionFilter" in ins:
        if("UnhandledExceptionFilter" in seh_loc):
            seh_loc["UnhandledExceptionFilter"].append((hd))
        else:
            seh_loc["UnhandledExceptionFilter"] = []
            seh_loc["UnhandledExceptionFilter"].append((hd))
        
    elif "push" in ins and "fs:" in ins:
        # evil subroutine pushed immediately before, but check first
        # this is the code that malware wants to trigger on exception
        prev = hd
        function_head = GetfunctionAttr(prev, idc.FUNCATTR_START)
        while(prev != function_head):
            prev = prev_head(prev)
            if print_insn_mnem(prev) in "push":
                # get actual address, if it's an address
                pushed_addr = get_operand_value(prev, 0)
                # add to structure
                seh_loc[hd] = ["0x%08x"%(hd), pushed_addr, print_operand(prev, 0)]
                # todo? more analysis necessary?
                return

def inline_beingdebugged(hd):
    """
        looking for something like this:
        mov     eax, large fs:30h
        movzx   eax, byte ptr [eax+2]

        OR

        mov     eax, large fs:30h
        movzx   eax, byte ptr [eax+18h] (ProcessHeap) 
        cmp dword ptr ds:[eax+10h], 0 (ForceFlags field) (10h winxp, 0x44h win7)

        OR
        NtGlobalFlag @ offset 0x68 (if value is 0x70)
    """

    if ("fs:30h" in print_operand(hd, 1) or "fs:0x30" in print_operand(hd, 1)) and "mov" in print_insn_mnem(hd):
        op = print_operand(hd, 0)
        op_list = [op + "+2", op + "0x02", op + "0x2", op + "+18h", op + "+24", op + "+68h", op+"104"]   

        next_hd = next_head(hd)
        op2 = print_operand(next_hd, 1)
        for new_op in op_list:
            if new_op in op2 and "mov" in print_insn_mnem(next_hd):
                if(new_op is op_list[3] or new_op is op_list[3]):
                    # if it's querying the Process Heap, check for Force Flags and Flags field
                    op = print_operand(next_hd, 0)
                    next_hd = next_head(hd)
                    
                    op2 = print_operand(next_hd, 1)
                    if op2 in (op + "0xc") or op2 in (op + "12") or op2 in (op + "ch") or op2 in (op + "0x0c"):
                        # PEB.ProcessHeap.Flags
                        if new_op in debugger_loc:                    
                            debugger_loc["PEB.ProcessHeap.Flags"].append(next_hd)
                        else:
                            debugger_loc["PEB.ProcessHeap.Flags"] = []
                            debugger_loc["PEB.ProcessHeap.Flags"].append(next_hd)
                        trace_reg(next_hd, print_operand(next_hd, 0))
                        return
                    elif op2 in (op + "0x10") or op2 in (op + "10h") or op2 in (op + "16"):
                        # PEB.ProcessHeap.ForceFlags
                        if new_op in debugger_loc:                    
                            debugger_loc["PEB.ProcessHeap.ForceFlags"].append(next_hd)
                        else:
                            debugger_loc["PEB.ProcessHeap.ForceFlags"] = []
                            debugger_loc["PEB.ProcessHeap.ForceFlags"].append(next_hd)              
                        trace_reg(next_hd, print_operand(next_hd, 0))
                        return
                else:
                    # 0x68 is PEB.NtGlobalFlag, 0x2 is IsDebugged flag
                    if new_op in debugger_loc:
                        debugger_loc[new_op].append(next_hd)
                    else:
                        debugger_loc[new_op] = []
                        debugger_loc[new_op].append(next_hd)
                    trace_reg(next_hd, print_operand(next_hd, 0))
                    return                

        return True

    return False


def anti_debug(hd):
    # todo: http://unprotect.tdgt.org/index.php/Anti-debugging
    if inline_beingdebugged(hd):
        return
    operand = str(print_operand(hd, 0))
    if "call" in idc.print_insn_mnem(hd):       
        # WinAPI Debugger detection     
        if "Debugger" in operand or "OutputDebugString" in operand:  
            if operand in debugger_loc:
                debugger_loc[operand].append(hd)
            else:
                debugger_loc[operand] = []
                debugger_loc[operand].append(hd)
            trace_reg(hd, "eax")    
            return
        # Debugger Detection
        if "FindWindow" in operand or "FindProcess" in operand or "BadStringFormat" in operand:
            if operand in debugger_loc:
                debugger_loc[operand].append(hd)
            else:
                debugger_loc[operand] = []
                debugger_loc[operand].append(hd)
            trace_reg(hd, "eax") 
            return      

def term():
    names = Names()
    seg = Segments()
    #print("0x%08x"%(next(seg)))
    while True:
        try:
            name = next(names)
            if "ExitProcess" in name[1] or "TerminateProcess" in name[1] or "ExitThread" in name[1] or "_endthread" in name[1]:
                print("-----" + name[1] + "-----")
                xrefs = XrefsTo(name[0])
                for xref in xrefs:
                    print(xref.type, XrefTypeName(xref.type), 'from', "0x%08x"%(xref.frm), 'to', "0x%08x"%(xref.to))
        except StopIteration:
            break        
        
    # search in strings for potential exit functions
    slist = search_strings("Exit")    
    for s in slist:
        xrefs = XrefsTo(s.ea)
        for x in xrefs:
            print(x.type, XrefTypeName(x.type), 'from', "0x%08x"%(x.frm), 'to', "0x%08x"%(x.to))
            
    # TODO next step - for each xref, determine if 
    # exit CURRENT process or OTHER process
    # get currentprocessid is a "hint" to own process

def init_strings():
    # look for xrefs to AppPolicyGetProcessTerminationMethod
    # look for xrefs to data containing "exit"
    sc = idautils.Strings()
    return sc

def search_strings(term):
    # return a list of strings w/ term in it
    strlist = []
    for s in strlist:
        if lower(term) in lower(str(s)):
            strlist.append(s)
            print "%x: len=%d-> '%s'" % (s.ea, s.length, str(s))
    return strlist            

def parse_args(argv):
    p = 0
    for arg in argv:
        if "-p" in arg:
            p = 1
            continue
        elif arg[0] is "-":
            flags.append(arg)
        elif "int3" in arg or "timing" in arg or "debug" in arg:
            flags.append(arg)
    for f in flags:
        print(f) 

def main_loop():
    nc = 0
    for func in Functions():
        end = get_func_attr(func, FUNCATTR_END)
        hds = idautils.Heads(func, end)
        for hd in hds:
            ins = idc.print_insn_mnem(hd)
            if cpuid_flags() and "cpuid" in ins:  
                nc = nc+1        
                #print(get_func_name(func))
                cpuid_addrs[hd] = func
            # possible encryption
            elif xor_flags() or "xor" in ins:
                src = print_operand(hd, 0)
                dst = print_operand(hd, 1)
                if src != dst:
                    xor_loc[hd] = [src, dst, func]   
                    # "0x%08x"%(hd)

            elif int3_flags() and ida_bytes.get_byte(hd) is 0xCC:                
                int3_loc.append(hd)
                if "int3" in flags:
                    hijack_int3(hd)

            #debugger checks
            if(dbg_flags):
                anti_debug(hd)
            if(time_flags):
                find_timing(hd)
            if(seh_flags):
                seh(hd)

                # todo - if these exist, find if malware counts them?
    return nc

def main():
    # run: ida64 -S"<path\to\script> <flag> <flag> <etc>" <path\to\exe>
    """
    flags:
    -a  all (except patch)
    -p  <type> (autopatch - see below)
        int3   replace int3 with nop
        timing replace jumps from timing/etc with opposite jump
        debug  replace jumps from debug/etc with opposite jump 
    -j  ??
    -t  timing
    -i  int3
    -c  cpuid
    -s  seh
    -d  debug
    -x  xor
    -term   termination analysis
    -log <file>
    """
    # -A ?
    # TODO: log to file
    # or idat.exe
    # flags: idc.ARGV 
    """
    print(timing)
    print(xor_loc)
    print(seh_loc)
    print(debugger_loc)
    if(num_cpuid != 0):
        print("cpuids")
        for c in cpuid_addrs:
            print("0x%08x"%(c))
    """
    """
    init_strings()
    search_strings("crss")
    term()
    """   
    start()
    parse_args(idc.ARGV)
    num_cpuid = main_loop()

    if cpuid_flags():
        cpuid()
    if term_flags():
        init_strings()
        term()
    
if __name__ == "__main__":
    main()

"""
from idc import *
idc.exit()
"""