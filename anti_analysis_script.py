import idautils
import idc
import idaapi
import ida_ua
import ida_segment
from ida_funcs import *

###### Globals ######

num_cpuid = 0
fp = 0
int3_loc = []
cpuid_addrs = {}
debugger_loc= {}
xor_loc     = {}
timing      = {}
seh_loc     = {}
terminate_process = {} # list of (head, hprocesshandle, jump_result) tuples
flags = []
outfile = "aa_outfile.txt"
###### End Globals ######

""" 
jumpers table rules

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
     

###### rly dumb flag helper funcs that i need to keep my brain functional ######

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
       
def patch_flags():
    if "patch" in flags:
        return True
    else:
        return False


###### end rly dumb helper funcs that i need to keep my brai nfunctional

###### Other helpers ######    
def start():
    log("\n\n###########################")
    log("\nyee let's get this party started")
    log("###########################\n")

def finish():
    log("\n\n##############	Analysis Finished	#############\n")


def is_jump(hd):
	byte = ida_bytes.get_byte(hd)
	if (byte >= 0x72) and (byte <= 0x7F):
		return True
	return False

def log(*string):
    if "-L" in flags:
        fp = open(outfile, "a+")
        for s in string:
            if type(s) is dict:
                if "TerminateProcess" in s:
                    for key in terminate_process.keys():
                        fp.write("### " + str(key) + "###\n")
                        if key in "TerminateProcess" and "imp" not in key:
                            fp.write("xref type\t|\txref\t|\thProcess\t|\tjumploc\t|\tcond.loc\t|\tsource\n")
                        else:
                            fp.write("xref type\t|\txref\n")
                        for each in terminate_process[key]:
                            for e in each:
                                fp.write(str(e) + "\t\t")
                            fp.write("\n")


                    continue
                for key in s.keys():
                    fp.write(str(key) + ": " + str(s[key]))
                    fp.write("\n")
            else:
                fp.write(str(s))
                fp.write("\n")
        fp.close()
            
			
    for s in string:
        if type(s) is dict:
            for key in s.keys():
                print(str(key) + ": " + str(s[key]))
        else:
            print(s)

def log_results():
    if cpuid_flags():
        log("\n##### CPUID contexts:")
        log(cpuid_addrs)

    if int3_flags():
        log("\n##### INT3 instructions found: " + str(len(int3_loc)))
        log("##### INT3 contexts:")
        #log(int3_loc)
        for i in int3_loc:
            log("0x%08x"%(i))

    if dbg_flags():
        log("\n##### Anti-Debugger anti-analysis contexts:")
        log("For reference:")
        log("offset 0x68: NtGlobalFlag")
        log("offset 0x2: inline IsBeingDebugged flag")
        log("offset 0xc: PEB.ProcessHeap.Flags")
        log("offset 0x10: PEB.ProcessHeap.ForceFlags \n")
        for key in debugger_loc.keys():  
            log("## " + key)
            for item in debugger_loc[key]:
                log("0x%08x"%(item))
        log(debugger_loc)

    if xor_flags():
        log("\n##### Fishy XOR anti-analysis contexts:")
        log("head:\tsrc\tdst\tfunc loc\txor loc")
        log(xor_loc)	

    if time_flags():
        log("\n##### Time-based anti-analysis contexts:")
        log(timing)

    if seh_flags():
        log("\n##### SEH anti-analysis contexts:")
        log(seh_loc)
        
    if term_flags():
        log("\n##### Termination condition analysis")
        log(terminate_process)
        # (XrefTypeName(xref.type), xref.frm, retval, jump_result))
                      

def parse_args(argv):
    p = 0
    log(argv)
    file = 0
    for i in range(len(argv)):
        if "-p" in argv[i]:
            p = 1
        if argv[i][0] is "-":
            flags.append(argv[i])
        elif "int3" in argv[i] or "patch" in argv[i]:
            flags.append(argv[i])
        if "-L" in argv[i]:
            fp = open(outfile, "w+")
            log("Writing to: " + outfile)
            fp.close()
        i = i+1

    for f in flags:
        log(f)     

def init_strings():
    # look for xrefs to AppPolicyGetProcessTerminationMethod
    sc = idautils.Strings()
    return sc        

###########################

# patch jump to do opposite - see jumper table above
def hijack(addr):   
    orig = GetDisasm(addr)
    # log(orig)
    if is_jump(addr):        
        byte = ida_bytes.get_byte(addr)
        if (byte >= 0x72) and (byte <= 0x7F):	        
	        if(byte % 2):
	            # is odd
	            patch_byte(addr, byte-1)
	        else:
	            # is even
	            patch_byte(addr, byte+1)
	        # log(GetDisasm(addr))
	        return "nice"


def hijack_int3(addr):   
    patch_byte(addr, 0x90)
    return "nice"
    
def findthejump(head):
    hd = head
    while(print_insn_mnem(hd) not in "retn"):
        if is_jump(hd):
            return hd
        hd = next_head(hd)
    return 0

def trace_back(head, target):
	# target is a register
	reg = target
	hd = head
	function_head = get_func_attr(hd, idc.FUNCATTR_START)
	while(hd != function_head):
		hd = prev_head(hd)
		# if reg/target is 'al' or 'eax', find the latest 'call'
		if reg in "al" or reg in "eax":
			if print_insn_mnem(hd) in "call":
				return print_operand(hd, 0)		
		# if reg/target is operand 0, and op1 is not a reg, return op1
		if print_operand(hd, 0) in reg and print_insn_mnem(hd) in "mov":
			if get_operand_type(hd, 1) != o_reg:
				return print_operand(hd, 1)
			else:
				reg = print_operand(hd, 1)

def trace_reg(start, target):
# forward
#tries to find where the target value ends up - ideally where the cmpare is
    head = start
    curr = target
    elsewhere = []
    #log("\nstart addr: " + " " + "0x%08x"%(head))
    while(print_insn_mnem(head) not in "retn"):    
        head = next_head(head)
        #test curr curr,cmp curr x or cmp x curr
        if(print_insn_mnem(head) in "test" or print_insn_mnem(head) in "cmp"):
            if(print_operand(head, 0) in curr or print_operand(head, 1) in curr):
                jump = findthejump(head)
                if isinstance(jump, int):
                    log("no jump before return, idk")
                    break
                # else, sucess
                if patch_flags():
                    print("hijacking")
                    hijack(jump)
                break
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
    #log("traced to: " + str(curr))
    return (curr, elsewhere)
   
    
def cpuid():
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
        # log("cpuid at 0x%08x"%(hd) + ": eax is " + str(eax))

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
        function_head = get_func_attr(prev, idc.FUNCATTR_START)
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
                        res = trace_reg(next_hd, print_operand(next_hd, 0))
                        tolog = "PEB.ProcessHeap.Flags value from " + "0x%08x"%(hd) + " traced to: " + str(res[0])
                        log(tolog)
                        return
                    elif op2 in (op + "0x10") or op2 in (op + "10h") or op2 in (op + "16"):
                        # PEB.ProcessHeap.ForceFlags
                        if new_op in debugger_loc:                    
                            debugger_loc["PEB.ProcessHeap.ForceFlags"].append(next_hd)
                        else:
                            debugger_loc["PEB.ProcessHeap.ForceFlags"] = []
                            debugger_loc["PEB.ProcessHeap.ForceFlags"].append(next_hd)              
                        res = trace_reg(next_hd, print_operand(next_hd, 0))
                        tolog = "PEB.ProcessHeap.ForceFlags value from " + "0x%08x"%(hd) + " traced to: " + str(res[0])
                        log(tolog)
                        return
                else:
                    # 0x68 is PEB.NtGlobalFlag, 0x2 is IsDebugged flag
                    if new_op in debugger_loc:
                        debugger_loc[new_op].append(next_hd)
                    else:
                        debugger_loc[new_op] = []
                        debugger_loc[new_op].append(next_hd)
                    res = trace_reg(next_hd, print_operand(next_hd, 0))
                    tolog = str(new_op) + " value from " + "0x%08x"%(hd) + " traced to: " + str(res[0])
                    log(tolog)
                    return                

        return True

    return False


def anti_debug(hd):
    #  http://unprotect.tdgt.org/index.php/Anti-debugging
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

def find_jump_to(hd):
	# for terminate/end process, findwhere the jump was and what it was tested on
	head = hd
	function_head = get_func_attr(head, idc.FUNCATTR_START)
	source = "<unknown>"
	while(head != function_head):
		head = prev_head(head)
		r = CodeRefsTo(head, 1)
		if r:
			for ref in r:
			    if is_jump(ref):
			        #log("curr: 0x%08x"%(head) + " jump ref: 0x%08x"%(ref) + " jumps to: " + "0x%08x"%(get_operand_value(ref, 0)))
			        # examine instructiion right before jump
			        head = prev_head(head)
			        head = prev_head(head)
			        op0 = print_operand(head, 0)
			        op1 = print_operand(head, 1)
			        if(print_insn_mnem(head) in "test"):
			        	if(print_operand(head, 0) in print_operand(head, 1)):
			        		# it's testing if operand is 0
			        		# now get the operand
			        		if(get_operand_type(head, 1) is o_reg):
			        			regnum = get_operand_value(head, o_reg)
			        			# if it's eax or al (0 or 16) check for a "call" recently
			        			# which is done in trace_back
			        			if regnum is 0 or regnum is 16:
			        			    source = trace_back(head, op0)
			        		operands = (op0, op1)			        			    
			        elif(print_insn_mnem(head) in "cmp"):
						if(op0 in "eax" or op0 in "al"):
							source = trace_back(head, op0)
						elif(op1 in "eax" or op1 in "al"):
							source = trace_back(head, op1)
					# return (jumploc, conditionalloc, source)
			        return ("0x%08x"%(ref), "0x%08x"%(head), source) 
	return ("<unk>", "<unk>", "<unk>")

def find_hProcess_handle(hd):
	head = hd
	# function_head = get_func_attr(hd, idc.FUNCATTR_START)
	head = prev_head(head) 	
	if print_insn_mnem(head) in "mov" and "[esp" in print_operand(head, 0):
	    handle = print_operand(head, 1)
	    if(get_operand_type(head, 1) is o_reg):
	       handle = trace_back(head, print_operand(head, 1))
	    return handle

def find_related_process(hd):
	"""
	GetCurrentProcessId
	OpenProcess
	CreateProcessA
	"""
	process_funcs = ["GetCurrentProcessId", "OpenProcess", "CreateProcess"]
	head = hd
	function_head = get_func_attr(head, idc.FUNCATTR_START)
	while(head != function_head):
		head = prev_head(head)
		if print_insn_mnem(head) in "call":
			for func in process_funcs:
			    if str.lower(func) in str.lower(GetDisasm(head)):                    
					if func is "GetCurrentProcessId":
						log("0x%08x"%(function_head) + " Function includes 'GetCurrentProcessId': Likely Terminating own process")
					elif func is "CreateProcess":
						log("0x%08x"%(function_head) + " Function includes 'CreateProcess': Likely Terminating a Created process")
					else:
					    log("0x%08x"%(function_head) + " Function includes 'OpenProcess': Possibly Terminating a different process")
	return

def term():
    names = Names()
    seg = Segments()
    #log("0x%08x"%(next(seg)))
    while True:
        try:
            name = next(names)
            if "ExitProcess" in name[1] or "ExitThread" in name[1] or "_endthread" in name[1] or "exit" in name[1]:
                xrefs = XrefsTo(name[0])
                if name[1] not in terminate_process:                    
                    terminate_process[name[1]] = []
                
                for xref in xrefs:
                    terminate_process[name[1]].append((XrefTypeName(xref.type), "0x%08x"%(xref.frm)))

            elif ("TerminateProcess" in name[1]):
            	if name[1] not in terminate_process:                    
                	terminate_process[name[1]] = []
                    
                xrefs = XrefsTo(name[0]) 				
                for xref in xrefs:
 				   find_related_process(xref.frm)
 				   retval = find_hProcess_handle(xref.frm)
 				   jump_result = find_jump_to(xref.frm) 				   
 				   terminate_process[name[1]].append((XrefTypeName(xref.type), "0x%08x"%(xref.frm), retval, jump_result[0], jump_result[1], jump_result[2]))
        except StopIteration:
            break        
        
    # search in strings for potential exit functions
    slist = search_strings("Exit")    
    for s in slist:
        xrefs = XrefsTo(s.ea)
        for x in xrefs:
            log(x.type, XrefTypeName(x.type), 'from', "0x%08x"%(x.frm), 'to', "0x%08x"%(x.to))
                  

def search_strings(term):
    # return a list of strings w/ term in it
    log("### Search results for term: " + term)
    strlist = []
    for s in strlist:
        if lower(term) in lower(str(s)):
            strlist.append(s)
            log("%x: len=%d-> '%s'" % (s.ea, s.length, str(s)))
    return strlist            

def main_loop():
    nc = 0
    for func in Functions():
        end = get_func_attr(func, FUNCATTR_END)
        hds = idautils.Heads(func, end)
        for hd in hds:
            ins = idc.print_insn_mnem(hd)
            if cpuid_flags() and "cpuid" in ins:  
                nc = nc+1        
                #log(get_func_name(func))
                cpuid_addrs[hd] = func
            # possible encryption
            if xor_flags() and "xor" in ins:
                src = print_operand(hd, 0)
                dst = print_operand(hd, 1)
                if src != dst:
                    xor_loc[hd] = [src, dst, "0x%08x"%(func), "0x%08x"%(hd)]   
                    # "0x%08x"%(hd)

            if int3_flags() and ida_bytes.get_byte(hd) is 0xCC:
                int3_loc.append(hd)
                if "int3" in flags:
                    hijack_int3(hd)
              	# todo - if these exist, find if malware counts them?
            #debugger checks
            if(dbg_flags):
                anti_debug(hd)
            if(time_flags):
                find_timing(hd)
            if(seh_flags):
                seh(hd)  
    return nc

def main():
    # run: ida64 -S"<path\to\script> <flag> <flag> <etc>" <path\to\exe>
    """
    flags:
    -a  all (except patch)
    -p  <type> (autopatch - see below)
        int3   replace int3 with nop
        patch replace jumps from timing and debug with opposite jump        
    -t  timing
    -i  int3
    -c  cpuid
    -s  seh
    -d  debug
    -x  xor
    -search <string>
    -term   termination analysis
    -L logs to directory of input executable
    # TODO: better flag parsing
    """
    # or idat.exe
    start()
    fp = 0
    parse_args(idc.ARGV)
    print(flags)
    num_cpuid = main_loop()
    print(int3_loc)
    if cpuid_flags():
        cpuid()
    if term_flags():
        init_strings()
        term()

    # close file pointer if it's been opened
    if fp:
    	fp.close()

    log_results()
    finish()

if __name__ == "__main__":
    main()

"""
from idc import *
idc.exit()
"""