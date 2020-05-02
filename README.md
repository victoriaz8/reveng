# reveng
RevEng project part 2 tool

Description
[Unnamed] is an automated anti-analysis Analysis tool. This tool statically analyzes a binary for anti-analysis techniques using IDA Python. It turned from a tool to help analyze the Project malware into a tool to analyze Almost Any malware for anti-analysis techniques - so go ahead and try it on other executables! (Excluding limitations, see below)

The tool takes an input executable, assuming it’s not packed, and outputs the locations and number of occurrences that they occur and their contexts. Additionally, the tool will try to locate all the termination conditions that might be considered anti-analysis and locate any notable conditions that causes those terminations.
It also has the functionality to automatically bypass some of these techniques without disrupting functionality of the original program. 
These include:
- Finding various timing anti-analysis techniques
- Finding the conditional branches based off the above, with the option to auto-patch that branch
- Finding anti-debugging techniques, including in-line PEB ProcessHeap accesses for relevant flags 
- Finding the conditional branches based off the above, with the option to auto-patch that branch
- Finding sketchy XOR calls
- Searching strings for a specific term
- Finding int3 locations, with the option to auto-patch them with nops
- Finding Set SEH filter locations and their corresponding calls
- Finding CPUID locations
- For all of the above, finding where the resulting interesting value ends up - 
- Tracing registers forwards and backwards
- Finding termination conditions for process and threads
- Finding whether the process involved is its own process or a different process, via the handle (if known statically)
- Finding conditional branches leading to those terminations
- Finding what the above condition is from - i.e. if it is based off return value from a subroutine/function


How to use
- Read the How to run section below
To do a broad sweep of all techniques, use flag -a
For any specifics, use the appropriate flag
Note that any auto-patch options will modify the binary, so keep a backup if you want to revert or diff
If you want to auto-patch, use 
-p int3 
or
-p patch
or
-p int3 patch
Don't ever do -int3 (for example). The flag parsing could definitely use some work.
-L to log to a file called aa_outfile.txt in the directory that the input executable is in

Limitations
- Architecture is limited to x86 windows executables
- the calling convention must be that eax holds the return value from function calls
- Tracing functions aren't terribly deep, they can analyze fairly simple functions, but not those that purposely obfuscate control flow
- It cannot do any dynamic analysis, thus many values/variables that may be clear at runtime will be unknown and hard to extrapolate statically
- Mainly it does within-subroutine analysis, important registers or data locations that are modified across subroutines are likely overlooked
- Not much in terms of recursive analysis

Future Work
- Give more context for everything that it finds - Right now /most/ of the output is configured for my brain when developing it
- overall make it more readable for the average user!
- Give user more options to make use of the modular functionality within the program
- allow user to input a file of heads and call a tool function on them
- I have some ideas about making it more thorough/able to handle complex flows, including peeking into data at times and keeping track of when/where those memory addresses are being accessed and whether it's READ/WRITE. That seems a bit out of scope for a first-time IDAPython project

Overall thoughts
- I had fun! My brain hurts a bit though. It's one thing to reverse engineer malware, it's another to program your computer to run through your thought process automatically and do it for you, backwards and forwards. Otherwise, I liked this part of the project - I learned a lot! Both about anti-analysis - which I had to do more in depth research on to try and cover as much ground as possible, and also about how IDA Python is a pain in the butt. Especially with spacing - sometimes I'd 'tab' and it'd complain at me until I use three spaces (when the rest of the program is 4 spaces/1 tab).


How to run:
Make sure you have IDA, IDAPython 64-bit v7.4.0 and Python2.7 (yeah I know, sorry) on your system.

Place the python file in the folder with your ida executables

run: `ida64 -S"<path\to\pythonscript> <flag> <flag> <etc>" <path\to\exe>`

```
Flags:
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
    -search <string> # NOT YET IMPLEMENTED
    -t   termination analysis
    -L logs to a file called "aa_outfile.txt" in the directory of input executable
```
