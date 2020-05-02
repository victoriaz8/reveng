# reveng
RevEng project part 2 tool

Description

How to use

Limitations

How to run:

Place the python file in the folder with your ida executables

run: ida64 -S"<path\to\pythonscript> <flag> <flag> <etc>" <path\to\exe>


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

