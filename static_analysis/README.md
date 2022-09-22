## Static Analysis
Perform taint analysis on the specified firmware, slice and patch the program for the taint analysis results.

This part uses the firmware collection in the evaluation_set folder as input.

### Instructions for running this tool

1. Download Ghidra (we use version 9.2.3).
2. Change MAXMEM=2G to MAXMEM=4G in the analyzeHeadless file in the support directory of Ghidra folder.
3. `sudo apt install openjdk-11-jdk`
4. Place each file in a specific directory according to run.sh or modify run.sh according to the file location.
5. Run run.sh for a single firmware or run run_all.py for the entire firmware set.

### Directories
```
├── README.md
├── findbase         #  Tool to discover the base address for firmware loading
├── unstrip          #  Tool for recovering the symbols of a specific function in unsigned binary
├── unstrip_from_log #  Tools for recovering function symbols based on information in the log function
├── statistics_script#  Scripts for supporting statistics
├── evaluation_set   #  Unpacked firmware collection
├── findtrace_output #  Static analysis results for firmware in evaluation_set
├── findtrace.py     #  Ghidra script that performs taint analysis and outputs slices and patches
├── run.sh           #  Shell scripts for processing individual firmware
├── run_all.py       #  Python script for batch processing of multiple firmware
└── setbase.py       #  Ghidra script for setting the base address for firmware loading
```

### Run

#### For processing individual firmware
**Be sure to modify run.sh according to the actual file location before you run it**
```
sudo ./run.sh firmware_path  arch  base_addr
```
example: 
```
sudo ./run.sh evaluation_set/DIR-100/30_DIR100 MIPS:BE:32:default 0x80000100
```
#### For batch processing of multiple firmware
```
sudo python3 run_all.py
```
#### Output
Most of the files end with an underscore and a number, which represents the number of the call tree corresponding to the current file.
```
30_DIR100_result/
├── call_checksum_0  # Address of checksum function calls
├── .......
├── call_checksum_7
├── calltrace_0      # Results of call trace in call tree
├── ........
├── calltrace_7
├── cbranch_info_0   # Jumping information at the branch
├── ........
├── cbranch_info_7
├── dict_0           # String information on the call tree (used to add to the AFL dictionary)
├── ........
├── dict_7
├── exec_0           # Contextual information used for fuzzing (source address and sink address, etc.)
├── ........
├── exec_7
├── patch_0          # Patch results for function calls or branches
├── ........
├── patch_7
├── sink_buf_0       # Information about the sink function address and its corresponding buffer
├── ........
├── sink_buf_7
├── stack_retaddr_0  # Return address information on the stack
├── ........
├── stack_retaddr_7
├── summary          # Statistical Information
├── summary.json
├── xalloc_0         # Cross-reference information for the alloc function
├── ........
└── xalloc_7
```