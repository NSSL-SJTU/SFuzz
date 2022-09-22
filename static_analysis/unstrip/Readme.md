# unstrip

Tool for recovering the symbols of a specific function in unsigned binary


## Usage
```
usage: unstrip [options] target
 -b,--base_address <arg>   Base address for the binary.
 -c,--create               Whether create a project for binary.
 -f,--file <arg>           File name in Ghidra project.
 -l,--language_id <arg>    Language id like x86:LE:32:default
 -O,--output <arg>         Path to save result.
 -p,--project_path <arg>   Path to create project.(Default:tmp)
 -w,--write                Whether write result to the project
```
## Reference commands
```
unstrip build/tmp/image_vx5_arm_little_endian.bin -c -l ARM:LE:32:v7 -b 0x0000001000
unstrip -f image_vx6_arm_little_endian.bin tmp/image_vx6_arm_little_endian.bin.rep
```

## How to compile

Download Ghidra, use the buildGhidraJar script in the Ghidra support directory to generate ghidra.jar, put ghidra.jar into the lib directory, then install gradle and use the gradle jar command to compile the current project
