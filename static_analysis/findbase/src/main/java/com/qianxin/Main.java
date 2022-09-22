package com.qianxin;
import com.qianxin.core.ProgramInfo;
import com.qianxin.helper.Finder;
import com.qianxin.utils.ColoredPrint;
import com.qianxin.utils.StringsUtils;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.PartitionCodeSubModel;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.RefType;
import ghidra.util.exception.CancelledException;
import org.apache.commons.cli.*;
import org.json.JSONArray;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

public class Main {

    private static CommandLine commandLine;
    private static String GhidraProjectSuffix = "rep";

    public static void main(String[] args) {

        long startTime=System.currentTimeMillis();
        initCliArgs(args);

        System.out.println("--------start findbase--------");

        if (commandLine.hasOption("output")) {
            String timeCostFilePath = commandLine.getOptionValue("output") + ".timecost";
            BufferedWriter bw = null;
            try {
                bw = new BufferedWriter(new FileWriter(timeCostFilePath));
                bw.write(String.valueOf(startTime) + "\n");
                findbase(args);
                long endTime=System.currentTimeMillis();
                bw.write(String.valueOf(endTime) + "\n");
            } catch (IOException e) {
                ColoredPrint.errorPrint("Fail to save result.");
            } finally {
                if (bw != null) {
                    try{
                        bw.close();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        } else {
            findbase(args);
        }
    }

    private static void findbase(String[] args) {
        String languageId = null;
        String filename = null;
        String projectPath = null;
        boolean isCreate = false;
        if (commandLine.hasOption("language_id")) {
            languageId = commandLine.getOptionValue("language_id");
        }
        if (commandLine.hasOption("file")) {
            filename = commandLine.getOptionValue("file");
        }
        if (commandLine.hasOption("create")) {
            isCreate = true;
        }
        if (commandLine.hasOption("project_path")) {
            projectPath = commandLine.getOptionValue("project_path");
        }
        boolean accurateMode = false;
        if (commandLine.hasOption("accurate")) {
            accurateMode = true;
        }
        File targetFile = new File(commandLine.getArgs()[0]);
        ProgramInfo programInfo = null;
        try {
            programInfo = new ProgramInfo(targetFile.getPath(),languageId,filename,isCreate,projectPath);
            Program program = programInfo.getProgram();
            if (program == null) {
                ColoredPrint.errorPrint("Load program failed.");
                System.exit(1);
            }

            System.out.println("Creating more strings.");

            new StringsUtils(program).createMoreString();

            System.out.println("Begin do disassemble.");
  
            doDisassemble(program);

            System.out.println("Begin finding image base.");
            Finder finder = new Finder(program,accurateMode);
            Long baseOffset = finder.findBase();
            String resultStr = "";
            if (baseOffset != null) {
                resultStr = String.format("base addr is 0x%x",baseOffset);
                if (finder.isHighConfidence()) {
                    resultStr += " (High Confidence).";
                } else {
                    resultStr += " (MayBe).";
                }
            } else {
                resultStr = "Can't find base addr.";
            }
            System.out.println(resultStr);
            if (commandLine.hasOption("output")) {
                storeRes(resultStr,commandLine.getOptionValue("output"));
            }
        } catch (IOException e) {
            ColoredPrint.errorPrint("Load target file failed.");
            System.exit(1);
        } finally {
            if (programInfo != null) {
                programInfo.close();
            }
        }
    }

    private static void storeRes(String resultStr, String savePath) {
        BufferedWriter bw = null;
        try {
            bw = new BufferedWriter(new FileWriter(savePath));
            bw.write(resultStr);
        } catch (IOException e) {
            ColoredPrint.errorPrint("Fail to save result.");
        } finally {
            if (bw != null) {
                try{
                    bw.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }


    private static void doDisassemble(Program program) {
        System.out.printf("Found %d instructions before disassemble.\n", program.getListing().getNumInstructions());
        //try to createFunction after terminals.
        FlatProgramAPI flatApi = new FlatProgramAPI(program);
        int pointSize = program.getDefaultPointerSize();
        Long maxOffset = program.getMaxAddress().getOffset();
        int txId = program.startTransaction("findIns");
        try {
            Address currentAddr = program.getMinAddress();
            int failedCount = 0;
            while(currentAddr != null) {
                Instruction currentIns = flatApi.getInstructionAt(currentAddr);
                boolean disasseSuccFlag = false;
                if (currentIns == null) {
                    try {
                        DisassembleCommand cmd = new DisassembleCommand(currentAddr,null,false);
                        cmd.applyTo(program,flatApi.getMonitor());
                        Address maxAddr = cmd.getDisassembledAddressSet().getMaxAddress();
                        if (maxAddr != null) {
                            failedCount = 0;
                            currentAddr = maxAddr;
                            disasseSuccFlag = true;
                        }
                    } catch (Exception e) {
                        //just ignore
                    }
                }
                if (disasseSuccFlag) {
                    currentAddr = currentAddr.next();
                } else {
                    try {
                        currentAddr = currentAddr.addNoWrap(pointSize);
                    } catch (AddressOverflowException e) {
                        return;
                    }
                }
                failedCount += 1;

                if (currentAddr.getOffset() > maxOffset || failedCount > 10000) {
                    break;
                }
            }
        } finally {
            program.endTransaction(txId, true);
        }
        System.out.printf("Found %d instructions after disassemble.\n", program.getListing().getNumInstructions());
    }

    private static void initCliArgs(String[] args) {
        Options options = new Options();
        options.addOption("f","file",true,"File name in Ghidra project.");
        options.addOption("O","output",true,"Path to save result.");
        options.addOption("c","create",false,"Whether create a project for binary.");
        options.addOption("p","project_path",true,"Path to create project.(Default:tmp)");
        options.addOption("l","language_id",true,"Language id like x86:LE:32:default");
        options.addOption("a","accurate",false,"Find in accurate mode (Slow).");

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();

        try {
            commandLine = parser.parse(options,args);
        } catch (Exception e) {
            formatter.printHelp("findbase [options] target",options,false);
            System.exit(1);
        }

        if (commandLine.hasOption("h")) {
            formatter.printHelp("findbase [options] target",  options, false);
            System.exit(0);
        }

        if (commandLine.getArgs().length != 1) {
            formatter.printHelp("findbase [options] target",options,false);
            System.exit(1);
        } else {

            File targetPath = new File(commandLine.getArgs()[0]);
            if (!targetPath.exists()) {
                ColoredPrint.errorPrint("Target file does not exist.");
                System.exit(1);
            } else if (targetPath.isDirectory()) {
    
                if (!targetPath.getName().endsWith(GhidraProjectSuffix)) {
                    ColoredPrint.errorPrint("Not a valid Ghidra project dir.");
                    System.exit(1);
                }
                if (!commandLine.hasOption("file")) {
                    ColoredPrint.errorPrint("Must choose a file name in Ghidra project.");
                    System.exit(1);
                }
            } else if (targetPath.isFile()) {
                if (commandLine.hasOption("file")) {
                    ColoredPrint.errorPrint("Invalid options.");
                    System.exit(1);
                }
            }
        }
    }
}
