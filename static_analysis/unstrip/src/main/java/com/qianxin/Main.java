package com.qianxin;
import com.qianxin.helper.WebParamFinder;
import com.qianxin.identifier.MatchRes;
import com.qianxin.identifier.Matcher;
import com.qianxin.core.ProgramInfo;
import com.qianxin.utils.ColoredPrint;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.plugin.core.analysis.DefaultDataTypeManagerService;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.cmd.Command;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.PartitionCodeSubModel;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
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
        System.out.println("--------start unstrip--------");

        if (commandLine.hasOption("output")) {
            String timeCostFilePath = commandLine.getOptionValue("output") + ".timecost";
            BufferedWriter bw = null;
            try {
                bw = new BufferedWriter(new FileWriter(timeCostFilePath));
                bw.write(String.valueOf(startTime) + "\n");
                doUnStrip(args,bw);
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
            doUnStrip(args,null);
        }
    }

    private static void doUnStrip(String[] args,BufferedWriter bw) {
        String languageId = null;
        String filename = null;
        Long baseAddr = null;
        String projectPath = null;
        boolean isCreate = false;
        boolean isWrite = false;
        String webFront = null;
        if (commandLine.hasOption("language_id")) {
            languageId = commandLine.getOptionValue("language_id");
        }
        if (commandLine.hasOption("file")) {
            filename = commandLine.getOptionValue("file");
        }
        if (commandLine.hasOption("webstrings")){
            webFront = commandLine.getOptionValue("webstrings");
        }
        if (commandLine.hasOption("base_address")) {
            String inputBaseAddr = commandLine.getOptionValue("base_address");
            try {
                if (inputBaseAddr.startsWith("0x")) {
                    inputBaseAddr = inputBaseAddr.substring(2);
                }
                baseAddr = Long.parseLong(inputBaseAddr, 16);
            }catch (NumberFormatException e) {
                ColoredPrint.errorPrint("Wrong base address format.");
                System.exit(1);
            }
        }
        if (commandLine.hasOption("create")) {
            isCreate = true;
        }
        if (commandLine.hasOption("write")) {
            isWrite = true;
        }
        if (commandLine.hasOption("project_path")) {
            projectPath = commandLine.getOptionValue("project_path");
        }
        File targetFile = new File(commandLine.getArgs()[0]);
        ProgramInfo programInfo = null;
        try {
            programInfo = new ProgramInfo(targetFile.getPath(),languageId,baseAddr,filename,isCreate,isWrite,projectPath);

            Program program = programInfo.getProgram();
            if (program == null) {
                ColoredPrint.errorPrint("Load program failed.");
                System.exit(1);
            }
            if (bw != null) {
                long afterAnalysis=System.currentTimeMillis();
                bw.write(String.valueOf(afterAnalysis) + "\n");
            }
            createMoreFunction(program);

            // Start our function semantic information regeneration process

            // Stage1: Function match based on given function features
            System.out.println("Stage 1: Emulation");
            Matcher matcher = Matcher.getInstance(program);
            matcher.doMatch();

            // Stage2: Function match based on web frontend string value, if no webFront we apply a single strategy
            System.out.println("Stage 2: Web Paramters Heuristics");
            if (webFront!=null) {
                WebParamFinder webfinder = new WebParamFinder(program, matcher, webFront);
                webfinder.doMatch();
            }

            System.out.println("All done.");


            List<MatchRes> matchResList = matcher.getMatchResults();

            if (matchResList != null) {
                if (commandLine.hasOption("output")) {
                    storeRes(matchResList,commandLine.getOptionValue("output"));
                }
                if (commandLine.hasOption("write")) {
                    write2Project(matchResList,programInfo);
                }
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

    private static void write2Project(List<MatchRes> matchResList,ProgramInfo programInfo) {
        Program program = programInfo.getProgram();
        FlatProgramAPI flatApi = new FlatProgramAPI(program);
        for (MatchRes res:matchResList) {
            FunctionSignatureParser parser = new FunctionSignatureParser(program.getDataTypeManager(), new DefaultDataTypeManagerService());
            Function funcItem = flatApi.getFunctionAt(flatApi.toAddr(res.getOffset()));
            FunctionDefinitionDataType fddt = null;
            try{
                fddt = parser.parse(funcItem.getSignature(),res.getFuncSign());
            }catch (ParseException | CancelledException e) {
                e.printStackTrace();
                continue;
            }
            if (fddt != null) {
                int txId = program.startTransaction("Change Func Sign");
                try {
                    ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(funcItem.getEntryPoint(),fddt, SourceType.USER_DEFINED,true,true);
                    cmd.applyTo(program,flatApi.getMonitor());
                } catch (Exception e) {
                    System.out.println(String.format("Change Func Sign failed."));
                }finally {
                    program.endTransaction(txId, true);
                }
            }
        }
    }

    private static void storeRes(List<MatchRes> matchResList,String savePath) {
        BufferedWriter bw = null;
        try {
            JSONArray jArray = new JSONArray();
            for (MatchRes res:matchResList) {
                jArray.put(res.toJsonStr());
            }
            bw = new BufferedWriter(new FileWriter(savePath));
            bw.write(jArray.toString(4));
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


    private static void createMoreFunction(Program program) {
        System.out.printf("Found %d functions.\n", program.getFunctionManager().getFunctionCount());
        //try to createFunction after terminals.
        FlatProgramAPI flatApi = new FlatProgramAPI(program);
        InstructionIterator instIter = program.getListing().getInstructions(true);
        int createCount = 0;
        while(instIter.hasNext() && !flatApi.getMonitor().isCancelled()) {
            Instruction instruction = instIter.next();
            if (instruction.getFlowType() == RefType.TERMINATOR) {
                try {
                    Address funcAddr = instruction.getMaxAddress().next();
                    Function func = program.getFunctionManager().getFunctionContaining(funcAddr);
                    if (func == null) {
                        Instruction funcBeginInstr =
                                program.getListing().getInstructionAt(funcAddr);
                        if (funcBeginInstr == null) {
             
                            funcBeginInstr = program.getListing().getInstructionAfter(funcAddr);
                            if (funcBeginInstr != null) {
                                funcAddr = funcBeginInstr.getAddress();
                                if (program.getFunctionManager().getFunctionContaining(funcAddr) !=null) {
                                    continue;
                                }
                            }
                        }
                        if (funcBeginInstr != null) {
                            //createFunctionNear
                            PartitionCodeSubModel partitionBlockModel = new PartitionCodeSubModel(program);
                            CodeBlock[] blocks = partitionBlockModel.getCodeBlocksContaining(funcAddr, flatApi.getMonitor());
                            if (blocks.length != 1) {
                                continue;
                            }
                            Address address = blocks[0].getFirstStartAddress();
                            Function newFunc = null;
                            int txId = program.startTransaction("createMoreFunc");
                            try {
                                newFunc = flatApi.createFunction(address, null);
                            } catch (Exception e) {
                                System.out.printf("Try to create function failed at 0x%x.\n",address.getOffset());
                            } finally {
                                program.endTransaction(txId, true);
                            }
                            if (newFunc != null) {
                                createCount += 1;
                            }
                        }
                    }
                } catch (CancelledException e) {
                    System.out.println("CancelledException occured.");
                }
            }
        }
        System.out.printf("Create %d more functions.\n", createCount);
        System.out.printf("Found %d functions.\n", program.getFunctionManager().getFunctionCount());
    }

    private static void initCliArgs(String[] args) {
        Options options = new Options();
        options.addOption("f","file",true,"File name in Ghidra project.");
        options.addOption("O","output",true,"Path to save result.");
        options.addOption("w","write",false,"Whether write result to the project");
        options.addOption("c","create",false,"Whether create a project for binary.");
        options.addOption("p","project_path",true,"Path to create project.(Default:tmp)");
        options.addOption("l","language_id",true,"Language id like x86:LE:32:default");
        options.addOption("b","base_address",true,"Base address for the binary.");
        options.addOption("W","webstrings", true, "Path to web frontstring extraction file");

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();

        try {
            commandLine = parser.parse(options,args);
        } catch (Exception e) {
            formatter.printHelp("unstrip [options] target",options,false);
            System.exit(1);
        }

        if (commandLine.hasOption("h")) {
            formatter.printHelp("unstrip [options] target",  options, false);
            System.exit(0);
        }
        if (commandLine.getArgs().length != 1) {
            formatter.printHelp("unstrip [options] target",options,false);
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
