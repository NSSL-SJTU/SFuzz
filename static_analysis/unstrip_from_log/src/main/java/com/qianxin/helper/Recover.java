package com.qianxin.helper;

import com.qianxin.core.FlowNode;
import com.qianxin.utils.CommonUtils;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import org.json.JSONArray;
import me.tongfei.progressbar.ProgressBar;

import java.util.*;
import java.util.concurrent.*;

public class Recover {
    private Program program;
    private FlatProgramAPI flatApi;
    private Map<Long,HighFunction> cachedHigh;
    protected DecompInterface decomplib;
    private Map<Long,HashSet<String>> results;

    public Map<Long, HashSet<String>> getResults() {
        return results;
    }

    public Recover(Program program) {
        this.program = program;
        this.flatApi = new FlatProgramAPI(program);
        this.cachedHigh = new HashMap<>();
        this.decomplib = setUpDecompiler();
        this.results = new HashMap<>();
    }


    private DecompInterface setUpDecompiler() {
        DecompInterface decompInterface = new DecompInterface();

        DecompileOptions options;
        options = new DecompileOptions();

        decompInterface.setOptions(options);

        decompInterface.toggleCCode(true);
        decompInterface.toggleSyntaxTree(true);
        decompInterface.setSimplificationStyle("decompile");

        return decompInterface;
    }


    protected List<Function> getAllCallingFunction(List<Reference> refs) {
        List<Function> functionsCallingSinkFunction = new ArrayList<>();
        HashSet<Long> offsets = new HashSet<>();
        for (Reference currentSinkFunctionReference : refs) {

            Function callingFunction = this.flatApi.getFunctionContaining(currentSinkFunctionReference.getFromAddress());

           
            if (callingFunction == null || callingFunction.isThunk()) {
                continue;
            }

            if (!callingFunction.getName().startsWith("FUN_")) {
                continue;
            }
            if (!offsets.contains(callingFunction.getEntryPoint().getOffset())) {
                offsets.add(callingFunction.getEntryPoint().getOffset());
                functionsCallingSinkFunction.add(callingFunction);
            }
        }
        return functionsCallingSinkFunction;
    }

    public HighFunction decompileFunction(Function f) {
        HighFunction hfunction = null;
        DecompileResults dRes = null;

        Long offset = f.getEntryPoint().getOffset();
        if (cachedHigh.containsKey(offset)) {
            HighFunction tmp = cachedHigh.get(offset);
            if (tmp != null) {
                return tmp;
            }
        }
        try {
            dRes = decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(), this.flatApi.getMonitor());
            hfunction = dRes.getHighFunction();
        }
        catch (Exception exc) {
            exc.printStackTrace();
        }
        if (hfunction != null) {
            cachedHigh.put(offset, hfunction);
        }
        return hfunction;
    }


    public ArrayList<PcodeOpAST> getFunctionCallSitePCodeOps(Function f, Long logFuncAddr){

        ArrayList<PcodeOpAST> pcodeOpCallSites = new ArrayList<PcodeOpAST>();

        HighFunction hfunction = decompileFunction(f);
        if(hfunction == null) {
            return null;
        }
        Iterator<PcodeOpAST> ops = hfunction.getPcodeOps();

        //iterate over all p-code ops in the function
        while (ops.hasNext() && !this.flatApi.getMonitor().isCancelled()) {
            PcodeOpAST pcodeOpAST = ops.next();

            if (pcodeOpAST.getOpcode() == PcodeOp.CALL) {

                //current p-code op is a CALL
                //get the address CALL-ed
                Varnode calledVarnode = pcodeOpAST.getInput(0);

                if (calledVarnode == null || !calledVarnode.isAddress()) {
                    continue;
                }
                //if the CALL is to our function, save this callsite
                Function calledFunc = this.flatApi.getFunctionAt(calledVarnode.getAddress());
                if (calledFunc == null) {
                    continue;
                }
                if(calledFunc.getEntryPoint().getOffset() ==  logFuncAddr) {
                    pcodeOpCallSites.add(pcodeOpAST);
                }
            }
        }
        return pcodeOpCallSites;
    }

    public boolean constAddrSection(Address address, String name) {
        MemoryBlock block = program.getMemory().getBlock(name);
        if (block == null) {
            return false;
        }
        return block.contains(address);
    }

    private String getAddrString(Address destAddr) {
        String constPtrValue = "";

        if (constAddrSection(destAddr, ".data") ||
                constAddrSection(destAddr, ".rodata")
                || (program.getMemory().getBlock(".rodata") == null && program.getMemory().contains(destAddr))) {
            Data data = this.flatApi.getDataAt(destAddr);
            if (data == null) {

                int txId = program.startTransaction("createAscii");
                try {
                    data = this.flatApi.createAsciiString(destAddr);
                } catch (Exception e) {
                    return null;
                } finally {
                    program.endTransaction(txId, true);
                }
            }
            if (data != null) {
                constPtrValue = data.getDefaultValueRepresentation();
                constPtrValue = constPtrValue.replace("\"","");
                constPtrValue = constPtrValue.replace("'","");
                if (constPtrValue.length() == 0){
                    return null;
                }
                return constPtrValue;
            }
        }
        return null;
    }

    public void doRecover(Long logFuncAddr,int paramIdx) {
        if (!decomplib.openProgram(program)) {
            System.out.printf("Decompiler error: %s\n", decomplib.getLastMessage());
            return;
        }

        Function logFunc = flatApi.getFunctionAt(flatApi.toAddr(logFuncAddr));
        if (logFunc == null) {
            System.out.println("Can't find function on addr.");
            System.exit(0);
        }
        ReferenceIterator refIter = program.getReferenceManager().getReferencesTo(logFunc.getEntryPoint());
        List<Reference> refs = new ArrayList<>();
        while(refIter.hasNext()) {
            refs.add(refIter.next());
        }
        System.out.printf("Found %d xrefs for log functions.\n",refs.size());

        List<Function> functionsCallingSinkFunction = getAllCallingFunction(refs);

        try (ProgressBar pb = new ProgressBar("Recovering", functionsCallingSinkFunction.size())) {
            for (Function currentFunction : functionsCallingSinkFunction) {
                pb.step();

                ArrayList<PcodeOpAST> callSites = getFunctionCallSitePCodeOps(currentFunction, logFuncAddr);


                if (callSites == null) {
                    continue;
                }
                Long currentFuncOffset = currentFunction.getEntryPoint().getOffset();

                for (PcodeOpAST callSite : callSites) {
                    if (paramIdx + 1 > callSite.getNumInputs()) {
                        continue;
                    }
                    Varnode functionNode = callSite.getInput(paramIdx);
                    Long val = new FlowNode(functionNode,program).getValue();
                    if (val != null) {
                        String funcName = getAddrString(flatApi.toAddr(val));
                        if (funcName != null) {
                            if (!results.containsKey(currentFuncOffset)) {
                                results.put(currentFuncOffset, new HashSet<>());
                            }
                            results.get(currentFuncOffset).add(funcName);
                        }
                    }
                }
            }
        }
    }
}
