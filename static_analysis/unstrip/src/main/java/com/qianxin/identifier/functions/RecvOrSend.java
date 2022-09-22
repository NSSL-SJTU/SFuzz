package com.qianxin.identifier.functions;

import com.qianxin.helper.BaseEmuer;
import com.qianxin.identifier.BaseFunc;
import com.qianxin.identifier.FuncFeature;
import com.qianxin.identifier.FuncTestData;
import com.qianxin.utils.CommonUtils;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import org.apache.commons.lang3.tuple.Pair;

import java.util.*;

public class RecvOrSend extends BaseFunc {
    @Override
    public List<FuncFeature> setFeatures() {
        List<FuncFeature> ret = new ArrayList<>();

        FuncFeature vxFeatures = new FuncFeature();
        vxFeatures.setParamNumRange(Pair.of(4,4));
        vxFeatures.setCalledFuncNumRange(Pair.of(2,2));
        vxFeatures.setCallNumRange(Pair.of(2,2));
        vxFeatures.setHasLoop(true);
        vxFeatures.setHasRetVal(true);
        vxFeatures.setBodySizeRange(Pair.of(100,400));
        vxFeatures.setCfgEdgeRange(Pair.of(10,20));
        vxFeatures.setCfgBlockRange(Pair.of(6,15));
        vxFeatures.setCriticalIndex(List.of(2));
        vxFeatures.setFuncType(this.userInterface);
        ret.add(vxFeatures);
        return ret;
    }

    @Override
    public List<FuncTestData> setTests() {
        List<FuncTestData> ret = new ArrayList<>();
        FuncTestData ftd = new FuncTestData();
  
        List<Long> args = new ArrayList<>();
        args.add((long) 1);
        args.add((long) 0x8000);
        args.add((long) 10);
        args.add((long) 0);
        ftd.setArguments(args);

        Map<Long,byte[]> preMem = new HashMap<>();
        preMem.put((long)0x8000,"helloworld".getBytes());
        ftd.setPresetMem(preMem);

        Map<Long,byte[]> conditions = new HashMap<>();
        conditions.put((long)0x8000,"helloworld".getBytes());
        ftd.setConditions(conditions);

        byte[] ret_value = {
                (byte)0,(byte)-1,(byte)-1,(byte)-1,(byte)-1
        };
        ftd.setRetVal(ret_value);
        ret.add(ftd);
        return ret;
    }

    @Override
    public String getFuncName() {
        return "recv_or_send";
    }

    @Override
    public String getFuncSign() {
        return "int recv_or_send (undefined4 s, char * buf, int len, int flags)";
    }

    /**
     * @param emuer
     * @return
     */
    public boolean customCheckCallInfo(BaseEmuer emuer) {
        Function thisFunc = emuer.getFunc();
        HighFunction highFunc = matcher.getHighFunc(thisFunc);
        if (highFunc == null) {
            return false;
        }
        FlatProgramAPI flatApi = new FlatProgramAPI(program);

        PcodeOp firstCallOp = CommonUtils.findFirstCall(highFunc);
        if (firstCallOp == null || firstCallOp.getNumInputs() < 1) {
            return false;
        }
        Function firstFunc = flatApi.getFunctionAt(firstCallOp.getInput(0).getAddress());
        HighFunction firtHighFunc = matcher.getHighFunc(firstFunc);
        if(firtHighFunc == null) {
            return false;
        }

        PcodeOp secondCallOp = CommonUtils.findFirstCall(firtHighFunc);
        if (secondCallOp == null || secondCallOp.getNumInputs() < 1) {
            return false;
        }
        Function secondFunc = flatApi.getFunctionAt(secondCallOp.getInput(0).getAddress());
        HighFunction secondHighFunc = matcher.getHighFunc(secondFunc);
        if(secondHighFunc == null) {
            return false;
        }

        PcodeOp thirdCallOp = CommonUtils.findFirstCall(secondHighFunc);
        if (thirdCallOp == null || thirdCallOp.getNumInputs() < 1) {
            return false;
        }

        Function thirdFunc = flatApi.getFunctionAt(thirdCallOp.getInput(0).getAddress());
        HighFunction thirdHighFunc = matcher.getHighFunc(thirdFunc);
        if(thirdHighFunc == null) {
            return false;
        }
        GlobalSymbolMap globalSymbols =  thirdHighFunc.getGlobalSymbolMap();
        if (globalSymbols == null) {
            return false;
        }
        Iterator<HighSymbol> symbolIter = globalSymbols.getSymbols();
        while(symbolIter.hasNext()) {
            HighSymbol symItem = symbolIter.next();
            if (symItem.getHighVariable() != null && symItem.getHighVariable().getRepresentative() != null) {
                Address dataAddr = symItem.getHighVariable().getRepresentative().getAddress();
                Data thisData = flatApi.getDataAt(dataAddr);
                if (thisData != null) {
                    if (thisData.getValue().toString().equalsIgnoreCase("0x3d0001")) {
                        return true;
                    }
                }
            }
        }
        DecompiledFunction dfunc = matcher.getDecompiledFunc(thirdFunc);
        if (dfunc == null) {
            return false;
        }
        if (dfunc.getC().contains("0x3d0001")) {
            return true;
        }
        return false;
    }
}
