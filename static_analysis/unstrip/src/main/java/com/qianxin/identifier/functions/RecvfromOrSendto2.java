package com.qianxin.identifier.functions;

import com.qianxin.identifier.FuncFeature;
import com.qianxin.identifier.FuncTestData;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RecvfromOrSendto2 extends RecvOrSend2 {
    @Override
    public List<FuncFeature> setFeatures() {
        List<FuncFeature> ret = new ArrayList<>();

        FuncFeature vxFeatures = new FuncFeature();
        vxFeatures.setParamNumRange(Pair.of(6,6));
        vxFeatures.setCalledFuncNumRange(Pair.of(1,2));
        vxFeatures.setCallNumRange(Pair.of(1,3));
        vxFeatures.setHasLoop(true);
        vxFeatures.setHasRetVal(true);
        vxFeatures.setBodySizeRange(Pair.of(180,430));
        vxFeatures.setCfgEdgeRange(Pair.of(18,35));
        vxFeatures.setCfgBlockRange(Pair.of(14,25));
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
        return "recvfrom_or_sendto";
    }

    @Override
    public String getFuncSign() {
        return "int recvfrom_or_sendto(int socket,  void * buffer,  int tsize,  int flags,  undefined * addr,  int * length)";
    }
}
