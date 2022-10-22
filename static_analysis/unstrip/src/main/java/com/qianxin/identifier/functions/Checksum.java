package com.qianxin.identifier.functions;

import com.qianxin.identifier.BaseFunc;
import com.qianxin.identifier.FuncFeature;
import com.qianxin.identifier.FuncTestData;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Checksum extends BaseFunc {
    @Override
    public List<FuncFeature> setFeatures() {
        List<FuncFeature> ret = new ArrayList<>();
        FuncFeature vxFeatures = new FuncFeature();
        vxFeatures.setParamNumRange(Pair.of(2,2));
        vxFeatures.setCallNumRange(Pair.of(0,0));
        vxFeatures.setCalledFuncNumRange(Pair.of(0,0));
        vxFeatures.setHasLoop(true);
        vxFeatures.setHasRetVal(true);
        vxFeatures.setBodySizeRange(Pair.of(20,350));
        vxFeatures.setCfgEdgeRange(Pair.of(2,20));
        vxFeatures.setCfgBlockRange(Pair.of(2,15));
        //vxFeatures.setXrefsRange(Pair.of(TOTAL_FUNC_NUM/100,TOTAL_FUNC_NUM));
        vxFeatures.setCriticalIndex(List.of(1,2,3,4,5,6,7,8));
        vxFeatures.setFuncType(this.checksum);
        ret.add(vxFeatures);
        return ret;
    }

    @Override
    public List<FuncTestData> setTests() {
        List<FuncTestData> ret = new ArrayList<>();

        FuncTestData ftd = new FuncTestData();

        List<Long> args = new ArrayList<>();
        args.add((long) 0x8000);
        args.add((long) 10);
        ftd.setArguments(args);

        Map<Long,byte[]> preMem = new HashMap<>();
        preMem.put((long)0x8000,"helloworld".getBytes());
        ftd.setPresetMem(preMem);

        Map<Long,byte[]> conditions = new HashMap<>();
        conditions.put((long)0x8000,"helloworld".getBytes());
        byte[] ret_value = {
                (byte) 0,  (byte) -33, (byte) -33
        };
        ftd.setRetVal(ret_value);
        ftd.setConditions(conditions);
        ret.add(ftd);


        FuncTestData ftd2 = new FuncTestData();

        List<Long> args2 = new ArrayList<>();
        args2.add((long) 0x8000);
        args2.add((long) 1);
        ftd2.setArguments(args2);

        Map<Long,byte[]> preMem2 = new HashMap<>();
        preMem2.put((long)0x8000,"\00".getBytes());
        ftd2.setPresetMem(preMem2);

        Map<Long,byte[]> conditions2 = new HashMap<>();
        conditions2.put((long)0x8000,"\00".getBytes());
        byte[] ret_value2 = {
                (byte) 0,  (byte) -1, (byte) -1
        };
        ftd2.setRetVal(ret_value2);
        ftd2.setConditions(conditions2);
        ret.add(ftd2);

        return ret;
    }

    @Override
    public String getFuncName() {
        return "checksum";
    }

    @Override
    public String getFuncSign() {
        return "int checksum(int *param_1,int param_2)";
    }
}
