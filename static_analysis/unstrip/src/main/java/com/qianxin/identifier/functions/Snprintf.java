package com.qianxin.identifier.functions;

import com.qianxin.identifier.BaseFunc;
import com.qianxin.identifier.FuncFeature;
import com.qianxin.identifier.FuncTestData;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Snprintf extends BaseFunc {

    @Override
    public List<FuncFeature> setFeatures() {
        List<FuncFeature> ret = new ArrayList<>();
        FuncFeature vxFeatures = new FuncFeature();
        vxFeatures.setParamNumRange(Pair.of(1,6));
        vxFeatures.setCallNumRange(Pair.of(1,3));
        vxFeatures.setCalledFuncNumRange(Pair.of(1,3));
        vxFeatures.setHasLoop(false);
        vxFeatures.setHasRetVal(true);
        vxFeatures.setBodySizeRange(Pair.of(40,300));
        vxFeatures.setCfgEdgeRange(Pair.of(0,15));
        vxFeatures.setCfgBlockRange(Pair.of(1,10));
        //vxFeatures.setXrefsRange(Pair.of(TOTAL_FUNC_NUM/100,TOTAL_FUNC_NUM));
        vxFeatures.setCriticalIndex(List.of(2,3,4,5,6,7,8));
        vxFeatures.setFuncType(this.dataSink);
        ret.add(vxFeatures);

        FuncFeature vxFeatures2 = new FuncFeature();
        vxFeatures2.setParamNumRange(Pair.of(1,6));
        vxFeatures2.setCalledFuncNumRange(Pair.of(1,3));
        vxFeatures2.setCallNumRange(Pair.of(1,3));
        vxFeatures2.setHasLoop(true);
        vxFeatures2.setHasRetVal(true);
        vxFeatures2.setBodySizeRange(Pair.of(40,100));
        vxFeatures2.setCfgEdgeRange(Pair.of(2,3));
        vxFeatures2.setCfgBlockRange(Pair.of(2,3));
        vxFeatures.setXrefsRange(Pair.of(TOTAL_FUNC_NUM/1000,TOTAL_FUNC_NUM));
        vxFeatures.setCriticalIndex(List.of(2,3,4,5,6,7,8));
        ret.add(vxFeatures2);
        return ret;
    }

    @Override
    public List<FuncTestData> setTests() {
        List<FuncTestData> ret = new ArrayList<>();
        FuncTestData ftd = new FuncTestData();

        List<Long> args = new ArrayList<>();
        args.add((long) 0x8000);
        args.add((long) 16);
        args.add((long) 0x4000);
        args.add((long) 0x2000);
        ftd.setArguments(args);

        Map<Long,byte[]> preMem = new HashMap<>();
        preMem.put((long) 0x8000,"Hell0\00abc".getBytes());
        preMem.put((long) 0x4000,"%s".getBytes());
        preMem.put((long) 0x2000,"real_world_hacking".getBytes());
        ftd.setPresetMem(preMem);

        Map<Long,byte[]> conditions = new HashMap<>();
        conditions.put((long)0x8000,"real_world_hack".getBytes());
        conditions.put((long)0x4000,"%s".getBytes());
        conditions.put((long)0x2000,"real_world_hacking".getBytes());
        ftd.setConditions(conditions);
        ret.add(ftd);
        return ret;
    }

    @Override
    public String getFuncName() {
        return "snprintf";
    }

    @Override
    public String getFuncSign() {
        return "int snprintf(char * str, int size, char * format, ...)";
    }
}
