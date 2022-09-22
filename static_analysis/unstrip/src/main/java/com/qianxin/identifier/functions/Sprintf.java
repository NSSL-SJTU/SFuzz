package com.qianxin.identifier.functions;

import com.qianxin.identifier.BaseFunc;
import com.qianxin.identifier.FuncFeature;
import com.qianxin.identifier.FuncTestData;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Sprintf extends BaseFunc {

    @Override
    public List<FuncFeature> setFeatures() {
        List<FuncFeature> ret = new ArrayList<>();

        FuncFeature vxFeatures = new FuncFeature();
        vxFeatures.setParamNumRange(Pair.of(1,6));
        vxFeatures.setCalledFuncNumRange(Pair.of(0,2));
        vxFeatures.setCallNumRange(Pair.of(0,2));
        vxFeatures.setHasLoop(false);
        vxFeatures.setHasRetVal(true);
        vxFeatures.setBodySizeRange(Pair.of(40,300));
        vxFeatures.setCfgEdgeRange(Pair.of(0,15));
        vxFeatures.setCfgBlockRange(Pair.of(1,10));
        vxFeatures.setCriticalIndex(List.of(2,3,4,5,6,7,8));
        vxFeatures.setFuncType(this.dataSink);
        ret.add(vxFeatures);
        return ret;
    }

    @Override
    public List<FuncTestData> setTests() {
        List<FuncTestData> ret = new ArrayList<>();
        FuncTestData ftd = new FuncTestData();

        List<Long> args = new ArrayList<>();
        args.add((long) 0x8000);
        args.add((long) 0x4000);
        args.add((long) 0x2000);
        ftd.setArguments(args);

        Map<Long,byte[]> preMem = new HashMap<>();
        preMem.put((long) 0x8000,"Hell0\00abc".getBytes());
        preMem.put((long) 0x4000,"hello %s world!".getBytes());
        preMem.put((long) 0x2000,"real".getBytes());
        ftd.setPresetMem(preMem);

        Map<Long,byte[]> conditions = new HashMap<>();
        conditions.put((long)0x8000,"hello real world!".getBytes());
        conditions.put((long)0x4000,"hello %s world!".getBytes());
        conditions.put((long)0x2000,"real".getBytes());
        ftd.setConditions(conditions);
        ret.add(ftd);
        return ret;
    }

    @Override
    public String getFuncName() {
        return "sprintf";
    }

    @Override
    public String getFuncSign() {
        return "int sprintf(char * restrict str, const char * restrict format, ...)";
    }
}
