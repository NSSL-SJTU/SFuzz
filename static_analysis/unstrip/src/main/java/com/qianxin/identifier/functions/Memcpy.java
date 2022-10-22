package com.qianxin.identifier.functions;

import com.qianxin.identifier.BaseFunc;
import com.qianxin.identifier.FuncFeature;
import com.qianxin.identifier.FuncTestData;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Memcpy extends BaseFunc {

    @Override
    public List<FuncFeature> setFeatures() {
        List<FuncFeature> ret = new ArrayList<>();
        FuncFeature vxFeatures = new FuncFeature();
        vxFeatures.setParamNumRange(Pair.of(2,3));
        vxFeatures.setCallNumRange(Pair.of(1,1));
        vxFeatures.setCalledFuncNumRange(Pair.of(1,1));
        vxFeatures.setHasLoop(false);
        vxFeatures.setHasRetVal(true);
        vxFeatures.setBodySizeRange(Pair.of(20,300));
        vxFeatures.setCfgEdgeRange(Pair.of(0,15));
        vxFeatures.setCfgBlockRange(Pair.of(1,10));
        vxFeatures.setXrefsRange(Pair.of(TOTAL_FUNC_NUM/100,TOTAL_FUNC_NUM));
        vxFeatures.setCriticalIndex(List.of(2,3));
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
        args.add((long) 6);
        ftd.setArguments(args);

        Map<Long,byte[]> preMem = new HashMap<>();
        preMem.put((long) 0x4000,"abcd\00a".getBytes());
        preMem.put((long)0x8000,"\00\00\00\00abc".getBytes());
        ftd.setPresetMem(preMem);

        Map<Long,byte[]> conditions = new HashMap<>();
        conditions.put((long)0x8000,"abcd\00ac".getBytes());
        conditions.put((long)0x4000,"abcd\00a".getBytes());
        ftd.setConditions(conditions);
        ret.add(ftd);
        return ret;
    }

    @Override
    public String getFuncName() {
        return "memcpy";
    }

    @Override
    public String getFuncSign() {
        return "void * memcpy (void * destin, void * source, int n)";
    }

    //must startswith customCheck
//    public boolean customCheckTest() {
//        System.out.println(program);
//        System.out.println(emuHelper);
//        System.out.println("in customCheckTest");
//        return true;
//    }
}
