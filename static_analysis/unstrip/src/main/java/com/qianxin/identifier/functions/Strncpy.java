package com.qianxin.identifier.functions;

import com.qianxin.identifier.BaseFunc;
import com.qianxin.identifier.FuncFeature;
import com.qianxin.identifier.FuncTestData;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Strncpy extends BaseFunc {

    @Override
    public List<FuncFeature> setFeatures() {
        List<FuncFeature> ret = new ArrayList<>();

        FuncFeature vxFeatures = new FuncFeature();
        vxFeatures.setParamNumRange(Pair.of(3,3));
        vxFeatures.setCalledFuncNumRange(Pair.of(0,0));
        vxFeatures.setCallNumRange(Pair.of(0,0));
        vxFeatures.setHasLoop(true);
        vxFeatures.setHasRetVal(true);
        vxFeatures.setBodySizeRange(Pair.of(30,250));
        vxFeatures.setCfgEdgeRange(Pair.of(3,25));
        vxFeatures.setCfgBlockRange(Pair.of(3,25));
        vxFeatures.setXrefsRange(Pair.of(TOTAL_FUNC_NUM/1000,TOTAL_FUNC_NUM));
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
        preMem.put((long)0x4000,"abcd\00a".getBytes());
        preMem.put((long)0x8000,"zzzzbb".getBytes());
        ftd.setPresetMem(preMem);

        Map<Long,byte[]> conditions = new HashMap<>();
        conditions.put((long)0x4000,"abcd\00a".getBytes());
        conditions.put((long)0x8000,"abcd\00\00".getBytes());
        ftd.setConditions(conditions);
        ret.add(ftd);

        return ret;
    }

    @Override
    public String getFuncName() {
        return "strncpy";
    }

    @Override
    public String getFuncSign() {
        return "char * strncpy(char * dst, char * src, int len)";
    }

    //must startswith customCheck
//    public boolean customCheckTest() {
//        System.out.println(program);
//        System.out.println(emuHelper);
//        System.out.println("in customCheckTest");
//        return true;
//    }
}
