package com.qianxin.identifier.functions;

import com.qianxin.identifier.BaseFunc;
import com.qianxin.identifier.FuncFeature;
import com.qianxin.identifier.FuncTestData;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Sscanf extends BaseFunc {

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
        //vxFeatures.setXrefsRange(Pair.of(TOTAL_FUNC_NUM/100,TOTAL_FUNC_NUM));
        vxFeatures.setCriticalIndex(List.of(1,2));
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
        preMem.put((long) 0x8000,"123456".getBytes());
        preMem.put((long) 0x4000,"%4s".getBytes());
        preMem.put((long) 0x2000,"real".getBytes());
        ftd.setPresetMem(preMem);

        Map<Long,byte[]> conditions = new HashMap<>();
        conditions.put((long)0x8000,"123456".getBytes());
        conditions.put((long)0x4000,"%4s".getBytes());
        conditions.put((long)0x2000,"1234".getBytes());
        ftd.setConditions(conditions);
        ret.add(ftd);

        FuncTestData ftd2 = new FuncTestData();

        List<Long> args2 = new ArrayList<>();
        args2.add((long) 0x8000);
        args2.add((long) 0x4000);
        args2.add((long) 0x2000);
        ftd2.setArguments(args2);

        Map<Long,byte[]> preMem2 = new HashMap<>();
        preMem2.put((long) 0x8000,"123456".getBytes());
        preMem2.put((long) 0x4000,"%3d".getBytes());
        preMem2.put((long) 0x2000,"0".getBytes());
        ftd2.setPresetMem(preMem2);

        Map<Long,byte[]> conditions2 = new HashMap<>();
        conditions2.put((long)0x8000,"123456".getBytes());
        conditions2.put((long)0x4000,"%3d".getBytes());
        byte[] value1 = {
                (byte)123,
        };
        conditions2.put((long)0x2000,value1);
        ftd2.setConditions(conditions2);
        ret.add(ftd2);

        return ret;
    }

    @Override
    public String getFuncName() {
        return "sscanf";
    }

    @Override
    public String getFuncSign() {
        return "int sscanf(const char * restrict s, const char * restrict format, ...)";
    }
}
