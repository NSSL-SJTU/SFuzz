package com.qianxin.identifier.functions;

import com.qianxin.identifier.BaseFunc;
import com.qianxin.identifier.FuncFeature;
import com.qianxin.identifier.FuncTestData;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Atoi extends BaseFunc {

    @Override
    public List<FuncFeature> setFeatures() {
        List<FuncFeature> ret = new ArrayList<>();
        FuncFeature vxFeatures = new FuncFeature();
        vxFeatures.setParamNumRange(Pair.of(1,1));
        vxFeatures.setCallNumRange(Pair.of(1,1));
        vxFeatures.setCalledFuncNumRange(Pair.of(1,1));
        vxFeatures.setHasLoop(false);
        vxFeatures.setHasRetVal(true);
        vxFeatures.setBodySizeRange(Pair.of(0,230));
        vxFeatures.setCfgEdgeRange(Pair.of(0,15));
        vxFeatures.setCfgBlockRange(Pair.of(1,10));
        //vxFeatures.setXrefsRange(Pair.of(TOTAL_FUNC_NUM/100,TOTAL_FUNC_NUM));
        vxFeatures.setCriticalIndex(List.of(1));
//        vxFeatures.setFuncType(this.dataSink);
        ret.add(vxFeatures);
        return ret;
    }

    @Override
    public List<FuncTestData> setTests() {
        List<FuncTestData> ret = new ArrayList<>();


        FuncTestData ftd2 = new FuncTestData();

        List<Long> args2 = new ArrayList<>();
        args2.add((long) 0x8000);
        ftd2.setArguments(args2);

        Map<Long,byte[]> preMem2 = new HashMap<>();
        preMem2.put((long)0x8000,"2147483648".getBytes());
        ftd2.setPresetMem(preMem2);

        Map<Long,byte[]> conditions2 = new HashMap<>();
        conditions2.put((long)0x8000,"2147483648".getBytes());
        byte[] ret_value2 = {
                (byte) 0x7f, (byte) 0xff,(byte) 0xff,(byte) 0xff
        };
        ftd2.setRetVal(ret_value2);
        ftd2.setConditions(conditions2);
        ret.add(ftd2);


        FuncTestData ftd = new FuncTestData();

        List<Long> args = new ArrayList<>();
        args.add((long) 0x8000);
        ftd.setArguments(args);

        Map<Long,byte[]> preMem = new HashMap<>();
        preMem.put((long)0x8000,"1234".getBytes());
        ftd.setPresetMem(preMem);

        Map<Long,byte[]> conditions = new HashMap<>();
        conditions.put((long)0x8000,"1234".getBytes());
        byte[] ret_value = {
                (byte) 0x04,  (byte) 0xd2
        };
        ftd.setRetVal(ret_value);
        ftd.setConditions(conditions);
        ret.add(ftd);

        return ret;
    }

    @Override
    public String getFuncName() {
        return "atoi";
    }

    @Override
    public String getFuncSign() {
        return "int * atoi(const char * str)";
    }

}
