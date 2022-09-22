package com.qianxin.identifier.functions;

import com.qianxin.identifier.BaseFunc;
import com.qianxin.identifier.FuncFeature;
import com.qianxin.identifier.FuncTestData;
import org.apache.commons.lang3.tuple.Pair;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Memcmp extends BaseFunc {

    @Override
    public List<FuncFeature> setFeatures() {
        List<FuncFeature> ret = new ArrayList<>();

        FuncFeature vxFeatures = new FuncFeature();
        vxFeatures.setParamNumRange(Pair.of(3,3));
        vxFeatures.setCallNumRange(Pair.of(0,1));
        vxFeatures.setCalledFuncNumRange(Pair.of(0,1));
        vxFeatures.setHasLoop(true);
        vxFeatures.setHasRetVal(true);
        vxFeatures.setBodySizeRange(Pair.of(30,300));
        vxFeatures.setCfgEdgeRange(Pair.of(3,24));
        vxFeatures.setCfgBlockRange(Pair.of(3,20));
        vxFeatures.setCriticalIndex(List.of(-1));
//        vxFeatures.setFuncType(this.checksum);
        ret.add(vxFeatures);
        return ret;
    }

    @Override
    public List<FuncTestData> setTests() {
        List<FuncTestData> ret = new ArrayList<>();
        FuncTestData ftd = new FuncTestData();

        //testcase 1

        List<Long> args = new ArrayList<>();
        args.add((long) 0x8000);
        args.add((long) 0x4000);
        args.add((long) 12);
        ftd.setArguments(args);
        Map<Long,byte[]> preMem = new HashMap<>();
        preMem.put((long)0x8000,"Hello World!".getBytes());
        preMem.put((long)0x4000,"Hello World".getBytes());
        ftd.setPresetMem(preMem);
        Map<Long,byte[]> conditions = new HashMap<>();
        conditions.put((long)0x8000,"Hello World!".getBytes());
        conditions.put((long)0x4000,"Hello World".getBytes());
        byte[] ret_value = {
               (byte) 0x21
        };
        ftd.setRetVal(ret_value);
        ftd.setConditions(conditions);
        ret.add(ftd);

        // testcase 2
        FuncTestData ftd02 = new FuncTestData();
        List<Long> args02 = new ArrayList<>();
        args02.add((long) 0x8000);
        args02.add((long) 0x4000);
        args02.add((long) 11);
        ftd02.setArguments(args02);
        Map<Long,byte[]> preMem02 = new HashMap<>();
        preMem02.put((long)0x8000,"Hello World!".getBytes());
        preMem02.put((long)0x4000,"Hello World".getBytes());
        ftd02.setPresetMem(preMem02);
        Map<Long,byte[]> conditions02 = new HashMap<>();
        conditions02.put((long)0x8000,"Hello World!".getBytes());
        conditions02.put((long)0x4000,"Hello World".getBytes());
        byte[] ret_value02 = {
                (byte) 0
        };
        ftd02.setRetVal(ret_value02);
        ftd02.setConditions(conditions02);
        ret.add(ftd02);


        //testcase3
        FuncTestData ftd03 = new FuncTestData();
        List<Long> args03 = new ArrayList<>();
        args03.add((long) 0x8000);
        args03.add((long) 0x4000);
        args03.add((long) 6);
        ftd03.setArguments(args03);
        byte[] value1 = {
                (byte)72, (byte)101, (byte)108, (byte)0, (byte)50, (byte)111
        }; // Hel\\x001o
        byte[] value2 = {
                (byte)72, (byte)101, (byte)108, (byte)0, (byte)49, (byte)111
        }; // Hel\x002o

        Map<Long,byte[]> preMem03 = new HashMap<>();
        preMem03.put((long)0x8000,value1);
        preMem03.put((long)0x4000,value2);
        ftd03.setPresetMem(preMem03);
        Map<Long,byte[]> conditions03 = new HashMap<>();
        conditions03.put((long)0x8000, value1);
        conditions03.put((long)0x4000, value2);
        byte[] ret_value03 = {
                (byte) 1
        };
        ftd03.setRetVal(ret_value03);
        ftd03.setConditions(conditions03);
        ret.add(ftd03);

        return ret;
    }

    @Override
    public String getFuncName() {
        return "memcmp";
    }

    @Override
    public String getFuncSign() {
        return "int memcmp(const void * s1, const void * s2, size_t n)";
    }
}
