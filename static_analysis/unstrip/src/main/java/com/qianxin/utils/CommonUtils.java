package com.qianxin.utils;

import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
//import javassist.bytecode.stackmap.BasicBlock;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.UUID;

public class CommonUtils {

    public static String createUUID() {
        String uuid = UUID.randomUUID().toString();
        uuid = uuid.replace("-", "");

        return uuid;
    }

    public static PcodeOp findFirstCall(HighFunction hfucntion) {
        ArrayList<PcodeBlockBasic> blocks = hfucntion.getBasicBlocks();
        for (PcodeBlockBasic bb:blocks) {
            Iterator<PcodeOp> iter =  bb.getIterator();
            while(iter.hasNext()) {
                PcodeOp opItem = iter.next();
                if (opItem.getOpcode() == PcodeOp.CALL) {
                    return opItem;
                }
            }
        }
        return null;
    }

    public static PcodeOp findLastCall(HighFunction hfucntion) {
        ArrayList<PcodeBlockBasic> blocks = hfucntion.getBasicBlocks();
        PcodeOp lastOp = null;
        for (PcodeBlockBasic bb:blocks) {
            Iterator<PcodeOp> iter =  bb.getIterator();
            while(iter.hasNext()) {
                PcodeOp opItem = iter.next();
                if (opItem.getOpcode() == PcodeOp.CALL) {
                    lastOp = opItem;
                }
            }
        }
        return lastOp;
    }
}
