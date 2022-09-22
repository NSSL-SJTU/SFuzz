package com.qianxin.helper;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class FlowNode {

    private Varnode var;
    private Program program;
    public FlowNode(Varnode var, Program program) {
        this.var = var;
        this.program = program;
    }

    public Long getValue() {
        if (var.isConstant()) {
            return var.getOffset();
        }
        if (var.isAddress()) {
            return null;
        }
        if (var.getAddress().isStackAddress()) {
            return this.calcPcodeOp(var.getDef());
        }
        if (var.isUnique()) {
            return this.calcPcodeOp(var.getDef());
        }
        if (var.isRegister()) {
            return this.calcPcodeOp(var.getDef());
        }
        return null;
    }

    public Long calcPcodeOp(PcodeOp def) {
        if (def == null) {
            return null;
        }
        int opcode = def.getOpcode();
        switch (opcode) {
            case PcodeOp.PTRSUB: {
                Address destAddr = HighFunctionDBUtil.getSpacebaseReferenceAddress(program, def);
                if (destAddr != null) {

                    long thisOffset = destAddr.getOffset();
                    if (thisOffset < 0) {
                        return null;
                    } else {
                        return thisOffset;
                    }
                }
                Long var1 = new FlowNode(def.getInput(0),program).getValue();
                Long var2 = new FlowNode(def.getInput(1),program).getValue();
                if (var1 !=null && var2 !=null) {
                    return var1 + var2;
                }
                break;
            }
            case PcodeOp.COPY:
            case PcodeOp.CAST:{
                Long var = new FlowNode(def.getInput(0),program).getValue();
                if (var != null) {
                    return var;
                }
                break;
            }
        }
        return null;
    }

}

