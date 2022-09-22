package com.qianxin.identifier;

import java.util.List;
import java.util.Map;


public class FuncTestData {

    private List<Long> arguments;
    private Map<Long,byte[]> presetMem;
    private Map<Long,byte[]> conditions;
    private long controlledRetAddr;
    private byte[] retVal;

    public FuncTestData() {
        this.controlledRetAddr = 0;
    }

    public FuncTestData(List<Long> arguments, Map<Long, byte[]> presetMem, Map<Long, byte[]> conditions) {
        this.arguments = arguments;
        this.presetMem = presetMem;
        this.conditions = conditions;
        this.controlledRetAddr = 0;
    }

    public void setControlledRetAddr(long controlledRetAddr) {
        this.controlledRetAddr = controlledRetAddr;
    }

    public byte[] getRetVal() {
        return retVal;
    }

    public void setRetVal(byte[] retVal) {
        this.retVal = retVal;
    }


    public long getControlledRetAddr() {
        return controlledRetAddr;
    }

    public List<Long> getArguments() {
        return arguments;
    }

    public void setArguments(List<Long> arguments) {
        this.arguments = arguments;
    }

    public Map<Long, byte[]> getPresetMem() {
        return presetMem;
    }

    public void setPresetMem(Map<Long, byte[]> presetMem) {
        this.presetMem = presetMem;
    }

    public Map<Long, byte[]> getConditions() {
        return conditions;
    }

    public void setConditions(Map<Long, byte[]> conditions) {
        this.conditions = conditions;
    }
}
