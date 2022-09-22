package com.qianxin.identifier;

import org.apache.commons.lang3.tuple.Pair;

import java.util.List;

public class FuncRealFeature {

    private Integer paramNum;
    private Integer calledFuncNum;
    private Integer callNum;
    private Boolean hasLoop;
    private Boolean hasRetVal;
    private Integer bodySize;
    private Integer cfgEdgeNum;
    private Integer cfgBlockNum;
    private Integer xrefsRange;

    private List<String> referStrings;

    private List<Long> magicValues;

    private FunctionEntrySign funcEntrySign;
    private List<Integer> criticalIndex;

    public Integer getCalledFuncNum() {
        return calledFuncNum;
    }

    public void setCalledFuncNum(Integer calledFuncNum) {
        this.calledFuncNum = calledFuncNum;
    }

    public Integer getParamNum() {
        return paramNum;
    }

    public void setParamNum(Integer paramNum) {
        this.paramNum = paramNum;
    }

    public Integer getCallNum() {
        return callNum;
    }

    public void setCallNum(Integer callNum) {
        this.callNum = callNum;
    }

    public Boolean getHasLoop() {
        return hasLoop;
    }

    public void setHasLoop(Boolean hasLoop) {
        this.hasLoop = hasLoop;
    }

    public Boolean getHasRetVal() {
        return hasRetVal;
    }

    public void setHasRetVal(Boolean hasRetVal) {
        this.hasRetVal = hasRetVal;
    }

    public Integer getBodySize() {
        return bodySize;
    }

    public void setBodySize(Integer bodySize) {
        this.bodySize = bodySize;
    }

    public Integer getCfgEdgeNum() {
        return cfgEdgeNum;
    }

    public void setCfgEdgeNum(Integer cfgEdgeNum) {
        this.cfgEdgeNum = cfgEdgeNum;
    }

    public Integer getCfgBlockNum() {
        return cfgBlockNum;
    }

    public void setCfgBlockNum(Integer cfgBlockNum) {
        this.cfgBlockNum = cfgBlockNum;
    }

    public Integer getXrefsRange() {
        return xrefsRange;
    }

    public void setXrefsRange(Integer xrefsRange) {
        this.xrefsRange = xrefsRange;
    }

    public List<String> getReferStrings() {
        return referStrings;
    }

    public void setReferStrings(List<String> referStrings) {
        this.referStrings = referStrings;
    }

    public List<Long> getMagicValues() {
        return magicValues;
    }

    public void setMagicValues(List<Long> magicValues) {
        this.magicValues = magicValues;
    }

    public FunctionEntrySign getFuncEntrySign() {
        return funcEntrySign;
    }

    public void setFuncEntrySign(FunctionEntrySign funcEntrySign) {
        this.funcEntrySign = funcEntrySign;
    }

    public void setCriticalIndex(List<Integer> criticalIndex) { this.criticalIndex = criticalIndex; }

    public List<Integer> getCriticalIndex() { return criticalIndex; }
}
