package com.qianxin.identifier;

import org.apache.commons.lang3.tuple.Pair;

import java.util.List;

public class FuncFeature {


    private Pair<Integer,Integer> paramNumRange;

    private Pair<Integer,Integer> calledFuncNumRange;

    private Pair<Integer,Integer> callNumRange;

    private Boolean hasLoop;

    private Boolean hasRetVal;

    private Pair<Integer,Integer> bodySizeRange;

    private Pair<Integer,Integer> cfgEdgeRange;

    private Pair<Integer,Integer> cfgBlockRange;

    private Pair<Integer,Integer> xrefsRange;

    private List<String> referStrings;

    private List<Long> magicValues;

    private List<FunctionEntrySign> funcEntrySigns;
   
    private List<Integer> criticalIndex = null;
    private String funcType = null;

    public FuncFeature() {

    }

    public FuncFeature(Pair<Integer,Integer> paramNumRange,Pair<Integer,Integer> calledFuncNumRange,
                       Pair<Integer,Integer> callNumRange,Boolean hasLoop,
                       Boolean hasRetVal,Pair<Integer,Integer> bodySizeRange,Pair<Integer,Integer> cfgEdgeRange,
                       Pair<Integer,Integer> cfgBlockRange,Pair<Integer,Integer> xrefsRange,List<String> referStrings,
                       List<Long> magicValues,List<FunctionEntrySign> funcEntrySigns,
                       List<Integer> criticalIndex) {
        this.paramNumRange = paramNumRange;
        this.calledFuncNumRange = calledFuncNumRange;
        this.callNumRange = callNumRange;
        this.hasLoop = hasLoop;
        this.hasRetVal = hasRetVal;
        this.bodySizeRange = bodySizeRange;
        this.cfgEdgeRange = cfgEdgeRange;
        this.cfgBlockRange = cfgBlockRange;
        this.xrefsRange = xrefsRange;
        this.referStrings = referStrings;
        this.magicValues = magicValues;
        this.funcEntrySigns = funcEntrySigns;
        this.criticalIndex = criticalIndex;
        this.funcType = funcType;
    }

    public Pair<Integer, Integer> getCalledFuncNumRange() {
        return calledFuncNumRange;
    }

    public void setCalledFuncNumRange(Pair<Integer, Integer> calledFuncNumRange) {
        this.calledFuncNumRange = calledFuncNumRange;
    }

    public Pair<Integer, Integer> getParamNumRange() {
        return paramNumRange;
    }

    public void setParamNumRange(Pair<Integer, Integer> paramNumRange) {
        this.paramNumRange = paramNumRange;
    }

    public Pair<Integer, Integer> getCallNumRange() {
        return callNumRange;
    }

    public void setCallNumRange(Pair<Integer, Integer> callNumRange) {
        this.callNumRange = callNumRange;
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

    public Pair<Integer, Integer> getBodySizeRange() {
        return bodySizeRange;
    }

    public void setBodySizeRange(Pair<Integer, Integer> bodySizeRange) {
        this.bodySizeRange = bodySizeRange;
    }

    public Pair<Integer, Integer> getCfgEdgeRange() {
        return cfgEdgeRange;
    }

    public void setCfgEdgeRange(Pair<Integer, Integer> cfgEdgeRange) {
        this.cfgEdgeRange = cfgEdgeRange;
    }

    public Pair<Integer, Integer> getCfgBlockRange() {
        return cfgBlockRange;
    }

    public void setCfgBlockRange(Pair<Integer, Integer> cfgBlockRange) {
        this.cfgBlockRange = cfgBlockRange;
    }

    public Pair<Integer, Integer> getXrefsRange() {
        return xrefsRange;
    }

    public void setXrefsRange(Pair<Integer, Integer> xrefsRange) {
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

    public void setCriticalIndex(List<Integer> criticalIndex) { this.criticalIndex = criticalIndex; }

    public List<Integer> getCriticalIndex() { return criticalIndex; }

    public void setFuncType(String funcType){this.funcType = funcType;}
    public String getFuncType(){return funcType;}
}
