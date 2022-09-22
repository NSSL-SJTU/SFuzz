package com.qianxin.identifier;

import org.json.JSONObject;

import java.util.List;

public class MatchRes {

    private long offset;
    private String funcName;
    private String funcSign;
    private String funcType;
    private List<Integer> criticalIndex;

    public MatchRes(long offset, String funcName, String funcSign, String funcType, List<Integer> criticalIndex) {
        this.offset = offset;
        this.funcName = funcName;
        this.funcSign = funcSign;
        this.criticalIndex = criticalIndex;
        this.funcType = funcType;
    }

    public JSONObject toJsonStr() {
        JSONObject job = new JSONObject();
        job.put("offset",String.format("0x%x",this.offset));
        job.put("funcName",this.funcName);
        job.put("funcSign",this.funcSign);
        job.put("funcType",this.funcType);
        if (this.criticalIndex!=null) {
//            System.out.println(this.criticalIndex);
            String criIdxStr = "[";
            for (Integer idx : this.criticalIndex) {
                criIdxStr += String.format("%d, ", idx);
            }
            criIdxStr = criIdxStr.substring(0, criIdxStr.length() - 2);
            criIdxStr += "]";
            job.put("criticalIndex", criIdxStr);
        }
        return job;
    }

    public long getOffset() {
        return offset;
    }

    public void setOffset(long offset) {
        this.offset = offset;
    }

    public String getFuncName() {
        return funcName;
    }

    public void setFuncName(String funcName) {
        this.funcName = funcName;
    }

    public String getFuncSign() {
        return funcSign;
    }

    public void setFuncSign(String funcSign) {
        this.funcSign = funcSign;
    }
}
