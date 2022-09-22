package com.qianxin.helper.emuer;

import com.qianxin.helper.BaseEmuer;
import com.qianxin.helper.LanguageId;

import java.util.List;

@LanguageId(processor = "x86",size = 32)
public class X8632 extends BaseEmuer {
    private String[] params = {};
    private String retReg = "eax";

    @Override
    protected boolean setArgs(List<Long> args) {
        emuHelper.writeRegister(emuHelper.getStackPointerRegister(),0x2FFF0000);
        for (int i=0; i < args.size(); i++) {
            if (i <= params.length - 1) {
                emuHelper.writeRegister(params[i],args.get(i));
            } else {
                try {
                    emuHelper.writeStackValue(4+(i- params.length)*4,4, args.get(i));
                } catch (Exception e) {
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    protected String getRetRegName() {
        return this.retReg;
    }
}
