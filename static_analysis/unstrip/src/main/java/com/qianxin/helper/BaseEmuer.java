package com.qianxin.helper;

import com.qianxin.identifier.BaseFunc;
import com.qianxin.identifier.FuncTestData;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public abstract class BaseEmuer {


    protected EmulatorHelper emuHelper;
    protected Program program;
    protected FlatProgramAPI flatApi;
    protected Function func;
    protected BaseFunc funcInfo;
    protected Address controlledReturnAddr;

    public void init(Program program,FlatProgramAPI flatApi, Function func,BaseFunc funcInfo) {
        this.program = program;
        this.flatApi = flatApi;
        this.func = func;
        this.funcInfo = funcInfo;
    }

    public Function getFunc() {
        return func;
    }

    protected void initEmuHelper() {
        this.emuHelper = new EmulatorHelper(program);
        emuHelper.writeRegister(emuHelper.getPCRegister(),func.getEntryPoint().getOffset());
    }

    private boolean emulating() {
        TaskMonitor monitor = flatApi.getMonitor();
        int maxCount = 10000;
        int count = 0;
        while(!monitor.isCancelled()) {
            count += 1;
            if (count > maxCount) {
                break;
            }
            Address executionAddress = emuHelper.getExecutionAddress();
//            System.out.printf("0x%x\n",executionAddress.getOffset());
            if (executionAddress.getOffset() == controlledReturnAddr.getOffset()) {
                return true;
            }
            try {
                boolean success = emuHelper.step(monitor);
                if (!success) {
                    return false;
                }
            } catch (CancelledException e) {
                return false;
            }
        }
        return false;
    }

    protected abstract boolean setArgs(List<Long> args);

    protected boolean preSetMem(Map<Long, byte[]> memConf) {
        for (Map.Entry<Long,byte[]> item:memConf.entrySet()) {
            emuHelper.writeMemory(flatApi.toAddr(item.getKey()),item.getValue());
        }
        return true;
    }

    protected boolean checkConditions(Map<Long, byte[]> conditions) {
        for (Map.Entry<Long,byte[]> item:conditions.entrySet()) {
            byte[] res = emuHelper.readMemory(flatApi.toAddr(item.getKey()),item.getValue().length);
            if (!Arrays.equals(res,item.getValue())) {
                return false;
            }
        }
        return true;
    }

    protected abstract String getRetRegName();

    protected boolean checkRet(byte[] expectedVal) {
        BigInteger bigInt = emuHelper.readRegister(getRetRegName());
//        System.out.println(Arrays.toString(bigInt.toByteArray()));
        BigInteger expectedBigInt = new BigInteger(expectedVal);
        if (bigInt.equals(expectedBigInt)) {
            return true;
        }
        return false;
    }

    protected void setRetAddr(long retAddr) {
        this.controlledReturnAddr = flatApi.toAddr(retAddr);
    }

    public boolean doEmulate() {
        if (funcInfo.getTests() == null) {
            return true;
        }
        for (FuncTestData testData:funcInfo.getTests()) {
            initEmuHelper();
            funcInfo.setEmuHelper(emuHelper);
            funcInfo.setProgram(program);
            try {
                setRetAddr(testData.getControlledRetAddr());
                List<Long> args = testData.getArguments();
                if (args != null) {
                    boolean setRes = setArgs(args);
                    if (!setRes) {
                        return false;
                    }
                }
                Map<Long,byte[]> memPreset = testData.getPresetMem();
                if (memPreset != null) {
                    boolean setMemRes = preSetMem(memPreset);
                    if (!setMemRes) {
                        return false;
                    }
                }
                boolean emuRes = emulating();
                if (!emuRes) {
                    return false;
                }
                Map<Long,byte[]> conditions = testData.getConditions();
                if (conditions != null) {
                    boolean checkRes = checkConditions(conditions);
                    if (!checkRes) {
                        return false;
                    }
                }
                byte[] retVal = testData.getRetVal();
                if (retVal != null) {
                    boolean retRes = checkRet(retVal);
                    if (!retRes) {
                        return false;
                    }
                }
                Method[] methods = funcInfo.getClass().getMethods();
                for(Method method:methods) {
                    if (method.getName().startsWith("customCheck")) {
                        try {
                            boolean checkRes = (Boolean) method.invoke(funcInfo, this);
                            if (!checkRes) {
                                return false;
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                            return false;
                        }
                    }
                }
            } finally {
                emuHelper.dispose();
            }
        }
        return true;
    }
}
