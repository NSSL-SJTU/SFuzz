package com.qianxin.identifier;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import org.apache.commons.lang3.tuple.Pair;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

public abstract class BaseFunc {


    protected int TOTAL_FUNC_NUM;
    protected Program program;
    protected EmulatorHelper emuHelper;
    protected List<FuncFeature> features;
    protected List<FuncTestData> testDataList;
    protected Matcher matcher;
    protected String userInterface = "UserInterface";
    protected String taskDataConvey = "TaskDataConvey";
    protected String dataSink = "DataSink";
    protected String checksum = "Checksum";


    public Matcher getMatcher() {
        return matcher;
    }

    public void setMatcher(Matcher matcher) {
        this.matcher = matcher;
    }

    public void setTOTAL_FUNC_NUM(int TOTAL_FUNC_NUM) {
        this.TOTAL_FUNC_NUM = TOTAL_FUNC_NUM;
    }

    public void setProgram(Program program) {
        this.program = program;
    }

    public void setEmuHelper(EmulatorHelper emuHelper) {
        this.emuHelper = emuHelper;
    }


    public abstract List<FuncFeature> setFeatures();

    public List<FuncFeature> getFeatures() {
        if (this.features == null) {
            this.features = this.setFeatures();
        }
        return this.features;
    }


    public List<FuncTestData> getTests() {
        if (this.testDataList == null) {
            this.testDataList = this.setTests();
        }
        return this.testDataList;
    }

    public abstract List<FuncTestData> setTests();


    public abstract String getFuncName();


    public abstract String getFuncSign();

}
