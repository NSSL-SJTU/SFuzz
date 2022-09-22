package com.qianxin.helper;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import me.tongfei.progressbar.ProgressBar;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.*;

public class Finder {

    private Program program;
    private FlatProgramAPI flatApi;
    private List<Long> loadTargets;
    private List<Long> strAddrs;
    private Listing listing;
    private int pointerSize;
    private boolean accurateMode;
    private boolean highConfidence;

    public Finder(Program program,Boolean accurateMode) {
        this.program = program;
        this.accurateMode = accurateMode;
        this.flatApi = new FlatProgramAPI(program);
        this.listing = program.getListing();
        this.pointerSize = this.program.getDefaultPointerSize();
        this.loadTargets = new ArrayList<>();
        this.strAddrs = new ArrayList<>();
        this.highConfidence = false;
    }

    public boolean isHighConfidence() {
        return highConfidence;
    }

    private void findLoadInArm() {
        InstructionIterator insIter = listing.getInstructions(true);
        while(insIter.hasNext()) {
            Instruction ins = insIter.next();
            PcodeOp[] ops = ins.getPcode();
            for(PcodeOp opItem:ops) {

                if (opItem.getOpcode() == PcodeOp.LOAD) {
                    Varnode loadAddr = opItem.getInput(1);
                    if (loadAddr.isConstant()) {
                        long loadOffset = loadAddr.getOffset();
                      
                        if (loadOffset >= program.getMinAddress().getOffset() && loadOffset <= program.getMaxAddress().getOffset()) {
                            try {
                                Long absAddr = null;
                                absAddr = program.getMemory().getLong(flatApi.toAddr(loadOffset));
                                //32bit
                                if (this.pointerSize == 4) {
                                    absAddr = absAddr & 0x00000000ffffffffL;
                                } else if (this.pointerSize == 8) {
                                    //64bit
                                    //to nothing
                                } else if (this.pointerSize == 2) {
                                    absAddr = absAddr & 0x000000000000ffffL;
                                } else {
                                    System.out.println("No support for other pointerSize");
                                    System.exit(1);
                                }
                                if (absAddr != null) {
                                    loadTargets.add(absAddr);
                                }
                            } catch (MemoryAccessException e) {
                                continue;
                            }
                        }
                    }
                }
            }
        }
    }

    private void findLoadInPowerPC() {
        InstructionIterator insIter = listing.getInstructions(true);
        Instruction lastIns = null;
        while(insIter.hasNext()) {
            Instruction ins = insIter.next();
            if (lastIns != null) {
                PcodeOp[] ops = ins.getPcode();
                PcodeOp[] lastOps = lastIns.getPcode();
                if (ops.length == 1 && lastOps.length == 1) {
                    PcodeOp thisOp = ops[0];
                    PcodeOp lastOp = lastOps[0];
                    if (thisOp.getOpcode() == PcodeOp.INT_ADD && lastOp.getOpcode() == PcodeOp.INT_LEFT
                    && thisOp.getOutput().toString().equals(lastOp.getOutput().toString())) {

                        long first = lastOp.getInput(0).getOffset();
                        long second = lastOp.getInput(1).getOffset();
                        long initVal = first << second;
                        int toAddVal = (int) thisOp.getInput(1).getOffset();
                        loadTargets.add(initVal + toAddVal);
                    }
                }
            }
            lastIns = ins;
        }
    }

    private void findAllLoadTarget() {
        String processor = program.getMetadata().get("Processor").toLowerCase();
        if (processor.equals("powerpc") || processor.equals("mips")) {
            findLoadInPowerPC();
        } else {
            findLoadInArm();
        }
    }

    private void findAllStrAddrs() {
        DataIterator dataIter = listing.getData(true);
        while(dataIter.hasNext()) {
            Data dataItem = dataIter.next();
            if(dataItem.getDataType().getName().toLowerCase().equals("string")) {
                this.strAddrs.add(dataItem.getAddress().getOffset());
            }
        }
    }

    private Long findBestBase() {
        Long baseOffset = null;
        if (loadTargets.size() == 0) {
            return baseOffset;
        }
        long middle = findMiddle();
        long binarySize = program.getMaxAddress().getOffset() - program.getMinAddress().getOffset();
        long minBase = middle - binarySize;
        Map<Long,Integer> records = new HashMap<>();
        try (ProgressBar pb = new ProgressBar("Finding", ((long)loadTargets.size()) * ((long)strAddrs.size()))) {
            for (long target:loadTargets) {
                for(long relativeOffset:strAddrs) {
                    long val = target - relativeOffset;
                    pb.step();
                    if (records.containsKey(val)) {
                        records.put(val, records.get(val) + 1);
                    } else {
                        records.put(val,1);
                    }
                }
            }
        }
        List<Map.Entry<Long, Integer>> recordsList = new ArrayList<>(records.entrySet());

        Collections.sort(recordsList, new Comparator<>() {
            @Override
            public int compare(Map.Entry<Long, Integer> o1, Map.Entry<Long, Integer> o2) {
                return o2.getValue() - o1.getValue();
            }
        });
        int recordListSize = recordsList.size();
        for(int i=0; i< recordListSize;i++) {
            long thisBase = recordsList.get(i).getKey();
            if (thisBase > minBase && thisBase < middle) {
                int thisVal = recordsList.get(i).getValue();
                if (i + 1 < recordListSize) {
                    int lastVal = recordsList.get(i+1).getValue();
                    if (thisVal > 3 * lastVal) {
                        this.highConfidence =true;
                    }
                }
                return thisBase;
            }
        }
        return baseOffset;
    }

    private Long rawFindBestBase() {
        Long baseOffset = null;
        if (loadTargets.size() == 0) {
            return baseOffset;
        }
        Set<Long> targetsSet = new HashSet<>(loadTargets);
        long middle = findMiddle();
        long binarySize = program.getMaxAddress().getOffset() - program.getMinAddress().getOffset();
        long minBase = middle - binarySize;
        if (middle > 0 && minBase < 0) {
            minBase = 0;
        }
        int stepSize = 1;
        if (accurateMode) {
            minBase = minBase & 0xfffffffffffffff0L;
            stepSize = this.pointerSize;
        } else {
            minBase = minBase & 0xfffffffffffff000L;
            stepSize = 0x1000;
        }
        int maxMatch = 0;
        int pbMax = (int) ((binarySize-1)/stepSize) + 1;
        try (ProgressBar pb = new ProgressBar("Finding", pbMax)) {
            for (long i=0; i<binarySize; i += stepSize) {
                pb.step();
                int mactchCount = 0;
                long currentBase = minBase + i;
                for (int j=0; j <strAddrs.size(); j++) {
                    if (targetsSet.contains(strAddrs.get(j) + currentBase)) {
                        mactchCount += 1;
                    }
                }
                if (mactchCount > maxMatch) {
                    if (maxMatch !=0 && mactchCount > maxMatch * 3) {
                        this.highConfidence = true;
                    } else {
                        this.highConfidence = false;
                    }
                    maxMatch = mactchCount;
                    baseOffset = currentBase;
//                    System.out.printf("%d @0x%x\n",maxMatch,baseOffset);
                    pb.setExtraMessage(String.format("Current res...:0x%x",baseOffset));
                }
            }
        }
        return baseOffset;
    }


    private Long findMiddle() {
        Collections.sort(loadTargets);
        int targetSize = loadTargets.size();
        if (targetSize % 2 == 0) {
            int halfPos = targetSize/2;
            return (loadTargets.get(halfPos) + loadTargets.get(halfPos + 1)) / 2;
        } else {

            return loadTargets.get(targetSize/2 + 1);
        }
    }

    public Long findBase() {
        Long baseOffset = null;

        findAllLoadTarget();

        findAllStrAddrs();
//        Collections.shuffle(loadTargets);
//        Collections.shuffle(strAddrs);
//        loadTargets = loadTargets.subList(0,10000);
//        strAddrs = strAddrs.subList(0,10000);
        System.out.printf("find %d load target.\n",this.loadTargets.size());
        System.out.printf("find %d str addr.\n",this.strAddrs.size());

        if (!accurateMode) {
            baseOffset = rawFindBestBase();
        }
        if (accurateMode || !this.highConfidence) {
            System.out.println("Not found in fast mode. Switch to accurate mode.");
            baseOffset = findBestBase();
        }
        return baseOffset;
    }
}
