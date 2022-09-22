package com.qianxin.utils;

import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

public class StringsUtils {

    private Program program;
    private FlatProgramAPI flatApi;
    private byte TERMINATOR = '\00';

    public StringsUtils(Program program) {
        this.program = program;
        this.flatApi = new FlatProgramAPI(program);
    }

    private boolean isAsciiAndNotTerminator(Address addr) {
        try {
            byte b = program.getMemory().getByte(addr);
            if (b == TERMINATOR) {
                return false;
            }
            return (b >= 0x20 && b <= 0x7f) || b == '\n' || b == '\r' || b == '\t';
        }
        catch (MemoryAccessException e) {
            return false;
        }
    }

    private Address findStartOfString(Address endAddr) {
        Address addr = endAddr;
        Address startAddr = endAddr;
        try {
            addr = addr.subtract(1);
            while (isAsciiAndNotTerminator(addr)) {
                startAddr = addr;
                addr = addr.subtractNoWrap(1);
            }
        }
        catch (AddressOverflowException e) {
            // TODO Auto-generated catch block
//            e.printStackTrace();
        }
        catch (AddressOutOfBoundsException e) {
            //do nothing
        }
        return startAddr;
    }

    private void myCreateAsciiString(Address startAddr, int length) throws Exception {
        int txId = program.startTransaction("createString");
        try {
            program.getListing().createData(startAddr, new StringDataType(), length);
        } catch (Exception e) {
            return;
        }finally {
            program.endTransaction(txId, true);
        }
//        System.out.printf("0x%x\n",startAddr.getOffset());
    }

    private void createString(Address endAddr) {
        Address startAddr = findStartOfString(endAddr);
        int length = (int) endAddr.subtract(startAddr) + 1;
        if (length < 10) {
            return;
        }
        try {
            Data thisData = flatApi.getDataAt(startAddr);
            if (thisData == null) {
                myCreateAsciiString(startAddr, length);
            }
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }


    public void createMoreString() {
        Address addr = flatApi.find(null, TERMINATOR);
        while (addr != null) {
            createString(addr);
            try {
                addr = addr.addNoWrap(1);
                addr = flatApi.find(addr, TERMINATOR);
            }
            catch (AddressOverflowException e) {
                // must be at largest possible address - so we are done
                return;
            }
        }
    }
}
