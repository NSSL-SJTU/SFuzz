package com.qianxin.helper;

import com.qianxin.identifier.MatchRes;
import com.qianxin.identifier.Matcher;
import ghidra.framework.main.logviewer.model.Pair;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import org.apache.commons.lang3.StringUtils;

import java.io.*;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.regex.Pattern;

public class WebParamFinder {

    private final HashMap<Address, Pair> candidate_functions;
    private Program program;
    private FlatProgramAPI flatApi;
    private HashSet<String> webParams;
    private Matcher matcher;
    private String webFront;
    private byte program_content[];
    private HashSet<Address> remove_list;

    public WebParamFinder(Program program, Matcher matcher, String webFront) {
        this.program = program;
        this.flatApi = new FlatProgramAPI(program);
        this.webParams = new HashSet<String>();
        this.matcher = matcher;
        this.webFront = webFront;
        this.candidate_functions = new HashMap<Address, Pair>(); // address->(hitcnt, retvalidx)
        this.remove_list = new HashSet<>();
    }

    public void doMatch() {
        this.findWebParams();
        for (String webparam:this.webParams){
            Address addr = findStrAddress(webparam);
//            System.out.print("webparam: "+webparam+", addr: 0x");System.out.println(addr);
            Reference[] refers = flatApi.getReferencesTo(addr);
            for (Reference refer: refers) {

                if (refer.getReferenceType() == RefType.PARAM) {
                    findCalledFunc(refer.getFromAddress());
                }
            }
        }
        judgeTrueWebFunc();
    }
    private void judgeTrueWebFunc(){
        // here we only find the function has the highest similarity
        for (Address addr:remove_list){
            candidate_functions.remove(addr);
        }
        long maxCnt = 0;
        Pair maxInfo = null;
        Address maxAddr = null;
        System.out.println("---------------");
        for (Address addr:candidate_functions.keySet()){
            Pair info = candidate_functions.get(addr);
            System.out.println(info);
            System.out.printf("currCnt %d, currAddr 0x%08x", info.getStart(), addr.getOffset());
            if (info.getStart() > maxCnt && !matcher.getunstripedSet().contains(addr.getOffset())){
                maxInfo = info;
                maxAddr = addr;
                maxCnt = info.getStart();
            }
        }
        System.out.println("================");
        if (maxInfo == null){
            System.out.println("Failed to find any web param related functions");
            return;
        }
        String funcsign=null;
        if (maxInfo.getEnd()==0){
            funcsign = "char* Packt_WebGetsVar(...)";
        }
        else if (maxInfo.getEnd()==1) {
            funcsign = "void Packt_WebGetsVar(char* input, ...)";
        }
        else if (maxInfo.getEnd()==2){
            funcsign = "void Packt_WebGetsVar(void*, char* input, ...)";
        }
        else if (maxInfo.getEnd()==3){
            funcsign = "void Packt_WebGetsVar(void*, void*, char* input, ...)";
        }
        else if (maxInfo.getEnd()==4){
            funcsign = "void Packt_WebGetsVar(void*, void*, void*, char* input, ...)";
        }
        else if (maxInfo.getEnd()==5){
            funcsign = "void Packt_WebGetsVar(void*, void*, void*, void*, char* input, ...)";
        }
        System.out.println("Function at "+maxAddr.toString()+" is found. funcsign: " + funcsign);
        matcher.getMatchResults().add(new MatchRes(maxAddr.getOffset(), "Packt_WebGetsVar", funcsign, "UserInterface", List.of((int)maxInfo.getEnd())));
    }

    private Function findCalledFunc(Address addr) {
        Function callingFunc = flatApi.getFunctionContaining(addr);
        CodeUnit cu = program.getListing().getCodeUnitContaining(addr);
        if (cu == null || callingFunc == null) {
            return null;
        }
        HighFunction hfunc = matcher.getHighFunc(callingFunc);
        if (hfunc == null) return null;
        Iterator<PcodeOpAST> iter = hfunc.getPcodeOps();
//        PcodeOpAST finded = null;

        while (iter.hasNext()) {
            PcodeOpAST thisOp = iter.next();
            long thisOpOffset = thisOp.getSeqnum().getTarget().getOffset();
            if (thisOp.getOpcode() == PcodeOp.CALL
                    && thisOpOffset >= cu.getMinAddress().getOffset()) {  
   
                System.out.printf("Find caller instr @ 0x%08x caller func @ 0x%08x\n", thisOp.getSeqnum().getTarget().getOffset(), callingFunc.getEntryPoint().getOffset());
                if (thisOp.getNumInputs()>=2){ 
         
                    Integer retValIdx=-1;
                    if (thisOp.getOutput()!=null){
        
                        retValIdx = 0;
                    }
                    else {
                      
                        for (int i = 1; i < thisOp.getNumInputs(); i++) {
                            if(thisOp.getInput(i).getDef()!=null){// && thisOp.getInput(i).isRegister()){
                                retValIdx = i;
                                break;
                            }
                        }
                    }
                    if (retValIdx<0){
                        System.out.println("Function call at "+thisOp.getInput(0).getAddress().toString()+" cannot extract input position(WebParamFinder)");
                       
                        remove_list.add(thisOp.getInput(0).getAddress());
                    }
                    else {
                        Address calleeFuncAddr = thisOp.getInput(0).getAddress();
                        if (candidate_functions.containsKey(calleeFuncAddr)) {
                            Pair info = (candidate_functions.get(calleeFuncAddr));
                            if (info.getEnd()!=retValIdx){
                               
                                remove_list.add(thisOp.getInput(0).getAddress());
                            }
                            else {
                                candidate_functions.put(calleeFuncAddr, new Pair(info.getStart() + 1, retValIdx));
                            }
                        } else {
                            candidate_functions.put(calleeFuncAddr, new Pair(1, retValIdx));
                        }
                    }
                }
                break;
            }
        }
        return null;
    }

    private Address findStrAddress(String target) {
        /*
        This method is much slower(deprecated)
        CodeUnitIterator cuIter = program.getListing().getCodeUnits(true);

        while(cuIter.hasNext() && !flatApi.getMonitor().isCancelled()) {
            CodeUnit cu = cuIter.next();
            if (cu instanceof Data) {
                Data data = (Data)cu;
                Object obj = data.getValue();
                if (obj != null) {
                    String str = obj.toString();
                    if (str != null) {
                        if (str.equals(target)) {
                            return data.getMinAddress();
                        }
                    }
                }
            }
        }
        return null;
        */
        return this.flatApi.findBytes(this.program.getMinAddress(), target);

    }

    private void findWebParams() {
        if (StringUtils.isEmpty(this.webFront)) {
            CodeUnitIterator cuIter = program.getListing().getCodeUnits(true);
            Pattern pattern = Pattern.compile("name=\"(.*?)\"");
            while(cuIter.hasNext() && !flatApi.getMonitor().isCancelled()) {
                CodeUnit cu = cuIter.next();
                if (cu instanceof Data) {
                    Data data = (Data)cu;
                    Object obj = data.getValue();
                    if (obj != null) {
                        String str = obj.toString();
 
                        if (str != null && str.length() > 100) {
                            if (str.contains("name=\"")) {
                                java.util.regex.Matcher matcher = pattern.matcher(str);
                                while (matcher.find()) {
               
                                    if (!matcher.group(1).strip().equals("")) {
                                        webParams.add(matcher.group(1));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        else{
            try {
                File file = new File(this.webFront);
                InputStreamReader input = new InputStreamReader(new FileInputStream(file));
                BufferedReader bf = new BufferedReader(input);
                String str;
                while ((str = bf.readLine()) != null) {
                    // Some of web params are actually not referenced in program, filter them out here
                    if (str.length()<=0) continue;
                    Address startaddr = this.program.getMinAddress();

                    Address addr = this.flatApi.findBytes(startaddr, str);
                    while (addr != null) {
                        Reference[] refers = flatApi.getReferencesTo(addr);
                        if (refers.length != 0){
                            webParams.add(str);
                            break;
                        }
                        else{
                            startaddr = addr.add(1);
                            addr = this.flatApi.findBytes(startaddr, str);
                        }
                    }
                    if (addr == null)
                        System.out.println("webparam " + str + " is not referenced in program");
                }
                bf.close();
                input.close();
            } catch (IOException e) {
                e.printStackTrace();
                System.exit(1);
            }
        }
    }
}
