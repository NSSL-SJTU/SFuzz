/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Decode Pcode for the cursor function

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.PartitionCodeSubModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import docking.widgets.OptionDialog;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import java.util.*;

public class GetBlockInfo extends GhidraScript {

    HighFunction hfunction = null;

    public boolean decompileFunction(Function f, DecompInterface decomplib) {

        DecompileResults decompRes = decomplib.decompileFunction(f, decomplib.getOptions().getDefaultTimeout(), monitor);
        //String statusMsg = decomplib.getDecompileMessage();

        hfunction = decompRes.getHighFunction();

        if (hfunction == null)
            return false;

        return true;
    }

    @Override
    public void run() throws Exception {
        DecompInterface decomplib = setUpDecompiler(currentProgram);
        try {
            if (!decomplib.openProgram(currentProgram)) {
                println("Decompile Error: " + decomplib.getLastMessage());
                return;
            }
            Function targetFunc = getFunctionAt(currentAddress);
            println("Func Name:" + targetFunc.getName());
            boolean success = decompileFunction(targetFunc, decomplib);
            if (success) {
                
                int edgeCount = 0;
                for (PcodeBlockBasic pbb:hfunction.getBasicBlocks()) {
                    edgeCount += pbb.getOutSize();
                }
            
                long realSize = targetFunc.getBody().getMaxAddress().getOffset() - targetFunc.getBody().getMinAddress().getOffset();
                println("param num is:" + String.valueOf(hfunction.getLocalSymbolMap().getNumParams()));
                println("call num is:" + String.valueOf(targetFunc.getCalledFunctions(monitor).size()));
                println("has loop:" + String.valueOf(hasloop(hfunction.getBasicBlocks())));
                println("has ret val:" + String.valueOf(!targetFunc.hasNoReturn()));
                println("func body size is:" + String.valueOf(realSize));
                println("basicblock edge is:" + String.valueOf(edgeCount));
                println("basicblock num is:" + String.valueOf(hfunction.getBasicBlocks().size()));
                println("xrefs num:" + String.valueOf(targetFunc.getCallingFunctions(monitor).size()));
            }
        }
        finally {
            decomplib.dispose();
        }
    }

    private boolean hasloop(ArrayList<PcodeBlockBasic> pbbs) {
        if (pbbs.size() < 1) {
            return false;
        }
        Set<Long> visited = new HashSet<>();
        PcodeBlockBasic firstPBB = pbbs.get(0);
        Queue<PcodeBlock> queue = new LinkedList<>();
        queue.add(firstPBB);
        //利用BFS的方式去判断是否存在环
        while(!queue.isEmpty()) {
            PcodeBlock thisPBB = queue.poll();
            Long thisPBBEntryOffset = thisPBB.getStart().getOffset();
            if (visited.contains(thisPBBEntryOffset)) {
                return true;
            } else {
                visited.add(thisPBB.getStart().getOffset());
            }
            for(int i = 0; i < thisPBB.getOutSize();i++) {
                queue.add(thisPBB.getOut(i));
            }
        }
        return false;
    }

    private DecompInterface setUpDecompiler(Program program) {
        DecompInterface decomplib = new DecompInterface();

        DecompileOptions options;
        options = new DecompileOptions();
        OptionsService service = state.getTool().getService(OptionsService.class);
        if (service != null) {
            ToolOptions opt = service.getOptions("Decompiler");
            options.grabFromToolAndProgram(null,opt,program);
        }
        decomplib.setOptions(options);

        decomplib.toggleCCode(true);
        decomplib.toggleSyntaxTree(true);
        decomplib.setSimplificationStyle("decompile");

        return decomplib;
    }
}