import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.block.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.File;

public class feature_extractor extends GhidraScript {

    @Override
    public void run() throws Exception {

        println("Script started...");

        if (getScriptArgs().length < 1) {
            println("Usage: feature_extractor.java <output_csv>");
            return;
        }

        String outputPath = getScriptArgs()[0];

        String binaryName = currentProgram.getName();

        Listing listing = currentProgram.getListing();
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        BasicBlockModel bbModel = new BasicBlockModel(currentProgram);

        File outFile = new File(outputPath);
        File parent = outFile.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        boolean writeHeader = !outFile.exists() || outFile.length() == 0;
        PrintWriter writer = new PrintWriter(new FileWriter(outFile, true));

        if (writeHeader) {
            writer.println(
                "binary,function,instructions,basic_blocks,edges," +
                "calls,indirect_calls,jumps,loops," +
                "mem_reads,mem_writes,stack_size," +
                "avg_bb_size,max_bb_size," +
                "call_density,mem_write_ratio,jump_density,label"
            );
        }

        while (funcs.hasNext()) {

            Function func = funcs.next();

            if (func.isExternal()) continue;
            if (func.getName().startsWith("_")) continue;
            if (func.getName().contains("clone")) continue;
            if (func.getName().contains("dtors")) continue;

            int label = func.getName().toLowerCase().contains("vuln") ? 1 : 0;

            AddressSetView body = func.getBody();

            int instructionCount = 0;
            int callCount = 0;
            int indirectCallCount = 0;
            int jumpCount = 0;
            int basicBlockCount = 0;
            int edgeCount = 0;
            int stackSize = 0;
            int memoryWriteCount = 0;
            int memoryReadCount = 0;
            int loopCount = 0;

            int maxBasicBlockSize = 0;
            int totalBasicBlockSize = 0;

            if (func.getStackFrame() != null) {
                stackSize = func.getStackFrame().getFrameSize();
            }

            InstructionIterator instructions =
                listing.getInstructions(body, true);

            while (instructions.hasNext()) {

                Instruction instr = instructions.next();
                instructionCount++;

                FlowType flow = instr.getFlowType();

                if (flow.isCall()) {
                    callCount++;
                    if (flow.isIndirect()) {
                        indirectCallCount++;
                    }
                }

                if (flow.isJump()) {
                    jumpCount++;

                    Address[] flows = instr.getFlows();
                    if (flows != null) {
                        for (Address target : flows) {
                            if (target.compareTo(instr.getAddress()) < 0) {
                                loopCount++;
                            }
                        }
                    }
                }

                for (int i = 0; i < instr.getNumOperands(); i++) {
                    RefType ref = instr.getOperandRefType(i);
                    if (ref != null) {
                        if (ref.isWrite()) memoryWriteCount++;
                        if (ref.isRead()) memoryReadCount++;
                    }
                }
            }

            CodeBlockIterator blocks =
                bbModel.getCodeBlocksContaining(body, TaskMonitor.DUMMY);

            while (blocks.hasNext()) {

                CodeBlock block = blocks.next();
                basicBlockCount++;

                int blockSize = 0;
                InstructionIterator bbInstructions =
                    listing.getInstructions(block, true);

                while (bbInstructions.hasNext()) {
                    bbInstructions.next();
                    blockSize++;
                }

                totalBasicBlockSize += blockSize;
                if (blockSize > maxBasicBlockSize) {
                    maxBasicBlockSize = blockSize;
                }

                CodeBlockReferenceIterator dests =
                    block.getDestinations(TaskMonitor.DUMMY);

                while (dests.hasNext()) {
                    dests.next();
                    edgeCount++;
                }
            }

            if (instructionCount < 5) continue;

            double avgBasicBlockSize =
                (basicBlockCount > 0) ?
                (double) totalBasicBlockSize / basicBlockCount : 0.0;

            double callDensity =
                (double) callCount / instructionCount;

            double memWriteRatio =
                (double) memoryWriteCount / instructionCount;

            double jumpDensity =
                (double) jumpCount / instructionCount;

            writer.println(
                binaryName + "," +
                func.getName() + "," +
                instructionCount + "," +
                basicBlockCount + "," +
                edgeCount + "," +
                callCount + "," +
                indirectCallCount + "," +
                jumpCount + "," +
                loopCount + "," +
                memoryReadCount + "," +
                memoryWriteCount + "," +
                stackSize + "," +
                avgBasicBlockSize + "," +
                maxBasicBlockSize + "," +
                callDensity + "," +
                memWriteRatio + "," +
                jumpDensity + "," +
                label
            );
        }

        writer.close();
        println("Dataset generated successfully.");
    }
}