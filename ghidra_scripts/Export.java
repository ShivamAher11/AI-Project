// Export Ghidra function decompilation, assembly, and direct call edges as JSON.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

public class Export extends GhidraScript {
    private static final int MAX_ASSEMBLY_CHARS = 12000;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("Expected one JSON output path.");
        }

        List<String> functions = new ArrayList<>();
        Set<String> callEdges = new TreeSet<>();
        DecompInterface decompiler = new DecompInterface();
        Listing listing = currentProgram.getListing();

        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("Could not initialize the Ghidra decompiler.");
            }
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext() && !monitor.isCancelled()) {
                Function function = iterator.next();
                String address = address(function.getEntryPoint());
                String decompiledCode = null;
                String decompilerStatus = "failed";
                DecompileResults result = decompiler.decompileFunction(function, 60, monitor);
                if (result != null && result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    decompiledCode = result.getDecompiledFunction().getC();
                    decompilerStatus = "ok";
                }

                String assembly = assemblyFor(function, listing, callEdges);
                String signature = function.getSignature().getPrototypeString();
                functions.add(
                    "{\"address\":" + quote(address) +
                    ",\"name\":" + quote(function.getName(true)) +
                    ",\"signature\":" + quote(signature) +
                    ",\"size\":" + function.getBody().getNumAddresses() +
                    ",\"decompiler_status\":" + quote(decompilerStatus) +
                    ",\"decompiled_code\":" + (decompiledCode == null ? "null" : quote(decompiledCode)) +
                    ",\"assembly_excerpt\":" + quote(assembly) + "}"
                );
            }
        }
        finally {
            decompiler.dispose();
        }

        List<String> edges = new ArrayList<>();
        for (String edge : callEdges) {
            int delimiter = edge.indexOf('\u0000');
            edges.add(
                "{\"caller\":" + quote(edge.substring(0, delimiter)) +
                ",\"callee\":" + quote(edge.substring(delimiter + 1)) +
                ",\"type\":\"direct\"}"
            );
        }
        String json = "{\"functions\":[" + String.join(",", functions) +
            "],\"edges\":[" + String.join(",", edges) + "]}\n";
        Files.write(Paths.get(args[0]), json.getBytes(StandardCharsets.UTF_8));
    }

    private String assemblyFor(Function function, Listing listing, Set<String> callEdges) {
        StringBuilder text = new StringBuilder();
        InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            if (text.length() < MAX_ASSEMBLY_CHARS) {
                text.append(address(instruction.getAddress()))
                    .append(": ")
                    .append(instruction.getMnemonicString());
                for (int operand = 0; operand < instruction.getNumOperands(); operand++) {
                    String representation = instruction.getDefaultOperandRepresentation(operand);
                    if (!representation.isEmpty()) {
                        text.append(operand == 0 ? " " : ", ").append(representation);
                    }
                }
                text.append('\n');
            }

            for (Reference reference : currentProgram.getReferenceManager().getReferencesFrom(instruction.getAddress())) {
                if (!reference.getReferenceType().isCall() || reference.getReferenceType().isComputed()) {
                    continue;
                }
                Function callee = currentProgram.getFunctionManager().getFunctionAt(reference.getToAddress());
                if (callee == null) {
                    callee = currentProgram.getFunctionManager().getFunctionContaining(reference.getToAddress());
                }
                if (callee != null) {
                    callEdges.add(address(function.getEntryPoint()) + "\u0000" + address(callee.getEntryPoint()));
                }
            }
        }
        return text.toString();
    }

    private String address(Address address) {
        return "0x" + Long.toHexString(address.getOffset());
    }

    private String quote(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder escaped = new StringBuilder("\"");
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"': escaped.append("\\\""); break;
                case '\\': escaped.append("\\\\"); break;
                case '\b': escaped.append("\\b"); break;
                case '\f': escaped.append("\\f"); break;
                case '\n': escaped.append("\\n"); break;
                case '\r': escaped.append("\\r"); break;
                case '\t': escaped.append("\\t"); break;
                default:
                    if (character < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) character));
                    }
                    else {
                        escaped.append(character);
                    }
            }
        }
        return escaped.append('"').toString();
    }
}