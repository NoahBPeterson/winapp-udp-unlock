# @category Analysis
# Locate the UDP gate in Windows App.
#
# Method (version-independent):
#   1. Find the string literal "EnableUdpSideTransport"
#   2. Find every instruction that references it
#   3. For each reference, identify the containing function
#   4. Of those, find the one where the string is used as a map key (WRITE), not a GetProperty arg (READ)
#   5. Within that function, find the outermost conditional branch whose "taken" path
#      skips past this string reference. That's the gate.
#
# Prints VA (virtual address) of the candidate branch instructions.
# Human review required before patching — this script does NOT write to the binary.

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

prog = currentProgram
listing = prog.getListing()
fm = prog.getFunctionManager()
ref_mgr = prog.getReferenceManager()

decomp = DecompInterface()
decomp.openProgram(prog)
monitor = ConsoleTaskMonitor()

TARGET_STRING = "EnableUdpSideTransport"

# Step 1: find the string
string_addrs = []
for d in listing.getDefinedData(True):
    v = d.getValue()
    if v is None:
        continue
    if str(v) == TARGET_STRING:
        string_addrs.append(d.getAddress())

print("=" * 60)
print("String %r found at: %s" % (TARGET_STRING, [str(a) for a in string_addrs]))
if not string_addrs:
    print("MISSING — feature likely removed from this build.")
    raise SystemExit

# Step 2-3: find all xrefs and their containing functions
candidate_fns = {}
for sa in string_addrs:
    for r in ref_mgr.getReferencesTo(sa):
        fn = fm.getFunctionContaining(r.getFromAddress())
        if fn:
            candidate_fns.setdefault(fn, []).append(r.getFromAddress())

print("\n%d unique function(s) reference the string:" % len(candidate_fns))
for fn, refs in candidate_fns.items():
    print("  - %s @ %s  (refs: %s)" % (fn.getName(True), fn.getEntryPoint(),
                                        ", ".join(str(r) for r in refs)))

# Step 4: find the function whose decompilation assigns the string as a map key.
# Heuristic: the WRITE call site usually has an adjacent "emplace"/"insert"/"__tree"
# or "variant" or "map" call; the READ site will have "GetProperty" or similar.
print("\n=" * 60)
print("Decompilation analysis:")
writer_fn = None
for fn in candidate_fns:
    res = decomp.decompileFunction(fn, 120, monitor)
    if not res or not res.decompileCompleted():
        continue
    body = res.getDecompiledFunction().getC()
    # simple signals
    has_write_signal = any(s in body for s in ["__emplace_unique_key_args", "__tree", "piecewise_construct"])
    has_read_signal = "GetProperty" in body
    n_occurrences = body.count('"EnableUdpSideTransport"')
    print("\n  %s" % fn.getName(True))
    print("    string occurrences in decomp: %d" % n_occurrences)
    print("    write signal (emplace/tree): %s" % has_write_signal)
    print("    read signal (GetProperty):   %s" % has_read_signal)
    if has_write_signal and not writer_fn:
        writer_fn = fn

if not writer_fn:
    print("\nCOULD NOT IDENTIFY WRITER — review above candidates manually.")
    raise SystemExit

print("\n" + "=" * 60)
print("WRITER: %s @ %s" % (writer_fn.getName(True), writer_fn.getEntryPoint()))

# Step 5: find candidate gate branches.
# Walk instructions in the writer function. For each conditional branch
# (cbz, cbnz, b.eq, b.ne, etc.) whose target is *beyond* the first reference
# to the string, collect it. The gate is typically the conditional whose
# branch target lands just past the entire UDP property-write block.
from ghidra.program.model.lang import OperandType
inst_iter = listing.getInstructions(writer_fn.getBody(), True)

# First, find the VA of the earliest reference to the string within this function
first_str_ref = min(candidate_fns[writer_fn])
last_str_ref  = max(candidate_fns[writer_fn])
print("String refs in writer: %s .. %s" % (first_str_ref, last_str_ref))

cond_mnemonics = {"cbz", "cbnz", "b.eq", "b.ne", "b.lt", "b.gt", "b.le", "b.ge",
                  "b.cc", "b.cs", "b.mi", "b.pl", "b.vs", "b.vc", "b.hi", "b.ls",
                  "tbz", "tbnz"}

gate_candidates = []
for inst in inst_iter:
    mn = inst.getMnemonicString().lower()
    if mn not in cond_mnemonics:
        continue
    # branch target is the last operand
    n_ops = inst.getNumOperands()
    target = None
    for i in range(n_ops):
        refs = inst.getOperandReferences(i)
        for r in refs:
            if r.getReferenceType().isJump():
                target = r.getToAddress()
                break
        if target:
            break
    if target is None:
        continue
    inst_va = inst.getAddress()
    # The UDP gate is a conditional BEFORE the first string ref whose target is AFTER the last string ref
    if inst_va.compareTo(first_str_ref) < 0 and target.compareTo(last_str_ref) > 0:
        gate_candidates.append((inst_va, mn, target))

print("\nGate candidates (branches skipping past all string refs):")
for va, mn, t in gate_candidates:
    print("  %s  %-6s  -> %s" % (va, mn, t))

if not gate_candidates:
    print("  NONE — the block may already be unconditional. Verify manually.")
else:
    print("\nRecommended patch target: LAST candidate in the list above.")
    print("(Outer gates short-circuit to the same skip; the innermost still-executing")
    print(" gate is the one immediately before the block starts.)")
    last = gate_candidates[-1]
    print("\nPatch: VA %s  (was %s) -> nop" % (last[0], last[1]))
    print("\nTo compute fat-file offset on the filesystem:")
    print("  arm64_offset=$(lipo -detailed_info <binary> | awk '$1==\"architecture\" && $2==\"arm64\" {f=1} f && $1==\"offset\" {print $2; exit}')")
    print("  fat_off = arm64_offset + (0x%s - 0x100000000)" % str(last[0]).lstrip("0"))
