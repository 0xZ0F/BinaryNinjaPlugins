# Binary Ninja Plugins

> These plugins are expirimental and designed for personal use.

Binary Ninja plugins for analyzing MSVC x86-64 binaries. They are to assist with vtable recovery and XFG (eXtended Flow Guard) analysis.

Requires Binary Ninja with an x86-64 binary open. The vtable plugins also need BN's RTTI analysis to have already run. All plugins bail cleanly on other architectures.

To install, copy the `.py` files to `%APPDATA%\Binary Ninja\plugins\`.

## VTables

Two plugins work together to recover typed vtable structs and improve virtual call display in the decompiler.

### vtable_autodefine.py

Builds typed vtable structs from RTTI symbols and wires them into class structs. Requires BN's RTTI analysis to have already produced symbols in MSVC format.

For each class it finds, the pipeline runs in this order:

1. Groups vtable symbols by class name
2. Computes slot counts from address gaps and forward scan
3. Creates `ClassName::VTable` structs with typed function pointer fields
4. Stamps the struct onto the vtable data variable
5. Finds vtable pointer offsets by scanning HLIL/MLIL constructors
6. Updates the class struct with correctly-typed vtable pointer fields
7. Retypes `this` in constructors and virtual methods so HLIL promotes field accesses

All commands are under Plugins -> VTables:

| Command | How to invoke | Description |
|---------|---------------|-------------|
| `Auto-Define for All Classes` | Plugins menu | Process every class with RTTI vtable symbols |
| `Auto-Define for This Class` | Right-click address or function | Process only the class at the cursor |
| `Navigate to Virtual Function` | Right-click call instruction address | Resolve the vtable dispatch and navigate to the target |

Navigate to Virtual Function reads the vtable slot offset from the call instruction, handling both standard and XFG-guarded dispatches. Candidates are ranked by calling class and vtable offset. When the result is unambiguous it navigates directly. Otherwise it shows a ranked chooser.

### vtable_improve.py

Re-types vtable struct fields from `void*` to proper named function pointers. Run this after `vtable_autodefine` if you still see raw output like `(*(r12->__offset(0x0).q + 0x230))(r12, 0)`. After it runs, calls display as `obj->vtable->MethodName(...)`.

The single command is under Plugins -> VTables:

| Command | How to invoke | Description |
|---------|---------------|-------------|
| `Type All Fields from Functions` | Plugins menu | Re-type all VTable struct slots and propagate to call sites |

### Recommended VTable Workflow

1. Open the binary and let BN finish its RTTI analysis.
2. Run **VTables -> Auto-Define for All Classes**. Wait for BN's analysis indicator to settle.
3. If virtual calls still appear as raw pointer arithmetic, run **VTables -> Type All Fields from Functions**.
4. Use **VTables -> Navigate to Virtual Function** (or `Ctrl+Shift+V`) to jump from a call site to the dispatched target.

### Recommended Keybindings

Set in Settings -> Keybindings (one-time per workstation):

| Action | Suggested binding |
|--------|------------------|
| `VTables\Navigate to Virtual Function` | `Ctrl+Shift+V` |

## XFG

### xfg_xrefs.py

Recovers cross-references and indirect call targets that MSVC's XFG (eXtended Flow Guard) breaks. XFG replaces indirect calls with a type-hash-checked dispatch through `__guard_xfg_dispatch_icall_fptr`, so BN's standard xref tracking loses the caller-to-callee edge. This plugin finds them by scanning for the `movabs r10, <hash>` instruction (encoding `49 BA <8 LE bytes>`) that MSVC emits before every XFG-guarded call.

The XFG hash stored at `func_start - 8` has bit 0 set. Call sites load the same value with bit 0 cleared. Results may include type-hash aliases, which are other functions that share the same XFG type signature (identical prototype). Disambiguate by checking the vtable slot offset loaded into RAX before each `movabs r10`.

All commands are under Plugins -> XFG:

#### XFG -> Cross-References

Registers user code xrefs visible in BN's cross-references panel.

| Command | How to invoke | Description |
|---------|---------------|-------------|
| `Find Here` | Right-click address | Add xrefs for the function at the cursor |
| `Find in This Function` | Right-click function | Same as above for a named function |
| `Add All` | Plugins menu | Scan entire binary and add every resolvable xref |
| `Remove All` | Plugins menu | Remove all xrefs added by this plugin |

#### XFG -> Indirect Calls

Registers indirect branch targets via `set_user_indirect_branches` and annotates the call site with an `XFG -> FuncName` comment so HLIL can resolve `(*(*ptr+N))(ptr)` patterns.

| Command | How to invoke | Description |
|---------|---------------|-------------|
| `Resolve Here` | Right-click XFG call/movabs site | Resolve one call site |
| `Remove Here` | Right-click XFG call/movabs site | Clear one call site |
| `Go to Target Here` | Right-click XFG site | Navigate to target; chooser on hash collision |
| `Resolve in This Function` | Right-click function | Resolve every XFG site in the function |
| `Remove in This Function` | Right-click function | Clear every XFG site in the function |
| `Resolve All` | Plugins menu | Scan entire binary and resolve all XFG call sites |
| `Remove All` | Plugins menu | Clear all targets and comments set by Resolve All |

#### XFG -> Reset Hash Map Cache

Invalidates the cached function-to-hash map. Use after adding or removing functions mid-session. The cache also self-invalidates when a slow-path scan finds a target the cache was missing.

### Recommended XFG Workflow

1. Run **XFG -> Indirect Calls -> Resolve All** to annotate every XFG-guarded call site in one pass. Each site gets an `XFG -> FuncName` comment and CFG edges to the target(s).
2. Optionally run **XFG -> Cross-References -> Add All** to populate the xrefs panel.
3. Use **Go to Target Here** (or `Shift+G`) to navigate from any XFG call site to its target while browsing.

### Recommended Keybindings

Set in Settings -> Keybindings (one-time per workstation):

| Action | Suggested binding |
|--------|------------------|
| `XFG\Indirect Calls\Go to Target Here` | `Shift+G` |
| `XFG\Indirect Calls\Resolve Here` | `Shift+R` |
| `XFG\Cross-References\Find Here` | `Shift+X` |
