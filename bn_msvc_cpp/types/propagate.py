"""Retype `this` parameters in constructors and virtual methods, and the
variables in callers that capture a constructor's return value, so HLIL
promotes raw pointer arithmetic to named field accesses.

Verbatim port of the relevant logic from `vtable_autodefine.py`.
"""

from binaryninja import BinaryView, log_info, log_warn
from binaryninja.enums import HighLevelILOperation, TypeClass
from binaryninja.types import FunctionParameter, Type

from ..util import demangled_function_name


def set_this_param_type(func, ptr_type) -> bool:
    """Change the first parameter of func to ptr_type via function-prototype update.

    Using set_user_type (prototype level) rather than create_user_var (HLIL annotation
    level) because BN's HLIL lift derives parameter types from the function prototype.
    create_user_var only affects the display annotation and is ignored during HLIL
    re-lifting, so field-access promotion never fires.
    """
    try:
        ft = func.type
        if ft.type_class != TypeClass.FunctionTypeClass:
            return False
        ft_params = list(ft.parameters)
        if not ft_params:
            return False
        new_params = [FunctionParameter(ptr_type, ft_params[0].name)] + [
            FunctionParameter(p.type, p.name) for p in ft_params[1:]
        ]
        new_ft = Type.function(ft.return_value, new_params, ft.calling_convention)
        func.set_user_type(new_ft)
        return True
    except Exception as e:
        log_warn(f"bn_msvc_cpp: couldn't retype 'this' prototype in {func.name}: {e}")
        return False


def update_constructor_this_types(
    bv: BinaryView, class_name: str, vtable_info: list
) -> set:
    """Retype 'this' in every function that stores the primary vtable (class_offset == 0).

    Only retypes functions whose demangled name lives under `class_name::`, so
    callers with the constructor inlined don't have their first parameter
    incorrectly changed.
    """
    if bv.get_type_by_name(class_name) is None:
        return set()

    nt = Type.named_type_from_registered_type(bv, class_name)
    ptr_type = Type.pointer(bv.arch, nt)
    updated: set = set()
    class_prefix = class_name + "::"

    for vtable_addr, _iface_name, _struct_name, class_offset in vtable_info:
        if class_offset != 0:
            continue
        for ref in bv.get_code_refs(vtable_addr):
            func = ref.function
            if func is None:
                continue

            fname = demangled_function_name(bv.arch, func.name)
            if not fname.startswith(class_prefix):
                continue

            if set_this_param_type(func, ptr_type):
                updated.add(func)
                log_info(
                    f"bn_msvc_cpp: retyped 'this' in {func.name} -> {class_name}*"
                )

    return updated


def update_vtable_method_this_types(
    bv: BinaryView, class_name: str, vtable_info: list
) -> set:
    """Retype 'this' parameter of every virtual method in the primary vtable to ClassName*.

    Only processes primary vtable entries (class_offset == 0). Secondary vtables
    have an adjusted 'this' pointer.
    """
    if bv.get_type_by_name(class_name) is None:
        return set()
    nt = Type.named_type_from_registered_type(bv, class_name)
    ptr_type = Type.pointer(bv.arch, nt)
    updated: set = set()

    for vtable_addr, _iface_name, struct_name, class_offset in vtable_info:
        if class_offset != 0:
            continue
        vtable_struct = bv.get_type_by_name(struct_name)
        if vtable_struct is None:
            continue
        for member in vtable_struct.members:
            slot_raw = bv.read(vtable_addr + member.offset, 8)
            if not slot_raw or len(slot_raw) < 8:
                continue
            fp_addr = int.from_bytes(slot_raw, "little")
            if fp_addr == 0:
                continue
            func = bv.get_function_at(fp_addr)
            if func is None:
                continue
            if set_this_param_type(func, ptr_type):
                updated.add(func)
                log_info(
                    f"bn_msvc_cpp: retyped 'this' in {func.name} -> {class_name}*"
                )
    return updated


def _is_hlil_call_to_addr(expr, target_addr: int) -> bool:
    """Return True if expr is HLIL_CALL whose destination is the constant target_addr."""
    try:
        if expr.operation != HighLevelILOperation.HLIL_CALL:
            return False
        dest = expr.dest
        return (
            dest.operation == HighLevelILOperation.HLIL_CONST_PTR
            and dest.constant == target_addr
        )
    except Exception:
        return False


def _hlil_call_result_var(insn, target_addr: int):
    """Return the Variable initialized from `call(target_addr)(...)` in insn, or None."""
    try:
        op = insn.operation
        if op == HighLevelILOperation.HLIL_VAR_INIT:
            return insn.dest if _is_hlil_call_to_addr(insn.src, target_addr) else None
        if op == HighLevelILOperation.HLIL_ASSIGN:
            dest = insn.dest
            if (
                dest.operation == HighLevelILOperation.HLIL_VAR
                and _is_hlil_call_to_addr(insn.src, target_addr)
            ):
                return dest.var
    except Exception:
        pass
    return None


def retype_call_result_vars(caller, target_addr: int, ptr_type) -> int:
    """Walk caller's HLIL and retype variables initialized from a call to target_addr.

    Setting the called function's prototype is not sufficient to make BN's HLIL
    re-lift the caller with the new return type. create_user_var on the variable
    that captures the call result forces a full re-lift; BN then splits SSA
    copies and field promotion fires on the typed copy.
    """
    try:
        hlil = caller.hlil
    except Exception:
        return 0
    if hlil is None:
        return 0

    retyped = 0
    for block in hlil:
        for insn in block:
            var = _hlil_call_result_var(insn, target_addr)
            if var is None:
                continue
            try:
                caller.create_user_var(var, ptr_type, var.name)
                retyped += 1
            except Exception as e:
                log_warn(
                    f"bn_msvc_cpp: couldn't retype {var.name} in {caller.name}: {e}"
                )
    return retyped
