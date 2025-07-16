from typing import Union, Optional

import binaryninja

from . import const
from . import utils

from functools import cached_property
import re

VTABLE_ADDRESS_SUFFIX = re.compile("_([0-9a-fA-F]+)$")

def extract_address_from_name(vtable_name: str) -> Optional[int]:
    result = VTABLE_ADDRESS_SUFFIX.search(vtable_name)
    if result is None:
        return None
    
    return int(result.group(1), 16)


class VtableMetadataStorage:
    METADATA_ROOT_KEY = const.plugin_name
    
    def __init__(self, bv: binaryninja.BinaryView):
        self.bv = bv

    # def add_data(self, )


def valid_function_pointer(bv: binaryninja.BinaryView, addr: int) -> bool:
    if not bv.is_offset_code_semantics(addr):
        return False
    
    if bv.get_function_at(addr) is None:
        return False
    
    return True

def create_function_pointer_type(bv: binaryninja.BinaryView, addr: int, const: bool=True) -> binaryninja.types.PointerType:
    function = bv.get_function_at(addr)
    assert function is not None, "Failed to get function at %#x" % (addr)

    return binaryninja.Type.pointer(bv.arch, function.type, const=const)


class VirtualTable:
    def __init__(self, bv: binaryninja.BinaryView, addr: int, name: Optional[str] = None):
        self.bv: binaryninja.BinaryView = bv
        self.addr: int = addr
        self.name = name or ("Vtable_%X" % addr)

    @cached_property
    def type(self) -> binaryninja.StructureType:
        current_address = self.addr

        typename = "Vtable_%X" % self.addr
        vtable = binaryninja.types.StructureBuilder.create()
        vtable.packed = True
        vtable.propagate_data_var_refs = True

        while True:
            function_address = self.bv.read_pointer(current_address)

            if not valid_function_pointer(self.bv, function_address):
                break

            function = self.bv.get_function_at(function_address)
            function_pointer_type = create_function_pointer_type(self.bv, function_address)
            
            # Don't know if i should use demangeled_name_to_c_str or not
            vtable.append(function_pointer_type, function.symbol.full_name)

            current_address+= self.bv.address_size

            code_refs = list(self.bv.get_code_refs(current_address))
            if len(code_refs) != 0:
                break

        return vtable.immutable_copy()

    @staticmethod
    def check(bv: binaryninja.BinaryView, addr: int, MIN_FUNCTIONS_REQUIRED: int=3) -> int:
        # 1 - there is code xref to this address
        # 2 - at least MIN_FUNCTIONS_REQUIRED valid function pointers

        functions_counted = 0
        while True:
            candidate_pointer = bv.read_pointer(addr + functions_counted * bv.address_size)
            if not valid_function_pointer(bv, candidate_pointer):
                break                

            functions_counted+= 1

            code_refs = list(bv.get_code_refs(addr + functions_counted * bv.address_size))
            if len(code_refs) != 0:
                break

        if functions_counted < MIN_FUNCTIONS_REQUIRED:
            return 0

        return functions_counted

    @classmethod
    def at_address(cls, bv: binaryninja.BinaryView, addr: int) -> 'VirtualTable':
        return VirtualTable(bv, addr)