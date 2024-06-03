from __future__ import annotations
import ctypes

import logging

from angr import BP_BEFORE, BP_AFTER, SimValueError

from sdks.SDKManager import SDKManager
from explorer import taint
from utilities.angr_helper import get_reg_value, set_memory_value, set_reg_value, get_reg_size
from functools import lru_cache

logger = logging.getLogger(__name__)


def eenter(enter_state):
    
    logger.info(f' --- Initializing state and making it ready for enter.')

    # First, call the eenter breakpoint
    enter_state._inspect(
        "eenter",
        BP_BEFORE
    )
    # Start the setup by marking the state global as not active. This should disable all breakpoints like tainting
    enter_state.globals['pandora_active'] = False

    # Initialize all registers as being attacker tainted
    for reg_name in enter_state.project.arch.register_names.values():
        size = get_reg_size(enter_state, reg_name)
        reg = taint.get_tainted_reg(enter_state, reg_name, size*8)
        set_reg_value(enter_state, reg_name, reg)

    # After tainting all registers, fill registers that are overwritten by sancus
    set_reg_value(enter_state, 'ip', SDKManager().get_base_addr()['text'])

    # At the moment no hooked instruction has been skipped
    enter_state.globals['prev_skipped_inst'] = None

    #Indicate states where the code writes to its own text section (such that these can be removed to errored stash)
    enter_state.globals['written_to_text_section'] = False
    enter_state.inspect.b('trusted_mem_write', when=BP_AFTER, action=check_write_to_text_section)

    #Indicate the protections as enabled (should only be disabled by 0x1380)
    enter_state.globals['protections_disabled'] = False

    # Finalize the setup by marking the state global as active 
    enter_state.globals['pandora_active'] = True
    logger.info(f' --- State initialization completed.')

    enter_state._inspect(
        "eenter",
        BP_AFTER
    )

"""
Function that changes the 'written_to_text_section' variable if there will be written to the 
text section of the enclave
"""
def check_write_to_text_section(state):
    addr = state.inspect.mem_write_address
    length = state.inspect.mem_write_length
    encl_range = get_enclave_range()
    write_addr_inside_encl = buffer_touches_enclave(state, addr, length, (encl_range['min_addr_text'], encl_range['max_addr_text']))
    if write_addr_inside_encl:
        state.globals['written_to_text_section'] = True

"""
Function that returns a dict of the start and end address of enclaves text and data section
@return dict{min_addr_text, max_addr_text, min_addr_data, max_addr_data}
    a dict with the min and max addresses of the text and data section
"""
def get_enclave_range():
    """
    Enclave range [min_addr,max_addr], i.e., both are *inclusive*.
    """
    base_addresses = SDKManager().get_base_addr()
    sizes = SDKManager().get_encl_size()

    min_addr_text = base_addresses['text']
    min_addr_data = base_addresses['data']

    # we do minus 1 here because min_addr+size is the first address _outside_
    # the enclave, and we want to have the range _inclusive_.
    max_addr_text = min_addr_text + sizes['text'] - 1
    max_addr_data = min_addr_data + sizes['data'] - 1

    return {'min_addr_text': min_addr_text, 
            'max_addr_text': max_addr_text, 
            'min_addr_data': min_addr_data, 
            'max_addr_data': max_addr_data}

def addr_in_text_section(addr):
    encl_range = get_enclave_range()
    text_min = encl_range['min_addr_text']
    text_max = encl_range['max_addr_text']
    return True if text_min <= addr and text_max >= addr else False 

def addr_in_data_section(addr):
    encl_range = get_enclave_range()
    data_min = encl_range['min_addr_data']
    data_max = encl_range['max_addr_data']
    return True if data_min <= addr and data_max >= addr else False 

    
def addr_in_enclave(addr):
    return addr_in_text_section(addr) or addr_in_data_section(addr)

"""
To speed things up, wrap the rest of the function in an inner function that utilizes lru_caching
Unfortunately, states are not always hashable (sometimes they are weak proxies). This is why we 
restrict the caching to addr and length plus the enclave range.
"""
@lru_cache(maxsize=256, typed=False)
def _check_touches(buffer_address, buffer_length, enclave_min_addr, enclave_max_addr, solver):
    if type(buffer_address) is int:
        bv_addr = solver.BVV(buffer_address, 16)
    else:
        # If addr is not an int, we can assume it is a BV
        bv_addr = buffer_address

    if type(buffer_length) is not int:
        if not solver.symbolic(buffer_length):
            buffer_length = solver.eval_one(buffer_length)
        else:
            length_max = solver.max_int(buffer_length)
            logger.debug(
                f'Concretized symbolic length in touches enclave check. Length is {buffer_length} and I concretized to {length_max}')
            buffer_length = length_max

    """
    Next, we calculate the maximum start address that the buffer may have BEFORE the enclave range.
    This is naturally the last address that even with the full length of the buffer does NOT touch the enclave yet.
      Note, we do not do +1 here as we do a strictly larger than comparison later.
      (i.e., the enclave_min_addr-len is the last address that is OKAY to use before the enclave memory)
    """
    max_addr_before_enclave = enclave_min_addr - buffer_length

    # The simplest check is max_addr_before_enclave < addr < enclave_max_addr
    touches_enclave = solver.And(bv_addr.UGT(max_addr_before_enclave), bv_addr.ULE(enclave_max_addr))

    if max_addr_before_enclave < 0:
        # We have to be careful about overflow here
        # Specifically, we can not use the max_addr_before_enclave anymore as that underflows

        # Either, the addr wraps the address space (overflows): Then, check whether the end reaches around
        does_wrap = bv_addr.UGE(bv_addr + buffer_length)
        wrap_and_touches_enclave = solver.And(bv_addr.UGT(max_addr_before_enclave), does_wrap)

        # If the addr does not wrap, then do the normal check with an overwritten max_addr_before_enclave
        does_not_wrap = bv_addr.ULT(bv_addr + buffer_length)
        bv_addr_end = bv_addr + buffer_length - 1 # Inclusive end
        touches_enclave = solver.Or(
            # Either the buffer start is inside the enclave range
            solver.And(bv_addr.UGE(enclave_min_addr), bv_addr.ULE(enclave_max_addr)),
            # Or the buffer end is inside the enclave range
            solver.And(bv_addr_end.UGE(enclave_min_addr), bv_addr_end.ULE(enclave_max_addr)),
            # Or the start is before the enclave start AND the end is after the enclave end (encapsulates the enclave)
            solver.And(bv_addr.ULE(enclave_min_addr), bv_addr_end.UGE(enclave_max_addr))
        )
        no_wrap_and_touches = solver.And(does_not_wrap, touches_enclave)

        e = solver.Or(wrap_and_touches_enclave, no_wrap_and_touches)

    else:
        # No overflow into enclave possible. Do the normal check
        e  = touches_enclave

    return solver.satisfiable(extra_constraints=[e])

def buffer_touches_enclave(state, buffer_address, buffer_length, use_enclave_range : None | tuple = None):
    """
    Function to determine whether the buffer [addr, addr+length[ *touches* the enclave range.
    --> Checks whether: enclave_min-len < addr && addr <= enclave_max

    :param state: Any state to run this on. Only used to access the solver.
    :param bufer_address: The start address of the buffer (inclusive)
    :param buffer_length: The length of the buffer so that addr + length is the first address AFTER the buffer.
    :param use_enclave_range: An OPTIONAL tuple to overwrite the enclave range or None to use the default enclave range. Use for testing only.
    """
    if not use_enclave_range:
        use_enclave_range = get_enclave_range()
        text_min = use_enclave_range['min_addr_text']
        text_max = use_enclave_range['max_addr_text']
        data_min = use_enclave_range['min_addr_data'] 
        data_max = use_enclave_range['max_addr_data'] 

        # Call this inner function (depending on cache, this call will be fast)
        return _check_touches(buffer_address, buffer_length, text_min, text_max, state.solver) or _check_touches(buffer_address, buffer_length, data_min, data_max, state.solver)
    else:
        (enclave_min, enclave_max) = use_enclave_range
        return _check_touches(buffer_address, buffer_length, enclave_min, enclave_max, state.solver)

"""
To speed things up, wrap the rest of the function in an inner function that utilizes lru_caching
Unfortunately, states are not always hashable (sometimes they are weak proxies), so we pass the solver.
Typed is set to default False to get the speedup and not incur additional checks.
"""
@lru_cache(maxsize=256, typed=False)
def _check_entirely_inside(buffer_address, buffer_length, enclave_min_addr, enclave_max_addr, solver):
    if type(buffer_length) is not int:
        if not solver.symbolic(buffer_length):
            buffer_length = solver.eval_one(buffer_length)
        else:
            length_max = solver.max_int(buffer_length)
            logger.debug(f'Concretized symbolic length in entirely inside enclave check. Length is {buffer_length} and I concretized to {length_max}')
            buffer_length = length_max

    """
    Now calculate the maximum allowed address for the buffer to still fully lie in the enclave.
    This is the address with which the last byte of the buffer is also the last byte of the enclave.
    With enclave_max_addr being inclusive, we add 1 to get there after subtracting the length.
    """
    max_allowed_addr_inside_enclave = enclave_max_addr - buffer_length + 1

    """
    We can abort immediately if the length of the buffer is larger than the size of the enclave.
    These buffers can never fully lie inside the enclave. 
    """
    if enclave_min_addr > max_allowed_addr_inside_enclave:
        return False

    if type(buffer_address) is int:
        bv_addr = solver.BVV(buffer_address, 16)
    else:
        # If addr is not an int, we can assume it is a BV
        bv_addr = buffer_address

    can_lie_outside = solver.Or(bv_addr.ULT(enclave_min_addr), bv_addr.UGT(max_allowed_addr_inside_enclave))

    """
    The buffer can wrap around (overflow), if the last byte in the buffer (inclusive) may be smaller than the address.
    We subtract one since addr + length is EXCLUSIVE and off by one.
    """
    can_wrap = bv_addr.UGT(bv_addr + buffer_length - 1)

    e = solver.Or(can_lie_outside, can_wrap)
    return not solver.satisfiable(extra_constraints=[e])


def buffer_entirely_inside_enclave(state, buffer_address, buffer_length, use_enclave_range : None | tuple = None):
    """
    Function to determine whether the buffer [addr, addr+length[ always lies *entirely* inside the enclave.
    --> Checks whether: enclave_min <= addr && addr+len-1 <= enclave_max

    :param state: Any state to run this on. Only used to access the solver.
    :param buffer_address: The start address of the buffer (inclusive)
    :param buffer_length: The length of the buffer so that addr + length is the first address AFTER the buffer.
    :param use_enclave_range: An OPTIONAL tuple to overwrite the enclave range or None to use the default enclave range. 
                                    ---> Is used in Sancus to check for writes to text section only
    """
    if not use_enclave_range:
        use_enclave_range = get_enclave_range()
        text_min = use_enclave_range['min_addr_text']
        text_max = use_enclave_range['max_addr_text']
        data_min = use_enclave_range['min_addr_data'] 
        data_max = use_enclave_range['max_addr_data'] 


        #If the data and text section are (accidentaly) contiguous
        if abs(text_max - data_min) == 1 or abs(data_max - text_min) == 1:
            logger.debug("Contiguous data and text section!")
            if text_min > data_max:
                return _check_entirely_inside(buffer_address, buffer_length, data_min, text_max, state.solver)
            else:
                return _check_entirely_inside(buffer_address, buffer_length, text_min, data_max, state.solver)
        # Call this inner function (depending on cache, this call will be fast)
        return _check_entirely_inside(buffer_address, buffer_length, text_min, text_max, state.solver) or _check_entirely_inside(buffer_address, buffer_length, data_min, data_max, state.solver)
    else:
        (enclave_min, enclave_max) = use_enclave_range
        return _check_entirely_inside(buffer_address, buffer_length, enclave_min, enclave_max, state.solver)