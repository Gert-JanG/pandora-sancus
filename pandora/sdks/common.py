import binascii
import ctypes
import ui.log_format

import archinfo

import logging
logger = logging.getLogger(__name__)

def create_versioned_struct(versioned_type, version_major, version_minor):
    fields = []
    added_names = []
    for (major_from, minor_from, name, ctype) in versioned_type._fields_versioned_:
        # note: in case of revised fields, specify newest revision first
        # -> any older ones with the same  name will not be added
        if version_major >= major_from and version_minor >= minor_from and not name in added_names:
            # recursively apply versioning to any contained subtypes
            if hasattr(ctype,'_fields_versioned_'):
                ctype = create_versioned_struct(ctype, version_major, version_minor)
            fields.append((name,ctype))
            added_names.append(name)

    # create and return the versioned type class dynamically
    t = type(f'{versioned_type.__name__}v{version_major}{version_minor}',
            (ctypes.LittleEndianStructure, ), {
            '_fields_' : fields,
            '__str__'  : versioned_type.__str__,
            'to_dict'  : versioned_type.to_dict
    })

    logger.debug(f'Dynamically created {t.__name__} struct with {len(fields)} members')
    return t

def write_struct_to_memory(state, addr, struct, with_enclave_boundaries=False):
    # logger.debug(f'Writing struct {str(type(struct))} to addr {addr:#x}. Struct bytes are {binascii.hexlify(bytes(struct))}')
    state.memory.store(addr, bytes(struct), size=ctypes.sizeof(struct), with_enclave_boundaries=with_enclave_boundaries)

def write_bvv_to_memory(state, addr, bvv_str, bits):
    bvv = state.solver.BVV(bvv_str, bits)
    enclave_file_base = state.project.loader.main_object.mapped_base
    addr = enclave_file_base + addr
    logger.debug(f'Writing BVV {bvv} to addr {addr:#x}.')
    state.memory.store(addr, bvv, endness=archinfo.Endness.LE, with_enclave_boundaries=False)

def load_struct_from_memory(state, addr, struct_type):
    """
    Helper function to convert a struct from angr memory.

    NOTE: The returned struct is a copy, so updating it won't update the memory.
    """
    # first load content as a bit vector
    struct_bv = state.memory.load(addr, size=ctypes.sizeof(struct_type), with_enclave_boundaries=False)

    # now evaluate the bit vector to bytes to get the actual data
    struct_bytes = state.solver.eval(struct_bv, cast_to=bytes, endness=archinfo.Endness.LE)
    # logger.debug(f'Reading struct {str(type(struct_type))} from addr {addr:#x}. Struct bytes are {binascii.hexlify(struct_bytes)}')

    # finally convert to the requested struct type
    struct = struct_type.from_buffer_copy(struct_bytes)
    return struct
