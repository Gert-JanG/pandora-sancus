from __future__ import annotations

import angr
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

import ui.log_format
from explorer.sancus_hooks import SimUnprotect, SimProtect, SimAttest, SimEncrypt, SimDecrypt, SimGetID, SimGetCallerID, SimNop
from sdks.SymbolManager import SymbolManager
from sdks.Sancus import SancusSDK

import logging

logger = logging.getLogger(__name__)
                   

class HookerManager:

    def __init__(self, init_state, live_console=None, task=None):
        self.init_state = init_state
        self.project = init_state.project

        logger.info("Hooking instructions.")
        
        loop_count = 0
        section_count = len(self.project.loader.main_object.sections)
        logger.debug(f'Address        \tInstruction\tOpstr               \tSize [Replacement function]')
        # Normal elf file, pick executable sections and start hooking
        if live_console:
            live_console.update(task, total=section_count, completed=0)
        for section in self.project.loader.main_object.sections:
            # note: skip NOBITS sections that are uninitialized
            if (section.is_executable and 
                not section.only_contains_uninitialized_data and
                '.text.sm' in section.name):
                self.hook_mem_region(section.vaddr)

            loop_count += 1
            live_console.update(task, completed=loop_count)
            
        logger.info("Hooking instructions completed.")

    """
    Hook all sancus related addresses in the project
    """
    def hook_mem_region(self, sectionAddr):
        SANC_INSTR_SIZE=2
        section = SancusSDK.get_section_string_representation(sectionAddr)
        sancusInstructions = SancusSDK._get_sancus_instr_addresses(section)
        for instr in sancusInstructions:
            #logger.debug("Address: " + str(instr['address']) + " opcode: " + instr['opcode'])
            sim_proc = self.instruction_replacement(instr)
            #logger.debug("Instr: " + instr['opcode'] + " at address " + instr['address'] + " replaced with simProc: " + str(sim_proc))
            if sim_proc is not None:
                # Trying to follow the HookerManager functions, but size is hardcoded here
                tab_str = f'{instr["address"]}:\t{instr["opcode"]:<10}\t{" ":<20}\t{str(SANC_INSTR_SIZE):<3}'
                logger.debug(tab_str)
            self.project.hook(int(instr['address'], 16), hook=sim_proc, length=SANC_INSTR_SIZE)


    """
    Replaces an instruction with a SimProcedure or returns None if no replacement is necessary
    @param instruction: (address-opcode) tuple 
    @return: A Simprocedure or None
    """    
    def instruction_replacement(self, instruction) -> angr.SimProcedure | None:
        op = instruction['opcode'] 
        if op in self.instruction_hooks:
            return self.instruction_hooks[op](opstr="", bytes_to_skip=2, mnemonic=op)
        else:
            return None

    instruction_hooks = { 
        '0x1380': SimUnprotect,
        '0x1381': SimProtect,
        '0x1382': SimAttest,
        '0x1384': SimEncrypt,
        '0x1385': SimDecrypt,
        '0x1386': SimGetID,
        '0x1387': SimGetCallerID,
        '0x1388': SimNop,
        '0x1389': SimNop,
    }