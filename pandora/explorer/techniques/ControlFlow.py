import logging

from angr import ExplorationTechnique, SimState

import ui
from explorer.enclave import buffer_entirely_inside_enclave, addr_in_text_section
from explorer.taint import is_tainted
from ui.action_manager import ActionManager
from ui.log_format import log_always
from ui.report import Reporter, SYSTEM_EVENTS_REPORT_NAME
from utilities.angr_helper import set_reg_value, get_reg_value, get_sym_memory_value, memory_is_tainted
from sdks.SDKManager import SDKManager

logger = logging.getLogger(__name__)
class ControlFlowTracker(ExplorationTechnique):
    """
    Tracks all active states before stepping them and makes sure we properly emulate SGX hardware behavior:
        1. terminate execution when jumping to non-exectable enclave pages; and
        2. terminate execution when jumping to memory outside the enclave (without EEXIT).

    NOTE: we can decide condition (2) here without an explicit call to the
        constraint solver, as pages outside the enclave are not supposed to be
        in the allowlist of executable pages for (1), so the check for (1) here
        implies the check for (2).
    """
    def __init__(self, init_state: SimState):
        super().__init__()

        self.init_state = init_state

    def step(self, simgr, **kwargs):
        """
        Before stepping, check all active states and compare their IP against the list of allowed IPs
        """

        wrong_jumps = []
        left_enclave = []
        for s in simgr.active:
            # NOTE IP should always be concrete at this point, as per angr internals
            ip = get_reg_value(s, 'ip')
            assert(type(ip) is int)

            executable = SDKManager().addr_in_executable_pages(ip)
            #unmeasured_tainted = SDKManager().addr_in_unmeasured_uninitialized_page(ip, 1) and memory_is_tainted(s, ip, 1)

            if not executable:
                wrong_jumps.append(s)
                logger.error(f'State {s.history.parent} incorrectly jumped to {ip:#x} which is not an allowed code page. Exiting this state.')
                bbl_addrs = list(s.history.bbl_addrs)
                if len(bbl_addrs) > 0:
                    ui.log_format.dump_asm(s.history.parent, logger, logging.ERROR,
                                           header_msg="Assembly code of the removed state before the jump:",
                                           use_rip=bbl_addrs[-1],
                                           angr_project=s.project) # Pass the project of the state since history doesn't have it

                # Send this as a system event to the reporter to log it properly
                bvv_at_target = get_sym_memory_value(s, ip, 6, with_enclave_boundaries=True)
                extra_sec = None
                if buffer_entirely_inside_enclave(s, ip, 6):
                    extra_sec = {'Execution state info': [(
                                 'Disassembly of jump target (not executed)',
                                 ui.log_format.format_asm(s, formatting=None, angr_project=s.project, use_rip=ip),
                                 'verbatim'
                    )]}
                ty =  'non-executable'
                Reporter().report(f'Aborted branch due to illegal jump to {ty} page',
                                  s, logger,
                                  SYSTEM_EVENTS_REPORT_NAME,
                                  severity= logging.ERROR,
                                  extra_info = {'Jump target' : hex(ip),
                                                'Jump target is tainted' : is_tainted(bvv_at_target),
                                                'Jump target (6 bytes)' : str(bvv_at_target),
                                                'Executable': executable,
                                                },
                                  extra_sections=extra_sec)
                # Trigger a user action if requested
                ActionManager().actions['system'](info='Aborted branch due to illegal jump',
                                                  state=s)

            
            #encl_range = SDKManager().get_enclave_range()
            #ip_inside_enclave = True if encl_range['min_addr_text'] <= ip and encl_range['max_addr_text'] >= ip else False
            ip_inside_enclave = addr_in_text_section(ip)

            # all states that have ip outside of the enclave
            # can occur in Sancus hand-written enclaves when the control flow just continues past the public_end section
            if not ip_inside_enclave:
                left_enclave.append(s)

            #Simplify the status register if its values get too complex 
            #Currently the threshold is 5000 characters, maybe a more appropriate
            #measure or heuristic would be suitable?
            sr_val = get_reg_value(s, 'r2')
            sr_size = len(str(sr_val))
            if sr_size > 5000:
                set_reg_value(s, 'r2', s.solver.simplify(sr_val))

        if len(left_enclave) > 0:
            simgr.move(from_stash='active', to_stash='deadended', filter_func=lambda x: x in left_enclave)

        if len(wrong_jumps) > 0:
            simgr.move(from_stash='active', to_stash='incorrect', filter_func=lambda x: x in wrong_jumps)
            logger.debug(f'Removed states {wrong_jumps}')
        simgr = simgr.step(**kwargs)
        return simgr
