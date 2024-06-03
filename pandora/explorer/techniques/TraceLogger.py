import logging
from angr import ExplorationTechnique

import ui
from ui.log_format import get_state_backtrace_formatted

logger = logging.getLogger(__name__)

class TraceLogger(ExplorationTechnique):

    """
    Exploration technique to trace log states.
    """
    def step(self, simgr, **kwargs):
        """
        Performs some trace logging for states.
        """

        # Only print states if they are less than 10 and the logger would even print this
        if logger.getEffectiveLevel() <= logging.TRACE:
            if len(simgr.active) < 10:
                logger.log(logging.TRACE, f'______________________CURRENT STEP ACTIVE STATES: {len(simgr.active)}_________________________________')
                #for s in simgr.deadended:
                for s in simgr.active:
                    ui.log_format.dump_asm(s, logger, logging.TRACE,
                                           header_msg="Assembly code of the current basic block:")
                    ui.log_format.dump_regs(s, logger, logging.TRACE, only_gen_purpose=False)
                    logger.log(logging.TRACE,'BACKTRACE: ' + ui.log_format.format_fields(get_state_backtrace_formatted(s)))
                    #ui.log_format.dump_vex(s, logger, logging.TRACE, header_msg='VEX representation of the current basic block')
                    logger.log(logging.TRACE, "\n\n")
                if len(simgr.deadended) > 0:
                    logger.log(logging.TRACE, "\n\n\n\n\n")
                #for s in simgr.deadended:
                #    ui.log_format.dump_asm(s, logger, logging.TRACE,
                #                           header_msg="Assembly code of the current basic block:")
                #    ui.log_format.dump_regs(s, logger, logging.TRACE, only_gen_purpose=False)
                #    logger.log(logging.TRACE,'BACKTRACE: ' + ui.log_format.format_fields(get_state_backtrace_formatted(s)))
                #    #ui.log_format.dump_vex(s, logger, logging.TRACE, header_msg='VEX representation of the current basic block')
                #logger.log(logging.TRACE, f'^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ACTIVE STATES^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
            else:
                logger.log(logging.TRACE, f'Not printing detailed states since there are too many ({len(simgr.active)})')
                #logger.log(logging.TRACE, f'\/\/\/\/\/\/\/\/\/\LET US LOOK AT THE ACTIVE STATES IP\/\/\/\/\/\/\/\/\/\/\/\/')
                #for s in simgr.active:
                #    ui.log_format.dump_ip(s, logger)

        # Nothing to be done for stepping
        simgr = simgr.step(**kwargs)
        return simgr
