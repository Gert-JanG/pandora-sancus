from sdks.AbstractSDK import AbstractSDK
import angr
import os
import re
import logging
logger = logging.getLogger(__name__)

class SancusSDK(AbstractSDK):
    #Static variable that contains all parsed sections
    sections = {}
    project = None

    def __init__(self, elffile, init_state, version_str, **kwargs):
        super().__init__(elffile, init_state, version_str, **kwargs)
        
        self.textStart, self.textSize = SancusSDK._parse_enclave_base_and_size(elffile.stream.name, 'public')
        self.dataStart, self.dataSize = SancusSDK._parse_enclave_base_and_size(elffile.stream.name, 'secret')


    @staticmethod
    def detect(elffile, binpath):
        arch = elffile.header.e_machine
        if "MSP430" in arch:
            # If it is an msp430 architecture, initialize the project for future static methods
            SancusSDK.project = angr.Project(binpath)
            # Dummy version as it basically treats the entire MSP430 architecture as Sancus
            # and the SDKManager recognizes an SDK based on a non empty return value for this function
            return 'v1'
        return ''

    @staticmethod
    def get_sdk_name():
        return "Sancus"

    """
    @param elffile: ELFFile 
    @return dict{text, data}
        set containing the base address of the text and data section
        keys: 'text' ; 'data'
    @throws AttributeError
                if base address of text or data section equals 0
                or project not initialized
    """
    @staticmethod
    def get_base_addr():
        if SancusSDK.project is None:
            raise AttributeError("Project not initialized for Sancus SDK")

        textBase, textSize = SancusSDK._parse_enclave_base_and_size(SancusSDK.project.filename, 'public')
        dataBase, dataSize = SancusSDK._parse_enclave_base_and_size(SancusSDK.project.filename, 'secret')
        if textBase == 0 or dataBase == 0:
            raise AttributeError("Enclave base address of 0 found during enclave parsing! Are you sure this file contains an enclave?")
        else:
            return {'text': textBase, 'data': dataBase}

    def get_encl_size(self):
        return {'text': self.textSize, 'data': self.dataSize}
    
    """"
    NOTE: This can not be done the same way like SGX as the binary compiled for MSP430 spans 
    the entire MCU memory. So the size is extracted from the elffile sections.
    @param fileName: String
        the name of the elf file
    @param sectionType: 'secret' | 'public'
        the type of the section that has to be parsed
        secret for the data section
        public for the text section which is the default
    @return start: int
        the base address of the section
    @return size: int 
        the size of the section
    @throws AttributeError
        if the requested section has not explicitly defined an _start and _end address
    """
    @staticmethod
    def _parse_enclave_base_and_size(fileName, sectionType='public'):
        # Parse the objdump's symboltable to search for the start and end of the public/secret section
        # For possible future extension to multiple enclaves, one can add the desired enclave name below like: grep {enclave_name}_{sectionType}_
        objdump = os.popen(f'msp430-objdump -t {fileName} | grep _{sectionType}_').read()
        lines = objdump.split('\n')
        start = 0
        end   = 0
        # If not at least a _public_start and a _public_end are found --> error as each enclave should contain a text section
        # OR
        # If not at least a _secret_start and a _secret_end are found --> error as each enclave should contain a data section
        if len(lines) < 2:
            raise AttributeError(f'No enclave {sectionType} section found')
        else:
            for line in lines:
                if f'_{sectionType}_start' in line:
                    addr = re.match(r'^([0-9a-fA-F]+)', line).group(0)
                    start = int(addr, 16)
                if f'_{sectionType}_end' in line:
                    addr = re.match(r'^([0-9a-fA-F]+)', line).group(0)
                    end = int(addr, 16) 
            if start == 0 or end == 0:
                logger.debug(f'Something went wrong parsing enclave {sectionType} section size!')

        size = end - start
        return start, size
 
    """
    This method formats a given section parsed from the objdump. It requires an address inside of the section and based on this the textual representation is returned
    @param addr: int 
        the address of which the section needs to get parsed
    @return: None | [String]
        if section can not be found -> None
        else a list of strings where each string is a textual representation of the objdump lines in the binary
    """
    @staticmethod
    def get_section_string_representation(addr):
        # Get the section the addr belongs to
        addr = hex(addr)
        sect = SancusSDK.project.loader.main_object.sections.find_region_containing(int(addr, 16))

        if sect is None:
            logger.debug(f'No section of code found in objdump for address {addr}')
            return
        else:
            # If section already parsed
            if sect.name in SancusSDK.sections:
                return SancusSDK.sections[sect.name]

            sectAddr = sect.vaddr
            OBJDUMP = os.popen("msp430-objdump -d {}".format(SancusSDK.project.filename)).read()
            lines = OBJDUMP.splitlines()
            lines = list(filter(None, lines))

            section = SancusSDK.parse_section_from_objdump(lines, sectAddr)
            SancusSDK.sections[sect.name] = section
            return section

    """
    Method that parses the lines of the enclave section out of the objdump. These lines are
    used for example in the pretty printing of basic blocks as capstone is not supported for MSP430
    @param lines: [String]
        objdump with empty lines filtered out 
    @return section: [String] 
        list of strings, all lines from the section in the objdump
    """
    @staticmethod
    def parse_section_from_objdump(lines, section_start_addr):
        # Create regex for start of enclave in objdump 
        # Always of format:
        #00006ba0 <LABEL>:
        startSection = re.compile('0000' + SancusSDK._get_hex_without_prefix(section_start_addr))
        # Create regex for end of enclave (when next section starts)
        # Always of format: 
        #Disassembly of section [SECTIONNAME]:
        endSection = re.compile('Disassembly of section')

        section = []
        for i in range(len(lines)):
           if startSection.match(lines[i]):
               j = i
               # While not the end of the objdump and still in the same section
               while j < len(lines) and not endSection.match(lines[j]):
                   section.append(lines[j])
                   j += 1
        return section

    """
    Return a list with (address-opcode) pairs of all Sancus related instructions
    @param section: [String]
        a list of strings containing the objdump of the project
    @return [dict{address, opcode}]
        a list with address opcode pairs
    """
    @staticmethod
    def _get_sancus_instr_addresses(section):
        instructions = []
        # Regex for following kind of line:
        #    6ca4:       86 13           .word   0x1386
        # where the address and the opcode (0x1386) get captured
        regex = re.compile(r'^\s{4}([0-9A-Fa-f]+).*\.word\s*(0x[0-9A-Fa-f]+)')
        for instr in section:
            if '.word' in instr:
                match = regex.match(instr)
                addr = match.group(1)
                op = match.group(2)
                instructions.append({"address": '0x' + str(addr), "opcode": op})
        return instructions
    
    """
    Return a hexadecimal string of a certain address without the 0x begin
    e.g.    27555  -> 6ba3
            0x6ba3 -> 6ba3
    @param addr: String | Int
        the address of which the prefix '0x' has to be stripped
    @return String
        the hex string without prefix
    """
    @staticmethod
    def _get_hex_without_prefix(addr):
        return hex(int(addr))[2:]