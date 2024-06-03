import logging
import os

from elftools.elf.elffile import ELFFile

import ui.log_format
import ui.log_format as fmt
from sdks import Sancus
from sdks.SymbolManager import SymbolManager
from sdks.common import load_struct_from_memory
from ui import log_format
from utilities.Singleton import Singleton
from utilities.helper import file_stream_is_elf_file

logger = logging.getLogger(__name__)

SDKS = {
    'sancus' : Sancus.SancusSDK,
}

class SDKManager(metaclass=Singleton):
    def __init__(self, executable_path='', requested_sdk='auto', elf_file=None, **kwargs):
        """
        SDKManager takes an elf_path and a requested_sdk to load the given binary as the SDK into angr.
        Default options exist to make the SDKManager callable as a Singleton.
        """
        # Define sdk and init_state, initialized as None
        self.sdk = None
        self.init_state = None
        self.rebased_oentry_addr = -1
        self.additional_args = kwargs
        self.elf_symb_file = elf_file
        self.executable_path = executable_path

        # Open the path as a stream to check for the elf magic number
        executable_stream = open(executable_path, 'rb')
        if file_stream_is_elf_file(executable_stream):
            # File is elf file. open stream as ELFfile to pass to SDK detectors
            self.executable_object = ELFFile(executable_stream)
        else:
            # This can not be an elf file, magic is missing.
            if requested_sdk in SDKS:
                logger.error(ui.log_format.format_error(f'Can not proceed with SDK {requested_sdk}, {executable_path} '
                                                        f'is not an ELF file!'))
                exit(1)

            # If auto was requested and we are not an elf file, set it to the enclave dump to skip the detection part
            if requested_sdk == 'auto':
                requested_sdk = 'dump'
                self.executable_object = executable_path
            else:
                self.executable_object = executable_stream

        # Interject if the name ends on .dump and we are auto detect, then we just assume that it is an enclave dump
        if requested_sdk == 'auto' and os.path.splitext(executable_path)[1] == '.dump':
            requested_sdk = 'dump'
            self.executable_object = executable_path

        # Detect the utilized SDK from the binary.
        if requested_sdk == 'auto':
            logger.debug("Starting SDK detection..")
            found = False
            self.possible_sdk = None
            self.possible_sdk_version = ''

            for name, sdk in SDKS.items():
                #detect method parses the version from the binary
                version = sdk.detect(self.executable_object, executable_path)
                if version != '':
                    logger.info('Binary seems to be compiled with the '
                                f'{fmt.format_header(sdk.get_sdk_name())} '
                                f'version {fmt.format_header(version)}')
                    if found:
                        logger.critical("Multiple matches for SDKs detected!")
                    self.possible_sdk = sdk
                    self.possible_sdk_version = version
                    found = True
                else:
                    logger.debug(f'Not a {sdk.get_sdk_name()} ELF file.')
 
            if self.possible_sdk is None:
                logger.critical("I could not detect which SDK this is! "
                                "Is it maybe an enclave memory dump? Then rerun with the "
                                f"{ui.log_format.format_inline_header('-s dump')} option.")
                exit(1)
            else:
                logger.debug('I have found my SDK.')

        # Or if specific SDK is requested, default to that
        else:

            if requested_sdk in SDKS.keys():
                logger.warning(f"Forcing requested SDK {requested_sdk}. Proceed at your own risk!")
                self.possible_sdk_version = SDKS[requested_sdk].detect(self.executable_object, executable_path)
                self.possible_sdk = SDKS[requested_sdk]
            #elif requested_sdk in ADDITIONAL_LOADING_OPTIONS.keys():
            #    logger.warning(f'Proceeding with SDK {requested_sdk}')
            #    self.possible_sdk_version = \
            #        ADDITIONAL_LOADING_OPTIONS[requested_sdk].detect(self.executable_object, executable_path)
            #    self.possible_sdk = ADDITIONAL_LOADING_OPTIONS[requested_sdk]
            #else:
            #    logger.error(ui.log_format.format_error(f"Unexpected error with SDK {requested_sdk} "
            #                                            f"(Accepted the SDK but can't find it now).")
            #                 + f" Aborting...")
            #    exit(1)

        if requested_sdk == 'dump' and self.additional_args['json_file'] is None:
            # Try to recover by checking if we can find a .json file of the same name as the .dump file
            file_stem = os.path.splitext(self.executable_path)[0]
            possible_json_file = file_stem + '.json'
            if os.path.isfile(possible_json_file):
                # Apparently there is a json file with that same name at that same location. Attempt to use that.
                self.additional_args['json_file'] = possible_json_file
                logger.warning(
                    f'I did not receive an explicit --sdk-json-file with my dump, but I found {possible_json_file} that I will attempt to use now.')
            else:
                logger.error(f'{ui.log_format.format_error("EnclaveDump SDK requires an additional json file.")} '
                             f'Give this through '
                             f'{ui.log_format.format_inline_header("--sdk-json-file")}. Aborting..')
                exit(1)

        self.unmeasured_uninitialized_pages = None

        # and store the requested sdk / final decided sdk
        self.requested_sdk = requested_sdk

    def initialize_sdk(self, init_state):
        """
        Initialize a new instance of the previously detected SDK, give elffile and init state
        """
        self.init_state = init_state
        logger.debug(f'Initializing SDK as {self.possible_sdk.get_sdk_name()} in version {self.possible_sdk_version}')

        # Execute the SDK specific constructor with blank state (with pandora options set) as starting point
        self.sdk = self.possible_sdk(self.executable_object, self.init_state, self.possible_sdk_version, **self.additional_args)

        # If we decided on the dump SDK and elf_file is none, do a double check if maybe
        if self.requested_sdk == 'dump' and self.elf_symb_file is None:
            file_stem = os.path.splitext(self.executable_path)[0]
            possible_elf_file = file_stem + '.so'
            if os.path.isfile(possible_elf_file):
                # Apparently there is a json file with that same name at that same location. Attempt to use that.
                self.elf_symb_file = possible_elf_file
                logger.warning(
                    f'I did not receive an explicit --sdk-elf-file with my dump, but I found {self.elf_symb_file} that I will attempt to use now.')

        SymbolManager(init_state=init_state, elf_file=self.elf_symb_file, base_addr=self.get_base_addr(), sdk_name=self.get_sdk_name())

    def prepare_init_state(self, init_state):
        """
        Called after explorer prepared the eenter but before exploration starts.
        Useful for SDKs that need to modify the initial state.
        """
        self.sdk.modify_init_state(init_state)

    def __get_sdk_class(self):
        """
        Returns either the initialized SDK or the possible sdk base class if one was detected.
        """
        target = None
        if self.sdk is not None:
            return self.sdk
        else:
            return self.possible_sdk

    def get_sdk_name(self):
        target_sdk = self.__get_sdk_class()
        if target_sdk is not None:
            return self.sdk.get_sdk_name()
        else:
            raise RuntimeError('SDK not initialized yet.')

    def get_encl_size(self):
        if self.sdk is not None:
            return self.sdk.get_encl_size()
        else:
            raise RuntimeError('SDK not initialized yet.')

    def get_base_addr(self):
        target_sdk = self.__get_sdk_class()
        if target_sdk is not None:
            # Add elffile object to get_base_address for MSP430 which have to parse 
            # enclave address specifics from elffile.
            base_addr = target_sdk.get_base_addr()
            if base_addr == -1:
                if self.init_state is None:
                    #TODO: This was something with JSON
                    pass
                else:
                    # We actually have an init state already. Use that:
                    return self.init_state.project.loader.main_object.min_addr
            return base_addr

        raise RuntimeError('SDK not initialized yet.')

    def rebase_addr(self, addr, name):
        base = self.get_base_addr()

        if base == -1:
            raise RuntimeError('SDK Manager not initialized yet, base addr below zero.')

        addr_rebased = base + addr
        logger.debug(f'Rebasing {log_format.format_inline_header(name)} from {addr:#x} to {addr_rebased:#x}')
        return addr_rebased


    def get_angr_backend(self):
        target_sdk = self.__get_sdk_class()
        if target_sdk is None:
            raise RuntimeError("SDK not initialized yet.")
        else:
            return target_sdk.get_angr_backend()

    @staticmethod
    def get_sdk_names():
        """
        Returns a list of all SDK short names
        """
        return list(SDKS.keys())


    def get_code_page_information(self):
        """
        If the SDK supports additional code page layout information via a JSON file, return that. Otherwise, return None.
        """
        return None
    
    def get_unmeasured_uninitialized_pages(self):
        return []

    def addr_in_unmeasured_uninitialized_page(self, addr, size):
        return False

    def addr_in_executable_pages(self, addr):
        """
        Returns a bool whether the given concrete IP is within an allowed executable section.
        If code_pages is set, relies on that information. Otherwise asks the angr project to resolve this.
        """
        code_pages = self.get_code_page_information()
        if code_pages is not None:
            exists = False
            for (page_addr, size) in code_pages:
                if page_addr <= addr < page_addr + size:
                    exists = True
                    break
            return exists
        else:
            section = self.init_state.project.loader.main_object.sections.find_region_containing(addr)
            if section is not None and section.is_executable:
                return True
            else:
                # allow the SDK to have the last word (to support unmeasured
                # executable page that are added to the ELF file after loading)
                return self.sdk.override_executable(addr)
