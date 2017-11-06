
#ifndef _MACHO_LOADER_H
#	include <mach-o/loader.h>
#	include <mach-o/fat.h>
#	include <mach-o/nlist.h>
#endif

#include <string>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <iostream>



const std::uint32_t load_command_list[] = {
	LC_REQ_DYLD,
	LC_SEGMENT,	
	LC_SYMTAB,
	LC_SYMSEG,
	LC_THREAD,
	LC_UNIXTHREAD,
	LC_LOADFVMLIB,
	LC_IDFVMLIB,
	LC_IDENT,
	LC_FVMFILE,
	LC_PREPAGE,   
	LC_DYSYMTAB,
	LC_LOAD_DYLIB,
	LC_ID_DYLIB	,
	LC_LOAD_DYLINKER ,
	LC_ID_DYLINKER,
	LC_PREBOUND_DYLIB ,
	LC_ROUTINES	,
	LC_SUB_FRAMEWORK ,
	LC_SUB_UMBRELLA ,
	LC_SUB_CLIENT	,
	LC_SUB_LIBRARY ,
	LC_TWOLEVEL_HINTS ,
	LC_PREBIND_CKSUM,
	LC_LOAD_WEAK_DYLIB ,
	LC_SEGMENT_64,
	LC_ROUTINES_64,
	LC_UUID,
	LC_RPATH,
	LC_CODE_SIGNATURE,
	LC_SEGMENT_SPLIT_INFO ,
	LC_REEXPORT_DYLIB,
	LC_LAZY_LOAD_DYLIB,
	LC_ENCRYPTION_INFO,
	LC_DYLD_INFO,
	LC_DYLD_INFO_ONLY,
	LC_LOAD_UPWARD_DYLIB,
	LC_VERSION_MIN_MACOSX,
	LC_VERSION_MIN_IPHONEOS,
	LC_FUNCTION_STARTS,
	LC_DYLD_ENVIRONMENT,
};
const int load_command_list_size = sizeof(load_command_list) / sizeof(uint32_t);

class MachO_Binary {
public:
    struct symbol_info {
        char name[256];
        uint64_t return_instruction_address[128];
        int n_return_instructions;
        struct nlist_64 nlist64;
    };
public:
    MachO_Binary(const std::string &filename);
    void unmap();
    void read_mach_header(void);
    void search_load_commands(void);
    struct load_command *get_load_command_address(std::uint32_t type);
    const char* get_mapped_address() const
    {
        return this->top_;
    }
    const std::vector<struct load_command*> &get_load_command_address_list()
    {   return this->load_command_ptrs_;    }
    void read_segment_defs();
    int get_namedsymbol_table();
    bool is_x86_64(void) const
    {   return (this->mh_.magic == MH_MAGIC_64 || this->mh_.magic == MH_CIGAM_64);  }
    std::string header(void) const;
    const std::vector<struct symbol_info>& get_symbol_info_list() const;
    std::uint32_t get_text_section(std::uint64_t &text_section_addr, std::uint64_t &text_section_size) const;

    size_t get_text_section_index() const
    {   return this->text_section_index_;    }
private:
    std::string filename_;
    int fd_; // File Descriptor   
    char *top_;
    bool is_mapped_;

    bool header_read_;
    struct mach_header mh_;  // 
    std::vector<struct load_command*> load_command_ptrs_;
    std::vector<struct symbol_info> symbol_info_list_;
    size_t text_section_index_;
};
