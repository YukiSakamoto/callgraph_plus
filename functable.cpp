#include <string>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <iostream>

// Mach-O Binary Related
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/nlist.h>

#include <mach/machine.h>

// System call Related Headers
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#include "functable.h"

MachO_Binary::MachO_Binary(const std::string &filename):
    filename_(filename), fd_(-1), top_(NULL), is_mapped_(false), header_read_(false)
{
    // Map the binary into memory
    int fd = open(filename.c_str() , O_RDONLY);
    if (fd == -1) { throw; }

    struct stat fs;
    if (fstat(fd, &fs) < 0) { throw;}

    this->top_ = reinterpret_cast<char*>(
            mmap(NULL, fs.st_size, PROT_READ, MAP_PRIVATE, fd, 0) );
    if (this->top_ == MAP_FAILED) {  throw; }
    is_mapped_ = true;

    read_mach_header();
    search_load_commands();

    
    read_segment_defs();

    get_namedsymbol_table();
}

void 
MachO_Binary::unmap() 
{
    if (is_mapped_ != false) {
        close(this->fd_);
        this->top_ = NULL;
        this->is_mapped_ = false;
    }
}

void 
MachO_Binary::read_mach_header(void) 
{
    char *cur = this->top_;
    this->mh_.magic = *(reinterpret_cast<std::uint32_t*>(cur));
    cur += sizeof(std::uint32_t);

    this->mh_.cputype = *(reinterpret_cast<cpu_type_t*>(cur));
    cur += sizeof(cpu_type_t);

    this->mh_.cpusubtype = *(reinterpret_cast<cpu_subtype_t*>(cur));
    cur += sizeof(cpu_subtype_t);

    this->mh_.filetype = *(reinterpret_cast<std::uint32_t*>(cur));
    cur += sizeof(std::uint32_t);

    this->mh_.ncmds = *(reinterpret_cast<std::uint32_t*>(cur));
    cur += sizeof(std::uint32_t);

    this->mh_.sizeofcmds = *(reinterpret_cast<std::uint32_t*>(cur));
    cur += sizeof(std::uint32_t);

    this->mh_.flags = *(reinterpret_cast<std::uint32_t*>(cur));

    this->header_read_ = true;
}

void 
MachO_Binary::search_load_commands(void)
{
    int n_cmds = this->mh_.ncmds;
    if(!this->is_mapped_) { throw;  }
    std::uint32_t magic;
    std::memcpy(&magic, this->top_, sizeof(std::uint32_t));
    char *current;
    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        current = (this->top_ + sizeof(struct mach_header_64));
    } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        current = (this->top_ + sizeof(struct mach_header_64) );
    }

    for(int i = 0; i < n_cmds; i++) {
        struct load_command *current_lc = reinterpret_cast<struct load_command*>(current);
        this->load_command_ptrs_.push_back(current_lc);
        std::printf("Load Command Type: 0x%x\n", current_lc->cmd);
        current += current_lc->cmdsize;
    }
}

struct load_command *
MachO_Binary::get_load_command_address(std::uint32_t type)
{
    // return the first-appeared specified load command.
    for(int i = 0; i < this->load_command_ptrs_.size(); i++) {
        struct load_command *current_lc = reinterpret_cast<struct load_command*>(load_command_ptrs_[i]);
        if (current_lc->cmd == type) {
            return current_lc;
        }
    }
    return NULL;
}

void 
MachO_Binary::read_segment_defs()
{
    size_t consective_section_index = 1;
    for(int i = 0; i < this->load_command_ptrs_.size(); i++) {
        struct load_command *lc_ptr = this->load_command_ptrs_[i];
        if (lc_ptr->cmd == LC_SEGMENT_64) {
            struct segment_command_64 segment_cmd = *(reinterpret_cast<struct segment_command_64*>(lc_ptr));
            std::printf("SEGMENT: 0x%llx(size: 0x%llx)  :  %s (seciton: %d) \n", segment_cmd.vmaddr, segment_cmd.vmsize, segment_cmd.segname, segment_cmd.nsects);
            ;
            // Following to the segment_command, there are section commands.
            char *ptr = reinterpret_cast<char*>(lc_ptr) + sizeof(struct segment_command_64);
            for(int j = 0; j < segment_cmd.nsects; j++) {
                struct section_64 *p_sec = reinterpret_cast<struct section_64*>(ptr);
                std::printf("\tSECTION: %s in %s : 0x%llx\n", p_sec->sectname, p_sec->segname, p_sec->addr);
                if ( std::strcmp(p_sec->sectname, "__text") == 0) {
                    this->text_section_index_ = consective_section_index;
                }
                ptr += sizeof(struct section_64);

                consective_section_index += 1;
            }
        }
    }
}

std::uint32_t 
MachO_Binary::get_text_section(std::uint64_t &text_section_addr, std::uint64_t &text_section_size) const
{
    std::uint32_t page_offset;
    std::uint64_t vmaddr;
    std::uint64_t size;
    for(int i = 0; i < this->load_command_ptrs_.size(); i++) {
        struct load_command *lc_ptr = this->load_command_ptrs_[i];
        if (lc_ptr->cmd == LC_SEGMENT_64) {
            struct segment_command_64 segment_cmd = *(reinterpret_cast<struct segment_command_64*>(lc_ptr));
            // Following to the segment_command, there are section commands.
            char *ptr = reinterpret_cast<char*>(lc_ptr) + sizeof(struct segment_command_64);
            for(int j = 0; j < segment_cmd.nsects; j++) {
                struct section_64 *p_sec = reinterpret_cast<struct section_64*>(ptr);
                if ( std::strcmp(p_sec->sectname, "__text") == 0) {
                    vmaddr = p_sec->addr;
                    page_offset = p_sec->offset;
                    size = p_sec->size;
                    break;
                }
                ptr += sizeof(struct section_64);
            }
        }
    }
    text_section_addr = vmaddr;
    text_section_size = size;
    return page_offset;
}


std::string 
MachO_Binary::header(void) const
{
    std::stringstream ss;
    if (!this->is_mapped_) {}
    // branch 32bit or 64 bit
    std::uint32_t magic = this->mh_.magic;
    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        ss << "32 bit binary" << std::endl;
    } else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        ss << "64 bit binary" << std::endl;
    }
    ss << "Load Commands: " << this->mh_.ncmds;
    return ss.str();
}


int MachO_Binary::get_namedsymbol_table()
{
    if (this->is_mapped_ != true || this->top_  == NULL) { throw;  }
    struct symtab_command *p_symtab = reinterpret_cast<struct symtab_command*>(
            this->get_load_command_address(LC_SYMTAB) );
    if (p_symtab == NULL) { return -1;  }
    char *p_symbol_string_table = this->top_ + p_symtab->stroff;
    struct nlist_64 *p_nlist = reinterpret_cast<struct nlist_64*>(this->top_ + p_symtab->symoff);
    int n_symbols = p_symtab->nsyms;

    this->symbol_info_list_.clear();
    // Copy each symbols
    for(int i = 0; i < n_symbols; i++) {
        symbol_info temp;
        std::strncpy(temp.name, p_symbol_string_table + p_nlist->n_un.n_strx, sizeof(temp.name)-1);
        temp.nlist64 = *p_nlist;
        this->symbol_info_list_.push_back(temp);
        p_nlist++;
    }
    return 0;
}

const std::vector<struct MachO_Binary::symbol_info>&
MachO_Binary::get_symbol_info_list() const
{
    return this->symbol_info_list_;
}


