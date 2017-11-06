/* Standard Libraries */
#include <cstdio>
#include <cstdlib>
#include <cstring>

/* UNIX System calls related */
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <dirent.h>
#include <errno.h>

/* Mach Port related */
#include <mach/mach.h>
#include <spawn.h>
#include <udis86.h>

/* This program's headers */
#include "tracer.h"
#include "memory_op.h"
#include "functable.h"

#include <vector>

extern int errno;
#define RESET_ERROR (errno=0)
#define ERROR_OCCURED (errno!=0)


class breakpoint_manager 
{
public:
    struct breakpoint {
        vm_address_t addr;
        unsigned char original_byte;
        bool valid;
    };
    typedef std::vector<breakpoint> breakpoint_list_type;

    breakpoint_manager(mach_port_t task)
        : task_(task)
    {;}

    bool set_breakpoint(vm_address_t target_addr) 
    {
        char breakpoint_instruction = 0xcc;
        bool already_registered(false);
        breakpoint_list_type::iterator it_entry = breakpoints_.begin();
        // Search the entry
        int index = this->find_breakpoint_entry(target_addr);
        if (index == -1) {
            // create_new_entry
            char original_instruction = 0x00;
            read_write_process_memory(
                    task_, target_addr, &original_instruction, NULL, sizeof(unsigned char));
            struct breakpoint new_entry = { target_addr, original_instruction, false };
            breakpoints_.push_back(new_entry);
            index = breakpoints_.size() - 1;
        }
        // Insert Breakpiont Instruction Code
        if ( read_write_process_memory(
                    task_, target_addr, NULL, &breakpoint_instruction, sizeof(unsigned char)) ) {
            breakpoints_[index].valid = true;
            return true;
        } else {
            return false;
        }
    }
    bool disable_breakpoint(const vm_address_t target_addr)
    {
        bool result = false;
        int brkpt_index = find_breakpoint_index(target_addr);
        if (brkpt_index != -1) {
            char orig_code = this->breakpoints_[brkpt_index].original_byte;
            if (read_write_process_memory(task_, target_addr, NULL, &orig_code, sizeof(unsigned char))) {
                result = true;
            }
        }
        return result;
    }
    int find_breakpoint_entry(const vm_address_t addr) const
    {
        // Search the index of breakpoint from the this->breakpoints_;
        // if not found, it will return -1;
        int i;
        for(i = 0; i < this->breakpoints_.size(); i++) {
            if (this->breakpoints_[i].addr == addr) {   break; }
        }

        if (i == this->breakpoints_.size()) {
            return -1;
        } else {
            return i;
        }

    }
    int find_breakpoint_index(const vm_address_t addr) const
    {
        // Search the index of breakpoint entry from this->breakpoints_.
        // it will return the index whenever it is valid or not.
        int index = find_breakpoint_entry(addr);
        if (index == -1) {
            return -1;
        } else if (breakpoints_[index].valid == true) {
            return index;
        } else {
            return -1;
        }
    }
private:
    mach_port_t task_;
    breakpoint_list_type breakpoints_;
};

// This process run in the child process.
void target_proc(int argc_child, char **argv_child)
{
    int ret;
    short ps_flags = 0;
    pid_t pid;
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attrs;
    
    // Disable ASLR
    RESET_ERROR;
    posix_spawn_file_actions_init(&actions);
    posix_spawnattr_init(&attrs);
#ifndef _POSIX_SPAWN_DISABLE_ASLR
#   define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif
    ps_flags |= POSIX_SPAWN_SETEXEC;
    ps_flags |= _POSIX_SPAWN_DISABLE_ASLR;
    ret = posix_spawnattr_setflags(&attrs, ps_flags);
    if (ret != 0) {
        std::fprintf(stderr, "cannot set posix_spawn flags\n");
        return;
    }

    // Wait until being attached from parent process
    ret = ptrace(PT_TRACE_ME, 0, 0, 0);
    std::printf("[ Debuggee ]  Attached Done\n");
    posix_spawn(&pid, argv_child[0], &actions, &attrs, argv_child, NULL);

    // NEVER GET HERE, since posix_spawn replace the process with specified program
    exit(1);
}

void insert_break_points()
{
    ;
}

bool is_exclude_func(const char *function_name)
{
    const int exclude_count = 1;
    const char* excludes[] = {
        "__mh_execute_header",
    };
    for(int i = 0; i < exclude_count; i++) {
        if (std::strcmp(function_name, excludes[i]) == 0) {
            return true;
        }
    }
    return false;
}

void debugger_proc(const pid_t child_pid, int argc, char **argv)
{
    int child_stat;
    int wait_count = 0;

    /* open the port (do as an administrator) */
    mach_port_t task;
    kern_return_t kret = task_for_pid(mach_task_self(), child_pid, &task);
    if (kret != KERN_SUCCESS) {
        std::fprintf(stderr, "[ Debugger ] task_for_pid() failed.\n");
        std::fprintf(stderr, "[ Debugger ] message from the operationg system : %s\n", mach_error_string(kret));
        exit(0);
    }

    breakpoint_manager brkpt_mng(task);
    std::string program_path(argv[0]);
    MachO_Binary binary(program_path);
    std::printf("**** Entering the main loop of %s: ****\n", program_path.c_str() );
    // main loop
    while(waitpid(child_pid, &child_stat, WUNTRACED)) {
        if (WIFEXITED(child_stat)) {
            /* Child Process Terminated */
            fprintf(stderr, "[ Debugger ]  Process :%d Terminated\n", child_pid);
            return;
        }
        if(wait_count == 0) { 
            std::printf("**** Analyzing the program of child process... ****\n");
            std::printf("**** Functions in %s: ****\n", program_path.c_str() );

            std::uint64_t text_section_size;
            std::uint64_t text_section_vmaddr;
            std::uint32_t text_section_offset = binary.get_text_section(text_section_vmaddr, text_section_size);
            std::printf("vm addr : 0x%llx\n", text_section_vmaddr);
            for(std::vector<MachO_Binary::symbol_info>::const_iterator it = binary.get_symbol_info_list().begin(); it != binary.get_symbol_info_list().end(); it++) {
                if (it->nlist64.n_sect == binary.get_text_section_index() && std::strcmp(it->name, "__mh_execute_header") != 0 ) {
                    std::printf("\t0x%llx (sect: %d) : %s\n", it->nlist64.n_value, it->nlist64.n_sect, it->name);
                    brkpt_mng.set_breakpoint(it->nlist64.n_value);
                }
            }
            // Set break point instruction for the return address
            ud_t ud_obj;
            ud_init(&ud_obj);
            ud_set_input_buffer(&ud_obj, reinterpret_cast<const std::uint8_t*>(text_section_offset + text_section_offset), text_section_size);
            ud_set_mode(&ud_obj, 64);
            //while(ud_disassemble(&ud_obj)) {
                //if (ud_obj.mnemonic == UD_Iret) {
                //    brkpt_mng.set_breakpoint(ud_obj.pc + text_section_vmaddr);
                //}
            //}
        } else {
            // Breakpoint
            // 1. Get Current address of RIP
            uint64_t rip;
            read_process_register_64(task, RIP, &rip);
            std::printf("**** Break at 0x%llx\n", rip);
            write_process_register_64(task, RIP, RELATIVE_VAL, -1);
            brkpt_mng.disable_breakpoint(rip - 1);
            ptrace(PT_STEP, child_pid, (caddr_t)1, 0);
            //XXX Proceed 1 instruction (here, RIP was incremented by 1)
            brkpt_mng.set_breakpoint(rip - 1);
            if (true) {
                ;
            } else {
                // Decrease the instruction pointer. This correspoinds to back only one instruction.
            }
        }
        wait_count += 1;
        ptrace(PT_CONTINUE, child_pid, (caddr_t)1, 0);
    }
}

int count_arg_child(int argc, char **argv)
{
    int argc_child = 0;
    for(int i = 0; i < argc; i++) {
        if (i == 0) { 
            // This program name
        } else {    
            argc_child += 1;
        }
    }
    return argc_child;
}

int main(int argc, char **argv)
{
    pid_t c_pid = fork();

    // check argv
    int argc_child = count_arg_child(argc, argv);
    // Extract arguments for the child process
    char **argv_child = new char*[argc_child + 1];
    int j = 0;
    for(int i = 0; i < argc; i++) {
        if (i == 0) {   
            ;
        } else {
            argv_child[j] = argv[i];    j += 1;
        }
    }
    argv_child[argc_child] = NULL;

    if (c_pid == -1) {
    } else if (c_pid == 0) {
        target_proc(argc_child, argv_child);  // debugee

        // Never get here!
        std::fprintf(stderr, "Child process aborted");
        delete[] argv_child;
    } else {
        std::printf("pid of child_proc: %d\n", c_pid);
        debugger_proc(c_pid, argc_child, argv_child);
    }
    return 0;
}
