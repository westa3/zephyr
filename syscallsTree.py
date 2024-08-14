from elftools.elf.elffile import ELFFile # pip install pyelftools
import os # pip install os

# Get the ELF file
def getElf(elffile):
    with open(elffile, 'rb') as f:
        elffile = ELFFile(f) # Parse the elf file

        if not elffile.has_dwarf_info(): # Check if the elf file has DWARF info
            print('no DWARF info')
            return

        dwarf_info = elffile.get_dwarf_info()

        return dwarf_info


# Get a list of syscalls for each file (either mrsh, vrfy or impl functions)
def get_syscalls(dwarf_info, cuOffsets, stack):
    syscall_table = {} # Key = file name, Value = list of syscalls within that file

    for CU in dwarf_info.iter_CUs(): # Iterate over the compilation units
        
        cuOffset = CU.cu_offset # Get the compilation unit offset
        
        # Get the file name and use it as a key for the syscall_table and cuOffsets dictionaries
        top_DIE = CU.get_top_DIE()
        file_name = top_DIE.attributes['DW_AT_name'].value.decode('utf-8')
        syscall_table[file_name] = []
        cuOffsets[file_name] = cuOffset

        for DIE in CU.iter_DIEs(): # Iterate over the debug information entries

            # Find the stack size using the thread_stack_header structure in userspace.c (CONFIG_USERSPACE has to be enabled)
            if DIE.tag == 'DW_TAG_structure_type' and 'userspace.c' in file_name:
                try:
                    func_name = DIE.attributes['DW_AT_name'].value.decode('utf-8')
                except KeyError:
                    continue

                if 'thread_stack_header' in func_name:
                    stack.append(DIE.attributes['DW_AT_byte_size'].value) # Won't update value if I do stack = DIE.attributes['DW_AT_byte_size'].value

            elif DIE.tag == 'DW_TAG_subprogram': # subprogram essentially means function
                
                try:
                    func_name = DIE.attributes['DW_AT_name'].value.decode('utf-8') # Get the name of the subprogram
                except KeyError:
                    continue

                address = DIE.offset # Get memory address of the function within the elf file

                if func_name.startswith(('z_mrsh', 'z_vrfy', 'z_impl')): # Only want the syscalls which are made up of these prefixes

                    if func_name not in syscall_table[file_name]:
                        syscall_table[file_name].append([func_name, address])

    return syscall_table


# Get the call tree for each syscall
def get_call_tree(dwarf_info, syscall_table, flags, cuOffsets):
    call_tree = {} # Key = file name, Value = list of functions within that file in the form of: [function address, depth], [function address, depth], ...

    for key in syscall_table: # Iterate over the files in the syscall_table

        call_tree[key] = [] 

        cuOffset = cuOffsets[key]

        for i in range(0, len(syscall_table[key])): # For each syscall in the file
            address = syscall_table[key][i][1]

            DIE = dwarf_info.get_DIE_from_refaddr(address) # Get the debug information entry for the syscall

            if address in [entry[0] for entry in call_tree[key]]: # If the syscall is already in the call tree, continue
                continue

            call_tree[key].append([address, 0]) # Add the syscall to the call tree as the root

            if DIE.has_children:
                check_call_sites(dwarf_info, DIE, cuOffset, call_tree, key, 1, flags) # Check the call sites/inlined subroutines/pointers for the syscall

        # print(f'File: {key}, Call Tree: {call_tree[key]}')

    return call_tree


# Recursively check the call sites for each function
def check_call_sites(dwarf_info, DIE, cuOffset, call_tree, key, depth, flags):
    for child in DIE.iter_children(): 

        # print(f'Key: {key}, Child: {child}')
        
        if child.tag == 'DW_TAG_GNU_call_site': # Check for call sites
            try:
                target_address = child.attributes['DW_AT_abstract_origin'].value + cuOffset
                target_DIE = dwarf_info.get_DIE_from_refaddr(target_address) 
                call_tree[key].append([target_address, depth])
                check_call_sites(dwarf_info, target_DIE, cuOffset, call_tree, key, depth + 1, flags)
            except KeyError:
                target_address = ""
        
        elif child.tag == 'DW_TAG_inlined_subroutine': # Check for inlined functions
            try:
                target_address = child.attributes['DW_AT_abstract_origin'].value + cuOffset
                target_DIE = dwarf_info.get_DIE_from_refaddr(target_address)
                call_tree[key].append([target_address, depth])
                if target_address not in flags:
                    flags[target_address] = 'inlined'
                check_call_sites(dwarf_info, target_DIE, cuOffset, call_tree, key, depth + 1, flags)
            except KeyError:
                target_address = ""
        
        else:
            # child_address = child.offset
            ptr_addresses = []
            tags(dwarf_info, call_tree, flags, child, cuOffset, ptr_addresses, 0) # Check for pointers
            for ptr in ptr_addresses:
                if ptr != 0:
                    call_tree[key].append([ptr, depth])
                if ptr not in flags:
                    flags[ptr] = 'pointer'
            
        if child.has_children:
            check_call_sites(dwarf_info, child, cuOffset, call_tree, key, depth, flags)


def tags(dwarf_info, call_tree, flags, DIE, cuOffset, ptr_addresses, at_name_addr):
    try:
        try:
            at_name = DIE.attributes['DW_AT_name'].value.decode('utf-8')
            at_name_addr = DIE.offset
            # print(f'Name: {at_name}')
        except KeyError:
            at_name = ""
        at_type = DIE.attributes['DW_AT_type'].value + cuOffset
        target_DIE = dwarf_info.get_DIE_from_refaddr(at_type)
        if target_DIE.tag == 'DW_TAG_pointer_type':
            tags(dwarf_info, call_tree, flags, target_DIE, cuOffset, ptr_addresses, at_name_addr)
        elif target_DIE.tag == 'DW_TAG_const_type':
            tags(dwarf_info, call_tree, flags, target_DIE, cuOffset, ptr_addresses, at_name_addr)
        elif target_DIE.tag == 'DW_TAG_variable':
            tags(dwarf_info, call_tree, flags, target_DIE, cuOffset, ptr_addresses, at_name_addr)
        elif target_DIE.tag == 'DW_TAG_structure_type':
            for c in target_DIE.iter_children():
                if c.tag == 'DW_TAG_member':
                    tags(dwarf_info, call_tree, flags, c, cuOffset, ptr_addresses, at_name_addr)
        elif target_DIE.tag == 'DW_TAG_subroutine_type':
            # print(f'at_name_addr: {at_name_addr}')
            ptr_addresses.append(at_name_addr)
    except KeyError:
        return
    


# Get the memory usage for each function
def get_memory_usage(dwarf_info, call_tree, flags):
    mem_usage_dict = {} # Key = function address, Value = max stack usage

    for key in call_tree:
        mem_usage = 0
        for i in range(0, len(call_tree[key])):
            address = call_tree[key][i][0]
            # print(f'Address: {address}')
            DIE = dwarf_info.get_DIE_from_refaddr(address)
            
            try:
                name = DIE.attributes['DW_AT_name'].value.decode('utf-8')
                # if name not in mem_usage_dict:
                    # mem_usage_dict[name] = []
            except KeyError:
                continue

            try:
                decl_line = DIE.attributes['DW_AT_decl_line'].value
                decl_column = DIE.attributes['DW_AT_decl_column'].value
            except KeyError:
                continue

            if address not in mem_usage_dict:
                mem_usage = su_files(key, decl_line, decl_column, name, address, flags) # Get the memory usage for the function
                mem_usage_dict[address] = mem_usage # Store the memory usage
                '''
                if get_by_name:
                    if name not in mem_by_name:
                        mem_by_name[name] = mem_usage
                    else:
                        mem_by_name[name] = max(int(mem_by_name[name]), int(mem_usage))
                '''
            
            else:
                continue

    return mem_usage_dict


def redo_memory(dwarf_info, original_mem, mem_by_name):
    new_mem = {}
    for key in original_mem:
        address = key
        DIE = dwarf_info.get_DIE_from_refaddr(address)
        name = DIE.attributes['DW_AT_name'].value.decode('utf-8')
        if name not in new_mem:
            new_mem[name] = original_mem[key]
        else:
            new_mem[name] = max(int(new_mem[name]), int(original_mem[key]))
        
        if name not in mem_by_name:
            mem_by_name[name] = 1
        else:
            mem_by_name[name] += 1

    for key in original_mem:
        address = key
        DIE = dwarf_info.get_DIE_from_refaddr(address)
        name = DIE.attributes['DW_AT_name'].value.decode('utf-8')

        new_memory = new_mem[name]
        original_mem[key] = new_memory

    # print(f'New Memory: {new_mem}')


# Find and store the .su file's path
def su_files(c_file, line, column, name, address, flags):
    home_path = os.path.expanduser('~') # Get the home path
    search_path = 'zephyrproject/zephyr/build' # Path to search for the .su files. It always starts from the build directory
    root_search = os.path.join(home_path, search_path) # Join the home path and the search path

    # original_c_file = c_file
    c_file = c_file.split('/')[-1] # Get just the file name without the path
    su_file = c_file + '.su' # Add the .su extension to the file name

    for root, dirs, files in os.walk(root_search):
        if su_file in files:

            target_line = str(line) + ':' + str(column) + ':' + name

            found_path = os.path.join(root, su_file)
            mem = confirm_su_file(found_path, target_line, address, flags) # Check if the function's stack usage is in the .su file

            break

        else:
            continue

    return mem


# A possible .su file is passed in. This checks if the function's stack usage is in that file
def confirm_su_file(file_name, find_line, address, flags):
    with open(file_name, 'r') as file:
        
        for line in file:
            
            if find_line in line:
                split_line = line.split()
                if address not in flags:
                    flags[address] = split_line[2]
                else:
                    if split_line[2] not in flags[address]:
                        flags[address] = flags[address] + ',' + ' ' + split_line[2]
                return split_line[1]

        if address not in flags:
            flags[address] = '*'
        else:
            if '*' not in flags[address]:
                flags[address] = flags[address] + ',' + ' ' + '*'    
        
        return 0


# Get the names of the functions for printing output
def get_names(call_tree, dwarf_info, mem_usage):
    for key in call_tree:
        for i in range(0, len(call_tree[key])):
            address = call_tree[key][i][0]
            DIE = dwarf_info.get_DIE_from_refaddr(address)
            try:
                name = DIE.attributes['DW_AT_name'].value.decode('utf-8')
            except KeyError:
                name = "NA"

            call_tree[key][i][0] = name

            call_tree[key][i].append(address)

            if address in mem_usage:
            # if name in mem_usage:
                call_tree[key][i].append(mem_usage[address])
                # call_tree[key][i].append(mem_usage[name])
            else:
                call_tree[key][i].append(0)



def max_mem_usage(call_tree, max_usage):
    for key in call_tree:
        # print(f'Call_tree: {call_tree[key]}')
        curr_stack = []
        max_stack = []
        root = 0
        max_mem_used = 0
        max_usage[key] = []
        for i in range(0, len(call_tree[key])):
            # print(f'Key: {key}, call_tree: {call_tree[key][i]}')
            '''
            if len(call_tree[key][i]) <= 2:
                call_tree[key][i] = ["NA", 0, 0, 0]
                continue
            '''
            curr_name = call_tree[key][i][0]
            curr_depth = call_tree[key][i][1]
            curr_address = call_tree[key][i][2]
            curr_usage = int(call_tree[key][i][3])
            
            if i+1 < len(call_tree[key]):
                next_depth = call_tree[key][i+1][1]
            else:
                next_depth = -1

            if curr_depth == 0:
                root = curr_address

            if curr_depth == 0 and (next_depth == 0 or next_depth == -1):
                max_usage[key].append([root, curr_usage])
                continue

            curr_stack.append([curr_name, curr_depth, curr_address, curr_usage])

            if curr_depth > next_depth:
                # print(f'Current stack: {curr_stack}')
                # print(f'Max stack: {max_stack}')
                max_stack = check_stacks(curr_stack, max_stack)
                # print(f'Max stack usage for {key}: {max_stack}')
                if next_depth == -1 or next_depth == 0:
                    for max in max_stack:
                        max_mem_used += max[3]
                    max_usage[key].append([root, max_mem_used])

                    curr_stack = []
                    max_stack = []
                    max_mem_used = 0
                
                else:
                    for func in curr_stack:
                        if func[1] >= next_depth:
                            curr_stack.remove(func)
                

def check_stacks(curr_s, max_s):
    max_mem = 0
    curr_mem = 0

    if max_s == []:
        max_s = curr_s

    for i in curr_s:
        curr_mem += i[3]

    if curr_s == max_s:
        return curr_s
    else:
        for i in max_s:
            max_mem += i[3]

        if curr_mem >= max_mem:
            max_s = curr_s
    
    # print(f'Max stack: {max_s}')
    return max_s


# Print the call tree with stack usage and informational flags
def print_tree(call_tree, flags, max_usage, stack_size, mem_by_name, get_by_name):
    for key in call_tree:
        print(f'File: {key}\n')
        prev_depth = -1
        # print(f'Memory Usage: {memory_usage}\n')
        for function, depth, address, mem in call_tree[key]:
            print_string = '   ' * depth

            if depth > prev_depth or depth == 0:
                print_string += '+'

            print_string += function + '   ' + str(mem)

            if address in flags:
                if get_by_name:
                    if '*' in flags[address]:
                        if mem_by_name[function] > 1:
                            flags[address] = flags[address].replace('*', 'external')
                print_string += '   ' + flags[address]

            if depth == 0:
                for entry in max_usage[key]:
                    if address == entry[0]:
                        print_string += '   ' + 'MAX MEMORY USAGE: ' + str(entry[1])
                        if entry[1] > (.9 * stack_size):
                            print_string += '   ' + 'WARNING: STACK USAGE EXCEEDS 90% OF STACK SIZE'

            print(print_string)
            
            prev_depth = depth
        
        print('\n')
    

def main():

    get_by_name = True

    flags = {} # Key = function address, Value = informational flags (string concatenation of all flags)

    cuOffsets = {} # Key = file name, Value = compilation unit offset for that file

    max_usage = {}

    mem_by_name = {}

    stack_size = [0]

    info = getElf('build/zephyr/zephyr.elf') # Get the DWARF info
    table = get_syscalls(info, cuOffsets, stack_size) # Get the syscalls
    full_call_tree = get_call_tree(info, table, flags, cuOffsets)
    memory = get_memory_usage(info, full_call_tree, flags)
    
    if get_by_name:
        redo_memory(info, memory, mem_by_name)
    
    get_names(full_call_tree, info, memory)
    max_mem_usage(full_call_tree, max_usage)
    
    stack_size = stack_size[-1]

    print_tree(full_call_tree, flags, max_usage, stack_size, mem_by_name, get_by_name)

    print(f'Stack size: {stack_size}')

    # for i in table:
        # print(f'Key: {i}, Functions: {table[i]}')

    # for i in memory:
        # print(f'Key: {i}, Memory: {memory[i]}')
    
    # for i in full_call_tree:
        # print(f'Key: {i}, Functions: {full_call_tree[i]}')

    # for i in max_usage:
         # print(f'Key: {i}, Max Usage: {max_usage[i]}')

main()