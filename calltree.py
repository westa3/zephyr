from elftools.elf.elffile import ELFFile # pip install pyelftools
import os # pip install os


# Global variable for list of subprograms (a dictionary)
# End result: {function name: [address, cuOffset, function1 name, function2 name, ...], function2 name: [address, cuOffset, function1 name, function2 name, ...], ...}
subprograms = {}


# Get the ELF file
def getElf(elffile):
    with open(elffile, 'rb') as f:
        elffile = ELFFile(f) # Parse the elf file

        if not elffile.has_dwarf_info(): # Check if the elf file has DWARF info
            print('no DWARF info')
            return

        dwarf_info = elffile.get_dwarf_info()

        return dwarf_info


# Get the subprogram names: if DIE of subprogram has children (i.e. other tags at a seperate depth in the elf file - ex. parameters), then it will look for one labeled DW_TAG_GNU_call_site and extract the addresses of those call sites
def callstruct(dwarf_info):
    full_table = {} # Dictionary of addresses, names and filenames. Format: full_table[address] = [name, .c_file_name, line, column, stack_usage, and eventually su_file]
    
    for CU in dwarf_info.iter_CUs(): # Iterate over the Compilation Units

        cuOffset = CU.cu_offset # Get the offset of the Compilation Unit to be added into the abstract origin value of call sites
        top_DIE = CU.get_top_DIE() # Get the top Debugging Information Entry which will be the .c file name that is calling the subprograms below it
        file_name = top_DIE.attributes['DW_AT_name'].value.decode('utf-8')

        for DIE in CU.iter_DIEs(): # Iterate over the Debugging Information Entries
            if DIE.tag == 'DW_TAG_subprogram': # Check if the DIE is a function
                
                try:
                    name = DIE.attributes['DW_AT_name'].value.decode('utf-8') # Get the function name
                    address = DIE.offset # Get the function address using the offset attribute of DIE
                    
                    full_table[address] = [name, file_name, DIE.attributes['DW_AT_decl_line'].value, DIE.attributes['DW_AT_decl_column'].value] # Append info to full_table. Decl_line and decl_column are the line and column of the function in the .c file

                    if name not in subprograms:
                        subprograms[name] = [name, address, DIE.attributes['DW_AT_decl_line'].value, DIE.attributes['DW_AT_decl_column'].value]

                    if DIE.has_children:
                        childCalls(name, DIE, cuOffset)

                except KeyError: # cases where something fails (usually subprogram doesn't have a name)
                    continue

    return full_table


# Finds every DW_TAG_GNU_call_site of the ONE subprogram passed in and appends the function addresse to subprograms[parentfunction_name] list
def childCalls(parentName, target_DIE, cuOffset):
    for c in target_DIE.iter_children():

        if c.has_children:
            childCalls(parentName, c, cuOffset) # Recursive call to get to leaf nodes as some GNU_call_sites are nested
        
        else:
            if c.tag == "DW_TAG_GNU_call_site": # Check if the child is a call site
                c_origin = c.attributes['DW_AT_abstract_origin'].value # Get the call site abstract origin value to calculate the memory address
                c_address = cuOffset + c_origin
                subprograms[parentName].append(c_address)


# Convert the addresses of child function calls in each subprogram key to the actual function name
def childNames(dwarf_info):
    for key in subprograms:

        for i in range(4, len(subprograms[key])): # start at 4 because the first four elements are: name, address, line, column
            address = subprograms[key][i]
            
            DIE = dwarf_info.get_DIE_from_refaddr(address) # Get the DIE based on address
            
            try:
                subprograms[key][i] = [DIE.attributes['DW_AT_name'].value.decode('utf-8'), address, DIE.attributes['DW_AT_decl_line'].value, DIE.attributes['DW_AT_decl_column'].value] # Try to turn the index that was a singular address into a list: [name, address, line, column]
            
            except KeyError:

                try:
                    decl_line = DIE.attributes['DW_AT_decl_line'].value
                except KeyError:
                    decl_line = "NA"
                
                try:
                    decl_column = DIE.attributes['DW_AT_decl_column'].value
                except KeyError:
                    decl_column = "NA"
                
                subprograms[key][i] = ["NA", address, decl_line, decl_column] # Catch any cases where there is no name, decl_line or decl_column


# Make the call tree for each function and delete cases where a function is both a root and child node within the entire tree dictionary
def consolidate():
    trees = {} # End result: {function name: [function name, 0, function1 name, depth1, function2 name, depth2, ...], function name: [function name, 0, function2 name, depth2, function3 name, depth3, ...], ...}
    visited = [] # Stack that keeps track of the visited subprograms - mini tree per function with a function followed by its depth. End result: deleted but right before: [function1, depth1, function2, depth2, function3, depth3, ...]
    to_remove = [] # list of functions that are child nodes of other functions and have a parent node (key) in subprorams. End result: deleted but right before: [function1 name, function2 name, ...]

    for key in subprograms:
        visited.clear() # Clear the visited stack
        trees[key] = [] # Add the key to the trees dictionary
        key_address = subprograms[key][1]
        recursive(key, key_address, 0, key, key_address, trees, visited, to_remove) # Call the recursive function to create a call tree for subprograms[key]
    
    for key in subprograms: # Remove the parent nodes that are child nodes in other functions
        if key in to_remove: 
            del trees[key]

    return trees


# Create a call tree for a specified root node
def recursive(target, target_address, depth, root_name, root_address, trees, visited, to_remove):
    if depth != 0:
        to_remove.append(target) # If a function is being called by another function, then get rid of the child function's key and value in subprograms

    if target not in subprograms: # Make sure that the function is in the subprograms dictionary
        return
    
    line = subprograms[target][2] # The line of the function in the .c file
    column = subprograms[target][3] # The column of the function in the .c file
    
    if len(subprograms[target]) > 4: # If the function has other functions that it calls because any other function calls are listed at or after index 4 of subprograms[key]
        
        for idx in range(4, len(subprograms[target])):
            if subprograms[target][idx][0] in visited: # If the function has already been visited, then check if it's at the same depth (meaning it could be making a tail recursive call)
                
                visited_depth = visited.index(subprograms[target][idx][0]) + 4  # subprograms[target][idx][0] is the function name. Get the index of the function name in the visited array and then get it's depth which is 4 indexes away from the name
                
                if visited_depth == depth:
                    continue # If it is the same depth, I don't want to add it to the tree again

                else:
                    visited.extend([target, target_address, line, column, depth]) # If it's not the same depth, then add the function to the tree and call the function recursively with increased depth
                    recursive(subprograms[target][idx][0], subprograms[target][idx][1], depth + 1, root_name, root_address, trees, visited, to_remove)

            if subprograms[target][idx][0] not in visited: # If the function hasn't been visited, then add it to the tree and call the function recursively with increased depth
                visited.extend([target, target_address, line, column, depth])
                recursive(subprograms[target][idx][0], subprograms[target][idx][1], depth + 1, root_name, root_address, trees, visited, to_remove)

            else:
                continue

    else: # Then the function doesn't call any other function and it's either at the end of the tree or it's simply a root with no leaves
        visited.extend([target, target_address, line, column, depth])

    trees[root_name] = visited.copy()  # Store the tree in the trees dictionary


# Find and store the .su files' paths for each function
def su_files(full_table):
    home_path = os.path.expanduser('~') # Get the home path
    search_path = 'zephyrproject/zephyr/build' # Path to search for the .su files. It always starts from the build directory
    root_search = os.path.join(home_path, search_path) # Join the home path and the search path

    for key in full_table:
        c_file = full_table[key][1] # Get the file name that called the function
        c_file = c_file.split('/')[-1] # Get just the file name without the path
        su_file = c_file + '.su' # Add the .su extension to the file name

        for root, dirs, files in os.walk(root_search):
            if su_file in files:

                exact_line = full_table[key][1] + ':' + str(full_table[key][2]) + ':' + str(full_table[key][3]) + ':' + full_table[key][0] # Format the line to search for in the .su file. Will be something like: path/to/file_name.c:line:column:function_name

                found_path = os.path.join(root, su_file)
                is_correct = confirm_su_file(found_path, exact_line, key, full_table) # Check if the function's stack usage is in the .su file

                if is_correct:
                    full_table[key].append(found_path) # If the function's stack usage is in the .su file, then append the path of the su file to the full_table
                    break

                else:
                    continue
            
            else:
                continue


# A possible .su file is passed in. This checks if the function's stack usage is in that file
def confirm_su_file(file_name, find_line, idx, full_table):
    with open(file_name, 'r') as file:
        
        for line in file:
            
            if find_line in line:
                split_line = line.split()
                full_table[idx].append(split_line[1])
                return True
            
        return False
        

# Adds up the memory usage of each function in the call tree
def calltree_usage(full_table, trees):
    tree_memory = {} # End result: {function name: [[function name, function address, memory usage], [function name, function address, memory usage], ...], function name: [[function name, function address, memory usage], [function name, function address, memory usage], ...], ...}
    
    for key in trees:
        
        memory_usage = 0 
        tree_memory[key] = [] # Add the key to the tree_memory dictionary
        
        for i in range(len(trees[key])-5, -1, -5): # Start at the end of the tree because that is where the leaf nodes start in the trees dictionary
            function_name = trees[key][i]
            function_address = trees[key][i+1]
            
            if function_address in full_table: 
                # print(f'Function: {function_name}, Memory Usage: {full_table[function_address][1]}, Total Before Adding: {memory_usage}')
                if len(full_table[function_address]) > 4: # If the function has a stack usage value, then add it to the memory_usage. Checks if greater than 4 because if the confirm su file function didn't find the stack usage, then the length of the full_table[function_address] will be 4
                    memory_usage += int(full_table[function_address][4]) # Add the stack usage to the memory_usage
                    tree_memory[key].append([function_name, function_address, memory_usage]) # Append the function name, address and memory usage to the tree_memory dictionary
                
                else: # If the function doesn't have a stack usage value, then add 0 to the memory_usage
                    memory_usage += 0
                    tree_memory[key].append([function_name, function_address, memory_usage])

    # For testing purposes   
    for i in tree_memory:
        print(f'{i}: {tree_memory[i]}')


'''
def calltree_depth():
    tree_memory = {}
    for key in trees:
        depth_memory = {}
        tree_memory[key] = []
        for i in range(0, len(trees[key]), +5):
            if len(full_table[trees[key][i+1]]) > 4:
                if trees[key][i+4] not in depth_memory:
                    depth_memory[trees[key][i+4]] = int(full_table[trees[key][i+1]][4])
                else:
                    depth_memory[trees[key][i+4]] += int(full_table[trees[key][i+1]][4])
        print(f'{key}: {depth_memory}')
'''


def main():
    info = getElf('build/zephyr/zephyr.elf') # Get the DWARF info
    table = callstruct(info) # Call the calltree function with the DWARF info
    # for j in full_table:
        # print(f'{j}: {full_table[j]}')
    # for a in subprograms:
        # print(f'{a}: {subprograms[a]}')
    childNames(info) # Convert the addresses of child function calls in each subprogram key to the actual function name
    # print(subprograms)
    full_tree = consolidate() # Make the call tree for each function and delete cases where a function is both a root and child node within the entire tree dictionary
    # print(trees)
    su_files(table) # Find and store the .su files' paths for each function
    # print(full_table)
    # for i in full_table:
        # print(f'{i}: {full_table[i]}')
    # for j in trees:
        # print(f'{j}: {trees[j]}')
    calltree_usage(table, full_tree) # Adds up the memory usage of each function in the call tree
    # calltree_depth()


main()