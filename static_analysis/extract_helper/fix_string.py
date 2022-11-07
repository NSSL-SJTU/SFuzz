import idautils
import idc
import idaapi

symfile_path = './15CBBA'    		# change this 
symbols_table_start = 8
strings_table_start = 8+8*0x34e4	# change this 

with open(symfile_path, 'rb') as f:
	symfile_contents = f.read()

symbols_table = symfile_contents[symbols_table_start:strings_table_start]
strings_table = symfile_contents[strings_table_start:]

def get_string_by_offset(offset):
    index = 0
    while True:
        if strings_table[offset+index] != 0x00:
            index += 1
        else:
            break
    return strings_table[offset:offset+index]


def get_symbols_metadata():
	symbols = []
	for offset in range(0, len(symbols_table),8):
		symbol_item = symbols_table[offset:offset+8]
		flag = symbol_item[0]   
		string_offset = int.from_bytes(symbol_item[1:4],'big')
		string_name = get_string_by_offset(string_offset)
		target_address = int.from_bytes(symbol_item[-4:],'big')
		symbols.append((flag, string_name, target_address))
	return symbols


def add_symbols(symbols_meta_data):
	for flag, string_name, target_address in symbols_meta_data:
		idc.set_name(target_address, string_name.decode())
		if flag == 0x54:
			idc.create_insn(target_address)
			ida_funcs.add_func(target_address)


if __name__ == "__main__":
	symbols_metadata = get_symbols_metadata()
	add_symbols(symbols_metadata)
