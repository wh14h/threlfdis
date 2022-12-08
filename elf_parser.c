#include<elf.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>

#include<sys/syscall.h>
#include<sys/types.h>

#include<pthread.h>

#include "capstone/include/capstone/capstone.h"

// EI_NIDENT == 16

struct padded_elf32 {
	Elf32_Ehdr e;
	char pad[sizeof(Elf64_Ehdr) - sizeof(Elf32_Ehdr)];
};

// Union between a padded ELF32 header and ELF64 header
union uelf{
	struct padded_elf32 e32;
	Elf64_Ehdr e64;
};

struct disassembler_thread_args {
	Elf64_Sym* function_symbols;
	int num_functions;
	int* current_job;
	pthread_mutex_t* index_lock;
	Elf64_Shdr* text_section_header;
	char* text_section;
	pthread_mutex_t* stdout_lock;
	int* insn_disassembled;
};

void get_symbol_table_section_header(char* buf, int num_sections, int strtab_index, Elf64_Shdr** sym_table_header, Elf64_Shdr** string_table_header);

void get_text_section_header(char* sections_buf, char* string_table, int num_sections, Elf64_Shdr** text_section_header);

Elf64_Sym* get_function_symbols(char* symbol_table, int num_symbols, int* num_functions);

char** parse_string_table(char* buf, int buf_size, int* num_found);
int search_string_table(char** str_table, int table_size, char* item, int size);

void grab_and_disassemble_loop(Elf64_Sym* syms, int num_funcs, int* index, pthread_mutex_t* index_lock, Elf64_Shdr* text_section_header, char* text_buf, pthread_mutex_t* stdout_lock, int* insn_disassembled);
void* grab_and_disassemble_thread_loop(void* args);

int main(int argc, char* argv[]) {
	int err;
	if (argc < 2) {
		fprintf(stderr, "Error: Must specify executable to study\n");
		exit(1);
	}
	FILE* fp = fopen(argv[1], "r");
	if (fp == NULL) {
		fprintf(stderr, "Error: File not found\n");
		exit(1);
	}

	union uelf elf_header;

	fread(&elf_header, 1, sizeof(Elf64_Ehdr), fp);
	if (elf_header.e64.e_ident[EI_MAG0] == 0x7f &&
		elf_header.e64.e_ident[EI_MAG1] == 'E' &&
		elf_header.e64.e_ident[EI_MAG2] == 'L' &&
		elf_header.e64.e_ident[EI_MAG3] == 'F')
	{
		printf("ELF Header detected\n");
	}
	else {
		fprintf(stderr, "ELF File header not detected\n");
		goto close_fail;
	}

	if (elf_header.e64.e_ident[EI_CLASS] == ELFCLASS64) {
		printf("64-bit ELF detected\n");
	} else if (elf_header.e64.e_ident[EI_CLASS] == ELFCLASS32) {
		fprintf(stderr, "32-bit ELF detected. This is not supported\n");
		goto close_fail;
	} else {
		fprintf(stderr, "Non 32-bit or 64-bit ELFs not supported\n");
		goto close_fail;
	}

	printf("ELF EI_DATA value %d\n", elf_header.e64.e_ident[EI_DATA]);
	printf("ELF EI_VERSION value %u == %d (EV_CURRENT)\n", elf_header.e64.e_ident[EI_VERSION], EV_CURRENT);
	printf("ELF EI_OSABI == %u\n", elf_header.e64.e_ident[EI_OSABI]);
	printf("ELF EI_ABIVERSION == %u\n", elf_header.e64.e_ident[EI_ABIVERSION]);

	printf("ELF e_type == %u\n", elf_header.e64.e_type);
	printf("ELF e_machine == %u\n", elf_header.e64.e_machine);
	if (elf_header.e64.e_version != 1) {
		fprintf(stderr, "Error: e_version is not 1\n");
		goto close_fail;
	}
	printf("ELF e_entry == %lu\n", elf_header.e64.e_entry); //entry
	printf("ELF e_phoff == %lu\n", elf_header.e64.e_phoff); // program header table
	printf("ELF e_shoff == %lu\n", elf_header.e64.e_shoff); // section header table
	printf("ELF e_flags == %u\n", elf_header.e64.e_flags);
	printf("ELF e_ehsize == %u\n", elf_header.e64.e_ehsize); // Elf header size
	printf("ELF e_phentsize == %u\n", elf_header.e64.e_phentsize); // size of one program header entry
	printf("ELF e_phnum == %u\n", elf_header.e64.e_phnum); // Number of program header entries
	printf("ELF e_shentsize == %u\n", elf_header.e64.e_shentsize); // Size of 1 section header entry
	printf("ELF e_shnum == %u\n", elf_header.e64.e_shnum); // Number of section header entries
	printf("ELF e_shstrndx == %u\n", elf_header.e64.e_shstrndx); // Section header for string table

	int entry_offset = elf_header.e64.e_entry;

	int sections_offset = elf_header.e64.e_shoff;
	int sections_size = elf_header.e64.e_shentsize;
	int num_sections = elf_header.e64.e_shnum;
	fseek(fp, sections_offset, 0);
	char* section_buffer = malloc(sections_size * num_sections);
	if (section_buffer == NULL) {
		fprintf(stderr, "Error in malloc\n");
		goto close_fail;
	}
	fread(section_buffer, 1, sections_size * num_sections, fp);

	int strtab_index = elf_header.e64.e_shstrndx;
	Elf64_Shdr* string_table_header = NULL;
	Elf64_Shdr* symtab_header = NULL;
	get_symbol_table_section_header(section_buffer, num_sections, strtab_index, &symtab_header, &string_table_header);
	if (symtab_header == NULL) goto close_fail;
	if (string_table_header == NULL) goto close_fail;

	int symbol_table_offset = symtab_header->sh_offset;
	int symbol_table_size = symtab_header->sh_size;
	int symbol_table_entry_size = symtab_header->sh_entsize;
	int num_symbols = symbol_table_size / symbol_table_entry_size;
	printf("Symbol table offset %x, size %x, entry size %x\n", symbol_table_offset, symbol_table_size, symbol_table_entry_size);

	int string_table_offset = string_table_header->sh_offset;
	int string_table_size = string_table_header->sh_size;
	printf("String table offset %x, size %x\n", string_table_offset, string_table_size);

	char* symbol_table = malloc(symbol_table_size);
	if (symbol_table == NULL) {
		fprintf(stderr, "Error in malloc\n");
		goto fail1;
	}
	fseek(fp, symbol_table_offset, 0);
	fread(symbol_table, 1, symbol_table_size, fp);

	char* string_table = malloc(string_table_size);
	if (string_table == NULL) {
		fprintf(stderr, "Error in malloc\n");
		goto fail2;
	}
	fseek(fp, string_table_offset, 0);
	fread(string_table, 1, string_table_size, fp);
	// int num_found_strings;
	// char** found_strings = parse_string_table(string_table, string_table_size, &num_found_strings);
	// printf("%d strings found\n", num_found_strings);

	// char* text_str = ".text";
	// int text_ind = search_string_table(found_strings, num_found_strings, text_str, strlen(text_str));
	// printf(".text string found in index %d of section header string table\n", text_ind);

	Elf64_Shdr* text_section_header = NULL;
	get_text_section_header(section_buffer, string_table, num_sections, &text_section_header);
	if (text_section_header == NULL) goto fail3;
	int text_section_offset = text_section_header->sh_offset;
	int text_section_size = text_section_header->sh_size;
	printf(".text starts at 0x%x size 0x%x\n", text_section_offset, text_section_size);

	char* text_section = malloc(text_section_size);
	if (text_section == NULL) {
		fprintf(stderr, "Error in malloc\n");
		goto fail3;
	}
	fseek(fp, text_section_offset, 0);
	fread(text_section, 1, text_section_size, fp);

	int num_functions = 0;
	Elf64_Sym* function_syms = get_function_symbols(symbol_table, num_symbols, &num_functions);
	int insn_disassembled = 0;

	int index=0;
	pthread_mutex_t index_lock, stdout_lock;
	err = pthread_mutex_init(&index_lock, NULL);
	if (err != 0) {
		fprintf(stderr, "Error in pthread_mutex_init (%d)\n", err);
		goto fail4;
	}
	err = pthread_mutex_init(&stdout_lock, NULL);
	if (err != 0) {
		fprintf(stderr, "Error in pthread_mutex_init (%d)\n", err);
		goto fail5;
	}

	if (num_functions > 0) {
		int num_threads = 0;
		char* env_var;
		if ((env_var = getenv("PTH_NUM_THREADS"))!=NULL) {
			num_threads = atoi(env_var);
			printf("PTH_NUM_THREADS says %d threads\n", num_threads);
		} else printf("PTH_NUM_THREADS not found. No threads will be created\n");

		struct disassembler_thread_args thread_args;
		thread_args.function_symbols = function_syms;
		thread_args.num_functions = num_functions;
		thread_args.current_job = &index;
		thread_args.index_lock = &index_lock;
		thread_args.text_section_header = text_section_header;
		thread_args.text_section = text_section;
		thread_args.stdout_lock = &stdout_lock;
		thread_args.insn_disassembled = &insn_disassembled;

		pthread_t* threads = malloc(sizeof(pthread_t) * num_threads);
		if (threads == NULL) {
			fprintf(stderr, "Error in malloc\n");
			goto fail6;
		}
		for(int i=0; i<num_threads; i++) {
			err = pthread_create(&threads[i], NULL, grab_and_disassemble_thread_loop, (void*)&thread_args);
			if (err != 0) {
				fprintf(stderr, "Error in pthread_create (%d)\n", err);
				exit(1);
			}
		}
		grab_and_disassemble_loop(function_syms, num_functions, &index, &index_lock, text_section_header, text_section, &stdout_lock, &insn_disassembled);
		for(int i=0; i<num_threads; i++) {
			err = pthread_join(threads[i], NULL);
			if (err != 0) {
				fprintf(stderr, "Error in pthread_join. Ignoring.\n");
			}
		}
		printf("DISASSEMBLED %d bytes\n", insn_disassembled);
	}
	else {
		fprintf(stderr, "There are no functions to disassemble.\n");
	}
	pthread_mutex_destroy(&index_lock);
	pthread_mutex_destroy(&stdout_lock);
	free(text_section);
	free(string_table);
	free(symbol_table);
	free(section_buffer);
	fclose(fp);
	return 0;
fail6:
	pthread_mutex_destroy(&index_lock);
fail5:
	pthread_mutex_destroy(&stdout_lock);
fail4:
	free(text_section);
fail3:
	free(string_table);
fail2:
	free(symbol_table);
fail1:
	free(section_buffer);
close_fail:
	fclose(fp);
	exit(1);
}

// pthread threads run this to parse args properly
void* grab_and_disassemble_thread_loop(void* args) {
	grab_and_disassemble_loop(
		((struct disassembler_thread_args*)args)->function_symbols,
		((struct disassembler_thread_args*)args)->num_functions,
		((struct disassembler_thread_args*)args)->current_job,
		((struct disassembler_thread_args*)args)->index_lock,
		((struct disassembler_thread_args*)args)->text_section_header,
		((struct disassembler_thread_args*)args)->text_section,
		((struct disassembler_thread_args*)args)->stdout_lock,
		((struct disassembler_thread_args*)args)->insn_disassembled
	);
}

// Loop for threads to disassemble functions.
// - syms is an array of function symbols from the symbol table.
// - num_funcs is the number of function symbols found.
// - index is shared and each thread grabs it and increments to pick up work.
// - index_lock is a lock for the index shared variable.
// - text_section_header is the .text section header
// - text_buf is a buffer for all of the .text section
// - stdout_lock is a lock for stdout to make sure printed results stay together.
// - insn_disassembled is a counter of how many instructions were disassembled.
void grab_and_disassemble_loop(Elf64_Sym* syms, int num_funcs, int* index,
	pthread_mutex_t* index_lock, Elf64_Shdr* text_section_header,
	char* text_buf, pthread_mutex_t* stdout_lock, int* insn_disassembled) {
	int my_index, count, code_sec_offset, func_file_offset, func_text_offset, size;
	char* function_code;
	uint32_t thread_id = syscall(__NR_gettid);
	int err;

	csh handle_local;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle_local) != CS_ERR_OK) {
		fprintf(stderr, "Capstone cs_open failed on thread %d\n", thread_id);
		return;
	}

	while(1) {
		err = pthread_mutex_lock(index_lock);
		if (err != 0) {
			fprintf(stderr, "Error in pthread_mutex_lock\n");
			exit(1);
		}
		if (*index < num_funcs) {
			my_index = *index;
			*index = (*index) + 1;
			// printf("%d starting %d\n", thread_id, my_index);
			err = pthread_mutex_unlock(index_lock);
			if (err != 0) {
				fprintf(stderr, "Error in pthread_mutex_unlock\n");
				exit(1);
			}
			count = syms[my_index].st_size;
			code_sec_offset = text_section_header->sh_offset;
			func_file_offset = syms[my_index].st_value;
			func_text_offset = syms[my_index].st_value - code_sec_offset;
			size = syms[my_index].st_size;
			cs_insn* insn;
			function_code = &text_buf[func_text_offset];
			count = cs_disasm(handle_local, function_code, size, func_file_offset, 0, &insn);
			if (count > 0) {
				// Print out results of disassembly
				err = pthread_mutex_lock(stdout_lock);
				if (err != 0) {
					fprintf(stderr, "Error in pthread_mutex_lock\n");
					exit(1);
				}
				*insn_disassembled += size; // Shared but locked with stdout_lock
				printf("BEGIN %d Disassembly of function at 0x%x by %d:\n", my_index, func_file_offset, thread_id);
				for (int j = 0; j < count; j++) {
					printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
				}
				printf("END %d disassembly of function at 0x%x\n", my_index, func_file_offset);
				err = fflush(stdout);
				if (err != 0) {
					fprintf(stderr, "Error in fflush\n");
					exit(1);
				}

				err = pthread_mutex_unlock(stdout_lock);
				if (err != 0) {
					fprintf(stderr, "Error in pthread_mutex_unlock\n");
					exit(1);
				}
			} else {
				printf("Disassembly by thread %d at 0x%x failed\n", thread_id, func_file_offset);
			}
		}
		else {
			err = pthread_mutex_unlock(index_lock);
			if (err != 0) {
				fprintf(stderr, "Error in pthread_mutex_unlock\n");
				exit(1);
			}
			// printf("%d done. index %d\n", thread_id, *index);
			return;
		}
	}
}

void get_text_section_header(char* sections_buf, char* string_table, int num_sections, Elf64_Shdr** text_section_header) {
	Elf64_Shdr* sh;
	sh = (Elf64_Shdr*)sections_buf;
	for (int i=0; i<num_sections; i++) {
		char* section_name = &string_table[sh->sh_name];
		if (strlen(section_name) == sizeof(".text")-1 && strncmp(section_name, ".text", 5) == 0) {
			printf("Found section header for .text\n");
			*text_section_header = sh;
			return;
		}
		sh = sh+1;
	}
	fprintf(stderr, "Failed to find .text section\n");
}

void get_symbol_table_section_header(char* sections_buf, int num_sections, int strtab_index, Elf64_Shdr** sym_table_header, Elf64_Shdr** string_table_header) {
	int headers_found=0;
	Elf64_Shdr* sh;
	sh = (Elf64_Shdr*)sections_buf;

	for (int i=0; i<num_sections; i++) {
		// printf("%d: Section %d %d %ld %ld\n", i, sh->sh_name, sh->sh_type, sh->sh_addr, sh->sh_size);
		if (sh->sh_type == SHT_SYMTAB) {
			headers_found++;
			*sym_table_header = sh;
			printf("Found symbol table\n");
		}
		else if (i == strtab_index) {
			headers_found++;
			*string_table_header = sh;
			printf("Found string table\n");
		}
		if (headers_found == 2) {
			return;
		}
		sh = sh + 1;
	}
	fprintf(stderr, "Failed to find ELF symbol table\n");
}

char** parse_string_table(char* buf, int buf_size, int* num_found) {
	int array_size = 4;
	char** strings_found = malloc(sizeof(char*) * array_size);
	if (strings_found == NULL) {
		fprintf(stderr, "Error in malloc\n");
		exit(1);
	}
	strings_found[0] = buf;
	*num_found = 1;
	char* charp = strchr(buf+1, 0); // Next null char location
	for(int i=1; strings_found[i-1] != charp-1 && charp-buf < buf_size; i++) {
		*num_found += 1;
		if(*num_found > array_size) {
			array_size *= 2;
			strings_found = realloc(strings_found, sizeof(char*) * array_size);
			if (strings_found == NULL) {
				fprintf(stderr, "Error in realloc\n");
				exit(1);
			}
		}
		strings_found[i] = charp+1;
		charp = strchr(charp+1, 0);
	}
	return strings_found;
}

// Search a string table. Linear search.
// param: size - strlen (no null) of item to search for
int search_string_table(char** str_table, int table_size, char* item, int size) {
	char* null_ind;
	for (int i=1; i<table_size; i++) {
		null_ind = strchr(str_table[i], 0);
		if ((size_t)null_ind - (size_t)str_table[i] == size) {
			if (strncmp(str_table[i], item, size)==0) {
				return i;
			}
		}
	}
}

Elf64_Sym* get_function_symbols(char* symbol_table, int num_symbols, int* num_functions) {
	int array_size = 4;
	Elf64_Sym* function_symbols = malloc(sizeof(Elf64_Sym) * array_size);
	if (function_symbols == NULL) {
		fprintf(stderr, "Error in malloc\n");
		exit(1);
	}
	Elf64_Sym* cur_sym = (Elf64_Sym*)symbol_table;
	for (int i=0; i<num_symbols; i++) {
		if (ELF64_ST_TYPE(cur_sym->st_info) == STT_FUNC && cur_sym->st_size > 0) {
			// printf("Function %d 0x%lx %ld\n", cur_sym->st_name, cur_sym->st_value, cur_sym->st_size);
			*num_functions = (*num_functions) + 1;
			if (*num_functions > array_size) {
				array_size = array_size * 2;
				function_symbols = realloc(function_symbols, sizeof(Elf64_Sym) * array_size);
				if (function_symbols == NULL) {
					fprintf(stderr, "Error in realloc\n");
					exit(1);
				}
			}
			memcpy(&(function_symbols[(*num_functions) -1]), cur_sym, sizeof(Elf64_Sym));
		}
		cur_sym += 1;
	}
	return function_symbols;
}
