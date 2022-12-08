CC ?= gcc

capstone_include = ./capstone/include/capstone/
libflags = -I$(capstone_include) -Lcapstone -lcapstone -lpthread

capstone_lib = ./capstone/libcapstone.so.5

sources = elf_parser.c
output = elf_parser.out

.PHONY all: $(output)

$(output): $(sources) $(capstone_lib)
	$(CC) $(sources) -g $(libflags) -o $(output)

$(capstone_lib):
	$(info libcapstone.so.5 may or may not need to be built in capstone/)
	$(info Perform the following steps to build:)
	$(info cd capstone)
	$(info ./make.sh)
	$(info  )

.PHONY clean:
clean:
	rm -f $(output)

