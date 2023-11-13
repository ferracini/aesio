SRCDIR = src
ODIR = build
BINDIR = bin

_DEPS = sha1.h sha256.h aes.h aesiofver.h aesom.h helper.h aesio.h
DEPS = $(patsubst %,$(SRCDIR)/%,$(_DEPS))

_OBJ = sha1.o sha256.o aes.o aesom.o aesio.o tests.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

# Specify compiler
CC=gcc
CFLAGS=-pedantic -Wall -O2 -mpclmul -msse2

# Link the object files into a binary
$(ODIR)/%.o: $(SRCDIR)/%.c $(DEPS)
  @mkdir -p $(BINDIR)
  @mkdir -p $(ODIR)
  $(CC) -c -o $@ $< $(CFLAGS)

# Compile the source files into object files
$(BINDIR)/aesio: $(OBJ)
  $(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean

clean:
  rm -f $(ODIR)/*.o

cleanall:
  rm -f $(BINDIR)/aesio
  rm -f $(ODIR)/*.o