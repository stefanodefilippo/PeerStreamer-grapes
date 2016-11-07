ifndef BASE
BASE = ../..
else
vpath %.c $(BASE)/src/$(notdir $(CURDIR))
endif
CFGDIR ?= ..

OBJS = topman.o tman.o dumbTopman.o

all: libtopman.a

include $(BASE)/src/utils.mak
