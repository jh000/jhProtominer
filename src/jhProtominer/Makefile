
obj=jhlib.o main.o protosharesMiner.o sha2.o transaction.o xptClient.o xptClientPacketHandler.o xptPacketbuffer.o xptServer.o xptServerPacketHandler.o

.o.c:
	@$(CC) $(CFLAGS) -o $< $@

jhProtominer: $(obj)
	@echo $(LD) $(LDFLAGS) -o $@ $(obj)

all: jhProtominer

clean:
	@-$(RM) *.o jhProtominer

.PHONY: all clean
