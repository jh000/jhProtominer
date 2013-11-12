
obj=jhlib.o main.o protosharesMiner.o sha2.o transaction.o xptClient.o xptClientPacketHandler.o xptPacketbuffer.o xptServer.o xptServerPacketHandler.o win.o

app=jhProtominer

all: $(app)

.o.c:
	$(CXX) $(CFLAGS) -o $< $@

jhProtominer: $(obj)
	$(CXX) $(LDFLAGS) -o $@ $(obj) -lpthread

clean:
	$(RM) *.o $(app)

.PHONY: all clean
