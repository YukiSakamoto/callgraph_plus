CC = clang
CXX = clang++

SPECIAL_FLAG = -sectcreate __TEXT __info_plist ./Info.plist

tracer: memory_op.o functable.o tracer.cpp tracer.h
	$(CXX) $(SPECIAL_FLAG) -o tracer tracer.cpp memory_op.o functable.o -ludis86

functable.o: functable.cpp functable.h
	$(CXX) -c -o functable.o functable.cpp 

memory_op.o: memory_op.c memory_op.h
	$(CC) -c -o memory_op.o memory_op.c  

clean:
	rm *.o ./tracer

run: tracer
	./tracer ./testcode/a.out

