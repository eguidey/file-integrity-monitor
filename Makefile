CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Werror -O2
LDLIBS  = -lcrypto
TARGET  = fim

$(TARGET): src/fim.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

# Build with AddressSanitizer + UBSan for development
debug: src/fim.c
	$(CC) -std=c11 -Wall -Wextra -g -O0 -fsanitize=address,undefined -o $(TARGET)-debug $< $(LDLIBS)

test: $(TARGET)
	./tests/run_tests.sh ./$(TARGET)

memcheck: $(TARGET)
	valgrind --leak-check=full --error-exitcode=9 -q ./$(TARGET) baseline src /tmp/fim_mc.txt
	valgrind --leak-check=full --error-exitcode=9 -q ./$(TARGET) check src /tmp/fim_mc.txt

clean:
	rm -f $(TARGET) $(TARGET)-debug

.PHONY: debug test memcheck clean
