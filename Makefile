name := server
LDFLAGS = -lssl -lcrypto

all: compile run clean
.PHONY: compile run clean

compile: $(name).cpp
	g++ $(name).cpp -o $(name).out $(LDFLAGS)

run: $(name).out
	./$(name).out

clean: $(name).out
	rm $(name).out