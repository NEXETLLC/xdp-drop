#clang -O2 -target bpf -c xdp_prog.c -o  xdp_prog.o

default: xdp_prog

xdp_prog:
	clang -O2 -g -target bpf -c xdp_prog.c -o  xdp_prog.o