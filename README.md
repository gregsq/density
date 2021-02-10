# density
Density homework

To build:

Create a directory called build, change to the directory and cmake ..
To use clang preface with CXX=clang++ CC=clang cmake ..

Line feeds are \n, not \r\n for testing with telnet.

Commands are of the form:
CMD [integer]\r\n

Increment the counter by 24 and notify all
INCR 24\r\n

Decrement the counter by 24 and notify all
DECR 24\r\n

Output the counter to the endpoint
OUTPUT\r\n