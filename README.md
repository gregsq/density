# density
Density homework

To build:

gcc v8 or greater required
clang v10 or later required

Create a directory called build, change to the directory and cmake ..
To use clang preface with CXX=clang++ CC=clang cmake ..

Line feeds can be \n or \r\n.

Commands are of the form:
INCR [integer]\r\n
DECR [integer]\r\n
OUTPUT\r\n

Examples:
Increment the counter by 24 and notify all
INCR 24\r\n

Decrement the counter by 24 and notify all
DECR 24\r\n

Output the counter to the endpoint
OUTPUT\r\n
