Writeup for Recho
=================

TODO. 

notes
-----

- close input filedescriptor to break the while loop and trigger the ROP chain
- syscall from read in libc. inspect implementation of read to find offset

- open, read, write since we cannot input anything after the input fd has been closed


