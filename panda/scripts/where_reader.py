#!/usr/bin/python2.7

import sys
import os
import zlib
import struct
from google.protobuf.json_format import MessageToJson
from os.path import dirname, join, realpath

panda_dir = dirname(dirname(dirname(realpath(sys.argv[0]))))

def try_path(*args):
    args = list(args) + ['i386-softmmu']
    build_dir = join(*args)
    if os.path.isdir(build_dir):
        sys.path.append(build_dir)
try_path(panda_dir, 'build')
try_path(panda_dir)
try_path(dirname(panda_dir), 'opt-panda')
try_path(dirname(panda_dir), 'debug-panda')
try_path(dirname(panda_dir), 'panda-build')
import plog_pb2

f = open(sys.argv[1])

version, _, dir_pos, _, chunk_size = struct.unpack('<IIQII', f.read(24))
#print version, dir_pos, chunk_size

f.seek(dir_pos)
num_chunks = struct.unpack('<I', f.read(4))[0]
#print num_chunks

if num_chunks == 0:
    sys.exit(0)

entries = []
for i in range(num_chunks):
    buf = f.read(24)
    entries.append(struct.unpack('<QQQ', buf))

if entries[-1][1] != dir_pos:
    entries.append((0, dir_pos, 0))

#print entries

import capstone

class WhereParser:
    def __init__(self):
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.print_tbs = False
        self.prev_msg = None

    def print_message(self, msg):
        where = msg.where
        print " -- PC = %x, ASID = %x, kernel = %s, instr = %d" % (msg.pc, where.asid, where.in_kernel, msg.instr),
        if where.HasField('filename'):
            print ", pos = %s:0x%x%s" % (where.filename, where.pos, "" if where.unique_digest else "*")
            disasm = self.disasm_msg(msg)
            for inst in disasm:
                print "0x%08x:\t%s\t%s" %(inst.address, inst.mnemonic, inst.op_str)
        else:
            print ""

    def disasm_msg(self, msg):
        where = msg.where
        with open(where.filename) as fin:
            fin.seek(where.pos)
            code = fin.read(where.tb_size)
            return self.md.disasm(code, where.pos)

    def test_event(self, msg):
        where = msg.where
        if self.prev_msg is None:
            return
        prev_msg = self.prev_msg
        prev_where = self.prev_msg.where

        # You can play with the conditions below to select the events interesting to you
        #if not where.HasField('filename'):
        #    return
        #if not where.filename.endswith('executable.exe'):
        #    return
        #if not prev_where.HasField('filename'):
        #    return
        #if where.filename == prev_where.filename:
        #    return

        # Find ring changes
        if prev_where.in_kernel == where.in_kernel:
            return
        # Select kernel entries
        #if prev_where.in_kernel and not where.in_kernel:
        #    return
        # Select kernel exits
        #if not prev_where.in_kernel and where.in_kernel:
        #    return

        #if prev_where.HasField('filename'):
        #    prev_disasm = list(self.disasm_msg(prev_msg))
        #    if prev_disasm[-1].mnemonic == "sysenter":
        #        return
        #    if prev_disasm[-1].mnemonic == "call" and prev_msg.where.in_kernel and where.in_kernel:
        #        return

        # If nothing impeded, then the event is interesting and we print it
        self.print_message(prev_msg)
        self.print_message(msg)
        print

    def parse_message(self, msg):
        #print msg.where
        #print dir(msg.where)
        if not msg.HasField('where'):
            return
        self.test_event(msg)
        #self.print_message(msg)
        self.prev_msg = msg

parser = WhereParser()
for entry, next_entry in zip(entries, entries[1:]):
    start_instr, start_pos, num_entries = entry
    next_pos = next_entry[1]
    f.seek(start_pos)
    zsize = next_pos - start_pos
    #print start_pos, next_pos, zsize,
    zdata = f.read(zsize)
    data = zlib.decompress(zdata, 15, chunk_size)
    #print len(data)
    i = 0
    while i < len(data):
        entry_size = struct.unpack('<I', data[i:i+4])[0]
        i += 4
        entry_data = data[i:i+entry_size]
        message = plog_pb2.LogEntry()
        message.ParseFromString(entry_data)
        parser.parse_message(message)
        i += entry_size
