#!/usr/bin/python
import gdb
import os
def parse_memory_mappings(l):
    dump_it = []
    for i in range(4,len(l)):
        dump_it.append(l[i])
        if ('heap' in l[i]):
            break
    clean_it = []
    for i in dump_it:
        a = list(filter(None,i.split(" ")))
        clean_it.append(a)
    addr = [ ( int(clean_it[0][0],16),int(clean_it[-2][1],16)-0x1000 ), ( int(clean_it[-1][0],16), int(clean_it[-1][1],16)) ]
    return addr
def execute_output(command):
    filename = os.getenv('HOME') + os.sep + 'gdb_output_' + str(os.getpid())
    gdb.execute('set logging file '+ filename)
    gdb.execute('set logging overwrite on')
    gdb.execute('set logging redirect on')
    gdb.execute('set logging on')

    try:
        gdb.execute(command)
    except:
        pass
    gdb.execute('set logging off')
    gdb.execute('set logging redirect off')
    output = ''
    with open(filename) as f:
        output = f.read()
    os.remove(filename)
    output = output.splitlines()
    return output
class UnpackUPX(gdb.Command):

  def __init__ (self):
    super (UnpackUPX, self).__init__ ("upx-unpack", gdb.COMMAND_USER)

  def invoke (self, arg, from_tty):
    gdb.execute('catch syscall munmap')
    gdb.execute('r')
    gdb.execute('c')
    mem = execute_output('info proc mappings')
    addr = parse_memory_mappings(mem)
    gdb.execute("dump binary memory upack_upx 0x{:x} 0x{:x}".format(addr[0][0],addr[0][1]))
    gdb.execute("append binary memory upack_upx 0x{:x} 0x{:x}".format(addr[1][0],addr[1][1]))
    print("Unpacking program have name upack_upx")
UnpackUPX()

