Скрипт для распаковки elf. Которые упакованы UPX.
Когда upx при распаковке выдает такую ошибку "upx: pack2: NotPackedException: not packed by UPX".
Как пользоваться:
gdb [packed_program]
gdb sourse unpack.py
gdb upx-unpack

Что делает скрипт:

gdb pack2

catch syscall munmap

r

c

(gdb) info proc mappings 

process 4880
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
            0x400000           0x401000     0x1000        0x0 
            0x401000           0x540000   0x13f000        0x0 
            0x540000           0x591000    0x51000        0x0 
            0x591000           0x5a2000    0x11000        0x0 [heap]
      0x7ffff7f6a000     0x7ffff7f6b000     0x1000        0x0 /mnt/hgfs/kali/pack2
      0x7ffff7ffa000     0x7ffff7ffd000     0x3000        0x0 [vvar]
      0x7ffff7ffd000     0x7ffff7fff000     0x2000        0x0 [vdso]
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
(gdb) dump binary memory unpack_ras 0x400000 0x590000
(gdb) append binary memory unpack_ras 0x591000 0x5a2000

