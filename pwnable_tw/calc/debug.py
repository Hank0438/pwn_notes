import gdb

gdb.execute("b* 0x0804945b")
gdb.execute("b* 0x08049494")
gdb.execute("run")
gdb.execute("set $eip=0x0804947b")
gdb.execute("c")
