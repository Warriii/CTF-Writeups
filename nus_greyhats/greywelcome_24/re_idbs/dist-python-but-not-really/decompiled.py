# uncompyle6 version 3.9.0
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.8.10 (default, Mar 13 2023, 10:26:41) 
# [GCC 9.4.0]
# Embedded file name: challenge.py
z = input('flag? ')
j = 0
print('correct' if ''.join([str(i - j) + ''.join([str(x ^ y) for x, y in enumerate(map(ord, z))])[j] if i == sum([1 for i in ''.join([str(x ^ y) for x, y in enumerate(map(ord, z))])]) else (str(i - j) + ''.join([str(x ^ y) for x, y in enumerate(map(ord, z))])[j], (j := i))[0] if ''.join([str(x ^ y) for x, y in enumerate(map(ord, z))])[i] != ''.join([str(x ^ y) for x, y in enumerate(map(ord, z))])[j] else '' for i in range(sum([1 for i in ''.join([str(x ^ y) for x, y in enumerate(map(ord, z))])]) + 1)]) == '11101321151110131122111217111028192112112211101211121621101813111221101211101229171821151110131715131621191122172112102116111217161721261521191615182721121417141714111211171817161716171521161911161917294128111019181916151710261110141911181618151810181918191617' else 'wrong')
# global j ## Warning: Unused global
# okay decompiling challenge.pyc
