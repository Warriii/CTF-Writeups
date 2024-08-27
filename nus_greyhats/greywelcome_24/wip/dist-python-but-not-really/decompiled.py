# uncompyle6 version 3.9.1
# Python bytecode version base 3.8.0 (3413)
# Decompiled from: Python 3.10.12 (main, Jul 29 2024, 16:56:48) [GCC 11.4.0]
# Embedded file name: challenge.py
# z = input("flag? ")
# j = 0
# print("correct" if "".join([str(i - j) + "".join([str(x ^ y) for x, y in enumerate(map(ord, z))])[j] if i == sum([1 for i in "".join([str(x ^ y) for x, y in enumerate(map(ord, z))])]) else (str(i - j) + "".join([str(x ^ y) for x, y in enumerate(map(ord, z))])[j], (j := i))[0] if "".join([str(x ^ y) for x, y in enumerate(map(ord, z))])[i] != "".join([str(x ^ y) for x, y in enumerate(map(ord, z))])[j] else "" for i in range(sum([1 for i in "".join([str(x ^ y) for x, y in enumerate(map(ord, z))])]) + 1)]) == "11101321151110131122111217111028192112112211101211121621101813111221101211101229171821151110131715131621191122172112102116111217161721261521191615182721121417141714111211171817161716171521161911161917294128111019181916151710261110141911181618151810181918191617" else "wrong")
# global j ## Warning: Unused global

# okay decompiling challenge.pyc

# j = 0
# def f(z):
#     global j
#     j = 0
#     return "".join([str(i - j) + "".join([str(x ^ y) for x, y in enumerate(map(ord, z))])[j] if i == sum([1 for i in "".join([str(x ^ y) for x, y in enumerate(map(ord, z))])]) else (str(i - j) + "".join([str(x ^ y) for x, y in enumerate(map(ord, z))])[j], (j := i))[0] if "".join([str(x ^ y) for x, y in enumerate(map(ord, z))])[i] != "".join([str(x ^ y) for x, y in enumerate(map(ord, z))])[j] else "" for i in range(sum([1 for i in "".join([str(x ^ y) for x, y in enumerate(map(ord, z))])]) + 1)])


# fl = "grey{"
# target =  "11101321151110131122111217111028192112112211101211121621101813111221101211101229171821151110131715131621191122172112102116111217161721261521191615182721121417141714111211171817161716171521161911161917294128111019181916151710261110141911181618151810181918191617"

# for x in range(0, 256):
#     test = fl + chr(x)
#     if target.startswith("".join(f(test))):
#         print(test.encode())





# j = 0
# z = "grey"
# xor_with_index = "".join([str(x ^ y) for x, y in enumerate(map(ord, z))])
# print(xor_with_index) # this is basically string of numbers

# lst = ""
# for i in range(len(xor_with_index)):
#     if i == len(xor_with_index):
#         lst += str(i - j) + xor_with_index[j]
#     else:
#         if xor_with_index[i] != xor_with_index[j]:
#             print(i, j)
#             lst += str(i - j) + "," + xor_with_index[j] + " "
#             j = i
#         else:
#             lst += "B "
# print(lst)

xor_str = ""
target = "11101321151110131122111217111028192112112211101211121621101813111221101211101229171821151110131715131621191122172112102116111217161721261521191615182721121417141714111211171817161716171521161911161917294128111019181916151710261110141911181618151810181918191617"
for i in range(0, len(target), 2):
    block = target[i:i+2]
    diff_index, xor_with_index_j = block[0], block[1]
    xor_str += int(diff_index) * str(xor_with_index_j)

xor_list = []
num = ""
for i in xor_str:
    num += i
    if 0x20 < int(num) < 0x80:
        xor_list.append(int(num))
        num = ""

flag = "".join([chr(x ^ y) for x, y in enumerate(xor_list)])
print(flag)

