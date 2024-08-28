z = input('flag? ')
j = 0

xor_by_index = ''.join([str(x ^ y) for x, y in enumerate(map(ord, z))])
z_len = sum([1 for i in xor_by_index])
target = '11101321151110131122111217111028192112112211101211121621101813111221101211101229171821151110131715131621191122172112102116111217161721261521191615182721121417141714111211171817161716171521161911161917294128111019181916151710261110141911181618151810181918191617'
ss = ''
for i in range(z_len + 1):
    if i == z_len:
        ss += str(i - j) + xor_by_index[j]
    elif xor_by_index[i] != xor_by_index[j]:
        ss += str(i - j) + xor_by_index[j]
        j = i
    else:
        ss += ''
if ss == target:
    print('correct')
else:
    print('wrong')