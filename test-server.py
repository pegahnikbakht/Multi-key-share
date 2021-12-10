#!/usr/bin/env python

import collections
import random
import binascii
import sys
import hmac
import hashlib
from Crypto.Cipher import AES
import Padding


from progress.bar import ChargingBar
from PyInquirer import prompt
import keyboard
import time
import struct
import socket
import os
import sys
from math import ceil

Devices = {}
RetransmitDevices = {}
DeviceNames = []
Listening = True
Socket = None

MYPORT = 20001
MYGROUP_4 = '232.10.11.12'
MYTTL = 1 # Increase to reach other networks

keyboard.on_press_key("u", lambda _:Update())
keyboard.on_press_key("r", lambda _:Retransmit())


def Update():
    global Listening, Socket
    Listening = False
    try:
        Socket.shutdown(socket.SHUT_RDWR)
        Socket.close()
    except:
        pass

def Retransmit():
    global Listening, Socket
    Listening = False
    try:
        Socket.shutdown(socket.SHUT_RDWR)
        Socket.close()
    except:
        pass
  
def ChoiceDevices():
    global DeviceNames

    if len(DeviceNames) > 0:
    	widget = [
    	{
    	    'type':'checkbox',
    	    'name':'devices',
    	    'message':'Please select the devices whose operating system you want to update.',
    	    'choices': DeviceNames
    	}
    	]
    	result = prompt(widget)
    	UpdateAdvertisement(result["devices"])
    else:
    	print("There is no joined devices")
    	sys.exit()

def UpdateAdvertisement(DeviceList):
    print("Start sending key update command to the selected devices...")
    addrinfo = socket.getaddrinfo(MYGROUP_4, None)[0]
    s = socket.socket(addrinfo[0], socket.SOCK_DGRAM)
    ttl_bin = struct.pack('@i', MYTTL)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)
        
    for Device in DeviceList:
        s.sendto(b'NewKey', Devices[Device])
    
    print("Start key updating...")
    
    UpdateRoutine()

def UpdateRoutine():
    
    addrinfo = socket.getaddrinfo(MYGROUP_4, None)[0]
   
    Socket = socket.socket(addrinfo[0], socket.SOCK_DGRAM)

    # Set Time-to-live (optional)
    ttl_bin = struct.pack('@i', MYTTL)
    Socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)

    
    while datafile:
        Socket.sendto(datafile, (addrinfo[4][0], MYPORT))
        time.sleep(0.08)
        #time.sleep(0.08)
    print("\nKey update Done!")


def NodeJoin(DeviceName, DeviceInfo):
    global Devices, DeviceNames
    Devices[DeviceName] = DeviceInfo
    DeviceNames.append({'name':DeviceName})
    print (" %s)\t%s\t\t%s"  % (len(Devices),DeviceName, DeviceInfo)) 
    return 

def RetransmitNodeJoin(DeviceName, DeviceInfo,RetransmitIndex):
    global RetransmitDevices
    RetransmitDevices[DeviceName] = (DeviceInfo,RetransmitIndex)
    print (" %s)\t%s\t\t%s\t%s"  % (len(Devices),DeviceName,RetransmitIndex, DeviceInfo)) 
    return 

def Server():
    global Devices, Listening, Socket
    # Look up multicast group address in name server and find out IP version
    addrinfo = socket.getaddrinfo(MYGROUP_4, None)[0]

    # Create a socket
    Socket = socket.socket(addrinfo[0], socket.SOCK_DGRAM)

    # Allow multiple copies of this program on one machine
    # (not strictly needed)
    Socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind it to the port
    Socket.bind(('', MYPORT))

    group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
    # Join group
    mreq = group_bin + struct.pack('=I', socket.INADDR_ANY)
    Socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    # Loop, printing any data we receive
    DeviceNamesPrefix = "ESP32_"
    UplinkIndicator = "alive"

    print( "Server has started listening...")
    print( "Press u for updating key of appeared devices.")
    print( "Device list(updating...):" )
    print (" Number\tName\t\tInfo")
    while Listening:
        try:
            data, DeviceInfo = Socket.recvfrom(100)
            DeviceName = data.decode('ascii').split( ":")[0]
            DeviceData = data.decode('ascii').split( ":")[1].strip()
            while data[-1:] == '\0': data = data[:-1] # Strip trailing \0's
            if DeviceData == UplinkIndicator and DeviceNamesPrefix in DeviceName and DeviceName not in Devices:
                NodeJoin(DeviceName, DeviceInfo)
        except:
            pass


def RetransmitFirmware(rDevices):
    global RetransmitDevices
    
    addrinfo = socket.getaddrinfo(MYGROUP_4, None)[0]
   
    Socket = socket.socket(addrinfo[0], socket.SOCK_DGRAM)

    # Set Time-to-live (optional)
    ttl_bin = struct.pack('@i', MYTTL)
    Socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)

    
    while datafile:
        
        datafile = read

    for _device in rDevices:
    	Progress = ChargingBar('Retransmiting to ' + _device , max=ChunkCount - int(RetransmitDevices[_device][1]), suffix = '%(index)d/%(max)d [%(percent)d%%]')

    	for index in range( int(RetransmitDevices[_device][1]), ChunkCount):
                Socket.sendto(ChunkedSecureFirmware[index], RetransmitDevices[_device][0])
                time.sleep(0.08)
    print("\nRetransmiting Done!")


def ChoiceRetransmitDevices():
    global RetransmitDevices
    if len(RetransmitDevices) > 0:
    	_devices = [ {'name': name} for name in list(RetransmitDevices.keys())]
    	widget = [
    	{
    	    'type':'checkbox',
    	    'name':'devices',
    	    'message':'Please select the devices whose operating system you want to update agan.',
    	    'choices': _devices
    	}
    	]
    	result = prompt(widget)
    	RetransmitFirmware(result["devices"])
    else:
    	print("There is no joined devices")
    	sys.exit()

def Verify():
    global Devices, Listening, Socket
    global RetransmitDevices
    Listening = True
    # Look up multicast group address in name server and find out IP version
    addrinfo = socket.getaddrinfo(MYGROUP_4, None)[0]

    # Create a socket
    Socket = socket.socket(addrinfo[0], socket.SOCK_DGRAM)

    # Allow multiple copies of this program on one machine
    # (not strictly needed)
    Socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind it to the port
    Socket.bind(('', MYPORT))

    group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
    # Join group
    mreq = group_bin + struct.pack('=I', socket.INADDR_ANY)
    Socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    # Loop, printing any data we receive
    DeviceNamesPrefix = "ESP32_"
    RetransmitIndicator = "ret"
    print( "Server has started verifying...")
    print( "Press r for retransmit firmware to the appeared devices.")
    print( "Device list(updating...):" )
    print (" Number\tName\t\tIndex\tInfo")
    while Listening:
        try:
            data, DeviceInfo = Socket.recvfrom(100)
            DeviceName = data.decode('ascii').split( ":")[0]
            DeviceData = data.decode('ascii').split( ":")[1].strip()
            RetransmitIndex = DeviceData.replace(RetransmitIndicator,'')
            while data[-1:] == '\0': data = data[:-1] # Strip trailing \0's
            if RetransmitIndicator in DeviceData and DeviceName in Devices and DeviceName not in RetransmitDevices :
                RetransmitNodeJoin(DeviceName, DeviceInfo, RetransmitIndex)
        except:
            pass

#Firmware encrypting section
import http.server as SimpleHTTPServer
import socketserver


def Sha256(Input):
  Hash = hashlib.sha256()
  Hash.update(Input)
  return Hash.digest()


def MACI(IKSW, Index, EI, HASHIMINUS):
  c =  hmac.new(IKSW, digestmod="sha256")
  if HASHIMINUS:
    c.update(bytes((Index).to_bytes(4, byteorder='big') + EI + HASHIMINUS))
  else:
    #last index
    c.update(bytes((Index).to_bytes(4, byteorder='big') + EI ))
  return c.digest()




def enc_long(n):
    '''Encodes arbitrarily large number n to a sequence of bytes.
    Big endian byte order is used.'''
    s = ""
    while n > 0:
        s = chr(n & 0xFF) + s
        n >>= 8
    return s




# Padding for the input string --not
# related to encryption itself.
BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


def encrypt(plaintext,key, mode):
	encobj = AES.new(key,mode)
	return(encobj.encrypt(plaintext))

def decrypt(ciphertext,key, mode):
	encobj = AES.new(key,mode)
	return(encobj.decrypt(ciphertext))


EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)


# Modular arithmetic ##########################################################

def inverse_mod(k, p):
    """Returns the inverse of k modulo p.
    This function returns the only integer x such that (x * k) % p == 1.
    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p


# Functions that work on curve points #########################################

def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point

    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_neg(point):
    """Returns -point."""
    assert is_on_curve(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert is_on_curve(result)

    return result


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)

    assert is_on_curve(result)

    return result


def scalar_mult(k, point):
    """Returns k * point computed using the double and point_add algorithm."""
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result


# Keypair generation and ECDSA ################################################

def make_keypair():
    """Generates a random private-public key pair."""
    private_key = random.randrange(1, curve.n)
    public_key = scalar_mult(private_key, curve.g)

    return private_key, public_key


def verify_signature(public_key, message, signature):
    z = hash_message(message)

    r, s = signature

    w = inverse_mod(s, curve.n)
    u1 = (z * w) % curve.n
    u2 = (r * w) % curve.n

    x, y = point_add(scalar_mult(u1, curve.g),
                     scalar_mult(u2, public_key))

    if (r % curve.n) == (x % curve.n):
        return 'signature matches'
    else:
        return 'invalid signature'




Server()
ChoiceDevices()
Verify()
ChoiceRetransmitDevices()

message="Hello"
if (len(sys.argv)>1):
	message=str(sys.argv[1])

#Generate public and private key of the server
ds, Qs = make_keypair()
print("Private key of server:", hex(ds))
print(("Public key of server: (0x{:x}, 0x{:x})".format(*Qs)))



#Generate public and private key of the devices

deviceCount = 2
Privates = [None] * deviceCount
Publics = [None] * deviceCount
for x in range(deviceCount):
    d, Q = make_keypair()
    Privates[x] = d
    Publics[x] = Q
    print("Private key:", hex(d))
    print(("Public key: (0x{:x}, 0x{:x})".format(*Q)))

print("\n\n=========================")

r = random.randint(0, 2**128)
R = scalar_mult(r, curve.g)
S = [None] * deviceCount
X = [None] * deviceCount
Y = [None] * deviceCount
print("Random value: " , r)
print("R: " , R)

for j in range(deviceCount):
    #S[j] = scalar_mult(r,Publics[j])
    S[j] = scalar_mult(ds,Publics[j])
    S[j] = point_add (S[j],R)
    X[j] , Y[j] = S[j]
    if j == 1:
        print("Encryption key:",S[1],str(S[1]))


Sesseion_id = random.randint(0, 2**128)
X_prime = [None] * deviceCount
xored = 0
for j in range(deviceCount):
    for i in range(deviceCount):
        if j != i:
           xored = X[i] ^ xored
    X_prime[j] = xored ^ Y[j]
    xored = 0 

print("\n\n======Symmetric key========")
#print("Encryption key:",S[0],str(S[0]))
password='hello'

xorX = 0
for i in range(deviceCount):
           print("X is:",X[i])
           xorX = X[i] ^ xorX

print("Xor is:",xorX)
key = hashlib.sha256(str(xorX).encode()).digest()

key_star = b'gv4rrcQoL3PWZG8V'

Auth = hashlib.sha256((str(key)+str(R)+str(X_prime)).encode()).digest()

digest = hmac.new(key_star, (str(Sesseion_id)+str(Auth)+str(R)+str(X_prime)).encode(), hashlib.sha256).hexdigest()

message = Padding.appendPadding(message,blocksize=Padding.AES_blocksize,mode=0)

ciphertext = encrypt(message.encode(),key,AES.MODE_ECB)


print("Encrypted:\t",binascii.hexlify(ciphertext))

#Pretend to be the second device with j = 1

#Snew = scalar_mult(Privates[1],R)
Snew = scalar_mult(Privates[1],Qs)
Snew = point_add (Snew,R)
print("Encryption new key:",Snew[0],str(Snew[0]))
xor_new = X_prime[1]^X[1]^Y[1]
print("Xor new is:",xor_new)
K = hashlib.sha256(str(xor_new).encode()).digest()

if  Auth == hashlib.sha256((str(K)+str(R)+str(X_prime)).encode()).digest():
    device_id = random.randint(0, 2**128)
    Ack = hashlib.sha256((str(device_id)+str(Publics[1])).encode()).digest()
    print("\n\n======Successful key setup========")

key = hashlib.sha256(str(Snew[0]).encode()).digest()

text = decrypt(ciphertext,key,AES.MODE_ECB)


print("Decrypted:\t",Padding.removePadding(text.decode(),mode=0))

