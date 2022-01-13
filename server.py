#!/usr/bin/env python

import collections
import random
import binascii
import sys
import hmac
import hashlib
from Crypto.Cipher import AES
import Padding
import time

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
#Rnew = 0
XOR = 0
XPRIME = []
key_star = b'gv4rrcQoL3PWZG8V'

MYPORT = 20001
MYGROUP_4 = '232.10.11.12'
MYTTL = 1 # Increase to reach other networks

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
    	    'message':'Please select the devices whose operating system you want to update the key.',
    	    'choices': DeviceNames
    	}
    	]
    	result = prompt(widget)
    	UpdateAdvertisement(result["devices"])
    else:
    	print("There is no joined devices")
    	sys.exit()

def UpdateAdvertisement(DeviceList):
    global Rnew
    global XPRIME
    global XOR
    print("Start sending key update command to the selected devices...")
    addrinfo = socket.getaddrinfo(MYGROUP_4, None)[0]
    s = socket.socket(addrinfo[0], socket.SOCK_DGRAM)
    ttl_bin = struct.pack('@i', MYTTL)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)
        
    for Device in DeviceList:
        s.sendto(b'NewKey', Devices[Device])
    
    print("Start key updating...")
    
    Rnew, XOR, XPRIME = gen_keys_Sj(len(DeviceList))
    UpdateRoutine(len(DeviceList))

def UpdateRoutine(deviceCount):
    global Rnew
    global XPRIME
    global XOR
    global Sesseion_id
    addrinfo = socket.getaddrinfo(MYGROUP_4, None)[0]
   
    Socket = socket.socket(addrinfo[0], socket.SOCK_DGRAM)

    # Set Time-to-live (optional)
    ttl_bin = struct.pack('@i', MYTTL)
    Socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl_bin)

    Sesseion_id = random.randint(0, 2**128)
    print ("type xor is:", type(XOR))
    key = hashlib.sha256(XOR.to_bytes(32,'big')).digest()
    print ("key is:", key.hex())

    xPrimes = b''
    print ("XPRIME is:", XPRIME)
    for item in XPRIME:
        print ("item is:", hex(item))
        xPrimes += item.to_bytes(32,'big')
    
    print ("Auth before hash is: ", (key+Rnew[0].to_bytes(32,'big') + Rnew[1].to_bytes(32,'big')+xPrimes).hex())
    Auth = hashlib.sha256(key+Rnew[0].to_bytes(32,'big') + Rnew[1].to_bytes(32,'big')+xPrimes).digest()
    

    digest = hmac.new(key_star, (Sesseion_id.to_bytes(16,'big') + Auth + Rnew[0].to_bytes(32,'big') + Rnew[1].to_bytes(32,'big') + deviceCount.to_bytes(1,'big') + xPrimes), hashlib.sha256).digest()
    #length = session id is 39 bytes + auth is 32 + Rnew is a point each is 77 bytes + xprime depends on the length if len is 2 then it is 77*2 + digest is 32 bytes 
    print("\n session id is: ", hex(Sesseion_id))
    print("\n Auth is: ", Auth.hex())
    print ("Rnew 0 is:", hex(Rnew[0]))
    print ("Rnew 1 is:", hex(Rnew[1]))
    print ("xpime is:", xPrimes.hex())
    
    data = digest + Sesseion_id.to_bytes(16,'big') + Auth + Rnew[0].to_bytes(32,'big') + Rnew[1].to_bytes(32,'big') + deviceCount.to_bytes(1,'big') + xPrimes
    timestamp = time.time_ns()
    print ("Time is :", timestamp)
    Socket.sendto(data, (addrinfo[4][0], MYPORT))
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



def Verify():
    global Devices, Listening, Socket
    global Sesseion_id
    global RetransmitDevices
    global Publics
    global devicedata
    Listening = True
    # Look up multicast group address in name server and find out IP version
    addrinfo = socket.getaddrinfo(MYGROUP_4, None)[0]

    # Create a socket
    Socket = socket.socket(addrinfo[0], socket.SOCK_DGRAM)

    # Allow multiple copies of this program on one machine
    Socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind it to the port
    Socket.bind(('', MYPORT))

    group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
    # Join group
    mreq = group_bin + struct.pack('=I', socket.INADDR_ANY)
    Socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    #public_d = Publics[0]
    #device_id = b"202106128789"

    
    # Loop, printing any data we receive
    DeviceNamesPrefix = "ESP32_"
    RetransmitIndicator = "ret"
    print( "Server has started verifying...")
    #print( "Press r for retransmit firmware to the appeared devices.")
    print( "Device list(updating...):" )
    print (" Number\tName\t\tIndex\tInfo")

    
    while Listening:
        try:
            data , Deviceinfo = Socket.recvfrom(44)
            timestamp = time.time_ns()
            print ("Time of received is :", timestamp)
            print( "received ack is: ", data)
            for x in range(len(devicedata)):
                if  data[32:] == devicedata["data"][x]["deviceid"]:
                    public_d = devicedata["data"][x]["public"]
                    device_id = devicedata["data"][x]["deviceid"]
            hash_new = hashlib.sha256(Sesseion_id.to_bytes(16,'big')+public_d[0].to_bytes(32,'big') + public_d[1].to_bytes(32,'big')).digest()
            print( "hash new is: ", hash_new)
            if str(data[:32]) == str(hash_new):
                  if data[32:] == device_id:
                        timestamp = time.time_ns()
                        print ("Ack Time is :", timestamp)
                        print( "Ack checking was sussessful")
            #DeviceName = data.decode('ascii').split( ":")[0]
            #DeviceData = data.decode('ascii').split( ":")[1].strip()
            #RetransmitIndex = DeviceData.replace(RetransmitIndicator,'')
            while data[-1:] == '\0': data = data[:-1] # Strip trailing \0's
            #if RetransmitIndicator in DeviceData and DeviceName in Devices and DeviceName not in RetransmitDevices :
            #    RetransmitNodeJoin(DeviceName, DeviceInfo, RetransmitIndex)
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


#Functions that work on curve points #########################################

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


# Keypair generation and ECDSA signature ################################################

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


def gen_keys_Sj(deviceCount):
    global Publics
    global devicedata
    #Generate public and private key of the server
    #ds, Qs = make_keypair()
    ds = 0xB98574F2114AEBA4357E3C2B1CBF947F55BBF2BD78510EF30AD54707B55F2D7E
    #ds = ds.to_bytes(32,'big')
    Qs = (0x24DBCC31195B40A449A6FD36E6029EAC1C066264E8B3615E7019839331884A32,0x930D408DB48AD8599E4BE9A612D53E5678AB3BDF75E35CDD369BB6A639BCDFEF)
    #Qs = (Qs[0].to_bytes(32,'big'),Qs[1].to_bytes(32,'big'))
    print("Private key of server:", ds)
    #print(("Public key of server: (0x{:x}, 0x{:x})".format(*Qs)))

    #Generate public and private key of the devices
    devicedata = { "data":[]}
    
    device = {}

    Privates = [None] * deviceCount
    Publics = [None] * deviceCount
    for x in range(deviceCount):
        #d, Q = make_keypair()
        device["public"]= (0xEE8A1F7B47203A417B6AC299D094DA9172EED8D74BD0E08D45E01CAE5479066C,0x50EC2EE96645340A4BFD594CD00320CF10625F4781B3B84B05EC9196E3AF8BC4)
        device["private"]= 0x0C80F3C6B15DE1024C5EFAB9ECE80C395100D8BCECA36E02879146A138B6F072
        device["deviceid"]= b"202106128789"
        devicedata["data"].append(device)
        #print("device data is :", devicedata["data"])
        #print("public is :", devicedata["data"][0]["public"])
        Privates[x] = 0x0C80F3C6B15DE1024C5EFAB9ECE80C395100D8BCECA36E02879146A138B6F072
        #Privates[x] = Privates[x].to_bytes(32,'big')
        Publics[x] = (0xEE8A1F7B47203A417B6AC299D094DA9172EED8D74BD0E08D45E01CAE5479066C,0x50EC2EE96645340A4BFD594CD00320CF10625F4781B3B84B05EC9196E3AF8BC4)
        #Q = Publics[x]
        #Q = (Q[0].to_bytes(32,'big'),Q[1].to_bytes(32,'big')) 
        #Publics[x] = Q 
        print("Private key:", Privates[x])
        #print(("Public key: (0x{:x}, 0x{:x})".format(*Publics[x])))

    print("\n\n=========================")
    r = random.randint(0, 2**128)
    R = scalar_mult(r, curve.g)
    S = [None] * deviceCount
    X = [None] * deviceCount
    Y = [None] * deviceCount
    print("Random value: " , r)
    print("R: " , R)
    for j in range(deviceCount):
        S[j] = scalar_mult(ds,Publics[j])
        S[j] = point_add (S[j],R)
        X[j] , Y[j] = S[j]
        #if j == 1:
        print("Sx is:",hex(S[j][0]))
        print("Sy is:", hex(S[j][1]))

    X_prime = [None] * deviceCount
    xored = 0
    for j in range(deviceCount):
        for i in range(deviceCount):
            if j != i:
               xored = X[i] ^ xored
        X_prime[j] = xored ^ Y[j]
        xored = 0 
       
    xorX = 0
    for i in range(deviceCount):
           print("X is:",X[i])
           xorX = X[i] ^ xorX

    print("Xor is:",hex(xorX))
    print("prime function is:",X_prime)
    return R, xorX, X_prime 


if __name__ == '__main__':

   
    #ds, Qs = make_keypair()
    #client private: 0x65087f1beacc0491abf08417e80e6be17e19011bff9b7f9b31a476ce4b74eca3
    #client public key: (0x31c841b6495b3ad2e28a4331a88bc89e22af5b0567c5e4f04c713545ad2a51d2, 0xbce8421f85aacbe9f5b0b79f3a345949a943486bc6e20275f4e9d3ac5fdeed2d)
    #server private:0xd967af0f977b7a12741e909b44d6c45195686c98054df60002e9af120d5a1c6d
    #server public key: (0x4cff8e2285425bb823629e77491bbd3b99d0131a10c1dd552ae5a5e817a43fa5, 0xcc905c4bbb754243c10d6f23ffdf1b6af7b94fd0cc53cfb0afe132255d9a672e)
    #print("Private key of server:", hex(ds))
    #print(ds.to_bytes(32,'big'))
    #listTestByte = list(ds.to_bytes(32,'big'))
    #print(listTestByte) 
    #print(Qs[0].to_bytes(32,'big'))
    #print(Qs[1].to_bytes(32,'big'))
    #print(("Public key of server: (0x{:x}, 0x{:x})".format(*Qs)))
    Server()
    ChoiceDevices()

    Verify()
   




