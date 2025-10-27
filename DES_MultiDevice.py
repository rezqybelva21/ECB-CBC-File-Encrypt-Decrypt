import socket
from threading import Thread
from time import sleep

# ===========================================================
# ===============  DES IMPLEMENTATION  ======================
# ===========================================================

IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]
S_BOX = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ]
] * 8
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]
PC2 = [14, 17, 11, 24, 1, 5, 3, 28,
       15, 6, 21, 10, 23, 19, 12, 4,
       26, 8, 16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55, 30, 40,
       51, 45, 33, 48, 44, 49, 39, 56,
       34, 53, 46, 42, 50, 36, 29, 32]
SHIFT = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def nsplit(s, n): return [s[k:k+n] for k in range(0, len(s), n)]
def binvalue(val, bitsize): return bin(val)[2:].zfill(bitsize)
def str_to_bit_array(text): return [int(x) for c in text for x in binvalue(ord(c), 8)]
def bit_array_to_str(array): return ''.join(chr(int(''.join(map(str, _bytes)), 2)) for _bytes in nsplit(array, 8))
def permute(block, table): return [block[x-1] for x in table]
def shift_left(block, n): return block[n:] + block[:n]
def xor(t1, t2): return [x ^ y for x, y in zip(t1, t2)]

class DES:
    def __init__(self): self.keys = []

    def generate_keys(self, key):
        self.keys.clear()
        key_bits = str_to_bit_array(key)
        key_bits = permute(key_bits, PC1)
        left, right = nsplit(key_bits, 28)
        for i in range(16):
            left = shift_left(left, SHIFT[i])
            right = shift_left(right, SHIFT[i])
            self.keys.append(permute(left + right, PC2))

    def substitute(self, block):
        blocks = nsplit(block, 6)
        result = []
        for i, b in enumerate(blocks):
            row = int(str(b[0]) + str(b[5]), 2)
            col = int(''.join(str(x) for x in b[1:5]), 2)
            val = S_BOX[i][row][col]
            result += [int(x) for x in binvalue(val, 4)]
        return result

    def run(self, key, text, action='ENCRYPT'):
        self.generate_keys(key)
        result = []
        for block in nsplit(text, 8):
            block_bits = str_to_bit_array(block)
            block_bits += [0]*(64-len(block_bits))
            block_bits = permute(block_bits, IP)
            left, right = nsplit(block_bits, 32)
            for i in range(16):
                right_expanded = permute(right, E)
                temp = xor(right_expanded, self.keys[i if action == 'ENCRYPT' else 15-i])
                temp = self.substitute(temp)
                temp = permute(temp, P)
                temp = xor(left, temp)
                left = right
                right = temp
            result += permute(right + left, FP)
        return bit_array_to_str(result)

    def encrypt_hex(self, key, text):
        return ''.join([format(ord(c), '02x') for c in self.run(key, text, 'ENCRYPT')])

    def decrypt_hex(self, key, hex_text):
        text = ''.join([chr(int(hex_text[i:i+2], 16)) for i in range(0, len(hex_text), 2)])
        return self.run(key, text, 'DECRYPT')

# ===========================================================
# ===============  NETWORK COMMUNICATION  ====================
# ===========================================================

def get_local_ip():
    """Deteksi IP LAN otomatis"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    s.close()
    return ip

def start_receiver(key, port):
    """Mode menerima pesan terenkripsi dan mendekripsi"""
    local_ip = get_local_ip()
    print(f"\n[Receiver] IP kamu: {local_ip}")
    print(f"[Receiver] Jalankan pengirim dengan IP ini dan port {port}\n")

    des = DES()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", port))
    s.listen(1)
    print(f"[Receiver] Listening on {local_ip}:{port} ... Menunggu pesan terenkripsi...")

    conn, addr = s.accept()
    data = conn.recv(4096).decode('utf-8')
    print(f"\nPesan terenkripsi diterima dari {addr[0]}:")
    print(f"Ciphertext: {data}")
    try:
        decrypted = des.decrypt_hex(key, data)
        print(f"Plaintext hasil dekripsi: {decrypted}")
    except Exception as e:
        print("Gagal mendekripsi:", e)
    conn.close()
    s.close()

def send_encrypted_message(key, target_ip, port, message):
    """Mode mengirim teks terenkripsi"""
    des = DES()
    encrypted = des.encrypt_hex(key, message)
    print(f"\nTeks terenkripsi (hex): {encrypted}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, port))
    s.send(encrypted.encode('utf-8'))
    s.close()
    print(f"Pesan terenkripsi berhasil dikirim ke {target_ip}:{port}")

# ===========================================================
# ===============  MAIN MENU  ===============================
# ===========================================================

def main():
    print("\n===========================================")
    print("  DES ENCRYPT-DECRYPT MULTI DEVICE")
    print("===========================================\n")

    mode = input("Pilih mode: \n1. Encrypt & Send\n2. Receive & Decrypt\n>> ").strip()
    key = input("Masukkan key (8 karakter): ").strip()
    if len(key) != 8:
        print("Key harus 8 karakter!")
        return

    if mode == "1":
        target_ip = input("Masukkan IP device tujuan: ").strip()
        port = int(input("Masukkan port tujuan: ").strip())
        message = input("Masukkan teks yang ingin dienkripsi: ").strip()
        send_encrypted_message(key, target_ip, port, message)
    elif mode == "2":
        port = int(input("Masukkan port untuk menerima pesan: ").strip())
        start_receiver(key, port)
    else:
        print("Pilihan tidak valid!")

if __name__ == "__main__":
    main()
