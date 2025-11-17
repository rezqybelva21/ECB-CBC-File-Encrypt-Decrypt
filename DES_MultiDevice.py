import socket
import random
import string
import math
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
    def __init__(self): 
        self.keys = []

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
# ===============  RSA IMPLEMENTATION  =======================
# ===========================================================

def is_prime(n):
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    r = int(math.isqrt(n))
    f = 3
    while f <= r:
        if n % f == 0:
            return False
        f += 2
    return True

def generate_prime(bits=16):
    while True:
        # angka acak ganjil
        p = random.getrandbits(bits) | 1
        if is_prime(p):
            return p

def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception("Tidak ada inverse modular")
    return x % m

def generate_rsa_keys(bits=16):
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    # pilih e
    e_candidates = [65537, 257, 17, 5, 3]
    for cand in e_candidates:
        if math.gcd(cand, phi) == 1:
            e = cand
            break
    else:
        # fallback brute force
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2

    d = modinv(e, phi)
    return (n, e, d)

def rsa_encrypt_text(text, n, e):
    """
    Enkripsi setiap karakter key DES secara per-karakter.
    Hasil: string berupa angka-angka dipisah koma, misal: '1234,5678,90'
    """
    cipher_ints = [pow(ord(ch), e, n) for ch in text]
    return ','.join(str(c) for c in cipher_ints)

def rsa_decrypt_text(cipher_text, n, d):
    cipher_ints = [int(x) for x in cipher_text.split(',') if x.strip() != '']
    chars = [chr(pow(c, d, n)) for c in cipher_ints]
    return ''.join(chars)

def generate_des_key():
    chars = string.ascii_letters + string.digits + string.punctuation
    # 8 karakter sebagai DES key
    return ''.join(random.choice(chars) for _ in range(8))

# ===========================================================
# ===============  NETWORK COMMUNICATION  ====================
# ===========================================================

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    s.close()
    return ip

def start_receiver(port):
    """
    Receiver:
    1. Generate RSA (n, e, d)
    2. Listen TCP
    3. Kirim public key (n,e) ke sender
    4. Terima DES key terenkripsi (pakai RSA)
    5. Terima ciphertext (DES)
    6. Dekripsi DES key, lalu dekripsi pesan
    """
    local_ip = get_local_ip()
    print("\n[Receiver] Meng-generate pasangan kunci RSA ...")
    n, e, d = generate_rsa_keys()
    print("[Receiver] Public key (n, e)  =", n, e)
    print("[Receiver] Private key (d)    =", d)

    print(f"\n[Receiver] IP kamu: {local_ip}")
    print(f"[Receiver] Jalankan pengirim dengan IP ini dan port {port}\n")

    des = DES()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", port))
    s.listen(1)
    print(f"[Receiver] Listening on {local_ip}:{port} ... Menunggu koneksi...")

    conn, addr = s.accept()
    print(f"[Receiver] Koneksi dari {addr[0]}")

    # 1) Kirim public key ke sender
    public_key_str = f"{n},{e}\n"
    conn.sendall(public_key_str.encode('utf-8'))
    print("[Receiver] Public key (n,e) dikirim ke pengirim.")

    # 2) Terima data: baris pertama = DES key terenkripsi (RSA),
    #                 baris kedua   = ciphertext (DES, hex)
    data = conn.recv(8192).decode('utf-8')
    if not data:
        print("[Receiver] Tidak ada data diterima.")
        conn.close()
        s.close()
        return

    try:
        enc_key_line, ciphertext_line = data.split('\n', 1)
    except ValueError:
        print("[Receiver] Format data tidak sesuai (harus 2 baris).")
        conn.close()
        s.close()
        return

    enc_key_line = enc_key_line.strip()
    ciphertext_line = ciphertext_line.strip()

    print(f"\n[Receiver] DES key terenkripsi (RSA): {enc_key_line}")
    print(f"[Receiver] Ciphertext (DES, hex): {ciphertext_line}")

    # 3) Dekripsi DES key dengan RSA
    try:
        des_key = rsa_decrypt_text(enc_key_line, n, d)
        print(f"[Receiver] DES key hasil dekripsi RSA: {des_key}")
    except Exception as e_err:
        print("[Receiver] Gagal mendekripsi DES key dengan RSA:", e_err)
        conn.close()
        s.close()
        return

    # 4) Dekripsi pesan dengan DES
    try:
        decrypted = des.decrypt_hex(des_key, ciphertext_line)
        print(f"\n[Receiver] Plaintext hasil dekripsi DES: {decrypted}")
    except Exception as e_des:
        print("[Receiver] Gagal mendekripsi ciphertext DES:", e_des)

    conn.close()
    s.close()

def send_encrypted_message(target_ip, port, message):
    """
    Sender:
    1. Konek ke receiver
    2. Terima public key (n,e)
    3. Generate DES key random
    4. Enkripsi DES key pakai RSA (n,e)
    5. Enkripsi pesan pakai DES key
    6. Kirim: (DES key terenkripsi) + newline + (ciphertext DES)
    """
    des = DES()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"\n[Sender] Menghubungi {target_ip}:{port} ...")
    s.connect((target_ip, port))
    print("[Sender] Terhubung ke receiver.")

    # 1) Terima public key
    header = s.recv(1024).decode('utf-8')
    if not header:
        print("[Sender] Tidak menerima public key dari receiver.")
        s.close()
        return

    try:
        n_str, e_str = header.strip().split(',')
        n = int(n_str)
        e = int(e_str)
    except ValueError:
        print("[Sender] Format public key salah.")
        s.close()
        return

    print(f"[Sender] Public key diterima: n = {n}, e = {e}")

    # 2) Generate DES key random
    des_key = generate_des_key()
    print(f"[Sender] DES key yang di-generate: {des_key}")

    # 3) Enkripsi DES key dengan RSA
    enc_key_str = rsa_encrypt_text(des_key, n, e)
    print(f"[Sender] DES key terenkripsi (RSA): {enc_key_str}")

    # 4) Enkripsi pesan dengan DES
    ciphertext_hex = des.encrypt_hex(des_key, message)
    print(f"[Sender] Ciphertext (DES, hex): {ciphertext_hex}")

    # 5) Kirim ke receiver:
    #    baris 1: DES key terenkripsi (RSA)
    #    baris 2: ciphertext DES (hex)
    payload = enc_key_str + "\n" + ciphertext_hex
    s.sendall(payload.encode('utf-8'))
    print(f"[Sender] Data terenkripsi berhasil dikirim ke {target_ip}:{port}")

    s.close()

# ===========================================================
# ===============  MAIN MENU  ===============================
# ===========================================================

def main():
    print("\n===========================================")
    print("  DES ENCRYPT-DECRYPT MULTI DEVICE")
    print("  with RSA Public Key Distribution")
    print("===========================================\n")

    mode = input("Pilih mode: \n1. Sender (Encrypt & Send)\n2. Receiver (Receive & Decrypt)\n>> ").strip()

    if mode == "1":
        target_ip = input("Masukkan IP device tujuan: ").strip()
        port = int(input("Masukkan port tujuan: ").strip())
        message = input("Masukkan teks yang ingin dienkripsi: ").strip()
        send_encrypted_message(target_ip, port, message)
    elif mode == "2":
        port = int(input("Masukkan port untuk menerima pesan: ").strip())
        start_receiver(port)
    else:
        print("Pilihan tidak valid!")

if __name__ == "__main__":
    main()
