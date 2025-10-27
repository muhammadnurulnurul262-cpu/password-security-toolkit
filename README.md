# password-security-toolkit
A strict, safety-first Python toolkit for generating and assessing secure passwords — no cracking, no excuses.

import re
import secrets
import string
import random  # Untuk shuffle yang cryptographically secure
import getpass  # Untuk input tersembunyi
import math  # Untuk perhitungan entropy
import bcrypt  # Opsional: untuk hashing (pip install bcrypt)

try:
    import zxcvbn  # Opsional: untuk analisis kekuatan canggih (pip install zxcvbn)
    ZXCVBN_AVAILABLE = True
except ImportError:
    ZXCVBN_AVAILABLE = False

def estimate_entropy(password):
    """
    Estimasi entropy sederhana dalam bit.
    Berdasarkan panjang dan variasi karakter (huruf kecil/besar, angka, simbol).
    Rumus: log2(jumlah kemungkinan kombinasi).
    """
    length = len(password)
    if length == 0:
        return 0
    
    # Hitung jumlah karakter unik per kategori
    lower = len(set(string.ascii_lowercase) & set(password))
    upper = len(set(string.ascii_uppercase) & set(password))
    digits = len(set(string.digits) & set(password))
    symbols = len(set(string.punctuation) & set(password))
    
    # Total karakter unik
    unique_chars = lower + upper + digits + symbols
    if unique_chars == 0:
        return 0
    
    # Entropy = log2(unique_chars ^ length)
    entropy = length * math.log2(unique_chars)
    return round(entropy, 2)

def check_password_strength(password):
    """
    Memeriksa kekuatan password dengan skor 0-10 yang jelas dan estimasi entropy.
    Menggunakan zxcvbn jika tersedia, atau algoritma sederhana.
    """
    if ZXCVBN_AVAILABLE:
        # Gunakan zxcvbn untuk analisis canggih
        result = zxcvbn.zxcvbn(password)
        score = result['score'] * 2.5  # Skala zxcvbn 0-4, konversi ke 0-10
        strength = ["Lemah", "Sedang", "Sedang", "Kuat", "Sangat Kuat"][result['score']]
        suggestions = result['feedback']['suggestions']
        entropy = estimate_entropy(password)  # Tambahan
        return score, strength, suggestions, entropy
    else:
        # Algoritma sederhana (fallback)
        score = 0
        suggestions = []
        
        # Kriteria dengan skor tetap (total 10 poin)
        if len(password) >= 8:
            score += 2
        else:
            suggestions.append("Password harus minimal 8 karakter.")
        
        if re.search(r'[a-z]', password):
            score += 1
        else:
            suggestions.append("Tambahkan huruf kecil (a-z).")
        
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            suggestions.append("Tambahkan huruf besar (A-Z).")
        
        if re.search(r'\d', password):
            score += 1
        else:
            suggestions.append("Tambahkan angka (0-9).")
        
        if re.search(r'[!@#$%^&*()_+\-=\$\${};\':"\\|,.<>\/?]', password):
            score += 1
        else:
            suggestions.append("Tambahkan simbol khusus (misalnya !@#$%).")
        
        if len(password) >= 12:
            score += 2
        
        if re.search(r'(password|123456|qwerty)', password.lower()):
            score = max(0, score - 2)
            suggestions.append("Hindari pola umum seperti 'password' atau '123456'.")
        
        strength = "Lemah" if score <= 3 else "Sedang" if score <= 6 else "Kuat"
        entropy = estimate_entropy(password)
        return score, strength, suggestions, entropy

def generate_strong_password(length=12):
    """
    Menghasilkan password acak yang kuat dengan panjang tertentu.
    Menggunakan kombinasi huruf, angka, dan simbol.
    """
    if length < 8:
        raise ValueError("Panjang password minimal 8 karakter untuk keamanan.")
    
    chars = string.ascii_letters + string.digits + string.punctuation
    
    # Pastikan ada setidaknya satu dari setiap kategori
    password = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(string.punctuation)
    ]
    
    # Isi sisanya secara acak
    for _ in range(length - 4):
        password.append(secrets.choice(chars))
    
    # Shuffle dengan random.SystemRandom (cryptographically secure)
    random.SystemRandom().shuffle(password)
    
    return ''.join(password)

def hash_password(password):
    """
    Opsional: Hash password menggunakan bcrypt untuk penyimpanan/verifikasi aman.
    """
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(password, hashed_password):
    """
    Opsional: Verifikasi password terhadap hash bcrypt.
    """
    password_bytes = password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)

# Menu utama tools
def main():
    print("=== Password Security Toolkit (Improved) ===")
    print("PERINGATAN: Jangan log, simpan, atau commit password apa pun. Gunakan hanya untuk edukasi pribadi.")
    while True:
        print("\nPilih opsi:")
        print("1. Periksa Kekuatan Password")
        print("2. Generate Password Kuat")
        print("3. Hash Password (Opsional)")
        print("4. Verifikasi Password (Opsional)")
        print("5. Keluar")
        
        choice = input("Masukkan pilihan (1/2/3/4/5): ").strip()
        
        if choice == "1":
            password = getpass.getpass("Masukkan password untuk diperiksa (tidak terlihat di layar): ")
            score, strength, suggestions, entropy = check_password_strength(password)
            print(f"\nKekuatan Password: {strength} (Skor: {score}/10, Entropy: {entropy} bit)")
            if suggestions:
                print("Saran perbaikan:")
                for sug in suggestions:
                    print(f"- {sug}")
            else:
                print("Password Anda sudah kuat!")
        
        elif choice == "2":
            try:
                length = int(input("Masukkan panjang password (minimal 8): "))
                password = generate_strong_password(length)
                print(f"\nPassword yang dihasilkan: {password}")
                print("Simpan dan gunakan dengan bijak! Jangan bagikan.")
            except ValueError as e:
                print(f"Error: {e}")
        
        elif choice == "3":
            password = getpass.getpass("Masukkan password untuk di-hash (tidak terlihat): ")
            hashed = hash_password(password)
            print(f"Hashed Password (simpan ini, bukan plaintext): {hashed}")
        
        elif choice == "4":
            password = getpass.getpass("Masukkan password untuk verifikasi: ")
            hashed_input = input("Masukkan hash yang tersimpan: ")
            if verify_password(password, hashed_input):
                print("Password benar!")
            else:
                print("Password salah!")
        
        elif choice == "5":
            print("Terima kasih telah menggunakan tools ini!")
            break
        
        else:
            print("Pilihan tidak valid. Coba lagi.")

if __name__ == "__main__":
    main()
