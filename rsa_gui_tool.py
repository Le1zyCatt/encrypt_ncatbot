import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import base64
import subprocess
import os
import sys
import random
import gmpy2
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as pad_module
from cryptography.hazmat.backends import default_backend
from tkinter import filedialog

# ---------图片加密解密------------

def encrypt_image():
    try:
        key = base64.b64decode(aes_key_entry.get())
        mode = aes_mode_var.get()

        filepath = filedialog.askopenfilename(title="选择要加密的图片", filetypes=[("Images", "*.png;*.jpg;*.jpeg;*.bmp;*.gif")])
        if not filepath:
            return

        with open(filepath, "rb") as f:
            image_data = f.read()

        padder = pad_module.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(image_data) + padder.finalize()

        backend = default_backend()

        if mode == "CBC":
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_data = iv + ciphertext
        else:
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_data = ciphertext

        save_path = filedialog.asksaveasfilename(defaultextension=".enc", title="保存加密文件")
        if save_path:
            with open(save_path, "wb") as f:
                f.write(encrypted_data)
            messagebox.showinfo("加密成功", f"图片已加密保存到:\n{save_path}")

    except Exception as e:
        messagebox.showerror("图片加密失败", str(e))


def decrypt_image():
    try:
        key = base64.b64decode(aes_key_entry.get())
        mode = aes_mode_var.get()

        filepath = filedialog.askopenfilename(title="选择加密文件", filetypes=[("Encrypted Files", "*.enc")])
        if not filepath:
            return

        with open(filepath, "rb") as f:
            enc_data = f.read()

        backend = default_backend()

        if mode == "CBC":
            iv = enc_data[:16]
            ciphertext = enc_data[16:]
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        else:
            ciphertext = enc_data
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)

        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = pad_module.PKCS7(algorithms.AES.block_size).unpadder()
        plain = unpadder.update(padded_plain) + unpadder.finalize()

        save_path = filedialog.asksaveasfilename(defaultextension=".jpg", title="保存解密图片")
        if save_path:
            with open(save_path, "wb") as f:
                f.write(plain)
            messagebox.showinfo("解密成功", f"图片已解密保存到:\n{save_path}")
    except Exception as e:
        messagebox.showerror("图片解密失败", str(e))



# ===================== RSA 功能 =====================
def encrypt_text(original_text, peer_public_key_str):
    """使用RSA公钥加密文本"""
    public_key = serialization.load_pem_public_key(peer_public_key_str.encode('utf-8'))
    cipher_text = public_key.encrypt(
        original_text.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(cipher_text).decode('utf-8')


def decrypt_text(base64_cipher_text, private_key_str):
    """使用RSA私钥解密文本"""
    cipher_bytes = base64.b64decode(base64_cipher_text)
    private_key = serialization.load_pem_private_key(private_key_str.encode('utf-8'), password=None)
    plain_bytes = private_key.decrypt(
        cipher_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plain_bytes.decode('utf-8')


def generate_key_from_pq(p, q):
    """根据素数p和q生成RSA密钥对"""
    try:
        cmd = [sys.executable, "rsatool.py", "-p", str(p), "-q", str(q), "-o", "private.pem"]
        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode != 0:
            raise RuntimeError(f"rsatool 执行失败：\n{result.stderr}")

        with open("private.pem", "rb") as f:
            private_key = load_pem_private_key(f.read(), password=None)

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        os.remove("private.pem")
        return public_pem, private_pem
    except Exception as e:
        raise ValueError(f"密钥生成失败：{e}")


def generate_prime(bits):
    """生成指定位数的大素数"""
    return int(gmpy2.next_prime(random.getrandbits(bits)))


def auto_generate_pq():
    """自动生成RSA所需的大素数p和q"""
    try:
        bits = int(bit_entry.get())
        p = generate_prime(bits)
        q = generate_prime(bits)
        p_input.delete(0, tk.END)
        p_input.insert(0, str(p))
        q_input.delete(0, tk.END)
        q_input.insert(0, str(q))
        messagebox.showinfo("成功", f"已生成 {bits} 位大素数 p 和 q")
    except Exception as e:
        messagebox.showerror("错误", f"生成失败：{e}")


def on_generate_keys():
    """根据输入的p和q生成RSA密钥"""
    try:
        p = int(p_input.get())
        q = int(q_input.get())
        pub, priv = generate_key_from_pq(p, q)
        pubkey_input.delete("1.0", tk.END)
        pubkey_input.insert(tk.END, pub)
        privkey_input.delete("1.0", tk.END)
        privkey_input.insert(tk.END, priv)
        messagebox.showinfo("密钥生成成功", "RSA 密钥已生成并填入框中")
    except Exception as e:
        messagebox.showerror("生成失败", str(e))


def on_encrypt():
    """执行RSA加密操作"""
    pubkey = pubkey_input.get("1.0", tk.END).strip()
    message = message_input.get("1.0", tk.END).strip()
    if not pubkey or not message:
        messagebox.showwarning("输入不完整", "请填写公钥和要加密的消息")
        return
    try:
        encrypted = encrypt_text(message, pubkey)
        encrypt_output.delete("1.0", tk.END)
        encrypt_output.insert(tk.END, encrypted)
        messagebox.showinfo("加密成功", "消息已成功加密")
    except Exception as e:
        messagebox.showerror("加密失败", str(e))


def on_decrypt():
    """执行RSA解密操作"""
    privkey = privkey_input.get("1.0", tk.END).strip()
    cipher = cipher_input.get("1.0", tk.END).strip()
    if not privkey or not cipher:
        messagebox.showwarning("输入不完整", "请填写私钥和密文")
        return
    try:
        decrypted = decrypt_text(cipher, privkey)
        decrypt_output.delete("1.0", tk.END)
        decrypt_output.insert(tk.END, decrypted)
        messagebox.showinfo("解密成功", "密文已成功解密")
    except Exception as e:
        messagebox.showerror("解密失败", str(e))


# ===================== AES 功能 =====================
def aes_encrypt():
    """执行AES加密操作"""
    try:
        # 从Base64解码获取密钥字节
        key = base64.b64decode(aes_key_entry.get())
        plaintext = aes_plaintext_input.get("1.0", tk.END).strip()

        if not key or not plaintext:
            messagebox.showwarning("输入不完整", "请填写AES密钥和明文")
            return

        # 根据模式处理加密
        mode = aes_mode_var.get()
        backend = default_backend()

        if mode == "CBC":
            iv = os.urandom(16)
            # 创建填充器
            padder = pad_module.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(plaintext.encode()) + padder.finalize()

            # 创建加密器并加密
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # 组合IV和密文
            result = base64.b64encode(iv + ciphertext).decode('utf-8')

        elif mode == "ECB":
            # 创建填充器
            padder = pad_module.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(plaintext.encode()) + padder.finalize()

            # 创建加密器并加密
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            result = base64.b64encode(ciphertext).decode('utf-8')

        aes_ciphertext_output.delete("1.0", tk.END)
        aes_ciphertext_output.insert(tk.END, result)
        messagebox.showinfo("AES加密成功", "消息已成功加密")
    except Exception as e:
        messagebox.showerror("AES加密失败", f"错误: {str(e)}")


def aes_decrypt():
    """执行AES解密操作"""
    try:
        # 从Base64解码获取密钥字节
        key = base64.b64decode(aes_key_entry.get())
        ciphertext = aes_ciphertext_input.get("1.0", tk.END).strip()

        if not key or not ciphertext:
            messagebox.showwarning("输入不完整", "请填写AES密钥和密文")
            return

        # 根据模式处理解密
        mode = aes_mode_var.get()
        raw = base64.b64decode(ciphertext)
        backend = default_backend()

        if mode == "CBC":
            iv = raw[:16]
            ct = raw[16:]

            # 创建解密器
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            decryptor = cipher.decryptor()

            # 解密
            padded_plaintext = decryptor.update(ct) + decryptor.finalize()

            # 移除填充
            unpadder = pad_module.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            plaintext = plaintext.decode()

        elif mode == "ECB":
            # 创建解密器
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
            decryptor = cipher.decryptor()

            # 解密
            padded_plaintext = decryptor.update(raw) + decryptor.finalize()

            # 移除填充
            unpadder = pad_module.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            plaintext = plaintext.decode()

        aes_result_output.delete("1.0", tk.END)
        aes_result_output.insert(tk.END, plaintext)
        messagebox.showinfo("AES解密成功", "密文已成功解密")
    except Exception as e:
        messagebox.showerror("AES解密失败", f"错误: {str(e)}")


def generate_aes_key():
    """生成随机AES密钥"""
    key_size = int(aes_key_size_var.get())
    key = os.urandom(key_size)
    aes_key_entry.delete(0, tk.END)
    aes_key_entry.insert(0, base64.b64encode(key).decode('utf-8'))
    messagebox.showinfo("成功", f"已生成{key_size * 8}位AES密钥")


# ===================== GUI 界面 =====================
root = tk.Tk()
root.title("🔐 RSA/AES 加密解密工具")
root.geometry("900x1100")

# 创建选项卡
tab_control = ttk.Notebook(root)

# RSA选项卡
rsa_tab = ttk.Frame(tab_control)
tab_control.add(rsa_tab, text='RSA 加密')
tab_control.pack(expand=1, fill="both", padx=10, pady=10)

# p, q 位数生成区域
tk.Label(rsa_tab, text="🧮 指定位数生成 p 和 q", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(10, 5))
bit_frame = tk.Frame(rsa_tab)
bit_frame.pack(fill="x", padx=10)

tk.Label(bit_frame, text="位数:").grid(row=0, column=0, sticky="w")
bit_entry = tk.Entry(bit_frame, width=10)
bit_entry.grid(row=0, column=1, sticky="w")
bit_entry.insert(0, "1024")

tk.Button(bit_frame, text="🎲 自动生成 p 和 q", command=auto_generate_pq, bg="#9C27B0", fg="white").grid(row=0, column=2,
                                                                                                        padx=10)

# p, q 输入
pq_frame = tk.Frame(rsa_tab)
pq_frame.pack(fill="x", padx=10, pady=(5, 5))

tk.Label(pq_frame, text="p:").grid(row=0, column=0, sticky="w")
p_input = tk.Entry(pq_frame, width=70)
p_input.grid(row=0, column=1, padx=5)

tk.Label(pq_frame, text="q:").grid(row=1, column=0, sticky="w")
q_input = tk.Entry(pq_frame, width=70)
q_input.grid(row=1, column=1, padx=5)

tk.Button(pq_frame, text="🔧 根据 p 和 q 生成密钥", command=on_generate_keys, bg="#FF9800", fg="white").grid(row=0,
                                                                                                            column=2,
                                                                                                            rowspan=2,
                                                                                                            padx=10)

# RSA加密区域
tk.Label(rsa_tab, text="🔐 RSA 加密部分", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(20, 5))
tk.Label(rsa_tab, text="📌 公钥 (PEM)").pack(anchor="w", padx=10)
pubkey_input = scrolledtext.ScrolledText(rsa_tab, height=6)
pubkey_input.pack(fill="x", padx=10)

tk.Label(rsa_tab, text="✉️ 明文").pack(anchor="w", padx=10)
message_input = scrolledtext.ScrolledText(rsa_tab, height=3)
message_input.pack(fill="x", padx=10)

tk.Button(rsa_tab, text="🔐 加密消息", command=on_encrypt, bg="#4CAF50", fg="white").pack(pady=5)

tk.Label(rsa_tab, text="📤 密文（Base64）").pack(anchor="w", padx=10)
encrypt_output = scrolledtext.ScrolledText(rsa_tab, height=3)
encrypt_output.pack(fill="x", padx=10, pady=(0, 20))

# RSA解密区域
tk.Label(rsa_tab, text="🔓 RSA 解密部分", font=("Arial", 12, "bold")).pack(anchor="w", padx=10)
tk.Label(rsa_tab, text="🔑 私钥 (PEM)").pack(anchor="w", padx=10)
privkey_input = scrolledtext.ScrolledText(rsa_tab, height=6)
privkey_input.pack(fill="x", padx=10)

tk.Label(rsa_tab, text="📥 密文（Base64）").pack(anchor="w", padx=10)
cipher_input = scrolledtext.ScrolledText(rsa_tab, height=3)
cipher_input.pack(fill="x", padx=10)

tk.Button(rsa_tab, text="🔓 解密密文", command=on_decrypt, bg="#2196F3", fg="white").pack(pady=5)

tk.Label(rsa_tab, text="📄 明文结果").pack(anchor="w", padx=10)
decrypt_output = scrolledtext.ScrolledText(rsa_tab, height=3)
decrypt_output.pack(fill="x", padx=10, pady=(0, 20))

# AES选项卡
aes_tab = ttk.Frame(tab_control)
tab_control.add(aes_tab, text='AES 加密')

# 图片加密选项卡
image_tab = ttk.Frame(tab_control)
tab_control.add(image_tab, text='🖼️ 图片加密')

tk.Label(image_tab, text="📷 图片加密与解密", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(10, 5))
tk.Label(image_tab, text="✅ 使用 AES（与 AES 密钥与模式同步）").pack(anchor="w", padx=10)

tk.Button(image_tab, text="🖼️ 加密图片文件", command=encrypt_image, bg="#4CAF50", fg="white").pack(padx=10, pady=10)
tk.Button(image_tab, text="🖼️ 解密为图片", command=decrypt_image, bg="#2196F3", fg="white").pack(padx=10, pady=(0, 20))

# AES密钥区域
tk.Label(aes_tab, text="🔑 AES 密钥设置", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(10, 5))
key_frame = tk.Frame(aes_tab)
key_frame.pack(fill="x", padx=10)

tk.Label(key_frame, text="密钥长度:").grid(row=0, column=0, sticky="w")
aes_key_size_var = tk.StringVar(value="32")
key_size_menu = ttk.Combobox(key_frame, textvariable=aes_key_size_var, width=10, state="readonly")
key_size_menu['values'] = ('16', '24', '32')  # 对应128/192/256位
key_size_menu.grid(row=0, column=1, sticky="w")

tk.Label(key_frame, text="加密模式:").grid(row=0, column=2, padx=(20, 0), sticky="w")
aes_mode_var = tk.StringVar(value="CBC")
mode_menu = ttk.Combobox(key_frame, textvariable=aes_mode_var, width=10, state="readonly")
mode_menu['values'] = ('CBC', 'ECB')
mode_menu.grid(row=0, column=3, sticky="w")

tk.Label(key_frame, text="密钥(Base64):").grid(row=1, column=0, sticky="w", pady=(5, 0))
aes_key_entry = tk.Entry(key_frame, width=70)
aes_key_entry.grid(row=1, column=1, columnspan=3, sticky="we", pady=(5, 0))

tk.Button(key_frame, text="🎲 生成随机密钥", command=generate_aes_key, bg="#9C27B0", fg="white").grid(row=0, column=4,
                                                                                                     rowspan=2, padx=10)

# AES加密区域
tk.Label(aes_tab, text="🔐 AES 加密", font=("Arial", 12, "bold")).pack(anchor="w", padx=10, pady=(20, 5))
tk.Label(aes_tab, text="✉️ 明文").pack(anchor="w", padx=10)
aes_plaintext_input = scrolledtext.ScrolledText(aes_tab, height=5)
aes_plaintext_input.pack(fill="x", padx=10)

tk.Button(aes_tab, text="🔐 加密消息", command=aes_encrypt, bg="#4CAF50", fg="white").pack(pady=5)

tk.Label(aes_tab, text="📤 密文（Base64）").pack(anchor="w", padx=10)
aes_ciphertext_output = scrolledtext.ScrolledText(aes_tab, height=5)
aes_ciphertext_output.pack(fill="x", padx=10, pady=(0, 20))

# AES解密区域
tk.Label(aes_tab, text="🔓 AES 解密", font=("Arial", 12, "bold")).pack(anchor="w", padx=10)
tk.Label(aes_tab, text="📥 密文（Base64）").pack(anchor="w", padx=10)
aes_ciphertext_input = scrolledtext.ScrolledText(aes_tab, height=5)
aes_ciphertext_input.pack(fill="x", padx=10)

tk.Button(aes_tab, text="🔓 解密密文", command=aes_decrypt, bg="#2196F3", fg="white").pack(pady=5)

tk.Label(aes_tab, text="📄 解密结果").pack(anchor="w", padx=10)
aes_result_output = scrolledtext.ScrolledText(aes_tab, height=5)
aes_result_output.pack(fill="x", padx=10, pady=(0, 20))

root.mainloop()
