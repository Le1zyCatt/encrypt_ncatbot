import tkinter as tk
from tkinter import messagebox, scrolledtext
import base64
import subprocess
import os
import sys
import random
import gmpy2
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def encrypt_text(original_text, peer_public_key_str):
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
    return int(gmpy2.next_prime(random.getrandbits(bits)))


def auto_generate_pq():
    try:
        bits = int(bit_entry.get())
        p = generate_prime(bits)
        q = generate_prime(bits)
        p_input.delete(0, tk.END)
        q_input.delete(0, tk.END)
        p_input.insert(0, str(p))
        q_input.insert(0, str(q))
        messagebox.showinfo("成功", f"已生成 {bits} 位大素数 p 和 q")
    except Exception as e:
        messagebox.showerror("错误", f"生成失败：{e}")


def on_generate_keys():
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


# ===================== GUI =====================
root = tk.Tk()
root.title("🔐 RSA 加密 / 解密工具（支持位数生成）")
root.geometry("800x900")

# p, q 位数生成区域
tk.Label(root, text="🧮 指定位数生成 p 和 q", font=("Arial", 14, "bold")).pack(anchor="w", padx=10, pady=(10, 0))
bit_frame = tk.Frame(root)
bit_frame.pack(fill="x", padx=10)

tk.Label(bit_frame, text="位数:").grid(row=0, column=0, sticky="w")
bit_entry = tk.Entry(bit_frame, width=10)
bit_entry.grid(row=0, column=1, sticky="w")
bit_entry.insert(0, "1024")

tk.Button(bit_frame, text="🎲 自动生成 p 和 q", command=auto_generate_pq, bg="#9C27B0", fg="white").grid(row=0, column=2, padx=10)

# p, q 输入
pq_frame = tk.Frame(root)
pq_frame.pack(fill="x", padx=10, pady=(5, 5))

tk.Label(pq_frame, text="p:").grid(row=0, column=0, sticky="w")
p_input = tk.Entry(pq_frame, width=70)
p_input.grid(row=0, column=1, padx=5)

tk.Label(pq_frame, text="q:").grid(row=1, column=0, sticky="w")
q_input = tk.Entry(pq_frame, width=70)
q_input.grid(row=1, column=1, padx=5)

tk.Button(pq_frame, text="🔧 根据 p 和 q 生成密钥", command=on_generate_keys, bg="#FF9800", fg="white").grid(row=0, column=2, rowspan=2, padx=10)

# 加密区域
tk.Label(root, text="🔐 加密部分", font=("Arial", 14, "bold")).pack(anchor="w", padx=10)
tk.Label(root, text="📌 公钥 (PEM)").pack(anchor="w", padx=10)
pubkey_input = scrolledtext.ScrolledText(root, height=6)
pubkey_input.pack(fill="x", padx=10)

tk.Label(root, text="✉️ 明文").pack(anchor="w", padx=10)
message_input = scrolledtext.ScrolledText(root, height=3)
message_input.pack(fill="x", padx=10)

tk.Button(root, text="🔐 加密消息", command=on_encrypt, bg="#4CAF50", fg="white").pack(pady=5)

tk.Label(root, text="📤 密文（Base64）").pack(anchor="w", padx=10)
encrypt_output = scrolledtext.ScrolledText(root, height=3)
encrypt_output.pack(fill="x", padx=10, pady=(0, 20))

# 解密区域
tk.Label(root, text="🔓 解密部分", font=("Arial", 14, "bold")).pack(anchor="w", padx=10)
tk.Label(root, text="🔑 私钥 (PEM)").pack(anchor="w", padx=10)
privkey_input = scrolledtext.ScrolledText(root, height=6)
privkey_input.pack(fill="x", padx=10)

tk.Label(root, text="📥 密文（Base64）").pack(anchor="w", padx=10)
cipher_input = scrolledtext.ScrolledText(root, height=3)
cipher_input.pack(fill="x", padx=10)

tk.Button(root, text="🔓 解密密文", command=on_decrypt, bg="#2196F3", fg="white").pack(pady=5)

tk.Label(root, text="📄 明文结果").pack(anchor="w", padx=10)
decrypt_output = scrolledtext.ScrolledText(root, height=3)
decrypt_output.pack(fill="x", padx=10, pady=(0, 20))

root.mainloop()
