#!/usr/bin/env python3
"""
stego_tool.py
Safe LSB steganography tool (embed/extract arbitrary files into/from PNG/BMP).
- No auto-execution, no persistence.
- Optional encryption using Fernet (symmetric).
- CLI + simple Tkinter GUI.

Usage (CLI examples):
  Generate key:
    python stego_tool.py genkey

  Embed:
    python stego_tool.py embed --cover cover.png --infile payload.dd --out stego.png
    python stego_tool.py embed --cover cover.png --infile payload.dd --out stego.png --key <BASE64_KEY>

  Extract:
    python stego_tool.py extract --stego stego.png --outdir ./extracted
    python stego_tool.py extract --stego stego.png --outdir ./extracted --key <BASE64_KEY>
"""

import os
import sys
import argparse
from PIL import Image
from cryptography.fernet import Fernet, InvalidToken
import tkinter as tk
from tkinter import filedialog, messagebox
import math

MAGIC = b"STEGOV1"  # magic marker to identify our container
MAGIC_LEN = len(MAGIC)
# Header layout after MAGIC:
# 4 bytes: payload length (big endian unsigned int)
# 2 bytes: filename length (big endian unsigned short)
# N bytes: filename (utf-8)
# Then payload bytes

def bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1

def bits_to_bytes(bits):
    b = bytearray()
    cur = 0
    cnt = 0
    for bit in bits:
        cur = (cur << 1) | bit
        cnt += 1
        if cnt == 8:
            b.append(cur)
            cur = 0
            cnt = 0
    return bytes(b)

def make_header(filename: str, payload: bytes):
    fname_b = filename.encode('utf-8')
    if len(fname_b) > 65535:
        raise ValueError("Filename too long (>65535 bytes)")
    plen = len(payload)
    header = MAGIC + plen.to_bytes(4, 'big') + len(fname_b).to_bytes(2, 'big') + fname_b
    return header

def parse_header(buf: bytes):
    if len(buf) < MAGIC_LEN + 6:
        raise ValueError("Header buffer too small")
    if buf[:MAGIC_LEN] != MAGIC:
        raise ValueError("Magic header not found — not a supported stego image")
    payload_len = int.from_bytes(buf[MAGIC_LEN:MAGIC_LEN+4], 'big')
    fname_len = int.from_bytes(buf[MAGIC_LEN+4:MAGIC_LEN+6], 'big')
    start_fname = MAGIC_LEN + 6
    end_fname = start_fname + fname_len
    if len(buf) < end_fname:
        raise ValueError("Incomplete header (filename truncated)")
    filename = buf[start_fname:end_fname].decode('utf-8', errors='replace')
    header_total = end_fname
    return filename, payload_len, header_total

def image_capacity_pixels(img: Image.Image):
    # capacity in bits = number of pixels * 3 (RGB channels)
    return img.width * img.height * 3

def embed_file_into_image(cover_image_path, file_to_hide_path, out_image_path, key_b64=None):
    # Load image
    img = Image.open(cover_image_path)
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    has_alpha = img.mode == "RGBA"
    pixels = list(img.getdata())
    total_capacity = len(pixels) * 3  # bits

    # Read file
    with open(file_to_hide_path, "rb") as f:
        payload = f.read()

    # Optional encryption
    if key_b64:
        fernet = Fernet(key_b64)
        payload = fernet.encrypt(payload)

    header = make_header(os.path.basename(file_to_hide_path), payload)
    blob = header + payload
    total_bits = len(blob) * 8

    if total_bits > total_capacity:
        raise ValueError(f"Payload too big for chosen cover image. Need {total_bits} bits, capacity {total_capacity} bits.")

    bit_iter = bytes_to_bits(blob)
    new_pixels = []
    used_bits = 0
    for px in pixels:
        r, g, b = px[:3]
        try:
            r = (r & ~1) | next(bit_iter); used_bits += 1
        except StopIteration:
            new_pixels.append((r, g, b) + ((px[3],) if has_alpha else ()))
            continue
        try:
            g = (g & ~1) | next(bit_iter); used_bits += 1
        except StopIteration:
            new_pixels.append((r, g, b) + ((px[3],) if has_alpha else ()))
            continue
        try:
            b = (b & ~1) | next(bit_iter); used_bits += 1
        except StopIteration:
            new_pixels.append((r, g, b) + ((px[3],) if has_alpha else ()))
            continue
        new_pixels.append((r, g, b) + ((px[3],) if has_alpha else ()))

    # append any remaining pixels unchanged
    if len(new_pixels) < len(pixels):
        new_pixels.extend(pixels[len(new_pixels):])

    img_out = Image.new(img.mode, img.size)
    img_out.putdata(new_pixels)
    img_out.save(out_image_path, format="PNG")
    return out_image_path

def extract_file_from_image(stego_image_path, out_folder, key_b64=None):
    img = Image.open(stego_image_path)
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    pixels = list(img.getdata())
    # read all LSBs
    bits = []
    for px in pixels:
        r, g, b = px[:3]
        bits.append(r & 1)
        bits.append(g & 1)
        bits.append(b & 1)

    # First read minimal header bytes
    min_header_bytes = (MAGIC_LEN + 6)  # MAGIC + 4 + 2
    min_header_bits = min_header_bytes * 8
    if len(bits) < min_header_bits:
        raise ValueError("Image does not contain header — or too small")

    header_bytes = bits_to_bytes(bits[:min_header_bits])
    # But file name may be longer — parse to find exact header size
    # We need enough bits for filename length + name
    try:
        # parse partial header: will raise if not enough bytes for filename
        _, payload_len, header_total = parse_header(header_bytes + b'\x00' * 0)
    except ValueError:
        # we need to read more bits to include filename — read some extra incremental approach
        # read first 64k filename worst-case? but safer approach: read first 6 bytes to get fname_len
        first6 = header_bytes[:MAGIC_LEN + 6]
        if first6[:MAGIC_LEN] != MAGIC:
            raise ValueError("Magic header not found — not a supported stego image")
        payload_len = int.from_bytes(first6[MAGIC_LEN:MAGIC_LEN+4], 'big')
        fname_len = int.from_bytes(first6[MAGIC_LEN+4:MAGIC_LEN+6], 'big')
        header_total = MAGIC_LEN + 6 + fname_len

    # Now ensure we have header_total bytes
    header_total_bits = header_total * 8
    if len(bits) < header_total_bits:
        raise ValueError("Image truncated: incomplete header")

    header_all_bytes = bits_to_bytes(bits[:header_total_bits])
    filename, payload_len_check, header_end = parse_header(header_all_bytes)
    payload_len = payload_len_check

    payload_bits_start = header_total_bits
    payload_bits_end = payload_bits_start + payload_len * 8
    if len(bits) < payload_bits_end:
        raise ValueError("Image does not contain full payload bytes")

    payload_bytes = bits_to_bytes(bits[payload_bits_start:payload_bits_end])

    # Optional decryption
    if key_b64:
        fernet = Fernet(key_b64)
        try:
            payload_bytes = fernet.decrypt(payload_bytes)
        except InvalidToken as e:
            raise ValueError("Decryption failed — wrong key or corrupted payload") from e

    out_path = os.path.join(out_folder, filename)
    with open(out_path, "wb") as f:
        f.write(payload_bytes)
    return out_path

# ---------------------------
# Simple Tkinter GUI
# ---------------------------
class StegoGUI:
    def __init__(self, root):
        self.root = root
        root.title("Stego Tool (LSB) — Safe Embed/Extract")
        frame = tk.Frame(root, padx=10, pady=10)
        frame.pack(fill="both", expand=True)

        tk.Label(frame, text="Embed file into image").grid(row=0, column=0, sticky="w", pady=(0,6))

        tk.Button(frame, text="Choose cover image", command=self.choose_cover).grid(row=1, column=0, sticky="w")
        self.cover_lbl = tk.Label(frame, text="No file chosen", anchor="w")
        self.cover_lbl.grid(row=1, column=1, sticky="w")

        tk.Button(frame, text="Choose file to hide", command=self.choose_file).grid(row=2, column=0, sticky="w")
        self.file_lbl = tk.Label(frame, text="No file chosen", anchor="w")
        self.file_lbl.grid(row=2, column=1, sticky="w")

        tk.Label(frame, text="Output stego image path:").grid(row=3, column=0, sticky="w")
        self.out_entry = tk.Entry(frame, width=40)
        self.out_entry.grid(row=3, column=1, sticky="w")
        tk.Button(frame, text="Browse", command=self.choose_out).grid(row=3, column=2, sticky="w")

        tk.Label(frame, text="(Optional) Fernet key for encryption:").grid(row=4, column=0, sticky="w", pady=(8,0))
        self.key_entry = tk.Entry(frame, width=50)
        self.key_entry.grid(row=4, column=1, columnspan=2, sticky="w", pady=(8,0))

        tk.Button(frame, text="Embed", command=self.gui_embed).grid(row=5, column=0, pady=(12,6))
        tk.Button(frame, text="Generate Key", command=self.gui_genkey).grid(row=5, column=1, pady=(12,6), sticky="w")

        tk.Label(frame, text="").grid(row=6, column=0)

        tk.Label(frame, text="Extract file from image").grid(row=7, column=0, sticky="w", pady=(6,6))
        tk.Button(frame, text="Choose stego image", command=self.choose_stego).grid(row=8, column=0, sticky="w")
        self.stego_lbl = tk.Label(frame, text="No file chosen", anchor="w")
        self.stego_lbl.grid(row=8, column=1, sticky="w")

        tk.Label(frame, text="Output directory:").grid(row=9, column=0, sticky="w")
        self.outdir_entry = tk.Entry(frame, width=40)
        self.outdir_entry.grid(row=9, column=1, sticky="w")
        tk.Button(frame, text="Browse", command=self.choose_outdir).grid(row=9, column=2, sticky="w")

        tk.Label(frame, text="(Optional) Fernet key to decrypt:").grid(row=10, column=0, sticky="w", pady=(8,0))
        self.dkey_entry = tk.Entry(frame, width=50)
        self.dkey_entry.grid(row=10, column=1, columnspan=2, sticky="w", pady=(8,0))

        tk.Button(frame, text="Extract", command=self.gui_extract).grid(row=11, column=0, pady=(12,0))

        # internal state
        self.cover = None
        self.infile = None
        self.outpath = None
        self.stego = None
        self.outdir = None

    def choose_cover(self):
        p = filedialog.askopenfilename(filetypes=[("PNG/BMP", "*.png;*.bmp"), ("All files", "*.*")])
        if p:
            self.cover = p
            self.cover_lbl.config(text=os.path.basename(p))

    def choose_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.infile = p
            self.file_lbl.config(text=os.path.basename(p))

    def choose_out(self):
        p = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG","*.png")])
        if p:
            self.outpath = p
            self.out_entry.delete(0, tk.END)
            self.out_entry.insert(0, p)

    def choose_stego(self):
        p = filedialog.askopenfilename(filetypes=[("PNG","*.png"),("All files","*.*")])
        if p:
            self.stego = p
            self.stego_lbl.config(text=os.path.basename(p))

    def choose_outdir(self):
        p = filedialog.askdirectory()
        if p:
            self.outdir = p
            self.outdir_entry.delete(0, tk.END)
            self.outdir_entry.insert(0, p)

    def gui_genkey(self):
        k = Fernet.generate_key().decode()
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, k)
        messagebox.showinfo("Fernet Key", "Generated key placed into the encryption field. Save this key securely!")

    def gui_embed(self):
        try:
            cover = self.cover
            infile = self.infile
            out = self.out_entry.get().strip() or self.outpath
            if not cover or not infile or not out:
                messagebox.showerror("Missing", "Choose cover image, file to hide and output path.")
                return
            key = self.key_entry.get().strip() or None
            key_bytes = key.encode() if key else None
            embed_file_into_image(cover, infile, out, key_b64=key_bytes)
            messagebox.showinfo("Done", f"Embedded {os.path.basename(infile)} into {out}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def gui_extract(self):
        try:
            stego = self.stego
            outdir = self.outdir_entry.get().strip() or self.outdir
            if not stego or not outdir:
                messagebox.showerror("Missing", "Choose stego image and output directory.")
                return
            key = self.dkey_entry.get().strip() or None
            key_bytes = key.encode() if key else None
            out_path = extract_file_from_image(stego, outdir, key_b64=key_bytes)
            messagebox.showinfo("Done", f"Extracted file saved: {out_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

# ---------------------------
# CLI wrapper
# ---------------------------
def gen_key():
    return Fernet.generate_key().decode()

def cli_main():
    parser = argparse.ArgumentParser(description="Safe LSB stego tool (embed/extract files inside PNG/BMP).")
    sub = parser.add_subparsers(dest="cmd")

    p1 = sub.add_parser("embed", help="Embed file")
    p1.add_argument("--cover", required=True, help="Cover image (PNG/BMP recommended)")
    p1.add_argument("--infile", required=True, help="File to hide")
    p1.add_argument("--out", required=True, help="Output stego image (PNG recommended)")
    p1.add_argument("--key", required=False, help="Optional base64 Fernet key for encryption")

    p2 = sub.add_parser("extract", help="Extract hidden file")
    p2.add_argument("--stego", required=True, help="Stego image")
    p2.add_argument("--outdir", required=True, help="Directory for extracted file")
    p2.add_argument("--key", required=False, help="Optional base64 Fernet key used during embedding")

    p3 = sub.add_parser("genkey", help="Generate a Fernet key")

    p4 = sub.add_parser("gui", help="Start GUI")

    args = parser.parse_args()
    if args.cmd == "embed":
        keyb = args.key.encode() if args.key else None
        out = embed_file_into_image(args.cover, args.infile, args.out, key_b64=keyb)
        print(f"Saved stego image: {out}")
    elif args.cmd == "extract":
        keyb = args.key.encode() if args.key else None
        outp = extract_file_from_image(args.stego, args.outdir, key_b64=keyb)
        print(f"Extracted file saved as: {outp}")
    elif args.cmd == "genkey":
        print(gen_key())
    elif args.cmd == "gui":
        root = tk.Tk()
        app = StegoGUI(root)
        root.mainloop()
    else:
        parser.print_help()

if __name__ == "__main__":
    cli_main()
