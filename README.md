# Portable Cipher Studio

A minimalist desktop app for encrypting and decrypting files or folders with a modern monochrome UI. Built with Python + Tkinter so it runs without extra packaging; just install the dependencies and start the app.

## Fitur utama
- Pilih file **atau folder** dan lihat preview (gambar atau teks) sebelum diproses.
- Deteksi otomatis file terenkripsi berkat header khusus sehingga mode dekripsi aktif otomatis.
- Pilihan algoritma: **AES-256-GCM** atau **ChaCha20-Poly1305** dengan KDF PBKDF2-HMAC-SHA256.
- Header terstruktur menyimpan nama asli, tipe (file/folder), nonce, dan salt untuk dekripsi aman.
- Tombol **GO** berdesain minimalis, toggle tampilkan/sembunyikan password, dan status proses real-time.

## Menjalankan secara lokal
Pastikan Python 3.10+ tersedia.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
# jalankan dari root repo agar impor paket bekerja
python -m src.app
```

## Cara pakai
1. Klik **Choose file/folder** lalu pilih berkas atau direktori yang ingin diproses.
2. Masukkan password. Toggle "Tampilkan" untuk melihat/menyembunyikan input.
3. Pilih **Enkripsi** atau **Dekripsi** (akan otomatis berpindah ke dekripsi jika file memiliki header CXENC01).
4. Pilih algoritma yang diinginkan.
5. Tekan tombol **GO**.
   - Enkripsi akan membuat file baru dengan sufiks `.enc`.
   - Dekripsi akan menulis kembali berkas asli (atau mengekstrak folder) di lokasi yang sama.

## Catatan keamanan
- Gunakan password kuat; kunci dis derivasi dengan 390k iterasi PBKDF2-HMAC-SHA256.
- Header tidak dienkripsi (agar bisa dideteksi), jadi nama asli terlihat—hindari menyimpan info sensitif di nama file.
- Simpan cadangan sebelum mengenkripsi data penting.
