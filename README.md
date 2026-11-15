# VideoIzin

Aplikasi ringan berbasis Flask untuk mengelola customer, unggahan video lokal, permintaan akses, dan izin menonton dengan masa berlaku.

## Menjalankan dengan Docker

Dari folder proyek:

```sh
docker compose up --build
```

Buka `http://localhost:5000`. Database dan file video dibuat otomatis dan disimpan pada Docker volumes sehingga tetap ada saat container dibuat ulang.

Login awal admin:

- Email: `admin@example.com`
- Kata sandi: `admin12345`

Ganti kredensial bawaan sebelum digunakan bersama pengguna lain. Dapat diatur lewat variabel `ADMIN_EMAIL`, `ADMIN_PASSWORD`, dan `SECRET_KEY` di environment atau file `.env` lokal.

## Alur penggunaan

1. Admin masuk, membuat akun customer, lalu mengunggah file video.
2. Customer masuk dan mengirim permintaan akses video.
3. Admin menyetujui permintaan dengan durasi dalam jam atau menolaknya.
4. Customer dapat menonton hanya selama izin masih aktif. URL media memeriksa izin setiap kali video diminta.

## Fitur

- Dua peran: admin dan customer.
- Admin: CRUD customer, CRUD video (unggah file, bukan URL), tinjau permintaan, dan menetapkan durasi akses.
- Customer: mengajukan permintaan dan menonton video yang disetujui selama masa akses.
- SQLite dengan empat tabel: `users`, `videos`, `access_requests`, dan `video_permissions`.
- File video dibatasi 500 MB; format yang didukung MP4, WebM, MOV, dan M4V.
- Data SQLite dan unggahan disimpan di Docker volumes `app_data` dan `video_uploads`.



