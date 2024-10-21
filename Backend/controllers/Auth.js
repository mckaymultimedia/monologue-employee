import DataPegawai from '../models/DataPegawaiModel.js';
import argon2 from 'argon2';
import { verifyUser } from '../middleware/AuthUser.js';
import path from 'path';

export const Login = async (req, res) => {
  let user = {};
  const pegawai = await DataPegawai.findOne({
    where: {
      username: req.body.username,
    },
  });

  if (!pegawai) {
    return res.status(404).json({ msg: 'Data Pegawai Tidak Ditemukan' });
  }

  const match = await argon2.verify(pegawai.password, req.body.password);

  if (!match) {
    return res.status(400).json({ msg: 'Password Salah' });
  }

  req.session.userId = pegawai.id_pegawai;

  user = {
    id_pegawai: pegawai.id,
    nama_pegawai: pegawai.nama_pegawai,
    username: pegawai.username,
    hak_akses: pegawai.hak_akses,
  };

  res.status(200).json({
    id_pegawai: user.id_pegawai,
    nama_pegawai: user.nama_pegawai,
    username: user.username,
    hak_akses: user.hak_akses,
    msg: 'Login Berhasil',
  });
};

export const Me = async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ msg: 'Mohon Login ke Akun Anda!' });
  }
  const pegawai = await DataPegawai.findOne({
    attributes: ['id', 'nik', 'nama_pegawai', 'username', 'hak_akses'],
    where: {
      id_pegawai: req.session.userId,
    },
  });
  if (!pegawai) return res.status(404).json({ msg: 'User Tidak di Temukan' });
  res.status(200).json(pegawai);
};

export const LogOut = (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(400).json({ msg: 'Tidak dapat logout' });
    res.status(200).json({ msg: 'Anda Telah Logout' });
  });
};

export const changePassword = async (req, res) => {
  await verifyUser(req, res, () => {});

  const userId = req.userId;

  const user = await DataPegawai.findOne({
    where: {
      id: userId,
    },
  });

  const { password, confPassword } = req.body;

  if (password !== confPassword) return res.status(400).json({ msg: 'Password dan Konfirmasi Password Tidak Cocok' });

  try {
    const hashPassword = await argon2.hash(password);

    await DataPegawai.update(
      {
        password: hashPassword,
      },
      {
        where: {
          id: user.id,
        },
      },
    );
    res.status(200).json({ msg: 'Password Berhasil di Perbarui' });
  } catch (error) {
    res.status(400).json({ msg: error.message });
  }
};

// Register function
export const Register = async (req, res) => {
  const {
    nik,
    nama_pegawai,
    username,
    password,
    confPassword,
    jenis_kelamin,
    jabatan,
    tanggal_masuk,
    status,
    hak_akses,
  } = req.body;

  if (password !== confPassword) {
    return res.status(400).json({ msg: 'Password dan Konfirmasi Password Tidak Cocok' });
  }

  if (!req.files || !req.files.photo) {
    return res.status(400).json({ msg: 'Upload Foto Gagal Silahkan Upload Foto Ulang' });
  }

  const file = req.files.photo;
  const fileSize = file.data.length;
  const ext = path.extname(file.name);
  const fileName = file.md5 + ext;
  const url = `${req.protocol}://${req.get('host')}/images/${fileName}`;
  const allowedTypes = ['.png', '.jpg', '.jpeg'];

  if (!allowedTypes.includes(ext.toLowerCase())) {
    return res.status(422).json({ msg: 'File Foto Tidak Sesuai Dengan Format' });
  }

  if (fileSize > 2000000) {
    return res.status(422).json({ msg: 'Ukuran Gambar Harus Kurang Dari 2 MB' });
  }

  file.mv(`./public/images/${fileName}`, async (err) => {
    if (err) {
      return res.status(500).json({ msg: err.message });
    }

    const hashPassword = await argon2.hash(password);

    try {
      await DataPegawai.create({
        nik: nik,
        nama_pegawai: nama_pegawai,
        username: username,
        password: hashPassword,
        jenis_kelamin: jenis_kelamin,
        jabatan: jabatan,
        tanggal_masuk: tanggal_masuk,
        status: status,
        photo: fileName,
        url: url,
        hak_akses: hak_akses,
      });

      res.status(201).json({ success: true, message: 'Registrasi Berhasil' });
    } catch (error) {
      console.log(error.message);
      res.status(500).json({ success: false, message: error.message });
    }
  });
};
