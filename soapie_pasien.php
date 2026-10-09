<?php
session_start();
include 'koneksi.php';

// Pastikan wajib login
$nip = isset($_SESSION['nik']) ? $_SESSION['nik'] : (isset($_SESSION['username']) ? $_SESSION['username'] : '');
if (empty($nip)) {
    header("Location: login.php");
    exit();
}

// Filter Data
$tgl_awal = isset($_GET['tgl_awal']) ? $_GET['tgl_awal'] : date('Y-m-d');
$tgl_akhir = isset($_GET['tgl_akhir']) ? $_GET['tgl_akhir'] : date('Y-m-d');
$status_lanjut = isset($_GET['status_lanjut']) ? $_GET['status_lanjut'] : 'Ranap';
$kd_bangsal = isset($_GET['kd_bangsal']) ? $_GET['kd_bangsal'] : '';
$keyword = isset($_GET['keyword']) ? $_GET['keyword'] : '';

// Ambil daftar bangsal untuk pilihan filter
$list_bangsal = [];
$query_bangsal = "SELECT DISTINCT bangsal.kd_bangsal, bangsal.nm_bangsal 
                  FROM bangsal 
                  INNER JOIN kamar ON bangsal.kd_bangsal = kamar.kd_bangsal 
                  WHERE kamar.statusdata = '1' 
                  ORDER BY bangsal.nm_bangsal ASC";
$res_bangsal = mysqli_query($koneksi, $query_bangsal);
if ($res_bangsal) {
    while ($rb = mysqli_fetch_assoc($res_bangsal)) {
        $list_bangsal[] = $rb;
    }
}


// Proses Simpan Data SOAPIE Baru (Copy & Edit)
$pesan = '';
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['simpan_soapie'])) {
    $no_rawat = mysqli_real_escape_string($koneksi, $_POST['no_rawat']);
    $suhu_tubuh = mysqli_real_escape_string($koneksi, $_POST['suhu_tubuh']);
    $tensi = mysqli_real_escape_string($koneksi, $_POST['tensi']);
    $nadi = mysqli_real_escape_string($koneksi, $_POST['nadi']);
    $respirasi = mysqli_real_escape_string($koneksi, $_POST['respirasi']);
    $tinggi = mysqli_real_escape_string($koneksi, $_POST['tinggi']);
    $berat = mysqli_real_escape_string($koneksi, $_POST['berat']);
    $spo2 = mysqli_real_escape_string($koneksi, $_POST['spo2']);
    $gcs = mysqli_real_escape_string($koneksi, $_POST['gcs']);
    $kesadaran = mysqli_real_escape_string($koneksi, $_POST['kesadaran']);
    $keluhan = mysqli_real_escape_string($koneksi, $_POST['keluhan']);
    $pemeriksaan = mysqli_real_escape_string($koneksi, $_POST['pemeriksaan']);
    $alergi = mysqli_real_escape_string($koneksi, $_POST['alergi']);
    $penilaian = mysqli_real_escape_string($koneksi, $_POST['penilaian']);
    $rtl = mysqli_real_escape_string($koneksi, $_POST['rtl']);
    $instruksi = mysqli_real_escape_string($koneksi, $_POST['instruksi']);
    $evaluasi = mysqli_real_escape_string($koneksi, $_POST['evaluasi']);
    
    $tgl_perawatan = date('Y-m-d');
    $jam_rawat = date('H:i:s');

    $query_insert = "INSERT INTO pemeriksaan_ranap 
                     (no_rawat, tgl_perawatan, jam_rawat, suhu_tubuh, tensi, nadi, respirasi, tinggi, berat, spo2, gcs, kesadaran, keluhan, pemeriksaan, alergi, penilaian, rtl, instruksi, evaluasi, nip) 
                     VALUES 
                     ('$no_rawat', '$tgl_perawatan', '$jam_rawat', '$suhu_tubuh', '$tensi', '$nadi', '$respirasi', '$tinggi', '$berat', '$spo2', '$gcs', '$kesadaran', '$keluhan', '$pemeriksaan', '$alergi', '$penilaian', '$rtl', '$instruksi', '$evaluasi', '$nip')";

    if (mysqli_query($koneksi, $query_insert)) {
        $pesan = "<div style='background:#d4edda;color:#155724;padding:15px;border-radius:8px;margin-bottom:20px;border:1px solid #c3e6cb;font-weight:bold;'>✅ Data SOAPIE berhasil dicopy dan disimpan sebagai record baru.</div>";
    } else {
        $pesan = "<div style='background:#f8d7da;color:#721c24;padding:15px;border-radius:8px;margin-bottom:20px;border:1px solid #f5c6cb;font-weight:bold;'>❌ Gagal menyimpan data: " . htmlspecialchars(mysqli_error($koneksi)) . "</div>";
    }
}

// Query Tampil Data
$search_condition = "";
if (!empty($keyword)) {
    $keyword_esc = mysqli_real_escape_string($koneksi, $keyword);
    $search_condition = " AND (pasien.nm_pasien LIKE '%$keyword_esc%' OR reg_periksa.no_rawat LIKE '%$keyword_esc%' OR pasien.no_rkm_medis LIKE '%$keyword_esc%') ";
}

$bangsal_condition = "";
if (!empty($kd_bangsal)) {
    $kd_bangsal_esc = mysqli_real_escape_string($koneksi, $kd_bangsal);
    $bangsal_condition = " AND (SELECT kamar.kd_bangsal 
                                FROM kamar_inap 
                                INNER JOIN kamar ON kamar_inap.kd_kamar = kamar.kd_kamar 
                                WHERE kamar_inap.no_rawat = reg_periksa.no_rawat 
                                ORDER BY kamar_inap.tgl_masuk DESC, kamar_inap.jam_masuk DESC 
                                LIMIT 1) = '$kd_bangsal_esc' ";
}

$query_tampil = "SELECT
    reg_periksa.no_rawat,
    pasien.no_rkm_medis,
    pasien.nm_pasien,
    pemeriksaan_ranap.tgl_perawatan,
    pemeriksaan_ranap.jam_rawat,
    pemeriksaan_ranap.suhu_tubuh,
    pemeriksaan_ranap.tensi,
    pemeriksaan_ranap.nadi,
    pemeriksaan_ranap.respirasi,
    pemeriksaan_ranap.tinggi,
    pemeriksaan_ranap.berat,
    pemeriksaan_ranap.spo2,
    pemeriksaan_ranap.gcs,
    pemeriksaan_ranap.kesadaran,
    pemeriksaan_ranap.keluhan,
    pemeriksaan_ranap.pemeriksaan,
    pemeriksaan_ranap.alergi,
    pemeriksaan_ranap.penilaian,
    pemeriksaan_ranap.rtl,
    pemeriksaan_ranap.instruksi,
    pemeriksaan_ranap.evaluasi,
    pegawai.nama AS nama_petugas,
    (SELECT bangsal.nm_bangsal 
     FROM kamar_inap 
     INNER JOIN kamar ON kamar_inap.kd_kamar = kamar.kd_kamar 
     INNER JOIN bangsal ON kamar.kd_bangsal = bangsal.kd_bangsal 
     WHERE kamar_inap.no_rawat = reg_periksa.no_rawat 
     ORDER BY kamar_inap.tgl_masuk DESC, kamar_inap.jam_masuk DESC 
     LIMIT 1) AS nm_bangsal,
    (SELECT kamar_inap.kd_kamar 
     FROM kamar_inap 
     WHERE kamar_inap.no_rawat = reg_periksa.no_rawat 
     ORDER BY kamar_inap.tgl_masuk DESC, kamar_inap.jam_masuk DESC 
     LIMIT 1) AS kd_kamar
    FROM pemeriksaan_ranap
    INNER JOIN reg_periksa ON pemeriksaan_ranap.no_rawat = reg_periksa.no_rawat
    INNER JOIN pasien ON reg_periksa.no_rkm_medis = pasien.no_rkm_medis
    INNER JOIN pegawai ON pemeriksaan_ranap.nip = pegawai.nik
    WHERE pemeriksaan_ranap.tgl_perawatan BETWEEN '$tgl_awal' AND '$tgl_akhir' 
    AND reg_periksa.status_lanjut = '$status_lanjut' $bangsal_condition $search_condition
    ORDER BY pemeriksaan_ranap.tgl_perawatan DESC, pemeriksaan_ranap.jam_rawat DESC";

$result = mysqli_query($koneksi, $query_tampil);

?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOAPIE Pasien - RSUD Pringsewu</title>
    <style>
        /* Gaya dasar */
        * { box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f4f6f9; margin: 0; padding: 20px; color: #333; }
        .container { background: #fff; padding: 25px; border-radius: 10px; box-shadow: 0 5px 15px rgba(0,0,0,0.05); max-width: 100%; margin: auto; }
        h2 { border-bottom: 3px solid #007bff; padding-bottom: 15px; margin-top: 0; margin-bottom: 25px; color: #2c3e50; }
        .form-filter { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 25px; border: 1px solid #e9ecef; display: flex; gap: 20px; align-items: center; flex-wrap: wrap; }
        .filter-group { display: flex; flex-direction: column; gap: 8px; }
        .filter-group label { font-weight: bold; color: #495057; font-size: 14px; }
        .form-filter input, .form-filter select { padding: 10px; border: 1px solid #ced4da; border-radius: 5px; font-size: 14px; min-width: 150px; }
        .btn-primary { background: linear-gradient(45deg, #007bff, #0056b3); color: #fff; border: none; cursor: pointer; font-weight: bold; padding: 10px 20px; border-radius: 5px; transition: 0.3s; }
        .btn-primary:hover { opacity: 0.9; transform: translateY(-1px); }
        .table-container { overflow-x: auto; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; background: white; }
        th, td { border-bottom: 1px solid #dee2e6; padding: 12px 15px; text-align: left; font-size: 14px; }
        th { background: #343a40; color: #fff; white-space: nowrap; }
        tr:nth-child(even) td { background: #f8f9fa; }
        tr:hover td { background: #e9ecef; }
        
        /* Modal Edit SOAPIE */
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.6); }
        .modal-content { background-color: #fff; margin: 3% auto; padding: 30px; border: none; width: 90%; border-radius: 12px; max-width: 900px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); position: relative; animation: modalopen 0.4s; }
        @keyframes modalopen { from { opacity: 0; transform: translateY(-50px); } to { opacity: 1; transform: translateY(0); } }
        .close { color: #aaa; position: absolute; right: 25px; top: 20px; font-size: 28px; font-weight: bold; cursor: pointer; transition: 0.2s; }
        .close:hover { color: #dc3545; }
        .modal-title { margin-top: 0; margin-bottom: 20px; color: #007bff; border-bottom: 2px solid #eee; padding-bottom: 15px; }
        
        .form-group { margin-bottom: 18px; }
        .form-group label { display: block; font-weight: bold; margin-bottom: 8px; color: #495057; font-size: 14px; }
        .form-group input, .form-group textarea { width: 100%; padding: 10px 12px; border: 1px solid #ced4da; border-radius: 6px; font-family: inherit; font-size: 14px; transition: border-color 0.3s; }
        .form-group input:focus, .form-group textarea:focus { outline: none; border-color: #007bff; box-shadow: 0 0 5px rgba(0,123,255,0.2); }
        .form-row { display: flex; gap: 20px; flex-wrap: wrap; }
        .form-row .form-group { flex: 1; min-width: 150px; }
        .alert-info { background: #e2e3e5; padding: 12px 15px; border-radius: 6px; margin-bottom: 20px; font-size: 14px; color: #383d41; border: 1px solid #d6d8db; }
    </style>
</head>
<body>

<div class="container">
    <h2>Daftar SOAPIE Pasien</h2>
    
    <?php echo $pesan; ?>

    <form method="GET" class="form-filter">
        <div class="filter-group">
            <label>Tanggal Awal</label>
            <input type="date" name="tgl_awal" value="<?php echo htmlspecialchars($tgl_awal); ?>" required>
        </div>
        
        <div class="filter-group">
            <label>Tanggal Akhir</label>
            <input type="date" name="tgl_akhir" value="<?php echo htmlspecialchars($tgl_akhir); ?>" required>
        </div>
        
        <div class="filter-group">
            <label>Status Lanjut</label>
            <select name="status_lanjut">
                <option value="Ranap" <?php if($status_lanjut == 'Ranap') echo 'selected'; ?>>Ranap</option>
                <option value="Ralan" <?php if($status_lanjut == 'Ralan') echo 'selected'; ?>>Ralan</option>
            </select>
        </div>
        
        <div class="filter-group">
            <label>Bangsal</label>
            <select name="kd_bangsal">
                <option value="">-- Semua Bangsal --</option>
                <?php foreach ($list_bangsal as $b): ?>
                    <option value="<?php echo htmlspecialchars($b['kd_bangsal']); ?>" <?php if($kd_bangsal == $b['kd_bangsal']) echo 'selected'; ?>>
                        <?php echo htmlspecialchars($b['nm_bangsal']); ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </div>
        
        <div class="filter-group">
            <label>Pencarian</label>
            <input type="text" name="keyword" value="<?php echo htmlspecialchars($keyword); ?>" placeholder="Nama / No RM / No Rawat">
        </div>
        
        <div class="filter-group" style="justify-content: flex-end;">
            <button type="submit" class="btn-primary">🔍 Tampilkan</button>
        </div>
    </form>

    <div class="table-container">
        <table>
            <thead>
                <tr>
                    <th>No. Rawat</th>
                    <th>No. RM</th>
                    <th>Nama Pasien</th>
                    <th>Bangsal / Kamar</th>
                    <th>Tgl / Jam</th>
                    <th>Petugas (Asal)</th>
                    <th>Keluhan (S)</th>
                    <th>Pemeriksaan (O)</th>
                    <th>Penilaian (A)</th>
                    <th>Instruksi (P)</th>
                    <th style="text-align:center;">Aksi</th>
                </tr>
            </thead>
            <tbody>
                <?php 
                if ($result && mysqli_num_rows($result) > 0) {
                    while ($row = mysqli_fetch_assoc($result)) {
                        // Data JSON untuk copy
                        $data_json = htmlspecialchars(json_encode($row), ENT_QUOTES, 'UTF-8');
                        ?>
                        <tr>
                            <td style="font-family: monospace; font-weight: bold;"><?php echo htmlspecialchars($row['no_rawat']); ?></td>
                            <td style="font-family: monospace;"><?php echo htmlspecialchars($row['no_rkm_medis']); ?></td>
                            <td><?php echo htmlspecialchars($row['nm_pasien']); ?></td>
                            <td>
                                <strong><?php echo htmlspecialchars(!empty($row['nm_bangsal']) ? $row['nm_bangsal'] : '-'); ?></strong>
                                <?php if (!empty($row['kd_kamar'])): ?>
                                    <br><small style="color: #6c757d; font-family: monospace;"><?php echo htmlspecialchars($row['kd_kamar']); ?></small>
                                <?php endif; ?>
                            </td>
                            <td><?php echo htmlspecialchars($row['tgl_perawatan'] . ' ' . $row['jam_rawat']); ?></td>
                            <td><?php echo htmlspecialchars($row['nama_petugas']); ?></td>
                            <td style="max-width: 200px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="<?php echo htmlspecialchars($row['keluhan']); ?>"><?php echo htmlspecialchars($row['keluhan']); ?></td>
                            <td style="max-width: 200px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="<?php echo htmlspecialchars($row['pemeriksaan']); ?>"><?php echo htmlspecialchars($row['pemeriksaan']); ?></td>
                            <td style="max-width: 150px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="<?php echo htmlspecialchars($row['penilaian']); ?>"><?php echo htmlspecialchars($row['penilaian']); ?></td>
                            <td style="max-width: 150px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="<?php echo htmlspecialchars($row['instruksi']); ?>"><?php echo htmlspecialchars($row['instruksi']); ?></td>
                            <td style="text-align:center;">
                                <button class="btn-primary" onclick="bukaModalCopy(<?php echo $data_json; ?>)">📝 Copy & Edit</button>
                            </td>
                        </tr>
                        <?php
                    }
                } else {
                    echo "<tr><td colspan='11' style='text-align:center; padding: 30px; color: #6c757d; font-style: italic;'>Tidak ada data SOAPIE pada kriteria yang dipilih.</td></tr>";
                }
                ?>
            </tbody>
        </table>
    </div>
</div>

<!-- Modal Copy SOAPIE -->
<div id="modalSoapie" class="modal">
    <div class="modal-content">
        <span class="close" onclick="tutupModal()">&times;</span>
        <h3 class="modal-title">Copy & Edit SOAPIE Pasien</h3>
        
        <div class="alert-info">
            <span style="font-size: 18px;">ℹ️</span> Anda akan menyalin data SOAPIE pasien <strong><span id="mdl_nm_pasien"></span></strong> (<span id="mdl_no_rm_display"></span>)<span id="mdl_bangsal_display"></span>. <br>
            Data yang disimpan akan tercatat sebagai record baru dengan tanggal & jam saat ini, atas nama Petugas (NIK): <strong><?php echo htmlspecialchars($nip); ?></strong>.
        </div>
        
        <form method="POST" action="">
            <input type="hidden" name="no_rawat" id="mdl_no_rawat">
            
            <h4 style="border-bottom: 1px solid #dee2e6; padding-bottom: 5px; color: #495057;">Tanda-Tanda Vital</h4>
            <div class="form-row">
                <div class="form-group">
                    <label>Suhu Tubuh (°C)</label>
                    <input type="text" name="suhu_tubuh" id="mdl_suhu_tubuh">
                </div>
                <div class="form-group">
                    <label>Tensi</label>
                    <input type="text" name="tensi" id="mdl_tensi">
                </div>
                <div class="form-group">
                    <label>Nadi (x/mnt)</label>
                    <input type="text" name="nadi" id="mdl_nadi">
                </div>
                <div class="form-group">
                    <label>Respirasi (x/mnt)</label>
                    <input type="text" name="respirasi" id="mdl_respirasi">
                </div>
            </div>
            
            <div class="form-row">
                <div class="form-group">
                    <label>Tinggi Badan (cm)</label>
                    <input type="text" name="tinggi" id="mdl_tinggi">
                </div>
                <div class="form-group">
                    <label>Berat Badan (kg)</label>
                    <input type="text" name="berat" id="mdl_berat">
                </div>
                <div class="form-group">
                    <label>SpO2 (%)</label>
                    <input type="text" name="spo2" id="mdl_spo2">
                </div>
                <div class="form-group">
                    <label>GCS</label>
                    <input type="text" name="gcs" id="mdl_gcs">
                </div>
            </div>

            <div class="form-row">
                <div class="form-group">
                    <label>Kesadaran</label>
                    <input type="text" name="kesadaran" id="mdl_kesadaran">
                </div>
                <div class="form-group">
                    <label>Alergi</label>
                    <input type="text" name="alergi" id="mdl_alergi">
                </div>
            </div>

            <h4 style="border-bottom: 1px solid #dee2e6; padding-bottom: 5px; color: #495057; margin-top: 20px;">Data SOAPIE</h4>
            <div class="form-group">
                <label>Subjek / Keluhan (S)</label>
                <textarea name="keluhan" id="mdl_keluhan" rows="3" required></textarea>
            </div>
            
            <div class="form-group">
                <label>Objek / Pemeriksaan (O)</label>
                <textarea name="pemeriksaan" id="mdl_pemeriksaan" rows="3"></textarea>
            </div>
            
            <div class="form-group">
                <label>Assessment / Penilaian (A)</label>
                <textarea name="penilaian" id="mdl_penilaian" rows="3"></textarea>
            </div>
            
            <div class="form-group">
                <label>Plan / Instruksi (P)</label>
                <textarea name="instruksi" id="mdl_instruksi" rows="3"></textarea>
            </div>
            
            <div class="form-group">
                <label>Rencana Tindak Lanjut (RTL)</label>
                <textarea name="rtl" id="mdl_rtl" rows="2"></textarea>
            </div>
            
            <div class="form-group">
                <label>Evaluasi</label>
                <textarea name="evaluasi" id="mdl_evaluasi" rows="2"></textarea>
            </div>
            
            <div style="text-align: right; margin-top: 30px;">
                <button type="button" class="btn-primary" style="background: #6c757d; margin-right: 10px;" onclick="tutupModal()">Batal</button>
                <button type="submit" name="simpan_soapie" class="btn-primary" style="padding: 12px 30px; font-size: 16px;">💾 Simpan Data Baru</button>
            </div>
        </form>
    </div>
</div>

<script>
    var modal = document.getElementById("modalSoapie");

    function bukaModalCopy(data) {
        // Info Header Modal
        document.getElementById('mdl_nm_pasien').innerText = data.nm_pasien;
        document.getElementById('mdl_no_rm_display').innerText = data.no_rkm_medis;
        var bangsalText = data.nm_bangsal ? ' - Bangsal: ' + data.nm_bangsal + (data.kd_kamar ? ' (' + data.kd_kamar + ')' : '') : '';
        document.getElementById('mdl_bangsal_display').innerText = bangsalText;
        
        // Isi form dengan data
        document.getElementById('mdl_no_rawat').value = data.no_rawat;
        document.getElementById('mdl_suhu_tubuh').value = data.suhu_tubuh;
        document.getElementById('mdl_tensi').value = data.tensi;
        document.getElementById('mdl_nadi').value = data.nadi;
        document.getElementById('mdl_respirasi').value = data.respirasi;
        document.getElementById('mdl_tinggi').value = data.tinggi;
        document.getElementById('mdl_berat').value = data.berat;
        document.getElementById('mdl_spo2').value = data.spo2;
        document.getElementById('mdl_gcs').value = data.gcs;
        document.getElementById('mdl_kesadaran').value = data.kesadaran;
        document.getElementById('mdl_alergi').value = data.alergi;
        
        document.getElementById('mdl_keluhan').value = data.keluhan;
        document.getElementById('mdl_pemeriksaan').value = data.pemeriksaan;
        document.getElementById('mdl_penilaian').value = data.penilaian;
        document.getElementById('mdl_instruksi').value = data.instruksi;
        document.getElementById('mdl_rtl').value = data.rtl;
        document.getElementById('mdl_evaluasi').value = data.evaluasi;
        
        modal.style.display = "block";
    }

    function tutupModal() {
        modal.style.display = "none";
    }

    window.onclick = function(event) {
        if (event.target == modal) {
            modal.style.display = "none";
        }
    }
</script>

</body>
</html>
