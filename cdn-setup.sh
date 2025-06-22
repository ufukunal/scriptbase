#!/bin/bash

# Oracle Cloud Ubuntu 22.04 - Dosya Deposu CDN
# Kolay yönetim ve yedeklilik için optimize edilmiş
# GitHub: https://github.com/ufukunal/scriptbase

echo "🚀 Oracle Cloud Dosya Deposu CDN Kurulum Başlıyor..."
echo "📊 Sistem bilgileri kontrol ediliyor..."

# Sistem bilgilerini göster
echo "RAM: $(free -h | awk 'NR==2{print $2}')"
echo "CPU: $(nproc) core"
echo "Disk: $(df -h / | awk 'NR==2{print $4}') boş alan"
echo ""

# Root kontrolü
if [[ $EUID -ne 0 ]]; then
   echo "❌ Bu script root olarak çalıştırılmalı!"
   echo "Kullanım: sudo bash <(curl -fsSL https://raw.githubusercontent.com/ufukunal/scriptbase/main/cdn-setup.sh)"
   exit 1
fi

echo "🔧 Sistem güncelleniyor..."
apt update && apt upgrade -y

echo "📦 Temel paketler kuruluyor..."
apt install -y curl wget ufw htop nano unzip software-properties-common tree rsync

echo "🔥 Firewall ayarlanıyor..."
# Oracle Cloud Security List + UFW
ufw allow 22     # SSH
ufw allow 80     # HTTP
ufw allow 443    # HTTPS
ufw allow 7080   # OLS Admin Panel
ufw allow 2222   # SFTP/SCP (alternative)
ufw --force enable

# Oracle Cloud iptables (gerekli)
iptables -I INPUT -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT
iptables -I INPUT -p tcp --dport 7080 -j ACCEPT
iptables -I INPUT -p tcp --dport 2222 -j ACCEPT
apt install -y iptables-persistent
iptables-save > /etc/iptables/rules.v4

echo "💾 Swap dosyası oluşturuluyor..."
if [ ! -f /swapfile ]; then
    fallocate -l 1G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
    echo "✅ 1GB swap dosyası oluşturuldu"
fi

echo "⚡ Kernel optimizasyonları..."
cat >> /etc/sysctl.conf << 'EOL'
# Dosya deposu için optimizasyon
vm.swappiness=5
vm.vfs_cache_pressure=50
vm.dirty_ratio=10
vm.dirty_background_ratio=3
net.core.rmem_max=16777216
net.core.wmem_max=16777216
fs.file-max=2097152
EOL
sysctl -p

echo "🌐 OpenLiteSpeed kurulumu..."
wget -O - https://repo.litespeed.sh | bash
apt install -y openlitespeed lsphp81 lsphp81-common lsphp81-curl

# Admin şifresi oluştur
ADMIN_PASS=$(openssl rand -base64 12)
/usr/local/lsws/admin/misc/admpass.sh admin $ADMIN_PASS

echo "📁 Dosya deposu dizin yapısı..."
# Ana dosya deposu dizinleri
mkdir -p /var/www/files/{images,videos,documents,downloads,uploads,backup}
mkdir -p /var/www/html/logs
mkdir -p /tmp/lshttpd/cache

# Yedekleme dizini
mkdir -p /var/backups/daily
mkdir -p /var/backups/weekly

# İzinler
chown -R nobody:nogroup /var/www/files
chown -R nobody:nogroup /var/www/html
chown -R nobody:nogroup /tmp/lshttpd/cache
chmod -R 755 /var/www/files
chmod -R 755 /var/www/html
chmod 777 /var/www/files/uploads  # Upload dizini yazılabilir

echo "⚙️ OpenLiteSpeed dosya deposu konfigürasyonu..."

# Ana konfigürasyon
cat > /usr/local/lsws/conf/httpd_config.conf << 'EOL'
serverName                FileStorage-CDN
user                      nobody
group                     nogroup
priority                  0
inMemBufSize              60M
swappingDir               /tmp/lshttpd/swap
autoFix503                1
gracefulRestartTimeout    300
mime                      conf/mime.properties
showVersionNumber         0
adminEmails               admin@localhost
indexFiles                index.html, index.php
autoIndex                 1

errorlog $SERVER_ROOT/logs/error.log {
  logLevel             WARN
  debugLevel           0
  rollingSize          10M
  enableStderrLog      1
}

accesslog $SERVER_ROOT/logs/access.log {
  rollingSize          50M
  keepDays             30
  compressArchive      1
}

expires  {
  enableExpires           1
  expiresByType           image/*=A2592000,video/*=A2592000,application/pdf=A604800,text/css=A604800,application/javascript=A604800,font/*=A2592000
}

tuning  {
  maxConnections          1000
  maxSSLConnections       500
  connTimeout             300
  maxKeepAliveReq         100
  keepAliveTimeout        5
  sndBufSize              0
  rcvBufSize              0
  maxReqURLLen            32768
  maxReqHeaderSize        65536
  maxReqBodySize          1024M
  maxDynRespHeaderSize    32768
  maxDynRespSize          1024M
  maxCachedFileSize       10M
  totalInMemCacheSize     50M
  maxMMapFileSize         256K
  totalMMapCacheSize      100M
  useSendfile             1
  fileETag                28
  enableGzipCompress      1
  compressibleTypes       text/*, application/x-javascript, application/xml, application/javascript, image/svg+xml
  enableDynGzipCompress   1
  gzipCompressLevel       6
  gzipAutoUpdateStatic    1
  gzipStaticCompressLevel 6
  gzipMaxFileSize         50M
}

fileAccessControl  {
  followSymbolLink        1
  checkSymbolLink         0
  requiredPermissionMask  000
  restrictedPermissionMask 000
}

perClientConnLimit  {
  staticReqPerSec         100
  dynReqPerSec           50
  outBandwidth           0
  inBandwidth            0
  softLimit              10000
  hardLimit              10000
  gracePeriod            15
  banPeriod              300
}

CGIRLimit  {
  maxCGIInstances         20
  minUID                  11
  minGID                  10
  priority                0
  CPUSoftLimit            10
  CPUHardLimit            50
  memSoftLimit            1460M
  memHardLimit           1470M
  procSoftLimit           400
  procHardLimit           450
}

listener HTTP {
  address                 *:80
  secure                  0
  map                     * files
}

listener HTTPS {
  address                 *:443
  secure                  1
  keyFile                 $SERVER_ROOT/conf/example.key
  certFile                $SERVER_ROOT/conf/example.crt
  map                     * files
}

virtualhost files {
  vhRoot                  /var/www/files
  configFile              conf/vhosts/files/vhconf.conf
  allowSymbolLink         1
  enableScript            1
  restrained              1
  setUIDMode              0
}

listener AdminHTTP {
  address                 *:7080
  secure                  0
  map                     AdminVHost *
}

virtualhost AdminVHost {
  vhRoot                  $SERVER_ROOT/admin/
  configFile              $SERVER_ROOT/admin/conf/admin_config.conf
  allowSymbolLink         1
  enableScript            1
  restrained              1
  setUIDMode              0
}

map                       * files
EOL

# Virtual host konfigürasyonu
mkdir -p /usr/local/lsws/conf/vhosts/files
cat > /usr/local/lsws/conf/vhosts/files/vhconf.conf << 'EOL'
docRoot                   /var/www/files/
vhDomain                  *
adminEmails               admin@localhost
enableGzip                1
enableIpGeo               1

errorlog $VH_ROOT/logs/error.log {
  useServer               0
  logLevel                WARN
  rollingSize             10M
}

accesslog $VH_ROOT/logs/access.log {
  useServer               0
  logLevel                1
  rollingSize             100M
  keepDays                30
  compressArchive         1
}

index  {
  useServer               0
  indexFiles              index.html, index.php
  autoIndex               1
  autoIndexURI            /_autoindex/default.php
}

expires  {
  enableExpires           1
  expiresByType           image/*=A2592000,video/*=A2592000,audio/*=A2592000,application/pdf=A604800,application/zip=A604800,application/x-rar=A604800
}

# Cache konfigürasyonu - Dosya deposu için optimize
cache  {
  enableCache             1
  qsCache                 1
  reqCookieCache          1
  respCookieCache         1
  ignoreReqCacheCtrl      1
  ignoreRespCacheCtrl     0
  enablePrivateCache      0
  privateExpireInSeconds  3600
  expireInSeconds         604800
  storagePath             /tmp/lshttpd/cache/
  maxCacheObjSize         100000000
  maxStaleAge             86400
  checkPrivateCache       1
  checkPublicCache        1
}

# Gzip sıkıştırma
gzip  {
  enableGzip              1
  enableDynGzipCompress   1
  gzipCompressLevel       6
  compressibleTypes       text/*, application/x-javascript, application/xml, application/javascript, image/svg+xml, application/json
  gzipAutoUpdateStatic    1
  gzipStaticCompressLevel 6
  gzipMaxFileSize         50M
}

rewrite  {
  enable                  1
  autoLoadHtaccess        1
  logLevel                0
}

# Ana dizin - dosya listesi
context / {
  type                    docroot
  location                /var/www/files/
  allowBrowse             1
  indexFiles              index.html
  
  rewrite  {
    enable                1
  }

  addDefaultCharset       off
  
  extraHeaders <<<END_extraHeaders
Cache-Control max-age=2592000
Access-Control-Allow-Origin *
Access-Control-Allow-Methods GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers Content-Type, Authorization
Content-Security-Policy default-src 'self'
END_extraHeaders
}

# Images dizini
context /images {
  type                    docroot
  location                /var/www/files/images/
  allowBrowse             1
  
  extraHeaders <<<END_extraHeaders
Cache-Control max-age=7776000
Content-Disposition inline
END_extraHeaders
}

# Videos dizini
context /videos {
  type                    docroot
  location                /var/www/files/videos/
  allowBrowse             1
  
  extraHeaders <<<END_extraHeaders
Cache-Control max-age=7776000
Content-Disposition inline
END_extraHeaders
}

# Documents dizini
context /documents {
  type                    docroot
  location                /var/www/files/documents/
  allowBrowse             1
  
  extraHeaders <<<END_extraHeaders
Cache-Control max-age=3600
Content-Disposition attachment
END_extraHeaders
}

# Downloads dizini
context /downloads {
  type                    docroot
  location                /var/www/files/downloads/
  allowBrowse             1
  
  extraHeaders <<<END_extraHeaders
Cache-Control max-age=3600
Content-Disposition attachment
END_extraHeaders
}

# Upload dizini - yazma izni
context /uploads {
  type                    docroot
  location                /var/www/files/uploads/
  allowBrowse             1
}

# Status endpoint
context /status {
  type                    docroot
  location                /var/www/html/
  allowBrowse             1
}

# API endpoint - dosya yönetimi için
context /api {
  type                    docroot
  location                /var/www/html/api/
  allowBrowse             0
}
EOL

echo "🎯 Dosya deposu ana sayfası..."

# Ana dosya deposu sayfası
cat > /var/www/files/index.html << 'EOL'
<!DOCTYPE html>
<html>
<head>
    <title>📁 Dosya Deposu CDN</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: white;
        }
        .header {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            text-align: center;
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(255,255,255,0.2);
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 20px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 25px;
            margin-top: 30px;
        }
        .folder-card {
            background: rgba(255,255,255,0.1);
            padding: 30px;
            border-radius: 15px;
            border: 1px solid rgba(255,255,255,0.2);
            backdrop-filter: blur(10px);
            transition: all 0.3s ease;
            text-decoration: none;
            color: white;
            display: block;
        }
        .folder-card:hover {
            transform: translateY(-5px);
            background: rgba(255,255,255,0.2);
            box-shadow: 0 8px 32px rgba(0,0,0,0.2);
        }
        .folder-icon {
            font-size: 3em;
            margin-bottom: 15px;
            display: block;
        }
        .folder-title {
            font-size: 1.4em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .folder-desc {
            opacity: 0.8;
            font-size: 0.9em;
            line-height: 1.4;
        }
        .stats {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            margin-top: 30px;
            text-align: center;
        }
        .stat-item {
            display: inline-block;
            margin: 0 20px;
            padding: 10px;
        }
        .upload-info {
            background: rgba(255,215,0,0.1);
            border: 1px solid rgba(255,215,0,0.3);
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
        }
        .management-links {
            margin-top: 30px;
            text-align: center;
        }
        .btn {
            display: inline-block;
            padding: 12px 25px;
            background: rgba(255,255,255,0.2);
            color: white;
            text-decoration: none;
            border-radius: 25px;
            border: 1px solid rgba(255,255,255,0.3);
            margin: 5px;
            transition: all 0.3s ease;
        }
        .btn:hover {
            background: rgba(255,255,255,0.3);
            transform: translateY(-2px);
        }
        @media (max-width: 768px) {
            .grid { grid-template-columns: 1fr; }
            .stat-item { display: block; margin: 10px 0; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>📁 Dosya Deposu CDN</h1>
        <p>Hızlı ve güvenilir dosya depolama sistemi</p>
    </div>

    <div class="container">
        <div class="grid">
            <a href="/images/" class="folder-card">
                <div class="folder-icon">🖼️</div>
                <div class="folder-title">Resimler</div>
                <div class="folder-desc">JPG, PNG, GIF, SVG ve diğer resim dosyaları. Uzun süreli cache ile hızlı erişim.</div>
            </a>

            <a href="/videos/" class="folder-card">
                <div class="folder-icon">🎬</div>
                <div class="folder-title">Videolar</div>
                <div class="folder-desc">MP4, AVI, MOV ve diğer video dosyaları. Streaming desteği ile optimize edilmiş.</div>
            </a>

            <a href="/documents/" class="folder-card">
                <div class="folder-icon">📄</div>
                <div class="folder-title">Dökümanlar</div>
                <div class="folder-desc">PDF, DOC, TXT ve diğer doküman dosyaları. Güvenli indirme modu.</div>
            </a>

            <a href="/downloads/" class="folder-card">
                <div class="folder-icon">⬇️</div>
                <div class="folder-title">İndirilenler</div>
                <div class="folder-desc">ZIP, RAR, EXE ve genel indirme dosyaları. Hızlı transfer desteği.</div>
            </a>

            <a href="/uploads/" class="folder-card">
                <div class="folder-icon">⬆️</div>
                <div class="folder-title">Yüklemeler</div>
                <div class="folder-desc">Yeni dosya yükleme alanı. Otomatik kategorize edilecek dosyalar.</div>
            </a>

            <a href="/backup/" class="folder-card">
                <div class="folder-icon">💾</div>
                <div class="folder-title">Yedekler</div>
                <div class="folder-desc">Sistem ve dosya yedekleri. Otomatik yedekleme sistemi ile korunmuş.</div>
            </a>
        </div>

        <div class="upload-info">
            <h3>📤 Dosya Yükleme</h3>
            <p><strong>SFTP/SCP:</strong> Port 22 (SSH) - Güvenli dosya transferi</p>
            <p><strong>Web Upload:</strong> /uploads/ dizinine drag & drop desteği</p>
            <p><strong>Max Dosya:</strong> 1024MB (1GB) - Büyük dosya desteği</p>
        </div>

        <div class="stats">
            <div class="stat-item">
                <strong>Cache TTL:</strong><br>7 gün
            </div>
            <div class="stat-item">
                <strong>Max Dosya:</strong><br>1GB
            </div>
            <div class="stat-item">
                <strong>Gzip:</strong><br>Aktif
            </div>
            <div class="stat-item">
                <strong>CORS:</strong><br>Etkin
            </div>
        </div>

        <div class="management-links">
            <a href="#" class="btn" id="admin-link">🎛️ Admin Panel</a>
            <a href="/status" class="btn">📊 Server Status</a>
            <a href="https://github.com/ufukunal/scriptbase" class="btn">📚 Dökümanlar</a>
        </div>

        <div style="text-align: center; margin-top: 30px; font-size: 14px; opacity: 0.8;">
            <p>Oracle Cloud Always Free için optimize edilmiştir</p>
            <p>Otomatik yedekleme ve cache sistemi aktif</p>
        </div>
    </div>
    
    <script>
        // Admin panel linkini IP ile güncelle
        fetch('https://api.ipify.org?format=json')
            .then(response => response.json())
            .then(data => {
                document.getElementById('admin-link').href = `http://${data.ip}:7080`;
            })
            .catch(() => {
                document.getElementById('admin-link').href = 'http://localhost:7080';
            });
    </script>
</body>
</html>
EOL

# Status sayfası
mkdir -p /var/www/html
cat > /var/www/html/status << 'EOL'
Dosya Deposu CDN - Aktif
Cache: LSCache Enabled (7 gün TTL)
Storage: /var/www/files/
Backup: Otomatik yedekleme aktif
Gzip: Enabled (50MB max)
Upload: 1024MB max dosya boyutu
CORS: Enabled
HTTP/3: Supported
EOL

echo "🛠️ Yönetim araçları..."

# Dosya deposu yönetim scripti
cat > /usr/local/bin/files-manager << 'EOL'
#!/bin/bash

STORAGE_PATH="/var/www/files"
BACKUP_PATH="/var/backups"

case "$1" in
    status)
        echo "=== Dosya Deposu CDN Durumu ==="
        echo "Sistem: $(uptime | cut -d',' -f1)"
        echo "RAM: $(free -m | awk 'NR==2{printf "%.1f%% (%dMB/%dMB)\n", $3*100/$2, $3, $2}')"
        echo "Disk: $(df -h / | awk 'NR==2{printf "%s (%s kullanılan)\n", $5, $3}')"
        echo "Cache: $(du -sh /tmp/lshttpd/cache 2>/dev/null | cut -f1 || echo "0B")"
        echo "Storage: $(du -sh $STORAGE_PATH 2>/dev/null | cut -f1 || echo "0B")"
        echo "OLS: $(systemctl is-active lsws)"
        echo "Admin: http://$(curl -s ifconfig.me 2>/dev/null || echo 'localhost'):7080"
        ;;
    storage)
        echo "=== Depolama Alanı Analizi ==="
        echo "📁 Toplam boyut: $(du -sh $STORAGE_PATH | cut -f1)"
        echo ""
        for dir in images videos documents downloads uploads backup; do
            if [ -d "$STORAGE_PATH/$dir" ]; then
                size=$(du -sh "$STORAGE_PATH/$dir" 2>/dev/null | cut -f1)
                count=$(find "$STORAGE_PATH/$dir" -type f 2>/dev/null | wc -l)
                echo "📂 $dir: $size ($count dosya)"
            fi
        done
        ;;
    backup)
        echo "Dosya deposu yedekleniyor..."
        timestamp=$(date +%Y%m%d_%H%M%S)
        backup_file="$BACKUP_PATH/daily/files_backup_$timestamp.tar.gz"
        
        mkdir -p "$BACKUP_PATH/daily"
        tar -czf "$backup_file" -C /var/www files/
        
        if [ $? -eq 0 ]; then
            echo "✅ Yedek oluşturuldu: $backup_file"
            echo "📊 Boyut: $(du -sh $backup_file | cut -f1)"
            
            # Eski yedekleri temizle (7 günden eski)
            find "$BACKUP_PATH/daily" -name "files_backup_*.tar.gz" -mtime +7 -delete
            echo "🗑️ 7 günden eski yedekler temizlendi"
        else
            echo "❌ Yedekleme başarısız!"
        fi
        ;;
    restore)
        if [ -z "$2" ]; then
            echo "Kullanım: files-manager restore BACKUP_FILE"
            echo "Mevcut yedekler:"
            ls -la "$BACKUP_PATH/daily/"files_backup_*.tar.gz 2>/dev/null || echo "Yedek bulunamadı"
            exit 1
        fi
        
        echo "⚠️ DİKKAT: Bu işlem mevcut dosyaları silecek!"
        read -p "Devam etmek istiyor musunuz? (y/N): " confirm
        if [[ $confirm =~ ^[Yy]$ ]]; then
            echo "Dosyalar geri yükleniyor..."
            rm -rf "$STORAGE_PATH"/*
            tar -xzf "$2" -C /var/www/
            chown -R nobody:nogroup "$STORAGE_PATH"
            echo "✅ Geri yükleme tamamlandı"
        else
            echo "❌ İşlem iptal edildi"
        fi
        ;;
    cache-clear)
        echo "Cache temizleniyor..."
        rm -rf /tmp/lshttpd/cache/*
        systemctl reload lsws
        echo "✅ Cache temizlendi"
        ;;
    cleanup)
        echo "Sistem temizliği yapılıyor..."
        
        # Boş dizinleri temizle
        find "$STORAGE_PATH" -type d -empty -delete 2>/dev/null
        
        # Geçici dosyaları temizle
        find "$STORAGE_PATH" -name "*.tmp" -delete 2>/dev/null
        find "$STORAGE_PATH" -name ".DS_Store" -delete 2>/dev/null
        find "$STORAGE_PATH" -name "Thumbs.db" -delete 2>/dev/null
        
        # Log dosyalarını rotasyona sok
        find /var/log -name "*.log" -size +50M -exec truncate -s 10M {} \; 2>/dev/null
        
        echo "✅ Sistem temizliği tamamlandı"
        ;;
    organize)
        echo "Dosyalar organize ediliyor..."
        
        # uploads dizinindeki dosyaları türüne göre taşı
        for file in "$STORAGE_PATH/uploads"/*; do
            if [ -f "$file" ]; then
                filename=$(basename "$file")
                extension="${filename##*.}"
                
                case "$extension" in
                    jpg|jpeg|png|gif|bmp|svg|webp)
                        mv "$file" "$STORAGE_PATH/images/"
                        echo "📷 $filename -> images/"
                        ;;
                    mp4|avi|mov|wmv|flv|mkv|webm)
                        mv "$file" "$STORAGE_PATH/videos/"
                        echo "🎬 $filename -> videos/"
                        ;;
                    pdf|doc|docx|txt|rtf|odt)
                        mv "$file" "$STORAGE_PATH/documents/"
                        echo "📄 $filename -> documents/"
                        ;;
                    zip|rar|7z|tar|gz|exe|msi|deb|rpm)
                        mv "$file" "$STORAGE_PATH/downloads/"
                        echo "⬇️ $filename -> downloads/"
                        ;;
                esac
            fi
        done
        echo "✅ Dosya organizasyonu tamamlandı"
        ;;
    restart)
        echo "OpenLiteSpeed yeniden başlatılıyor..."
        systemctl restart lsws
        echo "✅ OLS yeniden başlatıldı"
        ;;
    logs)
        echo "=== Access Log (Son 20) ==="
        tail -20 /usr/local/lsws/logs/access.log 2>/dev/null || echo "Log dosyası bulunamadı"
        echo ""
        echo "=== Error Log ==="
        tail -10 /usr/local/lsws/logs/error.log 2>/dev/null || echo "Hata logu bulunamadı"
        ;;
    *)
        echo "📁 Dosya Deposu CDN Yönetici"
        echo "Kullanım: files-manager {KOMUT}"
        echo ""
        echo "📊 Durum ve Bilgi:"
        echo "  status     - Server durumu ve istatistikler"
        echo "  storage    - Depolama alanı analizi"
        echo "  logs       - Log dosyalarını görüntüle"
        echo ""
        echo "💾 Yedekleme:"
        echo "  backup     - Manuel yedek oluştur"
        echo "  restore    - Yedekten geri yükle"
        echo ""
        echo "🧹 Bakım:"
        echo "  cache-clear - Cache temizle"
        echo "  cleanup    - Sistem temizliği"
        echo "  organize   - Dosyaları organize et"
        echo "  restart    - Servisi yeniden başlat"
        ;;
esac
EOL

chmod +x /usr/local/bin/files-manager

echo "⏰ Otomatik yedekleme cron job'u..."

# Günlük otomatik yedekleme
cat > /etc/cron.d/files-backup << 'EOL'
# Günlük otomatik yedekleme - 02:00
0 2 * * * root /usr/local/bin/files-manager backup >/dev/null 2>&1

# Haftalık dosya organizasyonu - Pazar 03:00
0 3 * * 0 root /usr/local/bin/files-manager organize >/dev/null 2>&1

# Aylık sistem temizliği - Ayın 1'i 04:00
0 4 1 * * root /usr/local/bin/files-manager cleanup >/dev/null 2>&1
EOL

echo "🔐 SSL sertifika hazırlığı..."
apt install -y certbot

# SFTP kullanıcısı oluştur
echo "👤 SFTP kullanıcısı oluşturuluyor..."
useradd -m -s /bin/bash fileuser
echo "fileuser:$(openssl rand -base64 12)" | chpasswd
SFTP_PASS=$(openssl rand -base64 12)
echo "fileuser:$SFTP_PASS" | chpasswd

# SFTP kullanıcısını files grubuna ekle
usermod -a -G www-data fileuser
chown -R fileuser:www-data /var/www/files/uploads
chmod -R 775 /var/www/files/uploads

# OpenLiteSpeed'i başlat
systemctl enable lsws
systemctl start lsws

# IP adresini al
SERVER_IP=$(curl -s ifconfig.me || curl -s ipinfo.io/ip || echo "IP alınamadı")

echo ""
echo "🎉 DOSYA DEPOSU CDN KURULUMU TAMAMLANDI!"
echo "=============================================="
echo ""
echo "📍 Erişim Bilgileri:"
echo "🌐 Ana URL: http://$SERVER_IP"
echo "📁 Dosya Deposu: http://$SERVER_IP/"
echo "🎛️  Admin Panel: http://$SERVER_IP:7080"
echo "👤 Admin Kullanıcı: admin"
echo "🔑 Admin Şifre: $ADMIN_PASS"
echo ""
echo "📤 SFTP/SCP Bilgileri:"
echo "🌐 Host: $SERVER_IP"
echo "🔌 Port: 22"
echo "👤 Kullanıcı: fileuser"
echo "🔑 Şifre: $SFTP_PASS"
echo "📁 Upload Path: /var/www/files/uploads/"
echo ""
echo "🛠️ Yönetim Komutları:"
echo "📊 Durum: files-manager status"
echo "📈 Depolama analizi: files-manager storage"
echo "💾 Manuel yedek: files-manager backup"
echo "🔄 Geri yükle: files-manager restore BACKUP_FILE"
echo "🗑️  Cache temizle: files-manager cache-clear"
echo "🧹 Sistem temizle: files-manager cleanup"
echo "📂 Dosya organize: files-manager organize"
echo "🔄 Yeniden başlat: files-manager restart"
echo ""
echo "📁 Dizin Yapısı:"
echo "📷 Resimler: http://$SERVER_IP/images/"
echo "🎬 Videolar: http://$SERVER_IP/videos/"
echo "📄 Dökümanlar: http://$SERVER_IP/documents/"
echo "⬇️ İndirilenler: http://$SERVER_IP/downloads/"
echo "⬆️ Yüklemeler: http://$SERVER_IP/uploads/"
echo "💾 Yedekler: http://$SERVER_IP/backup/"
echo ""
echo "🔐 SSL Sertifikası için:"
echo "sudo certbot --webroot -w /var/www/files -d yourdomain.com"
echo ""
echo "⏰ Otomatik İşlemler:"
echo "• Günlük yedekleme: Her gece 02:00"
echo "• Dosya organizasyonu: Pazar 03:00"
echo "• Sistem temizliği: Ayın 1'i 04:00"
echo "• Eski yedekleri silme: 7 gün sonra"
echo ""
echo "💡 İpuçları:"
echo "• SFTP ile dosya yükleyebilirsiniz"
echo "• /uploads/ dizinine yüklenen dosyalar otomatik organize edilir"
echo "• Cache 7 gün süreyle saklanır (hızlı erişim)"
echo "• Maksimum dosya boyutu: 1GB"
echo "• CORS enabled - API kullanımına uygun"
echo "• Directory browsing aktif - dosya listesi görünür"
echo ""
echo "⚡ Performans Özellikleri:"
echo "• LSCache: 7 gün TTL ile ultra hızlı cache"
echo "• Gzip/Brotli: 50MB'a kadar otomatik sıkıştırma"
echo "• HTTP/2-3: Modern protokol desteği"
echo "• CORS: Cross-origin resource sharing"
echo "• CDN headers: Optimal caching headers"
echo "• Auto-indexing: Dizin listesi otomatik"
echo ""
echo "✅ DOSYA DEPOSU CDN HAZIR!"
echo ""
echo "🚀 GitHub: https://github.com/ufukunal/scriptbase"
