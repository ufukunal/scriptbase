
# FTP portları da ekle
ufw allow 21       # FTP Control
ufw allow 40000:40100/tcp  # FTP Passive ports#!/bin/bash

# Oracle Cloud Ubuntu 22.04 - Basit CyberPanel Kurulumu
# Mail server olmadan, sadece web panel
# GitHub: https://github.com/ufukunal/scriptbase

echo "🚀 CyberPanel Basit Kurulum Başlıyor..."
echo "======================================"
echo ""
echo "📋 Kurulacaklar:"
echo "✅ CyberPanel (Web yönetim paneli)"
echo "✅ OpenLiteSpeed"
echo "✅ MariaDB (Database)"
echo "✅ PHP 8.1"
echo "✅ SSL/TLS desteği"
echo "✅ FTP server (Pure-FTPd)"
echo "❌ Mail server (kurulmayacak)"
echo ""

# Sistem bilgileri
echo "📊 Sistem Bilgileri:"
echo "RAM: $(free -h | awk 'NR==2{print $2}')"
echo "CPU: $(nproc) core"
echo "Disk: $(df -h / | awk 'NR==2{print $4}') boş alan"
echo ""

# Root kontrolü
if [[ $EUID -ne 0 ]]; then
   echo "❌ Bu script root olarak çalıştırılmalı!"
   echo "Kullanım: sudo bash <(curl -fsSL https://raw.githubusercontent.com/ufukunal/scriptbase/main/cyberpanel-setup.sh)"
   exit 1
fi

# RAM kontrolü
RAM_GB=$(free -g | awk 'NR==2{print $2}')
if [ "$RAM_GB" -lt 1 ]; then
    echo "⚠️ Uyarı: 1GB+ RAM önerilir. Mevcut: ${RAM_GB}GB"
    read -p "Devam etmek istiyor musunuz? (y/N): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        echo "❌ Kurulum iptal edildi"
        exit 0
    fi
fi

echo "🔧 Sistem hazırlığı..."

# Sistem güncelleme
apt update && apt upgrade -y

# Temel paketler
apt install -y curl wget ufw htop nano unzip software-properties-common

echo "🔥 Firewall ayarları..."

# Sadece gerekli portlar
ufw allow 22       # SSH
ufw allow 80       # HTTP
ufw allow 443      # HTTPS
ufw allow 8090     # CyberPanel
ufw allow 7080     # OpenLiteSpeed Admin (opsiyonel)
ufw allow 21       # FTP
ufw allow 40000:40100/tcp  # FTP Passive ports
ufw --force enable

# Oracle Cloud iptables
iptables -I INPUT -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -p tcp --dport 443 -j ACCEPT
iptables -I INPUT -p tcp --dport 8090 -j ACCEPT
iptables -I INPUT -p tcp --dport 7080 -j ACCEPT
iptables -I INPUT -p tcp --dport 21 -j ACCEPT
iptables -I INPUT -p tcp --dport 40000:40100 -j ACCEPT

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

echo "⚡ Sistem optimizasyonları..."
cat >> /etc/sysctl.conf << 'EOL'
# CyberPanel optimizasyonları
vm.swappiness=10
vm.vfs_cache_pressure=50
vm.dirty_ratio=15
vm.dirty_background_ratio=5
net.core.rmem_max=16777216
net.core.wmem_max=16777216
fs.file-max=2097152
EOL
sysctl -p

echo "📦 CyberPanel kurulumu..."
echo ""
echo "⚠️ Kurulum sırasında sorulacak seçenekler:"
echo "1. Install CyberPanel → 1 (ENTER)"
echo "2. Password → Otomatik oluşturulsun (ENTER)"
echo "3. Admin email → admin@localhost (ENTER)"  
echo "4. Remote MySQL → 1 (Local) (ENTER)"
echo "5. Install Memcached → y (ENTER)"
echo "6. Install Redis → y (ENTER)"
echo "7. Install PowerDNS → n (ENTER) - DNS istemiyoruz"
echo ""
echo "▶️ Kurulum başlıyor... (5-10 dakika sürebilir)"

# CyberPanel kurulum script'ini indir ve çalıştır
cd /tmp
wget -O cyberpanel_installer.sh https://cyberpanel.net/install.sh

# Manuel kurulum (kullanıcı seçimleri yapacak)
bash cyberpanel_installer.sh

echo "📡 FTP Server (Pure-FTPd) kuruluyor..."
apt install -y pure-ftpd

# FTP konfigürasyonu
echo "yes" > /etc/pure-ftpd/conf/ChrootEveryone
echo "yes" > /etc/pure-ftpd/conf/CreateHomeDir
echo "40000 40100" > /etc/pure-ftpd/conf/PassivePortRange
echo "30" > /etc/pure-ftpd/conf/MaxIdleTime
echo "10" > /etc/pure-ftpd/conf/MaxClientsNumber
echo "3" > /etc/pure-ftpd/conf/MaxClientsPerIP

# Pure-FTPd'yi yeniden başlat
systemctl restart pure-ftpd
systemctl enable pure-ftpd

echo "✅ FTP Server kuruldu ve yapılandırıldı"

# Kurulum sonucu kontrol
if systemctl is-active --quiet lscpd; then
    echo ""
    echo "🎉 CYBERPANEL KURULUMU TAMAMLANDI!"
    echo "=================================="
    echo ""
    
    # IP adresini al
    SERVER_IP=$(curl -s ifconfig.me || curl -s ipinfo.io/ip || echo "localhost")
    
    echo "📍 Erişim Bilgileri:"
    echo "🌐 CyberPanel: https://$SERVER_IP:8090"
    echo "🎛️ OpenLiteSpeed Admin: https://$SERVER_IP:7080"
    echo ""
    
    # CyberPanel admin bilgilerini bul
    if [ -f /home/cyberpanel/install-log.txt ]; then
        echo "🔑 Login Bilgileri:"
        grep -A 5 -B 5 "admin password" /home/cyberpanel/install-log.txt || echo "Admin şifresi log dosyasında bulunamadı"
    fi
    
    echo ""
    echo "📋 Sistem Durumu:"
    echo "🔧 CyberPanel: $(systemctl is-active lscpd)"
    echo "🌐 OpenLiteSpeed: $(systemctl is-active lsws)"
    echo "🗄️ MariaDB: $(systemctl is-active mariadb)"
    echo "📡 FTP Server: $(systemctl is-active pure-ftpd)"
    echo ""
    
    echo "💡 İlk Adımlar:"
    echo "1. 🌐 https://$SERVER_IP:8090 adresine gidin"
    echo "2. 👤 admin kullanıcısı ile giriş yapın"
    echo "3. 🌍 'Websites' menüsünden yeni site oluşturun"
    echo "4. 🔐 'SSL' menüsünden Let's Encrypt sertifikası alın"
    echo "5. 📁 'File Manager' ile dosyalarınızı yönetin"
    echo "6. 📡 'FTP' menüsünden FTP kullanıcıları oluşturun"
    echo ""
    
    echo "🛠️ CyberPanel Özellikleri:"
    echo "• 📊 Website yönetimi"
    echo "• 📁 Dosya yöneticisi"
    echo "• 🗄️ Database yönetimi"
    echo "• 🔐 SSL sertifika yönetimi"
    echo "• 📈 İstatistikler ve loglar"
    echo "• ⚡ LSCache yönetimi"
    echo "• 🔒 Backup/Restore"
    echo "• 📡 FTP kullanıcı yönetimi"
    echo ""
    
    echo "📡 FTP Bilgileri:"
    echo "🌐 FTP Server: $SERVER_IP"
    echo "🔌 Port: 21"
    echo "📂 Passive Ports: 40000-40100"
    echo "👤 FTP kullanıcıları CyberPanel'den oluşturulabilir"
    echo ""
    
    echo "📚 Dokümantasyon:"
    echo "🌐 https://cyberpanel.net/docs/"
    echo "🎥 https://www.youtube.com/c/CyberPanel"
    echo ""
    
    echo "✅ Kurulum başarıyla tamamlandı!"
    echo "🚀 GitHub: https://github.com/ufukunal/scriptbase"
    
else
    echo ""
    echo "❌ CyberPanel kurulumu başarısız!"
    echo "================================"
    echo ""
    echo "🔍 Sorun giderme:"
    echo "• Log kontrol: tail -f /home/cyberpanel/install-log.txt"
    echo "• Servis durumu: systemctl status lscpd"
    echo "• Manuel kurulum: sh <(curl https://cyberpanel.net/install.sh)"
    echo ""
    echo "💬 Destek:"
    echo "• Forum: https://community.cyberpanel.net/"
    echo "• Discord: https://discord.gg/cyberpanel"
    
    exit 1
fi
