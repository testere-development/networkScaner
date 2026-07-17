# networkScaner

```
 _____         _
|_   _|__  ___| |_ ___ _ __ ___
  | |/ _ \/ __| __/ _ \ '__/ _ \
  | |  __/\__ \ ||  __/ | |  __/
  |_|\___||___/\__\___|_|  \___|

  network scanner · github.com/testere-development/networkScaner
```

Python ilə yazılmış ARP/Port scanner. Şəbəkəndəki cihazları (IP, MAC, vendor) tapır və hədəf host üzərində port scan edir.

## Xüsusiyyətlər

- **Auto ARP scan** — linux üzərində aktiv şəbəkə interfeysini avtomatik tapıb skan edir
- **Manual ARP scan** — istənilən IP/subnet üçün cihaz kəşfi (`192.168.1.0/24`)
- **Port scan** — tək IP və ya IP + port siyahısı üçün açıq portları tapır (çoxaxınlı)
- **MAC → Vendor** — tapılan cihazların istehsalçısını `macvendors.com` / `maclookup.app` ilə göstərir
- Nəticələri fayla yazma seçimi

## Quraşdırma

```bash
git clone https://github.com/testere-development/networkScaner.git
cd networkScaner
pip install -r requirements.txt
```

> ARP scan `scapy` istifadə etdiyi üçün root/admin hüquqları tələb edir.

## İstifadə

```bash
sudo python discovery.py -a              # avtomatik ARP scan (linux)
sudo python discovery.py -t 192.168.1.0/24   # manual ARP scan
python discovery.py -p 192.168.1.1        # full port scan (0-65535)
python discovery.py -p 192.168.1.1:22,80,443 # spesifik portlar
python discovery.py -h                    # kömək
```

## Tələblər

- Python 3.8+
- `scapy`, `rich`, `requests`

## Xəbərdarlıq

Bu alət yalnız öz sahibi olduğun və ya icazəli olduğun şəbəkələrdə istifadə üçündür. İcazəsiz şəbəkə skanı qanunsuz ola bilər.

## Lisenziya

MIT
