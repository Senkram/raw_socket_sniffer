gcc -Wall test.c -o test
sudo ./test

Yapay zekadan yardım aldığım konular:
1- VLAN header formatı ve bit düzeyinde okuma yapma
2- C dilinde dosyaya yazma (loglama yapmak için) Not: C++'da genel hatlarıyla bilsem de C dilinde pek hakim değildim
3- Loglamada timestamp kullanmak için time fonksiyonları
4- Döngüyü paket sayısı ile (fikir olarak) (geçici)
(CTRL + C yaparak terminalden çıkıldığında loglama olamıyordu döngü bitmeden program sonlandırıldığı ve dosya kapatılmadığı için;
ayrıca SIGINT konusuna hakim olmadığım için direkt YZ'den kopyala yapıştır yapmak istemedim)
5- Soket oluştururken soketin tüm paketleri alması için
6- Soketteki paketi çekmek -> recvfrom metodu
7- Ethernet, IP, TCP gibi protokollerin struct kaynak dosyalarını include etme
8- Loopback filtresi
9- Hexadecimal formatı (printf kullanırken)
10- network to host ve host to network (ntoh(s/l)hton(s/l)) kullanımı (Verinin düşük bit öncelikli veya yüksek bit öncelikli dönüşümü (Little-endian/Big-endian))
11- Satır içi struct oluşturma
12- inet-ntoa kullanımı
13- Protokol header'larını struct'a koyarken (ip->ihl*4 gibi)
14- Pointer ve segmentation fault konularında araştırma
15- Debugging yapabilmek için IDE'ye (VSCode) yetki verme (sudo komutu gerektiriyor)
16- Terminal komutları (yetki vermek vs.)
17- Konfigürasyonlar

Not: Bu notları YZ kullanmadan kodu tekrardan gözden geçirerek çıkardım.

Yapay zekaya bu notları doğrulattım ve eksik bir şey olup olmadığını sordum:
- Docker (container) kullanmak
- Loglama olmamasının nedenini fprintf ile gönderilen değerin buffer'da tutulması ile alakalı olduğuyla ilgili beni düzeltti