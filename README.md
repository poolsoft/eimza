# eimza
E-İmza kütüphanesi (Deneysel)

## Amaç
PKCS11 kütüphanesi ile Akis Kart üzerindeki bilgileri okumak, PIN değiştirmek(şu anda yapmıyor), E-İmza atmak(şu anda atılan imza formal değil), vs.

## DİKKAT
Bu proje DENEYSEL bir projedir. Kullanımından tamamen kullanıcı sorumludur. Programcı hiç bir şekilde sorumlu tutulamaz.
**"Ne yaptığınızı bilmiyorsanız yapmayın."**

### Uyumluluk
* Akis kart ile test edilmiştir.
* Centos7 ile test edilmiştir.
* Windows ile test edilMEmiştir.

### Sorunlar ve Çözümler
* Akıllı kart sürücülerini yükleyin.
* Akis'in *.so dosyalarını ```/usr/lib```'e kopyaladıktan sonra ```ldconfig -v``` çalıştırın.

### Gerekli Paketler
libtool-ltdl
libtool-ltdl-devel
pcsc-lite
pcsc-lite-ccid
pcsc-lite-devel
pcsc-lite-libs
libusb (akıllı kart için)
libusbx
libusb-devel
libusbx-devel

