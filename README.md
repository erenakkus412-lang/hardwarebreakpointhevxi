# Windows Process Debugging & App‑Bound Encryption Bypass Framework

**A Comprehensive Educational Suite for Understanding Windows Internals: Hardware Breakpoints, Indirect Syscalls, and COM Elevation.**

---

## ENGLISH

### 1. Overview

This repository is a **professional-grade research and educational framework** that combines two advanced Windows security bypass techniques into a single, well-documented codebase. It is designed for cybersecurity researchers, Blue Teamers, SOC analysts, and Red Team professionals who want to understand the low-level internals of the Windows operating system.

The framework demonstrates:
- How to manipulate processes and threads at the kernel level without triggering user-mode hooks.
- How to extract encrypted browser data (cookies, passwords, payment cards) by bypassing Application-Bound Encryption (ABE) using native Windows COM interfaces.

All code is written from scratch, with a strong emphasis on **stealth**, **stability**, and **educational value**.

---

### 2. Technical Deep Dive

#### 2.1. Methodology 1: Hardware Breakpoints & Indirect Syscalls

This component replicates the behavior of advanced EDRs (Endpoint Detection and Response) and sophisticated malware by using **CPU debug registers** (DR0–DR7) to set hardware breakpoints.

- **Indirect Syscalls (NullGate):**  
  Instead of calling `NtGetContextThread` or `NtSetContextThread` through the standard `syscall` instruction or the Windows API (which are often hooked by security products), this framework uses an **indirect syscall** technique. It dynamically resolves the System Service Number (SSN) and executes the syscall directly from a non-hooked memory region (e.g., `ntdll.dll`). This bypasses user-mode EDR hooks placed on the `ntdll!Zw*` functions.

- **Hardware Breakpoint Management (DR0/DR7):**  
  The framework enumerates all threads of a target process using `NtGetNextThread` (undocumented but stable). It then suspends each thread, modifies the debug registers to set execution or access breakpoints, and resumes them. Unlike software breakpoints (`0xCC`), hardware breakpoints do not modify the code in memory, making them extremely difficult to detect via traditional integrity checks.

- **Process Memory Enumeration:**  
  Using `VirtualQueryEx`, the tool maps out the virtual address space of the target process, identifying writable, executable, and private memory regions – a common reconnaissance step before injecting payloads or extracting sensitive data.

#### 2.2. Methodology 2: App-Bound Encryption (ABE) Bypass via COM Elevator

Modern Chromium-based browsers (Chrome, Edge, Brave, Opera) protect sensitive data (cookies, passwords, credit cards) using **App-Bound Encryption (ABE)**. The decryption key is stored in the browser's `Local State` file, encrypted with a system-protected key that only the browser’s Elevator COM service can decrypt.

- **Direct COM Elevator (No DLL Injection):**  
  Instead of injecting a DLL into the browser process (which is highly detectable), this framework communicates directly with the Elevator COM server (`IElevator` / `IElevator2`). It uses `CoCreateInstance` to instantiate the server and invokes the `DecryptData` method manually via vtable offsets.

- **Dynamic CLSID/IID Resolution:**  
  The framework scans the Windows Registry (HKCR\CLSID) to automatically discover the correct CLSID and IID for the installed browsers. It supports:
  - **Chrome**: Fallback from `IElevator2` (Chrome 144+) to `IElevator` (older versions).
  - **Edge**: Specific interface chain (IEdgeElevator / IEdgeElevator2).
  - **Avast Browser**: Uses a different vtable slot (offset 12 instead of 3).
  
- **Self-Contained Parsing:**  
  The `Local State` file (JSON) is parsed manually – no external JSON libraries are required. The `app_bound_encrypted` Base64 string is decoded and passed to the COM decryptor. The decrypted binary key is then saved to disk.

- **AES-GCM Decryption:**  
  When a key candidate is found in memory (or provided), the framework uses Windows BCrypt API to decrypt `v20`-formatted cookies, extracting the plaintext value for exfiltration or analysis.

---

### 3. Key Features

| Module | Key Features |
| :--- | :--- |
| **Hardware Breakpoint Engine** | - Indirect Syscall execution (bypass user-mode hooks)<br>- Thread enumeration & suspension (`NtGetNextThread`)<br>- DR0/DR7 debug register manipulation<br>- Memory region scanning (`VirtualQueryEx`) |
| **ABE Bypass Engine** | - Direct COM Elevator invocation (No DLL injection)<br>- Automatic browser discovery (Chrome, Edge, Brave, Opera, Vivaldi)<br>- CLSID/IID resolution from Registry<br>- Manual JSON + Base64 parsing<br>- AES-GCM decryption via BCrypt |

---

### 4. Purpose & Legal Disclaimer

**IMPORTANT:** This project is provided **strictly for educational and defensive security research**.

The sole purpose of this framework is to help security professionals understand how low-level Windows APIs, hardware debug registers, and COM Elevation services work. By studying this code, Blue Teamers can develop better detection rules, SOC analysts can understand attack patterns, and malware researchers can reverse-engineer sophisticated threats more effectively.

**You are solely responsible for your actions.**
- **DO NOT** use this software against any system, network, or data without explicit, written permission from the owner.
- **DO NOT** use this software to steal data, bypass security controls for malicious purposes, or violate any applicable laws.
- The author (Eren Taha Akkuş) assumes **zero liability** for any damages, legal consequences, or ethical violations arising from the misuse of this software.
- By downloading, compiling, or executing this software, you acknowledge that you have read this disclaimer and agree to take full responsibility for your actions.

---

### Build Instructions via Python Compiler (`compilemenuv1.py`)

---

**ENGLISH:**

1. Download or clone the project repository to your local machine.  
2. Open your terminal or command prompt and navigate to the target project root directory.  
3. Run the build script by executing the following command:  
   `python3 compilemenuv1.py`  
4. When prompted, enter the required decryption / build password.  
5. The compilation process will start automatically.  
6. If the `build` folder does not already exist in the directory, the script will create it automatically.  
7. After the compilation finishes successfully, all compiled `.exe` files will be written inside this newly created (or existing) `build` folder.

---

### 5. Author & Acknowledgments

**Author:**  
Eren Taha Akkuş – Turkish Cybersecurity Researcher, specializing in Windows Internals, Offensive/Defensive Security, and Reverse Engineering.

**GitHub:** [erenakkus412-lang](https://github.com/erenakkus412-lang)

**Acknowledgments:**  
- The broader Windows security community for sharing research on indirect syscalls and COM Elevation.
- xaitax for initial public research on the COM Elevator technique (inspiration only; the implementation here is entirely original).

---

---

## 🇹🇷 TÜRKÇE

### 1. Genel Bakış

Bu depo, **profesyonel seviyede bir araştırma ve eğitim çerçevesidir**. Windows işletim sistemindeki iki gelişmiş güvenlik atlatma tekniğini, tek bir kapsamlı kod tabanında birleştirir. Siber güvenlik araştırmacıları, Mavi Takım (Blue Team) uzmanları, SOC analistleri ve Kırmızı Takım (Red Team) profesyonelleri için tasarlanmıştır.

Çerçeve şunları göstermektedir:
- Kullanıcı modu hook'larını tetiklemeden, süreç ve iş parçacıklarının çekirdek seviyesinde nasıl manipüle edileceği.
- Yerel Windows COM arayüzlerini kullanarak Uygulama Bağlı Şifreleme'yi (ABE) atlatarak şifrelenmiş tarayıcı verilerinin (çerezler, parolalar, kart bilgileri) nasıl çıkarılacağı.

Tüm kodlar sıfırdan yazılmış olup, **gizlilik**, **kararlılık** ve **eğitsel değer** üzerine odaklanmıştır.

---

### 2. Teknik Derinlemesine İnceleme

#### 2.1. Metodoloji 1: Donanım Kesme Noktaları ve Dolaylı Syscall'lar

Bu bileşen, gelişmiş EDR'lerin (Uç Nokta Algılama ve Müdahale) ve sofistike kötü amaçlı yazılımların davranışlarını taklit ederek, donanım kesme noktaları ayarlamak için **CPU debug register'larını** (DR0–DR7) kullanır.

- **Dolaylı Syscall'lar (NullGate):**  
  `NtGetContextThread` veya `NtSetContextThread` fonksiyonlarını standart `syscall` talimatı veya Windows API'si (güvenlik ürünleri tarafından sıklıkla hook'lanır) üzerinden çağırmak yerine, bu çerçeve **dolaylı syscall** tekniğini kullanır. Sistem Servis Numarasını (SSN) dinamik olarak çözümler ve syscall'u doğrudan hook'lanmamış bir bellek bölgesinden yürütür. Bu, `ntdll!Zw*` fonksiyonlarına yerleştirilen kullanıcı modu EDR hook'larını atlar.

- **Donanım Kesme Noktası Yönetimi (DR0/DR7):**  
  Çerçeve, `NtGetNextThread` (belgelenmemiş ancak kararlı) kullanarak hedef sürecin tüm iş parçacıklarını numaralandırır. Ardından her iş parçacığını askıya alır, yürütme veya erişim kesme noktaları ayarlamak için debug register'larını değiştirir ve devam ettirir. Yazılım kesme noktalarından (`0xCC`) farklı olarak, donanım kesme noktaları bellekteki kodu değiştirmez, bu da geleneksel bütünlük kontrolleriyle tespit edilmelerini son derece zorlaştırır.

- **Süreç Bellek Numaralandırması:**  
  `VirtualQueryEx` kullanılarak hedef sürecin sanal adres alanı haritalanır; yazılabilir, çalıştırılabilir ve özel bellek bölgeleri tespit edilir. Bu, yük enjekte etmeden veya hassas verileri çıkarmadan önce yapılan yaygın bir keşif adımıdır.

#### 2.2. Metodoloji 2: COM Elevator ile Uygulama Bağlı Şifreleme Atlatma

Modern Chromium tabanlı tarayıcılar (Chrome, Edge, Brave, Opera), hassas verileri (çerezler, parolalar, kredi kartları) **Uygulama Bağlı Şifreleme (ABE)** kullanarak korur. Şifre çözme anahtarı, tarayıcının `Local State` dosyasında saklanır ve yalnızca tarayıcının Elevator COM hizmetinin çözebileceği sistem korumalı bir anahtarla şifrelenir.

- **Doğrudan COM Elevator (DLL Enjeksiyonu Yok):**  
  Tarayıcı sürecine bir DLL enjekte etmek (ki bu oldukça tespit edilebilirdir) yerine, bu çerçeve doğrudan Elevator COM sunucusuyla (`IElevator` / `IElevator2`) iletişim kurar. `CoCreateInstance` kullanarak sunucuyu başlatır ve `DecryptData` metodunu vtable ofsetleri üzerinden manuel olarak çağırır.

- **Dinamik CLSID/IID Çözümlemesi:**  
  Çerçeve, yüklü tarayıcılar için doğru CLSID ve IID'yi otomatik olarak bulmak üzere Windows Kayıt Defteri'ni (HKCR\CLSID) tarar. Şunları destekler:
  - **Chrome**: IElevator2'den (Chrome 144+) eski sürümler için IElevator'a geri düşer.
  - **Edge**: Özel arayüz zinciri (IEdgeElevator / IEdgeElevator2).
  - **Avast Browser**: Farklı bir vtable yuvası kullanır (3 yerine ofset 12).

- **Kendi Kendine Yeten Ayrıştırma:**  
  `Local State` dosyası (JSON) manuel olarak ayrıştırılır – harici JSON kütüphanelerine ihtiyaç yoktur. Base64 kodlanmış `app_bound_encrypted` dizesi çözülür ve COM şifre çözücüye iletilir. Çözülen ikili anahtar diske kaydedilir.

- **AES-GCM Şifre Çözme:**  
  Bellekte (veya sağlanan) bir anahtar adayı bulunduğunda, çerçeve Windows BCrypt API'sini kullanarak `v20` formatındaki çerezleri çözer ve analiz veya sızdırma için düz metin değerini çıkarır.

---

### 3. Temel Özellikler

| Modül | Temel Özellikler |
| :--- | :--- |
| **Donanım Kesme Noktası Motoru** | - Dolaylı Syscall yürütme (kullanıcı modu hook'larını atlar)<br>- İş parçacığı numaralandırma ve askıya alma (`NtGetNextThread`)<br>- DR0/DR7 debug register manipülasyonu<br>- Bellek bölgesi tarama (`VirtualQueryEx`) |
| **ABE Atlatma Motoru** | - Doğrudan COM Elevator çağrısı (DLL enjeksiyonu yok)<br>- Otomatik tarayıcı keşfi (Chrome, Edge, Brave, Opera, Vivaldi)<br>- Kayıt Defteri'nden CLSID/IID çözümlemesi<br>- Manuel JSON + Base64 ayrıştırma<br>- BCrypt ile AES-GCM şifre çözme |

---

### 4. Amaç ve Yasal Sorumluluk Reddi

**ÖNEMLİ:** Bu proje **yalnızca eğitim ve savunma amaçlı güvenlik araştırmaları** için sağlanmaktadır.

Bu çerçevenin tek amacı, güvenlik uzmanlarının düşük seviyeli Windows API'lerinin, donanım debug register'larının ve COM Elevator hizmetlerinin nasıl çalıştığını anlamalarına yardımcı olmaktır. Bu kodu inceleyerek Mavi Takım uzmanları daha iyi tespit kuralları geliştirebilir, SOC analistleri saldırı modellerini anlayabilir ve kötü amaçlı yazılım araştırmacıları sofistike tehditleri daha etkili bir şekilde tersine mühendislik yapabilir.

**Eylemlerinizden tamamen siz sorumlusunuz.**
- Bu yazılımı, sahibinden açık ve yazılı izin almadan **HİÇBİR** sistem, ağ veya veriye karşı KULLANMAYIN.
- Bu yazılımı veri çalmak, kötü amaçlı güvenlik kontrollerini atlatmak veya geçerli yasaları ihlal etmek için KULLANMAYIN.
- Yazar (Eren Taha Akkuş), bu yazılımın kötüye kullanımından kaynaklanan herhangi bir hasar, yasal sonuç veya etik ihlalden **KESİNLİKLE SORUMLU DEĞİLDİR**.
- Bu yazılımı indirerek, derleyerek veya çalıştırarak, bu reddi okuduğunuzu ve eylemlerinizin tüm sorumluluğunu üstlenmeyi kabul ettiğinizi beyan edersiniz.

---

### Build Instructions via Python Compiler (`compilemenuv1.py`)

---

---

**TÜRKÇE:**

1. Proje deposunu (repository) bilgisayarınıza indirin veya klonlayın.  
2. Terminal ya da komut istemcisini (CMD) açarak hedef projenin ana dizinine gidin.  
3. Derleme betiğini çalıştırmak için aşağıdaki komutu girin:  
   `python3 compilemenuv1.py`  
4. Karşınıza gelen şifre sorusuna, derleme / şifre çözme işlemi için gereken şifreyi yazın.  
5. Derleme işlemi otomatik olarak başlayacaktır.  
6. Eğer dizin içerisinde `build` klasörü zaten yoksa, betik bu klasörü otomatik olarak oluşturacaktır.  
7. Derleme başarıyla tamamlandıktan sonra, derlenen tüm `.exe` dosyaları bu `build` klasörünün içerisine yazılacaktır.

### 5. Yazar ve Teşekkürler

**Yazar:**  
Eren Taha Akkuş – Windows İç Yapısı, Saldırı/Savunma Güvenliği ve Tersine Mühendislik alanlarında uzmanlaşmış Türk Siber Güvenlik Araştırmacısı.

**GitHub:** [erenakkus412-lang](https://github.com/erenakkus412-lang)

**Teşekkürler:**  
- Dolaylı syscall'lar ve COM Elevator hakkındaki araştırmaları paylaşan geniş Windows güvenlik topluluğu.
- COM Elevator tekniği üzerine ilk kamu araştırması için xaitax (yalnızca ilham kaynağı; buradaki uygulama tamamen özgündür).

---

**© 2026 Eren Taha Akkuş. Tüm hakları saklıdır. / All rights reserved.**
