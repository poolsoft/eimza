package main

import (
	//"encoding/asn1"
	"flag"
	"fmt"
	//"io/ioutil"
	"math/big"
	"os"
	"runtime"
	"strconv"

	//"github.com/ebfe/scard"
	"github.com/miekg/pkcs11"
)

type pkcsObject struct {
	obj   pkcs11.ObjectHandle
	label string
	id    []byte
	idstr string
}

type asn1set struct {
	id  []int //*asn1.ObjectIdentifier
	str []byte
}

var (
	p    *pkcs11.Ctx
	slot uint
	cers []pkcsObject
	pubs []pkcsObject
	pris []pkcsObject
)

func main() {

	akisfile := flag.String("akis", "", "akis kütüphane dosyasının yolu")
	flag.Parse()

	cers = make([]pkcsObject, 0)
	pubs = make([]pkcsObject, 0)
	pris = make([]pkcsObject, 0)

	fmt.Printf("=================================================\n")
	fmt.Printf("  Linux Elektronik İmza uygulama paketi\n")
	fmt.Printf("=================================================\n")

	fmt.Printf("AKİS kütüphanesi yükleniyor...\n")

	if *akisfile == "" {
		if runtime.GOOS == "windows" {
			*akisfile = "/windows/sytem32/libakisp11.dll"
		}
		if runtime.GOOS == "linux" {
			*akisfile = "/usr/lib/libakisp11.so"
		}
	}
	p = pkcs11.New(*akisfile)
	if p == nil {
		fmt.Fprintf(os.Stderr, "HATA : AKİS kütüphanesi yüklenemedi...\n")
		os.Exit(1)
	}
	err := p.Initialize()
	if err != nil {
		panic(err)
	}
	defer p.Destroy()
	defer p.Finalize()
	info, err := p.GetInfo()
	if err != nil {
		panic(err)
	}
	fmt.Printf("=================================================\n")
	fmt.Printf("KART BİLGİSİ\n")
	fmt.Printf("CryptokiVersion\t\t: %v\n", info.CryptokiVersion)
	fmt.Printf("ManufacturerID\t\t: %v\n", info.ManufacturerID)
	fmt.Printf("Flags\t\t\t: %v\n", info.Flags)
	fmt.Printf("LibraryDescription\t: %v\n", info.LibraryDescription)
	fmt.Printf("LibraryVersion\t\t: %v\n", info.LibraryVersion)

	slots, err := p.GetSlotList(false)
	if err != nil {
		panic(err)
	}

	if len(slots) == 0 {
		panic("Slot bulunamadı")
	}
	if len(slots) == 1 {
		slot = slots[0]
		fmt.Println("Slot seçildi")
	} else {
		// slotlar listenelir
		fmt.Printf("Slotlar\n")
		for i, s := range slots {
			fmt.Printf("\t[%d]%#v", i, s)
		}
		fmt.Printf("Slot seçiniz: ")
		var input string
		fmt.Scanln(&input)
		i, err := strconv.Atoi(input)
		if err != nil {
			panic(err)
		}
		slot = slots[i]
	}
	slotinfo, err := p.GetSlotInfo(slot)
	if err != nil {
		panic(err)
	}
	fmt.Printf("=================================================\n")
	fmt.Printf("SLOT BİLGİSİ:\n")
	fmt.Printf("FirmwareVersion\t\t: %v\n", slotinfo.FirmwareVersion)
	fmt.Printf("HardwareVersion\t\t: %v\n", slotinfo.HardwareVersion)
	fmt.Printf("Flags\t\t\t: %v\n", slotinfo.Flags)
	fmt.Printf("ManufacturerID\t\t: %v\n", slotinfo.ManufacturerID)
	fmt.Printf("SlotDescription\t\t: %v\n", slotinfo.SlotDescription)

	tokeninfo, err := p.GetTokenInfo(slot)
	if err != nil {
		panic(err)
	}
	fmt.Printf("=================================================\n")
	fmt.Printf("TOKEN BİLGİSİ:\n")
	fmt.Printf("FirmwareVersion\t\t: %v\n", tokeninfo.FirmwareVersion)
	fmt.Printf("HardwareVersion\t\t: %v\n", tokeninfo.HardwareVersion)
	fmt.Printf("Flags\t\t\t: %v\n", tokeninfo.Flags)
	fmt.Printf("ManufacturerID\t\t: %v\n", tokeninfo.ManufacturerID)
	fmt.Printf("FreePrivateMemory\t: %v\n", tokeninfo.FreePrivateMemory)
	fmt.Printf("FreePublicMemory\t: %v\n", tokeninfo.FreePublicMemory)
	fmt.Printf("Label\t\t\t: %v\n", string([]rune(tokeninfo.Label)))
	fmt.Printf("MaxPinLen\t\t: %v\n", tokeninfo.MaxPinLen)
	fmt.Printf("MaxRwSessionCount\t: %v\n", tokeninfo.MaxRwSessionCount)
	fmt.Printf("MaxSessionCount\t\t: %v\n", tokeninfo.MaxSessionCount)
	fmt.Printf("Model\t\t\t: %v\n", tokeninfo.Model)
	fmt.Printf("RwSessionCount\t\t: %v\n", tokeninfo.RwSessionCount)
	fmt.Printf("SerialNumber\t\t: %v\n", tokeninfo.SerialNumber)
	fmt.Printf("SessionCount\t\t: %v\n", tokeninfo.SessionCount)
	fmt.Printf("TotalPrivateMemory\t: %v\n", tokeninfo.TotalPrivateMemory)
	fmt.Printf("TotalPublicMemory\t: %v\n", tokeninfo.TotalPublicMemory)
	fmt.Printf("UTCTime\t\t\t: %v\n", tokeninfo.UTCTime)

	fmt.Printf("=================================================\n")
	fmt.Printf("OTURUM AÇILIYOR\n")

	session, err := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic(err)
	}
	defer p.CloseSession(session)

	fmt.Printf("Şifre: ")
	var sifre string
	fmt.Scanln(&sifre)

	err = p.Login(session, pkcs11.CKU_USER, sifre)
	if err != nil {
		panic(err)
	}
	defer p.Logout(session)

	certificates, err := getObjects(p, session, pkcs11.CKO_CERTIFICATE)
	if err != nil {
		panic("Sertifikalar alınamadı" + err.Error())
	}
	for _, c := range certificates {
		getCerInfo(p, session, c)
	}

	publickeys, err := getObjects(p, session, pkcs11.CKO_PUBLIC_KEY)
	if err != nil {
		panic("Public anahtarlar alınamadı" + err.Error())
	}
	for _, c := range publickeys {
		getPubInfo(p, session, c)
	}

	privatekeys, err := getObjects(p, session, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		panic("Private anahtarlar alınamadı" + err.Error())
	}
	for _, c := range privatekeys {
		getPriInfo(p, session, c)
	}

	fmt.Printf("=================================================\n")
	fmt.Printf("SERTİFİKALAR:\n")
	for i, c := range cers {
		fmt.Printf("%d : %s\n", i, c.label)
	}
	if len(cers) == 0 {
		fmt.Printf("Hiç sertifika bulunamadı.\n")
		return
	}

	cerno := 0
	pubno := 0
	prino := 0

	for {
		fmt.Printf("Sertifika seçiniz: ")
		var sertifikano string
		fmt.Scanln(&sertifikano)
		cerno, err = strconv.Atoi(sertifikano)
		if err == nil && cerno <= 0 || cerno < len(cers) {
			break
		}
	}

	for i, key := range pubs {
		if key.idstr == cers[cerno].idstr {
			pubno = i
			break
		}
	}

	for i, key := range pris {
		if key.idstr == cers[cerno].idstr {
			prino = i
			break
		}
	}

	fmt.Println(pubno, prino)

	p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, pris[prino].obj)
	//p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, pubs[pubno].obj)
	//p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, certs[serno].obj)
	test, e := p.Sign(session, []byte("Sign me!"))
	if e != nil {
		fmt.Printf("İmzalama başarısız: %s\n", e)
	}
	fmt.Printf("İMZA: %x\n", test)

	/*p.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256, nil)})
	hash, err := p.Digest(session, []byte("selam dünya"))
	if err != nil {
		panic(err)
	}

	for _, d := range hash {
		fmt.Printf("%x", d)
	}*/

	fmt.Printf("\n\n\n")

}

func getSlot(p *pkcs11.Ctx, label string) (uint, error) {
	slots, err := p.GetSlotList(true)
	if err != nil {
		return 0, err
	}
	for _, slot := range slots {
		_, err := p.GetSlotInfo(slot)
		if err != nil {
			return 0, err
		}
		tokenInfo, err := p.GetTokenInfo(slot)
		if err != nil {
			return 0, err
		}
		if tokenInfo.Label == label {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("Slot not found: %s", label)
}

func getObjects(p *pkcs11.Ctx, session pkcs11.SessionHandle, ObjectType uint) ([]pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, ObjectType),
	}

	if err := p.FindObjectsInit(session, template); err != nil {
		fmt.Printf("err")
	}
	objects, _, err := p.FindObjects(session, 100)
	if err != nil {
		return nil, err
	}
	if err = p.FindObjectsFinal(session); err != nil {
		return nil, err
	}
	return objects, nil
}

func getCerInfo(p *pkcs11.Ctx, session pkcs11.SessionHandle, cert pkcs11.ObjectHandle) error {
	var c pkcsObject
	c.obj = cert
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_SUBJECT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
		pkcs11.NewAttribute(pkcs11.CKA_SERIAL_NUMBER, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	}
	attr, err := p.GetAttributeValue(session, pkcs11.ObjectHandle(cert), template)
	if err != nil {
		return err
	}
	for _, a := range attr {
		//fmt.Printf("attr %d, type %d, valuelen %d, value: %v\n", i, a.Type, len(a.Value), a.Value)
		//fmt.Printf("attr %d, type %d, valuelen %d\n", i, a.Type, len(a.Value))

		if a.Type == pkcs11.CKA_SUBJECT {
			/*var s asn1.RawValue
			_, err := asn1.Unmarshal(a.Value, &s)
			if err != nil {
				fmt.Printf("%#v\n", err.Error())
			} else {
				fmt.Printf("SUBJECT: %#v\n", s)
			}
			_, err = asn1.Unmarshal(s.Bytes, &s)
			if err != nil {
				fmt.Printf("%#v\n", err.Error())
			} else {
				fmt.Printf("SUB SUB: %#v\n", s)
			}

			var test asn1set
			_, err = asn1.Unmarshal(s.Bytes, &test)
			if err != nil {
				fmt.Printf("%#v\n", err.Error())
			} else {
				fmt.Printf("TEST: %#v\n", test)
			}*/
		}

		if a.Type == pkcs11.CKA_ID {
			c.id = a.Value
			mod := big.NewInt(0)
			mod.SetBytes(a.Value)
			c.idstr = mod.String()
		}

		if a.Type == pkcs11.CKA_VALUE {
			//_ = ioutil.WriteFile(strconv.Itoa(k)+"test.cer", a.Value, 0644)
		}

		if a.Type == pkcs11.CKA_LABEL {
			//fmt.Printf("LABEL: %s\n", string(a.Value))
			c.label = string(a.Value)
		}
	}
	cers = append(cers, c)
	return nil
}

func getPubInfo(p *pkcs11.Ctx, session pkcs11.SessionHandle, o pkcs11.ObjectHandle) error {
	var pub pkcsObject
	pub.obj = o
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	}
	attr, err := p.GetAttributeValue(session, o, template)
	if err != nil {
		return err
	}
	for _, a := range attr {
		if a.Type == pkcs11.CKA_ID {
			pub.id = a.Value
			mod := big.NewInt(0)
			mod.SetBytes(a.Value)
			pub.idstr = mod.String()
		}
	}
	pubs = append(pubs, pub)
	return nil
}

func getPriInfo(p *pkcs11.Ctx, session pkcs11.SessionHandle, o pkcs11.ObjectHandle) error {
	var pri pkcsObject
	pri.obj = o
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
	}
	attr, err := p.GetAttributeValue(session, o, template)
	if err != nil {
		return err
	}
	for _, a := range attr {
		if a.Type == pkcs11.CKA_ID {
			pri.id = a.Value
			mod := big.NewInt(0)
			mod.SetBytes(a.Value)
			pri.idstr = mod.String()
		}
	}
	pris = append(pris, pri)
	return nil
}
