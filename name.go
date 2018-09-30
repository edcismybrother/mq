package main

import (
	"crypto/hmac"
	"crypto/rc4"
	"crypto/sha1"
	"fmt"
	"log"
	"math/rand"
	"reflect"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var Logs *logrus.Logger

type w struct {
	person *sync.Map
	bp     *sync.Map
	pt     *time.Ticker
	bpt    *time.Ticker
	lv     *time.Ticker
}

type p struct {
	id   uint64
	name string
	bp   *bang
	lv   uint64
}

type bang struct {
	id   uint64
	name string
	bz   uint64
	pp   *sync.Map
}

func main() {
	var ch chan bool
	go genP()
	go genBang()
	<-ch
}

func genP() {
	go lv()
	var i uint64 = 1
	for {
		select {
		case <-world.pt.C:
			{
				pe := new(p)
				pe.id = i
				pe.bp = new(bang)
				pe.name = randomName()
				i++
				logrus.WithFields(logrus.Fields{
					"id":        pe.id,
					"name":      pe.name,
					"join bang": pe.bp.id,
				}).Info("生成角色成功")
				world.person.Store(pe.id, pe)
			}
		}
	}
}

func lv() {
	for {
		select {
		case <-world.lv.C:
			{
				world.person.Range(func(key, value interface{}) bool {
					p := value.(*p)
					p.lv++
					return true
				})
			}
		}
	}

}

func randomName() (name string) {
	x := []string{"皮", "叶", "楚", "石"}
	m := []string{"哈哈", "哈", "呵呵", "呵"}
	name = fmt.Sprintf("%s%s", x[rand.Intn(4)], m[rand.Intn(4)])
	return
}

func genBang() {
	var bangID uint64 = 1
	for {
		select {
		case <-world.bpt.C:
			{
				world.person.Range(
					func(key, value interface{}) bool {
						p := value.(*p)
						if p.bp.id == 0 && p.lv >= 6 {
							b := new(bang)
							b.bz = p.id
							b.id = bangID
							bangID++
							b.name = fmt.Sprintf("%s%v%s", p.name, p.id, "帮")
							b.pp.Store(p.id, p)
							world.bp.Store(b.id, b)
							logrus.WithFields(logrus.Fields{
								"id": b.id,
								"帮主": b.id,
								"帮名": b.name,
							}).Info("帮派创建")
						}
						return true
					})
			}
		}
	}
}

var Bp sync.Map
var P sync.Map

var world = new(w)

func init() {
	Bp := new(sync.Map)
	P := new(sync.Map)
	world.bp = Bp
	world.person = P
	world.pt = time.NewTicker(time.Second * 30)
	world.bpt = time.NewTicker(time.Minute * 1)
	world.lv = time.NewTicker(time.Second * 20)
}

func initBp() {

}

// https://blog.csdn.net/lwldcr/article/details/78722330
// https://blog.csdn.net/weicaijiang/article/details/53218772

func t(l interface{}) {
	v := reflect.TypeOf(l)
	v1 := reflect.ValueOf(l)
	// if v. == logrus.Logger {
	fmt.Println(v)
	fmt.Println(v1.Type())
	switch l.(type) {
	case *logrus.Logger:
		{
			fmt.Println(true)
		}
	}
	// }
}

func init() {
	Logs = logrus.New()
	// entry := logrus.NewEntry(Logs)
	Logs.AddHook(&Client{Name: "haha"})
}

type Client struct {
	Name string
}

func (c *Client) Levels() []logrus.Level {
	return logrus.AllLevels
}
func (c *Client) Fire(entry *logrus.Entry) error {

	entry.Data["Client"] = c.Name
	return nil
}

type AuthCrypt struct {
	clientDecrypt *rc4.Cipher
	serverEncrypt *rc4.Cipher
	initialized   bool
}

func (ac *AuthCrypt) Init(k []byte) {
	ServerEncryptionKey := []uint8{0xCC, 0x98, 0xAE, 0x04, 0xE8, 0x97, 0xEA, 0xCA, 0x12, 0xDD, 0xC0, 0x93, 0x42, 0x91, 0x53, 0x57}
	serverEncryptHmac := hmac.New(sha1.New, ServerEncryptionKey)
	encryptHash := serverEncryptHmac.Sum(k)

	ServerDecryptionKey := []uint8{0xCC, 0x98, 0xAE, 0x04, 0xE8, 0x97, 0xEA, 0xCA, 0x12, 0xDD, 0xC0, 0x93, 0x42, 0x91, 0x53, 0x57}
	// ServerDecryptionKey := []uint8{0xC2, 0xB3, 0x72, 0x3C, 0xC6, 0xAE, 0xD9, 0xB5, 0x34, 0x3C, 0x53, 0xEE, 0x2F, 0x43, 0x67, 0xCE}
	clientDecryptHmac := hmac.New(sha1.New, ServerDecryptionKey)
	decryptHash := clientDecryptHmac.Sum(k)
	log.Println(encryptHash)
	log.Println(decryptHash)
	ac.clientDecrypt, _ = rc4.NewCipher(decryptHash)
	ac.serverEncrypt, _ = rc4.NewCipher(encryptHash)
	log.Println(ac.clientDecrypt)
	log.Println(ac.serverEncrypt)
	ac.initialized = true
}

func (ac *AuthCrypt) DecryptRecv(b []byte) {
	if !ac.initialized {
		return
	}
	ac.clientDecrypt.XORKeyStream(b, b)
}

func (ac *AuthCrypt) EncryptSend(b []byte) {
	if !ac.initialized {
		return
	}
	ac.serverEncrypt.XORKeyStream(b, b)
}
