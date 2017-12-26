// PingPlotter.go
package main

// typedef unsigned char Uint8;
// void my_audio_callback(void *userdata, Uint8 *stream, int len);
import "C"
import (
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	//	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	//	"./TimeFuncCounter"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/veandco/go-sdl2/sdl"
)

var (
	/// Window is the global SDL window.
	///
	Window *sdl.Window

	/// Renderer is the global SDL renderer.
	///
	Renderer *sdl.Renderer

	/// Screen is the global SDL render target for the VM's video memory.
	///
	Screen *sdl.Texture

	Bmp *sdl.Surface

	rect sdl.Rect
	/// Font is a fixed-width, bitmap font.
	///
	Font *sdl.Texture

	Gopher *sdl.Texture

	goph_y *sdl.Texture

	ox     int = 8
	oy     int = 8
	w      int = 286
	h      int = 480
	countx int = 11
	county int = 20
	wx     int
	hy     int
	// variable declarations
	//static Uint8 *audio_pos; // global pointer to the audio buffer to be played
	//static Uint32 audio_len; // remaining length of the sample we have to play
	audio_pos *uint8
	audio_len uint32

	KeyMap = map[sdl.Scancode]uint{
		sdl.SCANCODE_X: 0x0,
		sdl.SCANCODE_1: 0x1,
		sdl.SCANCODE_2: 0x2,
		sdl.SCANCODE_3: 0x3,
		sdl.SCANCODE_Q: 0x4,
		sdl.SCANCODE_W: 0x5,
		sdl.SCANCODE_E: 0x6,
		sdl.SCANCODE_A: 0x7,
		sdl.SCANCODE_S: 0x8,
		sdl.SCANCODE_D: 0x9,
		sdl.SCANCODE_Z: 0xA,
		sdl.SCANCODE_C: 0xB,
		sdl.SCANCODE_4: 0xC,
		sdl.SCANCODE_R: 0xD,
		sdl.SCANCODE_F: 0xE,
		sdl.SCANCODE_V: 0xF,
	}
)

const (
	toneHz   = 440
	sampleHz = 48000
	dPhase   = 2 * math.Pi * toneHz / sampleHz
)

//export my_audio_callback
func my_audio_callback(userdata unsafe.Pointer, stream *C.Uint8, length C.int) {
	n := int(length)
	//hdr := reflect.SliceHeader{Data: uintptr(unsafe.Pointer(stream)), Len: n, Cap: n}
	//buf := *(*[]C.Uint8)(unsafe.Pointer(&hdr))
	fmt.Println("/1/")
	if audio_len == 0 {
		return
	}
	if uint32(length) > audio_len {
		length = C.int(audio_len)
		rstream := (*uint8)(unsafe.Pointer(stream))
		sdl.MixAudio(rstream, audio_pos, uint32(length), sdl.MIX_MAXVOLUME)
		audio_len = 0
	} else {
		rstream := (*uint8)(unsafe.Pointer(stream))
		sdl.MixAudio(rstream, audio_pos, uint32(length), sdl.MIX_MAXVOLUME)
		l := (uintptr)(unsafe.Pointer(audio_pos))
		l += uintptr(n)
		audio_pos = (*uint8)(unsafe.Pointer(l))

		audio_len -= uint32(n)
	}
	//	fmt.Println("/2/")
	//	len = ( len > audio_len ? audio_len : len );
	//SDL_memcpy (stream, audio_pos, len); 					// simply copy from one buffer into the other
	//	SDL_MixAudio(stream, audio_pos, len, SDL_MIX_MAXVOLUME);// mix from one buffer into another

}
func minit() {
	runtime.LockOSThread()
}

func createWindow() {
	var err error

	// window attributes
	flags := sdl.WINDOW_OPENGL // | sdl.WINDOWPOS_CENTERED

	// create the window and renderer
	Window, Renderer, err = sdl.CreateWindowAndRenderer(700, 240, uint32(flags))
	if err != nil {
		panic(err)
	}

	// set the title
	Window.SetTitle("PingPlotter (GOlang+pCap+SDL2)!")

	// load the icon and use it if found
	//setIcon()

	// desired screen format and access
	format := sdl.PIXELFORMAT_RGB888
	access := sdl.TEXTUREACCESS_TARGET

	// create a render target for the display
	Screen, err = Renderer.CreateTexture(uint32(format), access, 128, 64)
	if err != nil {
		panic(err)
	}
}

/// loadFont loads the bitmap surface with font on it.
///
func loadFont() {
	var surface *sdl.Surface
	var err error

	if surface, err = sdl.LoadBMP("font.bmp"); err != nil {
		panic(err)
	}

	// get the magenta color
	mask := sdl.MapRGB(surface.Format, 255, 0, 255)

	// set the mask color key
	surface.SetColorKey(1, mask)

	// create the texture
	if Font, err = Renderer.CreateTextureFromSurface(surface); err != nil {
		panic(err)
	}

}

var (
	sema       = make(chan struct{}, 1)
	gIDcounter int32
)

func get_incrementor() int32 {
	var b int32
	sema <- struct{}{}
	b = gIDcounter
	if gIDcounter < 0xfffe {
		gIDcounter++
	} else {
		gIDcounter = 1
	}
	<-sema
	return b
}

const LEN_REZ = 120
const LEN_ARRAY = 500

type myarrf struct {
	flag       int
	TimeStampS time.Time
	TimeStampE time.Time
	ddur       int
	ip         [4]byte
	seq        int
	id         int
}

var pingArray [LEN_ARRAY]myarrf

type scll struct {
	max  int
	data [LEN_REZ]myarrf
}

var Msecond scll
var MuMsec sync.Mutex

var Mminutes scll
var MuMmin sync.Mutex

var Mhours scll
var MuMhour sync.Mutex

func AddToArray(id int, seq int, ip []byte) {
	var i, j int
	for i = LEN_ARRAY - 2; i >= 0; i-- {
		pingArray[i+1].flag = pingArray[i].flag
		pingArray[i+1].ddur = pingArray[i].ddur
		pingArray[i+1].id = pingArray[i].id
		pingArray[i+1].seq = pingArray[i].seq
		pingArray[i+1].TimeStampS = pingArray[i].TimeStampS
		pingArray[i+1].TimeStampE = pingArray[i].TimeStampE
		for j = 0; j < 4; j++ {
			pingArray[i+1].ip[j] = pingArray[i].ip[j]
		}
	}
	pingArray[0].flag = 1
	pingArray[0].id = id
	pingArray[0].seq = seq
	pingArray[0].TimeStampS = time.Now().UTC()
	for j = 0; j < 4; j++ {
		pingArray[0].ip[j] = ip[j]
	}
}
func FixToArray(id int, seq int) int {
	var f int = 0
	var r int = -1
	for i := 0; i < LEN_ARRAY && f == 0; i++ {
		if pingArray[i].flag == 1 {
			if id == pingArray[i].id && seq == pingArray[i].seq {
				pingArray[i].TimeStampE = time.Now().UTC()
				fdr := time.Since(pingArray[i].TimeStampS)
				r = int(fdr.Nanoseconds() / 1000000)
				pingArray[i].ddur = r
				pingArray[i].flag = 2
				f = 1
			}
		}
	}
	return r
}
func initD() {
	for i := 0; i < LEN_REZ; i++ {
		Mhours.data[i].flag = -1
		Mminutes.data[i].flag = -1
		Msecond.data[i].flag = -1
	}
}
func MenegerArray(chping chan string) {
	var ex int = 0
	var max int = 0
	var aver, maxflag int
	for ex == 0 {
		select {
		case xp := <-chping:
			xar := strings.Split(xp, "/")
			switch xar[0] {
			case "1": // add AddToArray(counter), Nochered, IPtoBytes(IPdata.srcIP))
				counter, _ := strconv.Atoi(xar[1])
				Nochered, _ := strconv.Atoi(xar[2])
				AddToArray(counter, Nochered, IPtoBytes(xar[3]))
				chping <- "ok"
			case "2": // fix FixToArray(id int,seq int)
				id, _ := strconv.Atoi(xar[1])
				seq, _ := strconv.Atoi(xar[2])
				zu := FixToArray(id, seq)
				chping <- strconv.Itoa(zu)
			}

		default:
			max = 0
			if pingArray[0].id != Msecond.data[0].id {
				MuMsec.Lock()
				for i := 0; i < LEN_REZ; i++ {
					switch pingArray[i].flag {
					case -1:
					case 0:
					case 1:
						ddur := time.Since(pingArray[i].TimeStampS)
						if int(ddur.Seconds()) > 4 {

							pingArray[i].flag = 3
							//fmt.Println("#")

						}
					case 2:
						if max < pingArray[i].ddur {
							max = pingArray[i].ddur
						}

					}
					Msecond.data[i].flag = pingArray[i].flag
					Msecond.data[i].ddur = pingArray[i].ddur
					Msecond.data[i].id = pingArray[i].id
					Msecond.data[i].seq = pingArray[i].seq
					Msecond.data[i].TimeStampS = pingArray[i].TimeStampS
					Msecond.data[i].TimeStampE = pingArray[i].TimeStampE
				}
				Msecond.max = max
				if Msecond.data[61].flag != -1 {
					MuMmin.Lock()
					ddur1 := time.Since(Msecond.data[61].TimeStampS)
					if Mminutes.data[0].flag > 0 {
						ddur2 := time.Since(Mminutes.data[0].TimeStampS)
						if int(ddur1.Minutes()) >= 1 && int(ddur2.Minutes()) >= 1 {
							// вставить
							max = 0

							for i := LEN_REZ - 2; i >= 0; i-- {
								Mminutes.data[i+1].ddur = Mminutes.data[i].ddur
								if max < Mminutes.data[i].ddur {
									max = Mminutes.data[i].ddur
								}
								Mminutes.data[i+1].flag = Mminutes.data[i].flag
								Mminutes.data[i+1].id = Mminutes.data[i].id
								Mminutes.data[i+1].TimeStampS = Mminutes.data[i].TimeStampS
							}
							aver = 0
							maxflag = 0
							for i := 0; i < 60; i++ {
								aver += Msecond.data[i].ddur
								if maxflag < Msecond.data[i].flag {
									maxflag = Msecond.data[i].flag
								}
							}
							Mminutes.data[0].ddur = aver / 60
							Mminutes.data[0].flag = maxflag
							Mminutes.data[0].id = Msecond.data[0].id
							Mminutes.data[0].TimeStampS = Msecond.data[0].TimeStampS
							if max < Mminutes.data[0].ddur {
								max = Mminutes.data[0].ddur
							}
							Mminutes.max = max
						}
					} else {
						//первый
						maxflag = 0
						aver = 0
						for i := 0; i < 60; i++ {
							if Msecond.data[i].flag == 3 {
								aver += 600
							} else {
								aver += Msecond.data[i].ddur
							}

							if maxflag < Msecond.data[i].flag {
								maxflag = Msecond.data[i].flag
							}
						}
						Mminutes.data[0].ddur = aver / 60
						Mminutes.max = Mminutes.data[0].ddur
						Mminutes.data[0].flag = maxflag
						Mminutes.data[0].id = Msecond.data[0].id
						Mminutes.data[0].TimeStampS = Msecond.data[0].TimeStampS
					}
					MuMmin.Unlock()
				}
				MuMsec.Unlock()
				MuMmin.Lock()
				MuMhour.Lock()

				if Mminutes.data[61].flag != -1 {

					ddur1 := time.Since(Mminutes.data[61].TimeStampS)
					if Mhours.data[0].flag > 0 {
						ddur2 := time.Since(Mhours.data[0].TimeStampS)
						if int(ddur1.Hours()) >= 1 && int(ddur2.Hours()) >= 1 {
							// вставить
							max = 0

							for i := LEN_REZ - 2; i >= 0; i-- {
								Mhours.data[i+1].ddur = Mhours.data[i].ddur
								if max < Mhours.data[i].ddur {
									max = Mhours.data[i].ddur
								}
								Mhours.data[i+1].flag = Mhours.data[i].flag
								Mhours.data[i+1].id = Mhours.data[i].id
								Mhours.data[i+1].TimeStampS = Mhours.data[i].TimeStampS
							}
							aver = 0
							maxflag = 0
							for i := 0; i < 60; i++ {
								aver += Mminutes.data[i].ddur
								if maxflag < Mminutes.data[i].flag {
									maxflag = Mminutes.data[i].flag
								}
							}
							Mhours.data[0].ddur = aver / 60
							Mhours.data[0].flag = maxflag
							Mhours.data[0].id = Mminutes.data[0].id
							Mhours.data[0].TimeStampS = Mminutes.data[0].TimeStampS
							if max < Mhours.data[0].ddur {
								max = Mhours.data[0].ddur
							}
							Mhours.max = max
						}
					} else {
						//первый
						maxflag = 0
						aver = 0
						for i := 0; i < 60; i++ {
							if Mminutes.data[i].flag == 3 {
								aver += 600
							} else {
								aver += Mminutes.data[i].ddur
							}

							if maxflag < Mminutes.data[i].flag {
								maxflag = Mminutes.data[i].flag
							}
						}
						Mhours.data[0].ddur = aver / 60
						Mhours.max = Mhours.data[0].ddur
						Mhours.data[0].flag = maxflag
						Mhours.data[0].id = Mminutes.data[0].id
						Mhours.data[0].TimeStampS = Mminutes.data[0].TimeStampS
					}

				}
				MuMmin.Unlock()
				MuMhour.Unlock()
				time.Sleep(1 * time.Microsecond)
			} else {
				time.Sleep(1 * time.Millisecond)
			}

		}
	}
}

/*
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;


//#################################################
typedef struct _TCPHeader
{
	unsigned short	SourcePort;
	unsigned short	DestinationPort;
	unsigned int		SequenceNumber;
	unsigned int		AcknowledgeNumber;
	unsigned char	DataOffset;		//Crappy MFC can't use bits
	unsigned char	Flags;
	unsigned short	Windows;
	unsigned short	Checksum;
	unsigned short	UrgentPointer;
} TCPHeader;

//#################################################




typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;

typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

typedef struct _ICMPHeader
{
  unsigned char		ICMPType;
  unsigned char		ICMPCode; // Type sub code
  unsigned short	ICMPChecksum;
  union
  {
	  struct {unsigned char uc1,uc2,uc3,uc4;} sUC;
	  struct {unsigned short us1,us2;} sUS;
	  unsigned long sUL;
  } sICMP;
  unsigned long		ICMP_Originate_Timestamp; // Not standard field in header, but reserved nonetheless
  unsigned long		ICMP_Receive_Timestamp;
  unsigned long		ICMP_Transmit_Timestamp;
} ICMPHeader;
*/
type icmp_header struct {
	ICMPType                 uint8
	ICMPCode                 uint8 // Type sub code
	ICMPChecksum             uint16
	sU                       uint64
	ICMP_Originate_Timestamp uint64
	ICMP_Receive_Timestamp   uint64
	ICMP_Transmit_Timestamp  uint64
}
type ip_header struct {
	ver_ihl        uint8      // Version (4 bits) + Internet header length (4 bits)
	tos            uint8      // Type of service
	tlen           uint16     // Total length
	identification uint16     // Identification
	flags_fo       uint16     // Flags (3 bits) + Fragment offset (13 bits)
	ttl            uint8      // Time to live
	proto          uint8      // Protocol
	crc            uint16     // Header checksum
	saddr          ip_address // Source address
	daddr          ip_address // Destination address
	op_pad         uint32     // Option + Padding
}
type ip_address struct {
	byte1 uint8
	byte2 uint8
	byte3 uint8
	byte4 uint8
}

var (
	device       string = "\\Device\\NPF_{D2076530-B496-4851-9CAA-B84E9F37030C}"
	snapshot_len int32  = 1024
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 1 * time.Millisecond
	handle       *pcap.Handle
	buffer       gopacket.SerializeBuffer
	options      gopacket.SerializeOptions
)

/*
unsigned short BytesTo16(unsigned char X,unsigned char Y)
{
     unsigned short Tmp = X;
     Tmp = Tmp << 8;
     Tmp = Tmp | Y;
     return Tmp;
}
*/
func BytesTo16(Xs uint8, Ys uint8) uint16 {
	var T uint16
	T = uint16(Xs)
	T = T << 8
	T = T | uint16(Ys)
	return T
}
func Int16ToBytes(value uint16) []byte {
	var rez []byte
	rez = make([]byte, 2)
	rez[1] = byte(value & 0xff)
	rez[0] = byte((value & 0xff00) >> 8)
	//	fmt.Println("Convert:", value, rez[0], rez[1])
	return rez
}

/*
unsigned short RawPacket::CalculateIPChecksum(void)
{
    unsigned short CheckSum = 0;
    for(int i = 14;i<34;i+=2)
    {
        unsigned short Tmp = BytesTo16(FinalPacket[i],FinalPacket[i+1]);
        unsigned short Difference = 65535 - CheckSum;
        CheckSum += Tmp;
        if(Tmp > Difference){CheckSum += 1;}
    }
    CheckSum = ~CheckSum;
    return htons(CheckSum);
}
*/
func htons(value uint16) uint16 {
	var (
		lowbyte  uint8  = uint8(value)
		highbyte uint8  = uint8(value << 8)
		ret      uint16 = uint16(lowbyte)<<8 + uint16(highbyte)
	)
	return ret
}

func CalculateIPChecksum(addr []byte, begin int, end int) uint16 {
	var CheckSum uint32 = 0xffff
	mlen := end - begin

	for i := 0; i+1 < mlen; i += 2 {

		Tmp := BytesTo16(addr[i+begin], addr[i+begin+1])
		CheckSum += uint32(Tmp)
		if CheckSum > 0xffff {
			CheckSum -= 0xffff
		}
	}
	if (mlen & 1) == 1 {
		Tmp := BytesTo16(addr[begin+mlen-1], 0)

		CheckSum += uint32(Tmp)
		if CheckSum > 0xffff {
			CheckSum -= 0xffff
		}
	}

	CheckSum = ^CheckSum
	CheckSum = CheckSum & 0xffff

	return uint16(CheckSum)

}

type IPdat struct {
	srcIP string
	dstIP string
	proto uint8
	ttl   uint8
}
type ICMPdat struct {
	kind uint8
	code uint8
	data string
}
type EthernDat struct {
	//00 14 D1 E5 9D 0C 24 FD 52 F7 3E 44 08 00
	MACsrc [6]byte
	MACdst [6]byte
	proto  uint16
}

/*
594fc029.937389 len:74 	192.168.10.204	 -> 8.8.4.4 (ICMP) Ask echo
00 14 D1 E5 9D 0C 24 FD 52 F7 3E 44 08 00 45 00 	| .Сеќ.$эRч>D..E.
00 3C 11 A1 00 00 80 01 51 A0 C0 A8 0A CC 08 08 	| .<Ў..Ђ.Q АЁ.М..
04 04 08 00 4D 47 00 01 00 14 61 62 63 64 65 66 	| ....MG...ABCDEF
67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 	| GHIJKLMNOPQRSTUV
77 61 62 63 64 65 66 67 68 69 	| WABCDEFGHI
*/
func addBytes(dst []byte, src []byte, len int) []byte {
	for i := 0; i < len; i++ {
		dst = append(dst, src[i])
	}
	return dst
}
func IPtoBytes(ip string) []byte {
	var rez []byte
	rez = make([]byte, 0)
	a_ip := strings.Split(ip, ".")
	for i := 0; i < 4 && i < len(a_ip); i++ {
		b, _ := strconv.Atoi(a_ip[i])
		rez = append(rez, byte(b))
	}
	return rez
}
func replaceBytes(src []byte) []byte {
	var b byte
	b = src[0]
	src[0] = src[1]
	src[1] = b
	return src
}
func createPacket(EthernetData EthernDat, IPdata IPdat, ICMPdata ICMPdat, counter int32, chp chan string) []byte {
	//	var gIp ip_header
	packet := make([]byte, 0)
	packet = addBytes(packet, EthernetData.MACdst[:6], 6)
	packet = addBytes(packet, EthernetData.MACsrc[:6], 6)
	zp := Int16ToBytes(EthernetData.proto)
	zp = replaceBytes(zp)
	packet = addBytes(packet, zp, 2)
	//ip
	version := 4
	headerLen := 5
	packet = append(packet, byte((version<<4)+headerLen))
	tos := 0
	packet = append(packet, byte(tos))
	TotalLen := 0x3C
	tt := Int16ToBytes(uint16(TotalLen))
	packet = addBytes(packet, tt, 2)
	Ident := 0x11A1
	zp = Int16ToBytes(uint16(Ident))
	packet = addBytes(packet, zp, 2)
	FrOffset := 0
	zp = Int16ToBytes(uint16(FrOffset))
	packet = addBytes(packet, zp, 2)
	packet = append(packet, byte(IPdata.ttl))
	packet = append(packet, byte(IPdata.proto))
	psevdoCrc := 0
	psevdoPos := len(packet)
	zp = Int16ToBytes(uint16(psevdoCrc))
	packet = addBytes(packet, zp, 2)
	ipp := IPtoBytes(IPdata.srcIP)
	packet = addBytes(packet, ipp, 4)
	ipp = IPtoBytes(IPdata.dstIP)
	packet = addBytes(packet, ipp, 4)
	RealCRC := CalculateIPChecksum(packet, 14, 34)
	zp = Int16ToBytes(RealCRC)
	packet[psevdoPos] = zp[0]
	packet[psevdoPos+1] = zp[1]
	// icmp
	posbegin := len(packet)
	packet = append(packet, byte(ICMPdata.kind))
	packet = append(packet, byte(ICMPdata.code))
	psevdoCrc = 0
	psevdoPos = len(packet)
	zp = Int16ToBytes(uint16(psevdoCrc))
	packet = addBytes(packet, zp, 2)
	identIcmp := counter
	zp = Int16ToBytes(uint16(identIcmp))
	packet = addBytes(packet, zp, 2)
	Nochered := rand.Intn(255)
	//fmt.Println(">>", identIcmp, Nochered)
	zp = Int16ToBytes(uint16(Nochered))
	packet = addBytes(packet, zp, 2)
	kbytes := []byte(ICMPdata.data)
	packet = addBytes(packet, kbytes, len(kbytes))
	posfinish := len(packet)
	RealCRC = CalculateIPChecksum(packet, posbegin, posfinish)
	zp = Int16ToBytes(RealCRC)
	packet[psevdoPos] = zp[0]
	packet[psevdoPos+1] = zp[1]
	zkstr := fmt.Sprintf("1/%d/%d/", int(counter), Nochered)
	zkstr += IPdata.srcIP
	chp <- zkstr

	//	AddToArray(int(counter), Nochered, IPtoBytes(IPdata.srcIP))
	return packet
}

func hexToByte(src string) byte {
	var kpt int = 1
	var l int
	var num uint16 = 0
	lstr := strings.TrimSpace(src)
	kar := strings.Split(lstr, "")
	for i := len(kar) - 1; i >= 0; i-- {
		switch kar[i] {
		case "0":
			l = 0
		case "1":
			l = 1
		case "2":
			l = 2
		case "3":
			l = 3
		case "4":
			l = 4
		case "5":
			l = 5
		case "6":
			l = 6
		case "7":
			l = 7
		case "8":
			l = 8
		case "9":
			l = 9
		case "A":
			l = 10
		case "a":
			l = 10
		case "B":
			l = 11
		case "b":
			l = 11
		case "C":
			l = 12
		case "c":
			l = 12
		case "D":
			l = 13
		case "d":
			l = 13
		case "E":
			l = 14
		case "e":
			l = 14
		case "F":
			l = 15
		case "f":
			l = 15

		}
		num = num + uint16(l*kpt)
		kpt = kpt * 16
	}
	return byte(num)
}
func generate(handle *pcap.Handle, IPsrc string, IPdst string, MACsrc string, MACdst string, chp chan string, che chan int) {
	var ex = 0
	var Ethernet EthernDat
	var IP IPdat
	var ICMP ICMPdat
	get_incrementor()
	fmt.Println("1.", MACsrc)
	yy1 := strings.Split(MACsrc, ":")
	for i := 0; i < 6; i++ {
		Ethernet.MACsrc[i] = hexToByte(yy1[i])
	}
	fmt.Println("2.", MACdst)
	yy1 = strings.Split(MACdst, ",")
	for i := 0; i < 6; i++ {
		Ethernet.MACdst[i] = hexToByte(yy1[i])
	}
	//	Ethernet.MACsrc = [6]uint8{0x00, 0x14, 0xD1, 0xE5, 0x9D, 0x0C}
	//	Ethernet.MACdst = [6]uint8{0x24, 0xFD, 0x52, 0xF7, 0x3E, 0x44}
	Ethernet.proto = 8
	IP.dstIP = IPdst
	IP.srcIP = IPsrc
	IP.proto = 1 //ICMP
	IP.ttl = 0x80
	ICMP.kind = 8
	ICMP.code = 0
	ICMP.data = "abcdefghijklmnopqrstuvwabcdefghi"
	for ex == 0 {
		//		time.Sleep(1 * time.Second)
		select {
		case <-che:
			ex = 1
		default:
			mypacket := createPacket(Ethernet, IP, ICMP, get_incrementor(), chp)
			/*fmt.Println("Len:", len(mypacket))
			for i := 0; i < len(mypacket); i += 16 {
				for j := 0; j < 16 && i+j < len(mypacket); j++ {
					ss := fmt.Sprintf("%x ", mypacket[i+j])
					fmt.Print(ss)
				}
				fmt.Println("")
			} */
			//fmt.Println("S+")
			err := handle.WritePacketData(mypacket)
			if err != nil {
				fmt.Println(err)
			}
			<-chp
			time.Sleep(1 * time.Second)
		}

	}

}

func getIPandMac() (string, string) {
	addrs, err := net.InterfaceAddrs()

	if err != nil {
		//		fmt.Println(err)
		return "", ""
	}

	var currentIP, currentNetworkHardwareName string

	for _, address := range addrs {

		// check the address type and if it is not a loopback the display it
		// = GET LOCAL IP ADDRESS
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				//fmt.Println("Current IP address : ", ipnet.IP.String())
				currentIP = ipnet.IP.String()
			}
		}
	}
	interfaces, _ := net.Interfaces()
	for _, interf := range interfaces {

		if addrs, err := interf.Addrs(); err == nil {
			for _, addr := range addrs {
				//fmt.Println("[", index, "]", interf.Name, ">", addr)

				// only interested in the name with current IP address
				if strings.Contains(addr.String(), currentIP) {
					//					fmt.Println("Use name : ", interf.Name)
					currentNetworkHardwareName = interf.Name
				}
			}
		}
	}

	//fmt.Println("------------------------------")

	// extract the hardware information base on the interface name
	// capture above
	netInterface, err := net.InterfaceByName(currentNetworkHardwareName)

	if err != nil {
		//		fmt.Println(err)
		return "", ""
	}

	//	name := netInterface.Name
	macAddress := netInterface.HardwareAddr

	//	fmt.Println("Hardware name : ", name)
	//	fmt.Println("MAC address : ", macAddress)

	// verify if the MAC address can be parsed properly
	hwAddr, err := net.ParseMAC(macAddress.String())

	if err != nil {
		//		fmt.Println("No able to parse MAC address : ", err)
		return "", ""
	}
	//	fmt.Printf("Physical hardware address : %s \n", hwAddr.String())
	return currentIP, hwAddr.String()
}
func getMACgate(MACsrc string, IPsrc string, IPdst string) (string, bool) {
	var flag int = 0
	var testIP [4]byte
	var Mdst []byte
	var rezult bool
	dIp := strings.Split(IPdst, ".")
	for i := 0; i < 4; i++ {
		lt, _ := strconv.Atoi(dIp[i])
		testIP[i] = byte(lt)
	}
	var ex int = 0
	var rezMAC = ""
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
		rezMAC = ""
		rezult = false
	} else {
		// Set filter
		var filter string = "tcp"
		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal(err)
			rezMAC = ""
			rezult = false
		} else {
			for ex == 0 {
				data, info, err := handle.ReadPacketData()
				if err == nil {
					if info.CaptureLength > 0 {
						//				Msrc := data[0:6]
						Mdst = data[0:6] //data[6:12]
						Idst := data[30:34]
						flag = 0
						for i := 0; i < 4 && flag == 0; i++ {
							if Idst[i] != testIP[i] {
								flag = 1
							}
						}
						if flag == 0 {
							ex = 1
							//					fmt.Println("Src=", Msrc)
							//					fmt.Println("Dst=", Mdst)
						}

					}
				}

			}
			rezMAC = ""
			for i := 0; i < 6; i++ {
				ll := fmt.Sprintf("%x", Mdst[i])
				rezMAC += ll
				if i < 5 {
					rezMAC += ","
				}
			}
			rezult = true
		}

		handle.Close()
	}

	return rezMAC, rezult
}
func tuneMAC(IPdst string, chi chan int) {
	var ex = 0
	var connectlink string
	connectlink = IPdst
	connectlink += ":11"
	for ex == 0 {
		select {
		case x := <-chi:
			ex = 1
			fmt.Println(x)
		default:
			_, _ = net.Dial("tcp", connectlink)
			time.Sleep(1 * time.Second)
		}
	}
}
func start_sniff(IPdst string, chp chan string) {
	// Open device
	var ex int = 0
	var ex2 int = 0
	IP, MAC := getIPandMac()
	fmt.Println("мой мак:", MAC)
	chi := make(chan int)
	che := make(chan int)
	rand.Seed(time.Now().UTC().UnixNano())
	go tuneMAC("10.10.10.10", chi)
	MAC2, rez := getMACgate(MAC, IP, "10.10.10.10")
	if rez == true {
		fmt.Println("MAC gate:", MAC2)
		chi <- -1

		for ex == 0 {
			handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
			if err != nil {
				log.Fatal(err)
			} else {
				go generate(handle, IP, IPdst, MAC, MAC2, chp, che)
				// Set filter
				var filter string = "icmp"
				err = handle.SetBPFFilter(filter)
				if err != nil {
					log.Fatal(err)
				} else {
					fmt.Println("Only icmp")
					ex2 = 0
					for ex2 == 0 {
						data, info, err := handle.ReadPacketData()
						if err == nil {
							if info.CaptureLength > 0 {
								if data[34] == 0 && data[35] == 0 {
									//fmt.Println(data)
									klu := (int(data[38]) << 8) + int(data[39])
									kl2 := (int(data[40]) << 8) + int(data[41])
									zz := fmt.Sprintf("2/%d/%d", klu, kl2)
									//fmt.Println(zz)
									chp <- zz
									ku := <-chp
									fmt.Println(ku, "milisec")
								}

							}
						} else {
							//
							if err.Error() != "Timeout Expired" {
								fmt.Println(err.Error())
								ex2 = 1
							}
							time.Sleep(1 * time.Microsecond)
						}
					}

					/*
						packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
						for packet := range packetSource.Packets() {
							// Do something with a packet here.
							uu := packet.Layers()
							ub := uu[2].LayerContents() //3-й слой
							//		fmt.Println(ub)
							if ub[0] == 0 && ub[1] == 0 {
								klu := (int(ub[4]) << 8) + int(ub[5])
								kl2 := (int(ub[6]) << 8) + int(ub[7])
								//			fmt.Println("Check:", klu)
								zz := fmt.Sprintf("2/%d/%d", klu, kl2)
								c := TimeFuncCounter.IniMyTimers()
								chp <- zz
								ku := <-chp
								TimeFuncCounter.SendMyTimers("between", c)
								fmt.Println(ku, "milisec")
							} else {
								if ub[0] == 3 && ub[1] == 0 {
									// невозможно доставить сеть
									//fmt.Println(">>", uu[3])
								} else {
									if ub[0] == 3 && ub[1] == 1 {
										// невозможно доставить на комп
										//fmt.Println(">>", uu[3])
									} else {
										if ub[0] == 11 && ub[1] == 0 {
											// превышен ttl
											//fmt.Println(">>>", uu[3])
											//chu <- 2
										}
									}
								}
							}

						} */
					che <- 1
					time.Sleep(5 * time.Second)
					handle.Close()
					fmt.Println("Close handle")
				}

			}
		}

	} else {
		fmt.Println("Install WinPCap library (https://www.winpcap.org/install/default.htm)")
	}

}

/// drawText using the bitmap font a string at a given location.
///
func drawText(s string, x, y int) {
	src := sdl.Rect{W: 5, H: 7}
	dst := sdl.Rect{
		X: int32(x),
		Y: int32(y),
		W: 5,
		H: 7,
	}

	// loop over all the characters in the string
	for _, c := range s {
		if c > 32 && c < 127 {
			src.X = (c - 33) * 6

			// draw the character to the renderer
			Renderer.Copy(Font, &src, &dst)
		}

		// advance
		dst.X += 7
	}
}

func loadGopher() {
	var usurface *sdl.Surface
	var err error

	if usurface, err = sdl.LoadBMP("gopher.bmp"); err != nil {
		panic(err)
	}

	// get the magenta color
	mask := sdl.MapRGB(usurface.Format, 255, 0, 255)

	// set the mask color key
	usurface.SetColorKey(1, mask)

	// create the texture
	if Gopher, err = Renderer.CreateTextureFromSurface(usurface); err != nil {
		panic(err)
	}

}
func draw_gopher(x, y int, offsetX int, wX int, offsetY int, hy int) {

	src := sdl.Rect{
		W: 180,
		H: 140,
		X: 0,
		Y: 0,
	}
	dst := sdl.Rect{
		X: int32(x),
		Y: int32(y),
		W: 180,
		H: 140,
	}

	Renderer.Copy(Gopher, &src, &dst)

}

func drawScreen(offsetX int, offsetY int, right int, bottom int) {
	/*
		Renderer.SetDrawColor(250, 250, 0, 255)
		Renderer.DrawLine(x, y, x+w, y)
	*/
	var offX, offY, KM int
	var Koeff float32
	draw_gopher(515, 95, 0, 180, 0, 140)
	MuMsec.Lock()
	offX = 9
	offY = 9
	Renderer.SetDrawColor(250, 250, 0, 255)
	if Msecond.max < 90 {
		KM = 90
	} else {
		KM = Msecond.max
	}
	Koeff = (float32(KM) / 67.0)
	if Koeff > 0.0 {
		//oldy = 0
		for i := 0; i < LEN_REZ; i++ {
			switch Msecond.data[i].flag {
			case 0:
				//oldy = 34
				//Renderer.SetDrawColor(0, 0, 0, 255)
				//Renderer.DrawLine(i*4+offX, offY, i*4+offX, 60+offY)
			case 1:
				//oldy = 34
				Renderer.SetDrawColor(0, 0, 0, 255)
				Renderer.DrawLine(i*4+offX, offY, i*4+offX, 60+offY)
			case 2:
				Renderer.SetDrawColor(250, 250, 0, 255)
				Renderer.DrawLine(i*4+offX, offY, i*4+offX, int(float32(Msecond.data[i].ddur)/Koeff)+offY)
				//oldy = int(float32(Msecond.data[i].ddur) / Koeff)
			case 3:
				Renderer.SetDrawColor(250, 0, 0, 255)
				Renderer.DrawLine(i*4+offX, offY, i*4+offX, 60+offY)
				//oldy = 34
			}
		}
	}
	frame2(460, 56, 47, 20)
	zpl := strconv.Itoa(KM)
	drawText("_"+zpl, 465, 65)
	//fmt.Println("+")
	MuMsec.Unlock()
	MuMmin.Lock()
	offX = 12
	offY = 85
	Renderer.SetDrawColor(0, 250, 0, 255)
	if Mminutes.max < 60 {
		KM = 60
	} else {
		KM = Mminutes.max
	}
	Koeff = (float32(KM) / 67.0)
	if Koeff > 0.0 {
		//oldy = 0
		for i := 0; i < LEN_REZ; i++ {
			switch Mminutes.data[i].flag {
			case 0:
				//oldy = 34
			case 1:
				//oldy = 34
				Renderer.SetDrawColor(0, 0, 0, 255)
				Renderer.DrawLine(i*4+offX, offY, i*4+offX, int(float32(Mminutes.data[i].ddur)/Koeff)+offY)
			case 2:
				Renderer.SetDrawColor(0, 250, 0, 255)
				Renderer.DrawLine(i*4+offX, offY, i*4+offX, int(float32(Mminutes.data[i].ddur)/Koeff)+offY)
				//oldy = int(float32(Msecond.data[i].ddur) / Koeff)
			case 3:
				Renderer.SetDrawColor(250, 0, 0, 255)
				Renderer.DrawLine(i*4+offX, offY, i*4+offX, int(float32(Mminutes.data[i].ddur)/Koeff)+offY)
				//oldy = 34
			}
		}
	}
	frame2(460, 132, 47, 20)
	zpl = strconv.Itoa(KM)
	drawText("_"+zpl, 465, 140)
	MuMmin.Unlock()

	MuMhour.Lock()
	offX = 12
	offY = 161
	Renderer.SetDrawColor(0, 250, 250, 255)
	if Mhours.max < 40 {
		KM = 40
	} else {
		KM = Mhours.max
	}
	Koeff = (float32(KM) / 67.0)
	if Koeff > 0.0 {
		//oldy = 0
		for i := 0; i < LEN_REZ; i++ {
			switch Mhours.data[i].flag {
			case 0:
				//oldy = 34
			case 1:
				//oldy = 34
				Renderer.SetDrawColor(0, 0, 0, 255)
				Renderer.DrawLine(i*4+offX, offY, i*4+offX, int(float32(Mhours.data[i].ddur)/Koeff)+offY)
			case 2:
				Renderer.SetDrawColor(0, 250, 250, 255)
				Renderer.DrawLine(i*4+offX, offY, i*4+offX, int(float32(Mhours.data[i].ddur)/Koeff)+offY)
				//oldy = int(float32(Msecond.data[i].ddur) / Koeff)
			case 3:
				Renderer.SetDrawColor(250, 0, 250, 255)
				Renderer.DrawLine(i*4+offX, offY, i*4+offX, int(float32(Mhours.data[i].ddur)/Koeff)+offY)
				//oldy = 34
			}
		}
	}
	frame2(460, 208, 47, 20)
	zpl = strconv.Itoa(KM)
	drawText("_"+zpl, 465, 216)
	MuMhour.Unlock()

	/*myfield.lock = true

	wx = int((right - offsetX) / countx)
	hy = int((bottom - offsetY) / county)
	//32, 42, 53,
	draw_gopher(80, 294, offsetX, wx, offsetY, hy)
	for i := 0; i < 20; i++ {
		for j := 0; j < 11; j++ {
			rect.X = int32(offsetX + j*wx + 2)
			rect.Y = int32(offsetY + i*hy + 2)
			rect.W = int32(wx - 4)
			rect.H = int32(hy - 4)
			switch myfield.field[i][j] {
			case 0:
				//Renderer.SetDrawColor(32, 42, 53, 255)
				//Renderer.FillRect(&rect)
			case 1:
				Renderer.SetDrawColor(132, 142, 153, 255)
				Renderer.DrawRect(&rect)
				rect.X += 1
				rect.Y += 1
				rect.W -= 2
				rect.H -= 2
				Renderer.SetDrawColor(0, 0, 0, 255)
				Renderer.DrawRect(&rect)
				rect.X += 1
				rect.Y += 1
				rect.W -= 2
				rect.H -= 2
				Renderer.SetDrawColor(90, 90, 190, 255)
				Renderer.FillRect(&rect)
			case 2:
				Renderer.SetDrawColor(132, 142, 153, 255)
				Renderer.DrawRect(&rect)
				rect.X += 1
				rect.Y += 1
				rect.W -= 2
				rect.H -= 2
				Renderer.SetDrawColor(0, 0, 0, 255)
				Renderer.DrawRect(&rect)
				rect.X += 1
				rect.Y += 1
				rect.W -= 2
				rect.H -= 2
				Renderer.SetDrawColor(90, 90, 190, 255)
				Renderer.FillRect(&rect)
			case -1:
				Renderer.SetDrawColor(190, 190, 190, 255)
				Renderer.DrawRect(&rect)
				rect.X += 1
				rect.Y += 1
				rect.W -= 2
				rect.H -= 2
				Renderer.SetDrawColor(0, 0, 0, 255)
				Renderer.DrawRect(&rect)
				rect.X += 1
				rect.Y += 1
				rect.W -= 2
				rect.H -= 2
				Renderer.SetDrawColor(90, 90, 90, 255)
				Renderer.FillRect(&rect)

			}
		}
	}
	drawText("Score:", 40, 500)
	drawText(strconv.Itoa(myfield.counter), 100, 500)
	myfield.lock = false */
}
func frame(x, y, w, h int) {
	Renderer.SetDrawColor(0, 0, 0, 255)
	Renderer.DrawLine(x, y, x+w, y)
	Renderer.DrawLine(x, y, x, y+h)

	// highlight
	Renderer.SetDrawColor(95, 112, 120, 255)
	Renderer.DrawLine(x+w, y, x+w, y+h)
	Renderer.DrawLine(x, y+h, x+w, y+h)

}
func frame2(x, y, w, h int) {
	Renderer.SetDrawColor(0, 0, 25, 255)
	rect.X = int32(x)
	rect.Y = int32(y)
	rect.W = int32(w)
	rect.H = int32(h)
	Renderer.FillRect(&rect)
	Renderer.SetDrawColor(0, 0, 0, 255)
	Renderer.DrawLine(x, y, x+w, y)
	Renderer.DrawLine(x, y, x, y+h)

	// highlight
	Renderer.SetDrawColor(95, 112, 120, 255)
	Renderer.DrawLine(x+w, y, x+w, y+h)
	Renderer.DrawLine(x, y+h, x+w, y+h)

}
func redraw() {
	//updateScreen()

	// clear the renderer
	Renderer.SetDrawColor(32, 42, 53, 255)
	rect.X = 0
	rect.Y = 0
	rect.W = 700
	rect.H = 240
	Renderer.FillRect(&rect)

	// frame the screen, instructions, log, and registers
	//frame(ox, oy, w, h)
	frame(8, 8, 500, 68)
	frame(8, 84, 500, 68)
	frame(8, 160, 500, 68)
	Renderer.SetDrawColor(20, 20, 40, 255)
	//	Renderer.DrawLine(258, 9, 258, 75)
	len := 5
	for i := 9; i < 75; i += len * 2 {
		Renderer.DrawLine(258, i, 258, i+len)
	}
	for i := 9; i < 508; i += len * 2 {
		Renderer.DrawLine(i, 42, i+len, 42)
	}
	for i := 85; i < 153; i += len * 2 {
		Renderer.DrawLine(258, i, 258, i+len)
	}
	for i := 9; i < 508; i += len * 2 {
		Renderer.DrawLine(i, 118, i+len, 118)
	}
	len = 3
	for i := 9; i < 508; i += len * 3 {
		Renderer.DrawLine(i, 194, i+len, 194)
	}
	for j := 105; j < 508; j += 96 {
		for i := 161; i < 228; i += len * 3 {
			Renderer.DrawLine(j, i, j, i+len)
		}
	}
	drawText("S", 500, 10)
	drawText("E", 500, 22)
	drawText("C", 500, 34)
	drawText("M", 500, 86)
	drawText("I", 500, 98)
	drawText("N", 500, 110)
	drawText("H", 500, 162)
	drawText("O", 500, 174)
	drawText("U", 500, 186)
	drawText("R", 500, 198)
	drawText("<DELIMITER-Lab>", 530, 9)
	drawText("Smolentsev Vladimir", 530, 22)
	drawText("telegram: @DelimiterVlad", 520, 43)
	//	frame(438, 8, 70, 68)
	//frame(438, 84, 70, 68)
	//frame(438, 160, 70, 68)
	//	frame2(438, 54, 70, 22)
	//frame2(438, 130, 70, 22)
	//frame2(438, 206, 70, 22)
	drawScreen(ox, oy, ox+w, oy+h)

	// show it
	Renderer.Present()
	Renderer.Clear()
	//Renderer.SetRenderTarget(nil)

}

func main() {
	//	fp := TimeFuncCounter.IniMyTiming()
	//	defer TimeFuncCounter.ShowTimeCounters(fp)
	initD()
	minit()
	chp := make(chan string)
	go MenegerArray(chp)
	//	rand.Seed(time.Now().UTC().UnixNano())
	if err := sdl.Init(sdl.INIT_VIDEO); err != nil {
		panic(err)
	}

	//go soundManager(chu)
	/*	spec := &sdl.AudioSpec{
			Freq:     sampleHz,
			Format:   sdl.AUDIO_U8,
			Channels: 2,
			Samples:  sampleHz,
			Callback: sdl.AudioCallback(C.SineWave),
		}
		sdl.OpenAudio(spec, nil)
		sdl.PauseAudio(false)
		time.Sleep(1 * time.Second)
		sdl.PauseAudio(true) */

	createWindow()
	loadFont()
	loadGopher()
	go start_sniff("8.8.8.8", chp)
	ch := make(chan int, 3)

	//	loadGopher()
	//	initField()
	//	init_generic()

	video := time.NewTicker(time.Second / 10)
	//	go manager(&myfield, ch)
	for processEvents(ch) {

		select {
		case <-video.C:
			redraw()

		}
		time.Sleep(1 * time.Millisecond)
	}

	sdl.Quit()
}
func processEvents(ch chan int) bool {
	rez := true
	for e := sdl.PollEvent(); e != nil; e = sdl.PollEvent() {
		switch ev := e.(type) {
		case *sdl.QuitEvent:
			return false
		case *sdl.DropEvent:

		case *sdl.KeyDownEvent:
			if _, ok := KeyMap[ev.Keysym.Scancode]; ok {
				//			if key, ok := KeyMap[ev.Keysym.Scancode]; ok {

			} else {
				switch ev.Keysym.Scancode {
				case sdl.SCANCODE_ESCAPE:
					rez = false

				case sdl.SCANCODE_UP:
					ch <- 1
				case sdl.SCANCODE_DOWN:
					ch <- 2
				case sdl.SCANCODE_SPACE:
					ch <- 3
				case sdl.SCANCODE_LEFT:
					ch <- 4
				case sdl.SCANCODE_RIGHT:
					ch <- 5
				}
			}
		case *sdl.KeyUpEvent:

		}
	}

	return rez
}
