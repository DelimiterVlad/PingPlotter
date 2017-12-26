// TimeFuncCounter.go
package TimeFuncCounter

import (
	"fmt"
	"time"
)

type TimeFuncCounter struct {
	RealMap  map[string]int
	ChTiming chan Bl_timer01
}
type Bl_timer01 struct {
	Name        string
	Timecounter int
}

var Zu *TimeFuncCounter

func (f *TimeFuncCounter) GetTimeCounters() {
	f.ChTiming = make(chan Bl_timer01)
	var ex int = 0
	for ex == 0 {
		lu := <-f.ChTiming
		//rk := strings.Split(lstr, "\t")
		pk := lu.Timecounter //strconv.Atoi(rk[1])
		f.RealMap[lu.Name] = int(((f.RealMap[lu.Name]) + pk) / 2)
	}
}
func IniMyTimers() time.Time {
	return time.Now().UTC()
}
func SendMyTimers(name string, mt time.Time) {
	var lu Bl_timer01
	ddur := time.Since(mt)
	lu.Name = name
	lu.Timecounter = int(ddur.Nanoseconds())
	Zu.ChTiming <- lu
}
func IniMyTiming() *TimeFuncCounter {
	Zu = new(TimeFuncCounter)
	Zu.RealMap = make(map[string]int)
	go Zu.GetTimeCounters()
	return Zu
}
func ShowTimeCounters(r *TimeFuncCounter) {
	time.Sleep(1000 * time.Millisecond)
	for namefunction, counter := range r.RealMap {
		fmt.Println(namefunction, counter, "nanosec")
	}
}
