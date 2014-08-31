package main

import (
    "os"
    "time"
    "encoding/json"
    "github.com/garyburd/redigo/redis"
)

type NodeState struct {
    Bind string	`json:"bind"`
    Live bool	`json:"live"`
}

func StateBeat(crs redis.Conn) {
    crs.Do("SADD","STATE_CLUS_BIND",BIND)
    file,_ := os.Open("/proc/cpuinfo")
    infobuf := make([]byte,65536)
    infolen,_ := file.Read(infobuf)
    file.Close()
    crs.Do("HSET","NODE@" + BIND,"CPUINFO",string(infobuf[:infolen]))
    for {
	file,_ := os.Open("/proc/loadavg")
	infolen,_ = file.Read(infobuf)
	file.Close()
	crs.Do("HSET","NODE@" + BIND,"LOAD",string(infobuf[:infolen]))
	crs.Do("EXPIRE","NODE@" + BIND,180)

	updateClus(crs)
	time.Sleep(60 * time.Second)
    }
}
func StateClus(crs redis.Conn) ([]map[string]NodeState,error) {
    updateClus(crs)

    logs,_ := redis.Values(crs.Do("LRANGE","STATE_CLUS_LOG",0,2))
    states := [](map[string]NodeState){}
    for _,log := range(logs) {
	var state map[string]NodeState
	json.Unmarshal(log.([]byte),&state)
	states = append(states,state)
    }

    return states,nil
}

func updateClus(crs redis.Conn) {
    if ok,_ := crs.Do(
	"SET",
	"STATE_CLUS_UPDATED",
	1,
	"EX",
	300,
	"NX",
    ); ok == nil {
	return
    }

    binds,_ := redis.Strings(crs.Do("SMEMBERS","STATE_CLUS_BIND"))
    for _,bind := range(binds) {
	crs.Send("EXISTS","NODE@" + bind)
    }
    crs.Flush()
    state := map[string]NodeState{}
    for _,bind := range(binds) {
	live := true
	if ret,_ := redis.Int64(crs.Receive()); ret == 0 {
	    live = false
	}
	state[bind] = NodeState{
	    Bind:bind,
	    Live:live,
	}
    }

    logbuf,_ := json.Marshal(state)
    crs.Do("LPUSH","STATE_CLUS_LOG",logbuf)
}
