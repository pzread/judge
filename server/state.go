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

func StateBeat(CRs redis.Conn) {
    CRs.Do("SADD","STATE_CLUS_BIND",BIND)
    file,_ := os.Open("/proc/cpuinfo")
    infobuf := make([]byte,65536)
    infolen,_ := file.Read(infobuf)
    file.Close()
    CRs.Do("HSET","NODE@" + BIND,"CPUINFO",string(infobuf[:infolen]))
    for {
	file,_ := os.Open("/proc/loadavg")
	infolen,_ = file.Read(infobuf)
	file.Close()
	CRs.Send("HSET","NODE@" + BIND,"LOAD",string(infobuf[:infolen]))
	CRs.Send("EXPIRE","NODE@" + BIND,180)
	CRs.Flush()
	CRs.Receive()
	time.Sleep(60 * time.Second)
    }
}
func StateClus(env *APIEnv) ([]map[string]NodeState,error) {
    states := [](map[string]NodeState){}

    if ok,_ := env.CRs.Do(
	"SET",
	"STATE_CLUS_UPDATED",
	1,
	"EX",
	10,
	"NX",
    ); ok != nil {
	binds,_ := redis.Strings(env.CRs.Do("SMEMBERS","STATE_CLUS_BIND"))
	for _,bind := range(binds) {
	    env.CRs.Send("EXISTS","NODE@" + bind)
	}
	env.CRs.Flush()
	state := map[string]NodeState{}
	for _,bind := range(binds) {
	    live := true
	    if ret,_ := redis.Int64(env.CRs.Receive()); ret == 0 {
		live = false
	    }
	    state[bind] = NodeState{
		Bind:bind,
		Live:live,
	    }
	}

	logbuf,_ := json.Marshal(state)
	env.CRs.Do("LPUSH","STATE_CLUS_LOG",logbuf)
    }

    logs,_ := redis.Values(env.CRs.Do("LRANGE","STATE_CLUS_LOG",0,2))
    for _,log := range(logs) {
	var state map[string]NodeState
	json.Unmarshal(log.([]byte),&state)
	states = append(states,state)
    }

    return states,nil
}
