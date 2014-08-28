package main

import (
    "os"
    "os/exec"
    "time"
    "encoding/json"
    "code.google.com/p/go-uuid/uuid"
    //"github.com/garyburd/redigo/redis"
)

type Package struct {
    env *APIEnv
    pkgid string
}

func PackageCreate(env *APIEnv) Package {
    return Package{
	env:env,
	pkgid:uuid.NewUUID().String(),
    }
}
func (pkg *Package) Import(pkgfpath string) error {
    var err error
    var meta map[string]interface{}

    pkgdpath,err := decompress(pkg.pkgid,pkgfpath)
    if err != nil {
	return err
    }

    metafile,err := os.Open(pkgdpath + "/meta.json")
    if err != nil {
	os.RemoveAll(pkgdpath)
	return err
    }
    metabuf := make([]byte,PKGMETA_MAXSIZE)
    metalen,err := metafile.Read(metabuf);
    metafile.Close()
    if err != nil {
	os.RemoveAll(pkgdpath)
	return err
    }
    if err := json.Unmarshal(metabuf[:metalen],&meta); err != nil {
	os.RemoveAll(pkgdpath)
	return err
    }
    //expire := int64(meta["expire"].(float64))
    meta["pkgid"] = pkg.pkgid
    meta["when"] = time.Now().Unix()

    metabuf,err = json.Marshal(meta)
    if err != nil {
	os.RemoveAll(pkgdpath)
	return err
    }
    metafile,err = os.Create(pkgdpath + "/meta.json")
    if err != nil {
	os.RemoveAll(pkgdpath)
	return err
    }
    _,err = metafile.Write(metabuf)
    metafile.Close()
    if err != nil {
	os.RemoveAll(pkgdpath)
	return err
    }

    return nil
}

func decompress(pkgid string,fpath string) (string,error) {
    dpath := STORAGE_PATH + "/package/" + pkgid
    if err := os.Mkdir(dpath,0700); err != nil {
	return "",err
    }
    cmd := exec.Command(TAR_PATH,"-Jxf",fpath,"-C",dpath)
    if err := cmd.Run(); err != nil {
	return "",err
    }
    return dpath,nil
}
