package main

import (
    "os"
    "os/exec"
    "fmt"
    "time"
    "crypto/sha256"
    "encoding/json"
    "code.google.com/p/go-uuid/uuid"
//  "github.com/garyburd/redigo/redis"
)

type Package struct {
    env *APIEnv
    pkgid string
}

func PackageCreate(env *APIEnv) Package {
    pkgid := fmt.Sprintf("%x",sha256.Sum256([]byte(uuid.NewUUID().String())))
    return Package{
	env:env,
	pkgid:pkgid,
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
    meta["pkgid"] = pkg.pkgid
    meta["apiid"] = pkg.env.apiid
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

    expire := int64(meta["expire"].(float64))
    pkg.env.prs.Do("HSET","PACKAGE@" + pkg.pkgid,"meta",metabuf)
    pkg.env.crs.Do("SADD","PKG_NODE@" + pkg.pkgid,BIND)
    pkg.env.prs.Do("EXPIRE","PACKAGE@" + pkg.pkgid,expire)
    pkg.env.crs.Do("EXPIRE","PKG_NODE@" + pkg.pkgid,expire)

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
