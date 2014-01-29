#define _GNU_SOURCE

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<signal.h>
#include<Python.h>
#include"klib/khash.h"

#include"ev.h"
#include"contro.h"

KHASH_MAP_INIT_INT(ptr,void*)

struct pyep_data{
    struct ev_data evdata;
    khash_t(ptr) *evhdr_ht;
};

static PyObject* pyext_epoll_create(PyObject *self,PyObject *args);
static PyObject* pyext_epoll_register(PyObject *self,PyObject *args);
static PyObject* pyext_epoll_unregister(PyObject *self,PyObject *args);
static PyObject* pyext_epoll_modify(PyObject *self,PyObject *args);
static PyObject* pyext_epoll_free(PyObject *self,PyObject *args);
static PyObject* pyext_epoll_poll(PyObject *self,PyObject *args);

static PyObject* pyext_chal_add(PyObject *self,PyObject *args);

static struct pyep_data* pyep_getby_epfd(int epfd);
static struct ev_header* evhdr_getby_fd(khash_t(ptr) *evhdr_ht,int fd);

static PyMethodDef pyext_method[] = {
    {"epoll_create",pyext_epoll_create,METH_VARARGS,
        "epoll_create"},
    {"epoll_register",pyext_epoll_register,METH_VARARGS,
        "epoll_register"},
    {"epoll_unregister",pyext_epoll_unregister,METH_VARARGS,
        "epoll_unregister"},
    {"epoll_modify",pyext_epoll_modify,METH_VARARGS,
        "epoll_modify"},
    {"epoll_free",pyext_epoll_free,METH_VARARGS,
        "epoll_free"},
    {"epoll_poll",pyext_epoll_poll,METH_VARARGS,
        "epoll_poll"},

    {"chal_add",pyext_chal_add,METH_VARARGS,
        "chal_add"},

    {NULL,NULL,0,NULL}
};
static struct PyModuleDef pyext_module = {
    PyModuleDef_HEAD_INIT,
    "pyext",
    NULL,
    -1,
    pyext_method
};

static khash_t(ptr) *pyep_ht = NULL;
static int contro_initflag = 0;

PyMODINIT_FUNC
PyInit_pyext(void){
    PyObject *mod;

    mod = PyModule_Create(&pyext_module);
    if(mod == NULL){
        return NULL;
    }

    pyep_ht = kh_init(ptr);
    //signal(SIGINT,handle_intsig);

    return mod;
}

static PyObject* pyext_epoll_create(PyObject *self,PyObject *args){
    int ret;

    struct pyep_data *pyep;
    khiter_t hit;

    if((pyep = malloc(sizeof(*pyep))) == NULL){
        return PyErr_NoMemory();
    }

    if(ev_init(&pyep->evdata)){
        PyErr_SetString(PyExc_SystemError,"epoll initialize failed");
        goto err;
    }
    if(contro_initflag == 0){
        if(contro_init()){
            PyErr_SetString(PyExc_SystemError,"controller initialize failed");
            goto err;
        }
        contro_initflag = 1;
    }

    pyep->evhdr_ht = kh_init(ptr);

    hit = kh_put(ptr,pyep_ht,pyep->evdata.epfd,&ret);
    kh_value(pyep_ht,hit) = pyep;

    return PyLong_FromLong(pyep->evdata.epfd);

err:

    if(pyep != NULL){
        free(pyep);
    }

    return NULL;
}
static PyObject* pyext_epoll_register(PyObject *self,PyObject *args){
    int ret;
    khiter_t hit;

    int epfd;
    int fd;
    uint32_t events;

    struct pyep_data *pyep;
    struct ev_header *evhdr;

    if(!PyArg_ParseTuple(args,"iiI",&epfd,&fd,&events)){
        PyErr_BadArgument();
        return NULL;
    }
    if((pyep = pyep_getby_epfd(epfd)) == NULL){
        PyErr_SetString(PyExc_KeyError,"epoll file descriptor not found");
        return NULL;
    }

    if((evhdr = malloc(sizeof(*evhdr))) == NULL){
        return PyErr_NoMemory();
    }
    evhdr->fd = fd;
    evhdr->handler = NULL;
    if(ev_add(&pyep->evdata,evhdr,events)){
        PyErr_SetString(PyExc_SystemError,"register event failed");
        return NULL;
    }
    
    hit = kh_put(ptr,pyep->evhdr_ht,fd,&ret);
    kh_value(pyep->evhdr_ht,hit) = evhdr;

    Py_INCREF(Py_None);
    return Py_None;
}
static PyObject* pyext_epoll_unregister(PyObject *self,PyObject *args){
    khiter_t hit;

    int epfd;
    int fd;

    struct pyep_data *pyep;
    struct ev_header *evhdr;

    if(!PyArg_ParseTuple(args,"ii",&epfd,&fd)){
        PyErr_BadArgument();
        return NULL;
    }
    if((pyep = pyep_getby_epfd(epfd)) == NULL){
        PyErr_SetString(PyExc_KeyError,"epoll file descriptor not found");
        return NULL;
    }
    if((evhdr = evhdr_getby_fd(pyep->evhdr_ht,fd)) == NULL){
        PyErr_SetString(PyExc_KeyError,"file descriptor not found");
        return NULL;
    }

    if(ev_del(&pyep->evdata,evhdr)){
        PyErr_SetString(PyExc_SystemError,"unregister event failed");
        return NULL;
    }
    
    hit = kh_get(ptr,pyep->evhdr_ht,fd);
    kh_del(ptr,pyep->evhdr_ht,hit);

    free(evhdr);

    Py_INCREF(Py_None);
    return Py_None;
}
static PyObject* pyext_epoll_modify(PyObject *self,PyObject *args){
    int epfd;
    int fd;
    uint32_t events;

    struct pyep_data *pyep;
    struct ev_header *evhdr;

    if(!PyArg_ParseTuple(args,"iiI",&epfd,&fd,&events)){
        PyErr_BadArgument();
        return NULL;
    }
    if((pyep = pyep_getby_epfd(epfd)) == NULL){
        PyErr_SetString(PyExc_KeyError,"epoll file descriptor not found");
        return NULL;
    }
    if((evhdr = evhdr_getby_fd(pyep->evhdr_ht,fd)) == NULL){
        PyErr_SetString(PyExc_KeyError,"file descriptor not found");
        return NULL;
    }

    if(ev_mod(&pyep->evdata,evhdr,events)){
        PyErr_SetString(PyExc_SystemError,"modify event failed");
        return NULL;
    }

    Py_INCREF(Py_None);
    return Py_None;
}
static PyObject* pyext_epoll_free(PyObject *self,PyObject *args){
    khiter_t hit;

    int epfd;
    struct pyep_data *pyep;

    if(!PyArg_ParseTuple(args,"i",&epfd)){
        PyErr_BadArgument();
        return NULL;
    }
    if((pyep = pyep_getby_epfd(epfd)) == NULL){
        PyErr_SetString(PyExc_KeyError,"epoll file descriptor not found");
        return NULL;
    }

    if(ev_close(&pyep->evdata)){
        PyErr_SetString(PyExc_SystemError,"epoll free failed");
        return NULL;
    }

    for(hit = kh_begin(pyep->evhdr_ht);hit != kh_end(pyep->evhdr_ht);hit++){
        if(kh_exist(pyep->evhdr_ht,hit)){
            free((struct ev_header*)kh_value(pyep->evhdr_ht,hit));
        }
    }
    
    kh_destroy(ptr,pyep->evhdr_ht);

    hit = kh_get(ptr,pyep_ht,epfd);
    kh_del(ptr,pyep_ht,hit);
    
    free(pyep);

    Py_INCREF(Py_None);
    return Py_None;
}
static PyObject* pyext_epoll_poll(PyObject *self,PyObject *args){
    int ret;

    int epfd;
    int timeout;
    struct pyep_data *pyep;
    struct ev_data *evdata;
    PyObject *pylist;

    if(!PyArg_ParseTuple(args,"ii",&epfd,&timeout)){
        PyErr_BadArgument();
        return NULL;
    }
    if((pyep = pyep_getby_epfd(epfd)) == NULL){
        PyErr_SetString(PyExc_KeyError,"epoll file descriptor not found");
        return NULL;
    }

    evdata = &pyep->evdata;
    if((ret = ev_poll(evdata,timeout)) < 0){
        //Preserve errno from ev_poll
        return PyErr_SetFromErrno(PyExc_SystemError);
    }

    if((pylist = PyList_New(ret)) == NULL){
        return PyErr_NoMemory();
    }
    for(;ret > 0;ret--){
        PyList_SetItem(pylist,ret - 1,PyTuple_Pack(
                    2,
                    PyLong_FromLong(evdata->polls[ret - 1].fd),
                    PyLong_FromUnsignedLong(evdata->polls[ret - 1].events)));
    }
    

    return pylist;
}

static struct pyep_data* pyep_getby_epfd(int epfd){
    khiter_t hit;

    if((hit = kh_get(ptr,pyep_ht,epfd)) == kh_end(pyep_ht)){
        return NULL;
    }

    return (struct pyep_data*)kh_value(pyep_ht,hit);
}
static struct ev_header* evhdr_getby_fd(khash_t(ptr) *evhdr_ht,int fd){
    khiter_t hit;

    if((hit = kh_get(ptr,evhdr_ht,fd)) == kh_end(evhdr_ht)){
        return NULL;
    }

    return (struct ev_header*)kh_value(evhdr_ht,hit);
}

static PyObject* pyext_chal_add(PyObject *self,PyObject *args){

    contro_test();

    Py_INCREF(Py_None);
    return Py_None;
}
