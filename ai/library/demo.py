import ctypes as ct
import numpy as np
import os, sys

LIBNAME = "libmlops_ml_asan.so" if os.path.exists("libmlops_ml_asan.so") else "libmlops_ml.so"
lib = ct.cdll.LoadLibrary(os.path.join(os.path.dirname(__file__), LIBNAME))
print("Loaded", LIBNAME)

lib.matmul.argtypes = [
    ct.POINTER(ct.c_double), ct.POINTER(ct.c_double), ct.POINTER(ct.c_double),
    ct.c_size_t, ct.c_size_t, ct.c_size_t
]
lib.matmul.restype = None

lib.relu_inplace.argtypes = [ct.POINTER(ct.c_double), ct.c_size_t]
lib.relu_inplace.restype = None

lib.softmax_to_fixedbuf.argtypes = [ct.POINTER(ct.c_double), ct.c_size_t, ct.c_char_p]
lib.softmax_to_fixedbuf.restype = None

lib.save_model_raw.argtypes = [ct.c_char_p, ct.POINTER(ct.c_double), ct.c_int]
lib.save_model_raw.restype = ct.c_int

lib.load_model_raw.argtypes = [ct.c_char_p, ct.POINTER(ct.c_int)]
lib.load_model_raw.restype = ct.POINTER(ct.c_double)

lib.c_free_model.argtypes = [ct.c_void_p]
lib.c_free_model.restype = None

lib.alloc_weights.argtypes = [ct.c_int]
lib.alloc_weights.restype = ct.POINTER(ct.c_double)

lib.copy_weights.argtypes = [ct.c_int, ct.POINTER(ct.c_double), ct.POINTER(ct.c_double)]
lib.copy_weights.restype = None

def np_ptr(arr: np.ndarray):
    return arr.ctypes.data_as(ct.POINTER(ct.c_double))

if __name__ == "__main__":
    A = np.ascontiguousarray([[1.,2.,3.],[4.,5.,6.]], dtype=np.float64)
    B = np.ascontiguousarray([[7.,8.],[9.,10.],[11.,12.]], dtype=np.float64)
    C = np.zeros((2,2), dtype=np.float64)
    lib.matmul(np_ptr(A), np_ptr(B), np_ptr(C), A.shape[0], A.shape[1], B.shape[1])
    print("A @ B =\n", C)

    x = np.array([-1.0, 0.5, -0.2, 3.0], dtype=np.float64)
    lib.relu_inplace(np_ptr(x), x.size)
    print("ReLU inplace:", x)

    z = np.array([1.0, 2.0, 3.0], dtype=np.float64)
    out_buf = (ct.c_char * 64)()
    lib.softmax_to_fixedbuf(np_ptr(z), z.size, ct.cast(out_buf, ct.c_char_p))
    print("softmax:", bytes(out_buf).partition(b'\x00')[0].decode(errors='replace'))

    basepath = b"." 
    weights = np.array([0.1, 0.2, 0.3, 0.4], dtype=np.float64)
    r = lib.save_model_raw(basepath, np_ptr(weights), weights.size)
    print("save result:", r)
    out_count = ct.c_int(0)
    p = lib.load_model_raw(basepath, ct.byref(out_count))
    if p:
        n = out_count.value
        loaded = np.ctypeslib.as_array(p, shape=(n,))
        print("loaded count:", n, "values:", loaded)
        lib.c_free_model(p)
    else:
        print("load failed")

    dst_ptr = lib.alloc_weights(4)
    if dst_ptr:
        dst = np.ctypeslib.as_array(dst_ptr, shape=(4,))
        dst[:] = 0.0
        lib.copy_weights(4, np_ptr(weights), dst_ptr)
        print("copied weights into dst:", np.ctypeslib.as_array(dst_ptr, (4,)).tolist())
        lib.c_free_model(dst_ptr)
    else:
        print("alloc failed")
