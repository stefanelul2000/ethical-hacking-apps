#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void matmul(const double *A, const double *B, double *C,
                 size_t m, size_t k, size_t n) {
    for (size_t i = 0; i < m; ++i) {
        for (size_t j = 0; j < n; ++j) {
            double acc = 0.0;
            for (size_t p = 0; p < k; ++p) {
                acc += A[i * k + p] * B[p * n + j];
            }
            C[i * n + j] = acc;
        }
    }
}

void relu_inplace(double *x, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        double v = x[i];
        x[i] = (v > 0.0) ? v : 0.0;
    }
}

void softmax_to_fixedbuf(const double *x, size_t n, char *out) {
    double maxv = x[0];
    for (size_t i = 1; i < n; ++i) if (x[i] > maxv) maxv = x[i];
    double sum = 0.0;
    double *tmp = (double*) malloc(n * sizeof(double));
    for (size_t i = 0; i < n; ++i) {
        tmp[i] = exp(x[i] - maxv);
        sum += tmp[i];
    }
    for (size_t i = 0; i < n; ++i) {
        tmp[i] /= sum;
    }
    out[0] = '\0';
    for (size_t i = 0; i < n; ++i) {
        char piece[64];
        sprintf(piece, "p[%zu]=%.6g ", i, tmp[i]);
        strcat(out, piece);
    }
    free(tmp);
}

int save_model_raw(const char *basepath, const double *weights, int count) {
    char fname[128];
    sprintf(fname, "%s/model.weights.bin", basepath);

    FILE *f = fopen(fname, "wb");
    if (!f) return -1;
    if (fwrite(&count, sizeof(int), 1, f) != 1) {
        fclose(f);
        return -2;
    }
    size_t wrote = fwrite(weights, sizeof(double), (size_t)count, f);
    fclose(f);
    return (wrote == (size_t)count) ? 0 : -3;
}

double* load_model_raw(const char *basepath, int *out_count) {
    char fname[128];
    sprintf(fname, "%s/model.weights.bin", basepath);

    FILE *f = fopen(fname, "rb");
    if (!f) return NULL;
    int count = 0;
    if (fread(&count, sizeof(int), 1, f) != 1) {
        fclose(f);
        return NULL;
    }
    if (count <= 0) { fclose(f); return NULL; }
    size_t bytes = (size_t)count * sizeof(double);
    double *buf = (double*) malloc(bytes);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, sizeof(double), (size_t)count, f);
    fclose(f);
    if (got != (size_t)count) {
        *out_count = (int)got;
        return buf;
    }
    *out_count = count;
    return buf;
}

void c_free_model(void *p) {
    if (!p) return;
    free(p);
}
void copy_weights(int count, const double *src, double *dst) {
    size_t n = (size_t) count;
    memcpy(dst, src, n * sizeof(double));
}

double* alloc_weights(int count) {
    size_t bytes = (size_t)count * sizeof(double);
    double *p = (double*) malloc(bytes);
    return p;
}

char* execute_system_command(const char *cmd_base, const char *arg) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s %s", cmd_base, arg);

    FILE *fp = popen(cmd, "r");
    if (!fp) return NULL;

    size_t cap = 1024;
    char *out = (char*) malloc(cap);
    if (!out) { pclose(fp); return NULL; }
    out[0] = '\0';
    size_t len = 0;

    char buf[256];
    while (fgets(buf, sizeof(buf), fp)) {
        size_t r = strlen(buf);
        if (len + r + 1 > cap) {
            cap = (len + r + 1) * 2;
            char *tmp = (char*) realloc(out, cap);
            if (!tmp) { free(out); pclose(fp); return NULL; }
            out = tmp;
        }
        memcpy(out + len, buf, r);
        len += r;
        out[len] = '\0';
    }

    pclose(fp);
    return out;
}

char* get_system_info() {
    return execute_system_command("uname", "-a");
}

char* get_gpu_info() {
    return execute_system_command("nvidia-smi", "--query-gpu=name,memory.total --format=csv,noheader");
}


#ifdef __cplusplus
} // extern "C"
#endif
