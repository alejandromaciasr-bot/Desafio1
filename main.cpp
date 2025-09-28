#include <iostream>
#include <cstdio>
#include <new>

using namespace std;

// rotación y desencriptado
static inline unsigned char rotar_derecha8(unsigned char b, int n) {
    n &= 7;
    return (unsigned char)(((b >> n) | (b << (8 - n))) & 0xFF);
}

bool desencriptar(const unsigned char* in, size_t len, int n, unsigned char K, unsigned char* out) {
    if (!in || !out) return false;
    for (size_t i = 0; i < len; ++i) {
        unsigned char v = (unsigned char)(in[i] ^ K);
        out[i] = rotar_derecha8(v, n);
    }
    return true;
}

//  buscar subcadena
bool contiene(const char* texto, size_t nt, const char* frag, size_t nf) {
    if (!texto) return false;
    if (!frag) return false;
    if (nf == 0) return false;
    if (nt < nf) return false;
    for (size_t i = 0; i + nf <= nt; ++i) {
        size_t j = 0;
        while (j < nf && texto[i + j] == frag[j]) {
            ++j;
        }
        if (j == nf) return true;
    }
    return false;
}

// RLE
bool rle(const unsigned char* in, size_t inLen, char** outText, size_t* outLen) {
    if (!in) return false;
    if ((inLen % 3) != 0) return false;

    size_t total = 0;
    for (size_t i = 0; i < inLen; i += 3) {
        unsigned short cnt = (unsigned short)((in[i] << 8) | in[i + 1]);
        if (cnt == 0) return false;
        total += cnt;
        if (total > (size_t)50 * 1024 * 1024) return false;
    }

    char* out = new (nothrow) char[total];
    if (!out) return false;

    size_t pos = 0;
    for (size_t i = 0; i < inLen; i += 3) {
        unsigned short cnt = (unsigned short)((in[i] << 8) | in[i + 1]);
        unsigned char ch = in[i + 2];
        for (unsigned short k = 0; k < cnt; ++k) {
            out[pos] = (char)ch;
            ++pos;
        }
    }

    *outText = out;
    *outLen = total;
    return true;
}

// LZ78
bool lz78(const unsigned char* in, size_t inLen, char** outText, size_t* outLen) {
    if (!in) return false;
    if (inLen < 3) return false;
    if ((inLen % 3) != 0) return false;

    const size_t numT = inLen / 3;
    size_t capOut = inLen * 8 + 1024;
    size_t capTmp = inLen * 4 + 1024;

    char* out = new (nothrow) char[capOut];
    char* tmp = new (nothrow) char[capTmp];
    unsigned short* parent = new (nothrow) unsigned short[numT + 2];
    unsigned char* ch = new (nothrow) unsigned char[numT + 2];

    if (!out) return false;
    if (!tmp) { delete[] out; return false; }
    if (!parent) { delete[] out; delete[] tmp; return false; }
    if (!ch) { delete[] out; delete[] tmp; delete[] parent; return false; }

    size_t posOut = 0;
    size_t dictSize = 1;

    for (size_t i = 0; i + 2 < inLen; i += 3) {
        unsigned short pref = (unsigned short)((in[i] << 8) | in[i + 1]);
        unsigned char c = in[i + 2];

        size_t tlen = 0;

        if (tlen + 1 > capTmp) {
            delete[] out;
            delete[] tmp;
            delete[] parent;
            delete[] ch;
            return false;
        }

        tmp[tlen] = (char)c;
        ++tlen;

        while (pref != 0) {
            if (pref >= dictSize) {
                delete[] out;
                delete[] tmp;
                delete[] parent;
                delete[] ch;
                return false;
            }
            if (tlen + 1 > capTmp) {
                delete[] out;
                delete[] tmp;
                delete[] parent;
                delete[] ch;
                return false;
            }
            tmp[tlen] = (char)ch[pref];
            ++tlen;
            pref = parent[pref];
        }

        if (posOut + tlen > capOut) {
            delete[] out;
            delete[] tmp;
            delete[] parent;
            delete[] ch;
            return false;
        }

        for (size_t k = 0; k < tlen; ++k) {
            out[posOut + k] = tmp[tlen - 1 - k];
        }

        posOut += tlen;

        if (dictSize + 1 >= numT + 2) {
            delete[] out;
            delete[] tmp;
            delete[] parent;
            delete[] ch;
            return false;
        }

        unsigned short pref2 = (unsigned short)((in[i] << 8) | in[i + 1]);
        parent[dictSize] = pref2;
        ch[dictSize] = c;
        ++dictSize;
    }

    delete[] tmp;
    delete[] parent;
    delete[] ch;

    *outText = out;
    *outLen = posOut;
    return true;
}

// fuerza bruta de (n, K)
enum Metodo { NINGUNO = 0, RLE = 1, LZ78 = 2 };

bool buscar_parametros(const unsigned char* enc, size_t encLen,
                       const char* frag, size_t fragLen,
                       Metodo* met, int* nOut, unsigned char* kOut,
                       char** plano, size_t* planoLen) {
    unsigned char* work = new (nothrow) unsigned char[encLen];
    if (!work) return false;

    for (int n = 1; n <= 7; ++n) {
        for (int Ki = 0; Ki <= 255; ++Ki) {
            unsigned char K = (unsigned char)Ki;

            if (!desencriptar(enc, encLen, n, K, work)) {
                continue;
            }

            char* p = 0;
            size_t L = 0;

            if (rle(work, encLen, &p, &L)) {
                if (contiene(p, L, frag, fragLen)) {
                    *met = RLE;
                    *nOut = n;
                    *kOut = K;
                    *plano = p;
                    *planoLen = L;
                    delete[] work;
                    return true;
                }
                delete[] p;
            }

            p = 0;
            L = 0;

            if (lz78(work, encLen, &p, &L)) {
                if (contiene(p, L, frag, fragLen)) {
                    *met = LZ78;
                    *nOut = n;
                    *kOut = K;
                    *plano = p;
                    *planoLen = L;
                    delete[] work;
                    return true;
                }
                delete[] p;
            }
        }
    }

    delete[] work;
    return false;
}

// leer archivo binario completo (encriptado)
bool leer_bin(const char* ruta, unsigned char** buf, size_t* len) {
    *buf = 0;
    *len = 0;

    FILE* f = fopen(ruta, "rb");
    if (!f) return false;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return false;
    }

    long sz = ftell(f);
    if (sz <= 0) {
        fclose(f);
        return false;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return false;
    }

    unsigned char* tmp = new (nothrow) unsigned char[(size_t)sz];
    if (!tmp) {
        fclose(f);
        return false;
    }

    size_t rd = fread(tmp, 1, (size_t)sz, f);
    fclose(f);

    if (rd != (size_t)sz) {
        delete[] tmp;
        return false;
    }

    *buf = tmp;
    *len = rd;
    return true;
}

// leer texto
bool leer_txt(const char* ruta, char** buf, size_t* len) {
    *buf = 0;
    *len = 0;

    FILE* f = fopen(ruta, "rb");
    if (!f) return false;

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return false;
    }

    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return false;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return false;
    }

    char* tmp = new (nothrow) char[(size_t)sz + 1];
    if (!tmp) {
        fclose(f);
        return false;
    }

    size_t rd = fread(tmp, 1, (size_t)sz, f);
    fclose(f);

    tmp[rd] = '\0';

    *buf = tmp;
    *len = rd;
    return true;
}

// main
int main() {
    int casos = 0;

    cout << "ingrese la cantidad de casos: " << endl;

    if (!(cin >> casos) || casos <= 0) {
        cout << "entrada invalida." << '\n';
        return 0;
    }

    for (int i = 1; i <= casos; ++i) {
        char rEnc[256];
        char rPis[256];

        snprintf(rEnc, sizeof(rEnc), "Encriptado%d.txt", i);
        snprintf(rPis, sizeof(rPis), "pista%d.txt", i);

        unsigned char* enc = 0;
        size_t encLen = 0;

        if (!leer_bin(rEnc, &enc, &encLen)) {
            cout << "[Caso " << i << "] no pude leer " << rEnc << '\n';
            continue;
        }

        char* frag = 0;
        size_t fragLen = 0;

        if (!leer_txt(rPis, &frag, &fragLen)) {
            cout << "[Caso " << i << "] no pude leer " << rPis << '\n';
            delete[] enc;
            continue;
        }

        Metodo m = NINGUNO;
        int n = 0;
        unsigned char K = 0;
        char* plano = 0;
        size_t planoLen = 0;

        bool ok = buscar_parametros(enc, encLen, frag, fragLen, &m, &n, &K, &plano, &planoLen);

        if (!ok) {
            cout << "[Caso " << i << "] no encontre parametros validos." << '\n';
            delete[] enc;
            delete[] frag;
            continue;
        }

        cout << "\n=== Caso " << i << " ===" << '\n';
        cout << "metodo: " << (m == RLE ? "RLE" : "LZ78") << '\n';
        cout << "rotacion n = " << n << '\n';
        cout << "clave K = " << std::showbase << std::hex << (unsigned)K << std::dec << '\n';

        size_t col = 0;
        for (size_t p = 0; p < planoLen; ++p) {
            cout << plano[p];
            ++col;
            if (col == 120) {
                cout << '\n';
                col = 0;
            }
        }

        if (col) {
            cout << '\n';
        }

        delete[] enc;
        delete[] frag;
        delete[] plano;
    }

    return 0;
}
