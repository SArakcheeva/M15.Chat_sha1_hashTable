#pragma once

#include "SHA1.h"
#include "string.h"

#define SIZE 10
#define LOGINLENGTH 10

class Chat {
public:
    Chat();
    void reg(char _login[LOGINLENGTH], char _pass[], int pass_length);
    bool login(char _login[LOGINLENGTH], char _pass[], int pass_length);
    void del(char _login[LOGINLENGTH]);

private:
    enum enumStatus {
        free,       // свободен
        engaged,    // занят
        deleted     // удален
    };

    struct AuthData {
        AuthData() :
            login(""),
            pass_sha1_hash(0),
            status(enumStatus::free) {
        }
        ~AuthData() {
            if (pass_sha1_hash != 0)
                delete[] pass_sha1_hash;
        }

        AuthData(char _login[LOGINLENGTH], uint* sh1) {
            memcpy(login, _login, LOGINLENGTH);
            pass_sha1_hash = sh1;
            status = enumStatus::engaged;
        }

        AuthData& operator = (const AuthData& other) {
            memcpy(login, other.login, LOGINLENGTH);

            if (pass_sha1_hash != 0)
                delete[] pass_sha1_hash;
            pass_sha1_hash = new uint[SHA1HASHLENGTHUINTS];

            memcpy(pass_sha1_hash, other.pass_sha1_hash, SHA1HASHLENGTHBYTES);

            status = other.status;

            return *this;
        }
        char login[LOGINLENGTH];
        uint* pass_sha1_hash;
        enumStatus status;
    };

    int hfunc_quadratic(char login[LOGINLENGTH], int offset); // хеш - функция, реализующая квадратичное пробирование
    int hfunc_multiplication(int val);  // метод умножения
    void resize();
    void add(char login[LOGINLENGTH], uint* hash);

    AuthData* data;
    int data_count;
    int mem_size;
};