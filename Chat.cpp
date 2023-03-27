// ��� ����� ����, �������� ���� ����� / ������, ��� ������ �������� � ������������� ����.
// ����� �������� ������ ����������� � ������� ������.

#include "Chat.h"
#include "iostream"
#include "string.h"


Chat::Chat() {

    data_count = 0;
    data = nullptr;

    mem_size = 8;
    data = new AuthData[mem_size];
}


// �����������
void Chat::reg(char _login[LOGINLENGTH], char _pass[], int pass_length) {

    // ��������� ��� � ������� ���������� ������� sha1
    uint* hash = sha1(_pass, pass_length);
    
    // ������� ������������ � ���� ������ - 
    // �.�. �������� �� ���������� ������ data[] ����� ������ ��� �������������� AuthData 
    // � ���� ���� ����� / ��� �� ������
    add(_login, hash);
}



// ������� ������������ �� ���� ������
void Chat::del(char login[LOGINLENGTH]) {

    int index;
    int i = 0;
    for (; i < mem_size; i++) {
        index = hfunc_quadratic(login, i);
        if (data[index].status == enumStatus::free)
            return;
        else if (data[index].status == enumStatus::engaged
            && !memcmp(login, data[index].login, LOGINLENGTH))
            break;
    }
    if (i >= mem_size) {
        return;
    }

    data[index].status = enumStatus::deleted;
}



// ����� ������
// (���������� true, ���� ����� ������ ������, � false � ��������� ������)
bool Chat::login(char _login[LOGINLENGTH], char _pass[], int pass_length) {

    int i = 0;
    int index = 0;

    // ���� �� ����������� ������ ���� � ������� �������
    // ���� ����� ����, �� ����������� ��� �� ����������� ������
    for (; i < mem_size; i++) {
        index = hfunc_quadratic(_login, i);
        if (data[index].status == enumStatus::free)
            return false;
        else if (data[index].status == enumStatus::engaged
            && !memcmp(_login, data[index].login, LOGINLENGTH)) // ������������ � ���, ��� ��� �������� �� ������ ��� �����������
            break;
    }

    if (i >= mem_size)
        return false;

    uint* hash = sha1(_pass, pass_length);

    bool result = !memcmp(data[index].pass_sha1_hash, hash, SHA1HASHLENGTHBYTES);
    delete[] hash;

    return result;
}


// ��� - �������, ����������� ������������ ������������
int Chat::hfunc_quadratic(char login[LOGINLENGTH], int offset) {
    // ��������� ������
    long sum = 0;
    for (int i = 0; i < LOGINLENGTH; i++) {
        sum += login[i];
    }
    // ������������ �����
    return (hfunc_multiplication(sum) + offset * offset) % mem_size;
}



// ����� ���������
// ������� ���������� ���� ����� ����� �������� ���:
// H(K) = [M * {K * A}]
// ���: [] - ������ ����� �����
//      {} - ������ ������� �����
//      ����� � � ��������� ����������� 0 < A < 1
// 
// ��������, ���������� ��� ���� ������� �� ����� K = 105, M = 9 � A = 0.7  
// H(105) = [9 * 105 * 0.7] = [9 * 73.5] = [9 * 0.5] = [4.5] = 4

int Chat::hfunc_multiplication(int val) {
    const double A = 0.7;
    return int(mem_size * (A * val - int(A * val)));
}



// �������� ������ �������
// ������� ���������� ��������� � ������ ������� �������, 
// ����� �������� ����� ������ � ����������� ������ �������, 
// �������� ������� count. 
// ����� ����� �� ���� ����� ���� ������� � �������� add ��� ������� ����.
// ����� ���������� ������ ��������� �� ����� �������� ��� ����� � ����� ���������� add.
void Chat::resize() {

    AuthData* save_data = data;// ���������� ������ ������
    int oldSize = mem_size;

    mem_size *= 2;  // ����������� ������ � ��� ���� 
    data_count = 0; // �������� ���������� ���������
    data = new AuthData[mem_size]; // �������� ����� ������
    for (int i = 0; i < mem_size; i++) {
        data[i] = AuthData();
    }

    for (int i = 0; i < oldSize; i++) {
        AuthData& old_data = save_data[i];
        if (old_data.status == enumStatus::engaged) {
            // ������������� ���� � ��������� � ����� ������
            // (���� ��������� ��� - ������� ����������� � ���, 
            //  ��� ����� ������ ��� ������� �������� � ��� ��������� ��� � �������� � ������ ������)
            uint* sha_hash_copy = new uint[SHA1HASHLENGTHUINTS];
            memcpy(sha_hash_copy, old_data.pass_sha1_hash, SHA1HASHLENGTHBYTES);

            add(old_data.login, sha_hash_copy);
        }
    }

    // ������ �� �����
    delete[] save_data;
}



// � ������ add � ����� �� i �� 0 �� mem_size - 1 �� ���� ��������� ������, 
// �������� �� ������(�� ����� enPairStatus::engaged).
// ���� ����� ������ �������, �� ��������� ���� � ������, 
// ����� ������ ������� �� ������ ����������(������ � ���� ����������).
void Chat::add(char login[LOGINLENGTH], uint* hash) {

    int index;
    int i = 0;
    // ����� ����� �� ���� i �� 0 �� ������� �������
    for (; i < mem_size; i++) {
        index = hfunc_quadratic(login, i);
        if (data[index].status == enumStatus::free) {
            // ������� ������ ������, �������� ��
            break;
        }
    }

    // ��� ���������, ��� ����� - �������� �������
    if (i >= mem_size) {
        resize(); // ��� ���������, ��� �����
        add(login, hash);
    }
    else {
        // ������ � ��������� ������ ����
        data[index] = AuthData(login, hash);
        data_count++;
    }
}