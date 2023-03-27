// Дан класс чата, хранящий пары логин / пароль, где пароль хранится в зашифрованном виде.
// Нужно написать методы регистрации и попытки логина.

#include "Chat.h"
#include "iostream"
#include "string.h"


Chat::Chat() {

    data_count = 0;
    data = nullptr;

    mem_size = 8;
    data = new AuthData[mem_size];
}


// Регистрация
void Chat::reg(char _login[LOGINLENGTH], char _pass[], int pass_length) {

    // вычислять хеш с помощью встроенной функции sha1
    uint* hash = sha1(_pass, pass_length);
    
    // заносим пользователя в базу данных - 
    // т.е. добавить во внутренний массив data[] новые данные для аутентификации AuthData 
    // в виде пары логин / хеш от пароля
    add(_login, hash);
}



// удалить пользователя из базы данных
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



// Метод логина
// (возвращает true, если логин удачно прошёл, и false в противном случае)
bool Chat::login(char _login[LOGINLENGTH], char _pass[], int pass_length) {

    int i = 0;
    int index = 0;

    // ищет по присланному логину пару с искомым логином
    // если такой есть, то вычисляется хеш от присланного пароля
    for (; i < mem_size; i++) {
        index = hfunc_quadratic(_login, i);
        if (data[index].status == enumStatus::free)
            return false;
        else if (data[index].status == enumStatus::engaged
            && !memcmp(_login, data[index].login, LOGINLENGTH)) // сравнивается с тем, что был вычислен от пароля при регистрации
            break;
    }

    if (i >= mem_size)
        return false;

    uint* hash = sha1(_pass, pass_length);

    bool result = !memcmp(data[index].pass_sha1_hash, hash, SHA1HASHLENGTHBYTES);
    delete[] hash;

    return result;
}


// хеш - функция, реализующая квадратичное пробирование
int Chat::hfunc_quadratic(char login[LOGINLENGTH], int offset) {
    // вычисляем индекс
    long sum = 0;
    for (int i = 0; i < LOGINLENGTH; i++) {
        sum += login[i];
    }
    // квадратичные пробы
    return (hfunc_multiplication(sum) + offset * offset) % mem_size;
}



// МЕТОД УМНОЖЕНИЯ
// Простым выражением этот метод можно записать так:
// H(K) = [M * {K * A}]
// где: [] - взятие целой части
//      {} - взятие дробной части
//      Число А — некоторый коэффициент 0 < A < 1
// 
// Например, подсчитаем хеш этой функции от числа K = 105, M = 9 и A = 0.7  
// H(105) = [9 * 105 * 0.7] = [9 * 73.5] = [9 * 0.5] = [4.5] = 4

int Chat::hfunc_multiplication(int val) {
    const double A = 0.7;
    return int(mem_size * (A * val - int(A * val)));
}



// ИЗМЕНИТЬ РАЗМЕР МАССИВА
// сначала запоминаем указатели и старые размеры массива, 
// также выделяем новую память и увеличиваем размер массива, 
// обнуляем счетчик count. 
// Потом бежим по всем узлам всех списков и вызываем add для каждого узла.
// После реализации метода пересчета ХТ нужно вставить его вызов в метод добавления add.
void Chat::resize() {

    AuthData* save_data = data;// запоминаем старый массив
    int oldSize = mem_size;

    mem_size *= 2;  // увеличиваем размер в два раза 
    data_count = 0; // обнуляем количество элементов
    data = new AuthData[mem_size]; // выделяем новую память
    for (int i = 0; i < mem_size; i++) {
        data[i] = AuthData();
    }

    for (int i = 0; i < oldSize; i++) {
        AuthData& old_data = save_data[i];
        if (old_data.status == enumStatus::engaged) {
            // пересчитываем хеши и добавляем в новый массив
            // (Идея пересчета хеш - таблицы заключается в том, 
            //  что нужно заново для каждого значения в ней посчитать хеш и добавить в нужный список)
            uint* sha_hash_copy = new uint[SHA1HASHLENGTHUINTS];
            memcpy(sha_hash_copy, old_data.pass_sha1_hash, SHA1HASHLENGTHBYTES);

            add(old_data.login, sha_hash_copy);
        }
    }

    // чистим за собой
    delete[] save_data;
}



// В методе add в цикле по i от 0 до mem_size - 1 мы ищем свободную ячейку, 
// проверяя ее статус(не равен enPairStatus::engaged).
// Если такая ячейка нашлась, мы добавляем пару в массив, 
// иначе просто выходим из метода добавления(именно в этой реализации).
void Chat::add(char login[LOGINLENGTH], uint* hash) {

    int index;
    int i = 0;
    // берем пробы по всем i от 0 до размера массива
    for (; i < mem_size; i++) {
        index = hfunc_quadratic(login, i);
        if (data[index].status == enumStatus::free) {
            // найдена пустая ячейка, занимаем ее
            break;
        }
    }

    // все перебрали, нет места - пересчет таблицы
    if (i >= mem_size) {
        resize(); // все перебрали, нет места
        add(login, hash);
    }
    else {
        // кладем в свободную ячейку пару
        data[index] = AuthData(login, hash);
        data_count++;
    }
}