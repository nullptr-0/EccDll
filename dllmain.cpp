// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "fstream"
#include <thread>
#include "Shlwapi.h"
#pragma comment(lib, "Shlwapi.lib")

#define DEBUG
#include "Ecc.hpp"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void Ecc(const char* fn, const char* pswfn, const char* c_p, const char* c_a, const char* c_gx, const char* c_gy, const char* c_qx, const char* c_qy)
{
#ifdef DEBUG
	time_t st = time(0);
#endif // DEBUG

	mp_int GX;
	mp_int GY;
	mp_int K;//私有密钥
	mp_int A;
	mp_int B;
	mp_int QX;
	mp_int QY;
	mp_int P;//Fp中的p(有限域P)


	mp_init(&GX);
	mp_init(&GY);
	mp_init(&K);
	mp_init(&A);
	mp_init(&B);
	mp_init(&QX);
	mp_init(&QY);
	mp_init(&P);

	char temp[800] = { 0 };

	fstream psw(pswfn, ios::out);

	srand((unsigned)time(0));

	//有限域 P
	if (strcmp(c_p, "") == 0)
	{
		GetPrime(&P, P_LONG);
		mp_to_radix(&P, temp, 800, NULL, 10);
		psw << "P: " << temp << endl;
#ifdef DEBUG
		cout << "有限域 P 是:" << endl;
		mp_to_radix(&P, temp, 800, NULL, 10);
		cout << temp << endl;
#endif // DEBUG
	}
	else
	{
		strcpy(temp, c_p);
		mp_read_radix(&P, temp, 10);
	}

	//曲线参数 A
	if (strcmp(c_a, "") == 0)
	{
		GetPrime(&A, 30);
		mp_to_radix(&A, temp, 800, NULL, 10);
		psw << "A: " << temp << endl;
#ifdef DEBUG
		cout << "曲线参数 A 是:" << endl;
		mp_to_radix(&A, temp, 800, NULL, 10);
		cout << temp << endl;
#endif // DEBUG
	}
	else
	{
		strcpy(temp, c_a);
		mp_read_radix(&A, temp, 10);
	}

	//曲线G点XY坐标
	if (strcmp(c_gx, "") == 0)
	{
		//曲线参数 B
		Get_B(&B, &A, &P);
		Get_G_X_Y(&GX, &GY, &B, &A);
#ifdef DEBUG
		cout << "曲线参数 B 是:" << endl;
		mp_to_radix(&B, temp, 800, NULL, 10);
		cout << temp << endl;
		cout << "曲线G点X坐标是:" << endl;
		mp_to_radix(&GX, temp, 800, NULL, 10);
		cout << temp << endl;
		cout << "曲线G点Y坐标是:" << endl;
		mp_to_radix(&GY, temp, 800, NULL, 10);
		cout << temp << endl;
#endif // DEBUG
	}
	else
	{
		strcpy(temp, c_gx);
		mp_read_radix(&GX, temp, 10);
		strcpy(temp, c_gy);
		mp_read_radix(&GY, temp, 10);
	}

	//私钥 K，公钥XY坐标
	if (strcmp(c_qx, "") == 0 || strcmp(c_qy, "") == 0)
	{
		do
		{
			GetPrime(&K, KEY_LONG);
		} while (!Ecc_points_mul(&QX, &QY, &GX, &GY, &K, &A, &P));
		mp_to_radix(&K, temp, 800, NULL, 10);
		psw << "K: " << temp << endl;
		mp_to_radix(&GX, temp, 800, NULL, 10);
		psw << "GX: " << temp << endl;
		mp_to_radix(&GY, temp, 800, NULL, 10);
		psw << "GY: " << temp << endl;
		mp_to_radix(&QX, temp, 800, NULL, 10);
		psw << "QX: " << temp << endl;
		mp_to_radix(&QY, temp, 800, NULL, 10);
		psw << "QY: " << temp << endl;
#ifdef DEBUG
		cout << "私钥 K 是:" << endl;
		cout << temp << endl;
		cout << "Q点X坐标是:" << endl;
		mp_to_radix(&QX, temp, 800, NULL, 10);
		cout << temp << endl;
		cout << "Q点Y坐标是:" << endl;
		mp_to_radix(&QY, temp, 800, NULL, 10);
		cout << temp << endl;

#endif // DEBUG
	}
	else
	{
		strcpy(temp, c_qx);
		mp_read_radix(&QX, temp, 10);
		strcpy(temp, c_qy);
		mp_read_radix(&QY, temp, 10);
	}

	psw.close();
	char tempFn[MAX_PATH] = { 0 };
	strcpy(tempFn, fn);
	//Ecc_encipher(tempFn, &QX, &QY, &GX, &GY, &A, &P);//加密
	fstream fp(tempFn, ios::binary | ios::in);
	fp.seekg(0, std::ios::end);
	size_t fileLength = (size_t)fp.tellg();
	fp.close();
	long filenum = slice(tempFn, (fileLength / THREAD_COUNT)+1);
#ifndef DEBUG
	//DeleteFileA(tempFn);
#endif // !DEBUG
	string fileNames[THREAD_COUNT];
	std::thread** tasks = new std::thread * [filenum];
	long FileNum = 0;
	while (filenum > FileNum)
	{
		completed[FileNum] = false;
		string fileEnc = tempFn;
		fileEnc += ".slice";
		fileEnc += to_string(++FileNum);
		fileNames[FileNum - 1] = fileEnc;
		//Ecc_encipher(fileenc, &QX, &QY, &GX, &GY, &A, &P);//加密
		tasks[FileNum - 1] = new std::thread(Ecc_encipher, fileEnc, &QX, &QY, &GX, &GY, &A, &P);//加密
		tasks[FileNum - 1]->detach();
	}
	bool finish = true;
	while (finish)
	{
		FileNum = 0;
		while (filenum > FileNum)
		{
			if (!completed[FileNum])
			{
				finish = false;
			}
			++FileNum;
		}
		finish = !finish;
		Sleep(3000);
	}
	combine(regex_replace(tempFn, regex{ "(.*)\\.(.+)" }, "$1.ecc$2"), filenum, "\x06\xA8\x52\x00", 4);
	FileNum = 0;
	while (filenum > FileNum)
	{
		DeleteFileA(fileNames[FileNum].c_str());
		fileNames[FileNum] = regex_replace(fileNames[FileNum], fileName_Enc_regex, "$1.ecc$2.slice$3");
		DeleteFileA(fileNames[FileNum++].c_str());
	}

	mp_clear(&GX);
	mp_clear(&GY);
	mp_clear(&K);//私有密钥
	mp_clear(&A);
	mp_clear(&B);
	mp_clear(&QX);
	mp_clear(&QY);
	mp_clear(&P);//Fp中的p(有限域P)
#ifdef DEBUG
	cout << "Encipher used " << time(0) - st << " s." << endl;
#endif // DEBUG
}

void Ecc(const char* fn, const char* c_p, const char* c_a, const char* c_k)
{
#ifdef DEBUG
	time_t st = time(0);
#endif // DEBUG

	mp_int K;//私有密钥
	mp_int A;
	mp_int P;//Fp中的p(有限域P)


	mp_init(&K);
	mp_init(&A);
	mp_init(&P);

	char temp[800] = { 0 };

	if (strcmp(c_k, "") != 0 && strcmp(c_a, "") != 0 && strcmp(c_p, "") != 0)
	{
		strcpy(temp, c_k);
		mp_read_radix(&K, temp, 10);
		strcpy(temp, c_a);
		mp_read_radix(&A, temp, 10);
		strcpy(temp, c_p);
		mp_read_radix(&P, temp, 10);
		char tempFn[MAX_PATH] = { 0 };
		strcpy(tempFn, fn);
		//Ecc_decipher(tempFn, &K, &A, &P);//解密
		long filenum = slice(tempFn, "\x06\xA8\x52\x00", 4);
		string fileNames[THREAD_COUNT];
		std::thread** tasks = new std::thread * [filenum];
		long FileNum = 0;
		while (filenum > FileNum)
		{
			completed[FileNum] = false;
			string fileDec = tempFn;
			fileDec += ".slice";
			fileDec += to_string(++FileNum);
			fileNames[FileNum-1]= fileDec;
			//Ecc_decipher(filedecs[FileNum-1], &K, &A, &P);//解密
			tasks[FileNum - 1] = new std::thread(Ecc_decipher, fileDec, &K, &A, &P);//解密
			tasks[FileNum - 1]->detach();
		}
		bool finish = true;
		while (finish)
		{
			FileNum = 0;
			while (filenum > FileNum)
			{
				if (!completed[FileNum])
				{
					finish = false;
				}
				++FileNum;
			}
			finish = !finish;
			Sleep(3000);
		}
		combine(regex_replace(tempFn, regex{ "(.*)\\.ecc(.+)" }, "$1.$2"), filenum, "", 0);
		FileNum = 0;
		while (filenum > FileNum)
		{
			DeleteFileA(fileNames[FileNum].c_str());
			fileNames[FileNum] = regex_replace(fileNames[FileNum], fileName_Dec_regex, "$1.$2.slice$3");
			DeleteFileA(fileNames[FileNum++].c_str());
		}
	}

	mp_clear(&K);//私有密钥
	mp_clear(&A);
	mp_clear(&P);//Fp中的p(有限域P)
#ifdef DEBUG
	cout << "Decipher used " << time(0) - st << " s." << endl;
#endif // DEBUG
}

extern "C" __declspec(dllexport) void EncEx(const char* fn, const char* pswfn, const char* c_p, const char* c_a, const char* c_gx, const char* c_gy, const char* c_qx, const char* c_qy)
{
	Ecc(fn, pswfn, c_p, c_a, c_gx, c_gy, c_qx, c_qy);
}

extern "C" __declspec(dllexport) void DecEx(const char* fn, const char* c_p, const char* c_a, const char* c_k)
{
	Ecc(fn, c_p, c_a, c_k);
}

extern "C" __declspec(dllexport) void Enc(const char* fn, const char* pswfn)
{
	Ecc(fn, pswfn, "", "", "", "", "", "");
}

extern "C" __declspec(dllexport) void Dec(const char* fn, const char* pswfn)
{
	string p = "";
	string a = "";
	string k = "";
	fstream fk(pswfn, ios::in);
	fk >> p >> p >> a >> a >> k >> k;
	fk.close();

	Ecc(fn, p.c_str(), a.c_str(), k.c_str());
}
