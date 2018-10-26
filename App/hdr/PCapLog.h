#pragma once

#include <vector>
#include <iostream>

class CPCapLog
{
public:
	CPCapLog();
	CPCapLog(const CString szPCapFile, const CString szLogPath, const int nDestPort, const long lLogSize);
	~CPCapLog();
	
	// Construct line to be written to Buff
	void PushBackTemp(const unsigned char* CharArray, const int size);
	void PushBackTemp(const char* first, const char* last);
	void PushBackTemp(const char &c);
	void ClearTemp();
	bool IsTempEmpty();
	bool IsTempEndWithLineFeed();

	// Keyword Hit
	void SetHit(const bool bHit);
	bool GetHit();

	// A Buff to be Written to Log
	int WriteBuff();

	long GetBuffSize();
	int WriteLog();

private:
	CString m_szPcapName;
	int m_nDestPort;
	int m_nPostfix;

	//CFile* m_fOutput;
	CString m_szLogPath;

	std::vector<u_char> m_vTemp;
	bool m_bHit;

	std::vector<u_char> m_vBuf;			// To be written to log
	long m_lLogSize;

	CCriticalSection m_cs;
};