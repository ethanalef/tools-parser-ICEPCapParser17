#pragma once

#include <iostream>
#include <winsock2.h>
#include <pcap.h>
#include <vector>
#include <algorithm>
#include <atomic>
#include <map>
#include <utility>
#include <string>
#include <deque>
#include <iomanip>
#include <sstream>

#include "ICEDefine.h"
#include "TCPPacket.h"
#include "PCapLog.h"

#include "ThreadPool.h"

#define STR_DATE_MEM_SPACE_EXTRA	21 + 6
#define STR_DATE_MEM_SPACE			21

#define MAX_NUM_OF_THREAD			20
#define DEFAULT_SPLIT_SIZE			500000000	// splite at ~500 MB
#define PCAP_EXTENSION				".pcap"
#define	LINE_FEED					char(10)

class CICEPCapParser
{
public:
	CICEPCapParser(const CString szPCap, const CString szResPath);
	~CICEPCapParser();

	CICEPCapParser(const CICEPCapParser&) = delete;
	CICEPCapParser &operator=(const CICEPCapParser&) = delete;

	// Init
	void AddKeyword(const CString szKeyword);
	void SetLogAll(const bool bLogAll);
	void SetSplitSize(const int nSplitSize);

	// Process
	void StartParseProcess();

	// Thread
	static int ParserThreadFunction(LPVOID pParam);

	// Getter
	int GetDestPortNum(const u_char* pucData);
	bool GetLogAll();

	// Tools
	int hex2dec(const u_char* ucPort, int nNumOfByte);
	void SetStartTimer();
	void SetEndTimer();

private:
	// Para
	bool m_bLogAll;
	int m_nSplitSize;		// in MB

	// Path
	std::vector<CString> m_szPending;
	CString m_szResPath;

	// Keyword
	bool m_bKeyword;
	std::vector<const u_char*> m_vKeyword;
	void DeleteKeyword();

	// Parser function
	int AddPending(const CString szFileNamePath);
	int ParsePCap(const CString szPCapFile);
	int _ParsePCap(const u_char* pucData, const u_int len, const char date[STR_DATE_MEM_SPACE], const CString szFileName, std::map<CString, std::shared_ptr<CPCapLog>>& map);
	bool CompareKeyword(const void* data);

	// Handle counter
	std::atomic<int> m_nHandle;
	void WaitUntilAllThreadDone();

	// Others
	void Epoch2DateTime(const time_t tEpoch, const long tUSec, char* cDateTime);

	// Thread
	typedef struct parserThreadData
	{
		CString	szPCapName;
		CICEPCapParser* pParser;
	} ParserThreadData;

	// Print Msg
	void CICEPCapParser::PrintMsg(const CString szMsg);
	CCriticalSection m_cs;

	// Timer
	std::chrono::system_clock::time_point m_begin;
	std::chrono::system_clock::time_point m_end;
};