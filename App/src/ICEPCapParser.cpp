#include "stdafx.h"
#include "ICEPCapParser.h"

CICEPCapParser::CICEPCapParser(const CString szPCap, const CString szResPath)
{
	m_bKeyword = false;
	m_nHandle = 0;
	m_bLogAll = false;
	m_nSplitSize = DEFAULT_SPLIT_SIZE;

	AddPending(szPCap);

	m_szResPath = szResPath;
}

CICEPCapParser::~CICEPCapParser()
{
	DeleteKeyword();
}

int CICEPCapParser::AddPending(const CString szFileNamePath)
{
	bool bIsFile = memcmp(szFileNamePath.Right(5), PCAP_EXTENSION, 5) == 0 ? true : false;

	if (bIsFile)
	{
		m_szPending.push_back(szFileNamePath);
		m_nHandle++;

		return 0;
	}
	else
	{
		WIN32_FIND_DATA search_data;
		memset(&search_data, 0, sizeof(WIN32_FIND_DATA));
		HANDLE handle = FindFirstFile(szFileNamePath + "\\*" + PCAP_EXTENSION, &search_data);

		while (handle != INVALID_HANDLE_VALUE)
		{
			// Found a .pcap file
			CString szPCap = search_data.cFileName;
			m_szPending.push_back(szFileNamePath + "\\" + szPCap);
			m_nHandle++;

			if (FindNextFile(handle, &search_data) == FALSE)
				break;
		}
	}

	return 1;
}

void CICEPCapParser::AddKeyword(const CString szKeyword)
{
	m_bKeyword = true;

	std::vector<u_char> vuc;
	vuc.resize(szKeyword.GetLength());
	std::transform(szKeyword.GetString(), szKeyword.GetString() + szKeyword.GetLength(), vuc.begin(),
		[](TCHAR c) { return static_cast<const unsigned char>(c); });

	u_char* puc = new u_char[vuc.size()];
	memcpy(puc, &vuc[0], vuc.size());

	m_vKeyword.push_back(puc);
}

void CICEPCapParser::SetLogAll(const bool bLogAll)
{
	m_bLogAll = bLogAll;
}

void CICEPCapParser::SetSplitSize(const int nSplitSize)
{
	m_nSplitSize = nSplitSize * 1000000;
}

bool CICEPCapParser::GetLogAll()
{
	return m_bLogAll;
}

void CICEPCapParser::DeleteKeyword()
{
	m_bKeyword = false;

	if (!m_vKeyword.empty())
	{
		for (const u_char* uc : m_vKeyword)
		{
			delete uc;
			uc = nullptr;
		}
	}
}

void CICEPCapParser::StartParseProcess()
{
	const int nNumOfThread = min(MAX_NUM_OF_THREAD, m_szPending.size());
	ThreadPool pool(nNumOfThread);
	std::vector<std::future<int>> results; 

	SetStartTimer();

	for (CString szPendingFile : m_szPending)
	{
		ParserThreadData* pThreadData = new ParserThreadData;
		pThreadData->szPCapName = szPendingFile;
		pThreadData->pParser = this;

		results.emplace_back(
			pool.enqueue([pThreadData] {
				return ParserThreadFunction(pThreadData);
				}
			)
		);
	}

	WaitUntilAllThreadDone();
	std::cout << "Done!" << "\n";

	SetEndTimer();
}

int CICEPCapParser::ParserThreadFunction(LPVOID pParam)
{
	ParserThreadData *pPara(reinterpret_cast<ParserThreadData*>(pParam));
	ParserThreadData Para = *pPara;
	delete pPara;

	CString szPCapName = Para.szPCapName;

	return Para.pParser->ParsePCap(szPCapName);
}

int CICEPCapParser::ParsePCap(const CString szPCapFile)
{
	PrintMsg("Parsing file: " + szPCapFile);

	// Open the file and store result in pointer to pcap_t
	// Use pcap_open_offline
	// http://www.winpcap.org/docs/docs_41b5/html/group__wpcapfunc.html#g91078168a13de8848df2b7b83d1f5b69
	char errbuff[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_offline(szPCapFile, errbuff);
	if (!pcap)
	{
		PrintMsg("*** " + szPCapFile + " is an invalid pcap file! ");
		m_nHandle--;
		return 1;
	}

	// Create a header object:
	// http://www.winpcap.org/docs/docs_40_2/html/structpcap__pkthdr.html
	pcap_pkthdr *header;

	// Result
	int nRes = 0;

	//
	// Loop through packets
	//
	const u_char* pucData;
	bool bHit = false;
	char date[STR_DATE_MEM_SPACE_EXTRA];
	long lWriteSize = 0;
	int hasNext = 0;
	CString szFileName = szPCapFile.Mid(szPCapFile.ReverseFind('\\') + 1);

	std::map<CString, std::shared_ptr<CPCapLog>> mLog;

	while (hasNext = pcap_next_ex(pcap, &header, &pucData) >= 0)
	{
		// Get packet date time
		Epoch2DateTime(header->ts.tv_sec, header->ts.tv_usec, date);

		nRes += _ParsePCap(pucData, header->len, date, szPCapFile, mLog);
	}

	// Write out
	for (auto const& x : mLog)
	{
		nRes += x.second->WriteLog();
	}

	if (nRes > 0)
	{
		PrintMsg("Error in parsing file: " + szFileName);
	}
	else
	{
		PrintMsg("Done parsing file: " + szFileName);
	}

	m_nHandle--;
	return nRes;
}

int CICEPCapParser::_ParsePCap(const u_char* pucData, const u_int len, const char date[STR_DATE_MEM_SPACE_EXTRA], const CString szPCapFile, std::map<CString, std::shared_ptr<CPCapLog>>& map)
{
	int nRes = 0; 

	int nDestPort = GetDestPortNum(pucData);
	CString szMapKey;
	szMapKey.Format("%s_%d", szPCapFile, nDestPort);

	if (map.empty() || !map.empty() && map.find(szMapKey) == map.end())
	{
		map.insert({ szMapKey, std::shared_ptr<CPCapLog>(new CPCapLog(szPCapFile, m_szResPath, nDestPort, m_nSplitSize)) });
	}

	std::shared_ptr<CPCapLog> log = map.find(szMapKey)->second;

	for (u_int index = PAYLOAD_POSN; index < len; index++)
	{
		// new line
		if (memcmp(&pucData[index], &PAYLOAD_START_CHAR, PAYLOAD_NUM_START_CHAR) == 0)
		{
			if (!log->IsTempEmpty() && !log->IsTempEndWithLineFeed())
			{
				log->PushBackTemp(LINE_FEED);	// add line feed
			}
			
			if (GetLogAll())
			{
				// include ms
				log->PushBackTemp(date, date + STR_DATE_MEM_SPACE_EXTRA - 1);
			}
			else
			{
				log->PushBackTemp(date, date + STR_DATE_MEM_SPACE - 1);
			}
			log->PushBackTemp(PAYLOAD_START_CHAR, PAYLOAD_NUM_START_CHAR);
			index += PAYLOAD_NUM_START_CHAR - 1;
			continue;
		}

		else if (!log->IsTempEmpty() && memcmp(&pucData[index], &PAYLOAD_END_CHAR, 1) == 0)
		{
			log->PushBackTemp(pucData[index]);
			log->PushBackTemp(LINE_FEED);	// add line feed

			if (m_bKeyword && !log->GetHit())
			{
				log->ClearTemp();
			}
			else if (m_bKeyword && log->GetHit())
			{
				nRes += log->WriteBuff();
				log->ClearTemp();
				log->SetHit(false);
			}
			else
			{
				nRes += log->WriteBuff();
				log->ClearTemp();
			}

		}
		// continued payload
		else
		{


			if (GetLogAll() && log->IsTempEmpty()) 
			{
				// supposed to be rubbish but log 
				if (m_bKeyword && !log->GetHit() && CompareKeyword(&pucData[index]))
				{
					log->SetHit(true);
				}
				log->PushBackTemp(date, date + STR_DATE_MEM_SPACE_EXTRA - 1);
				log->PushBackTemp(pucData[index]);
			}
			else if (!log->IsTempEmpty())
			{
				if (m_bKeyword && !log->GetHit() && CompareKeyword(&pucData[index]))
				{
					log->SetHit(true);
				}
				log->PushBackTemp(pucData[index]);
			}
		}
	}

	return nRes;
}

bool CICEPCapParser::CompareKeyword(const void* data)
{
	bool bMatch = false;
	size_t len;

	if (!m_vKeyword.empty())
	{
		for (const u_char* keyword : m_vKeyword)
		{
			len = strlen((char*)keyword);
			bMatch = memcmp(data, keyword, len) != 0 ? false : true;

			if (bMatch)
			{
				return bMatch;
			}
		}
	}

	return bMatch;
}

void CICEPCapParser::Epoch2DateTime(const time_t tEpoch, const long tUSec, char* cDateTime)
{
	const time_t temp = tEpoch;
	tm tm_gmt;
	gmtime_s(&tm_gmt, &temp);

	if (GetLogAll())
	{
		char cTemp[STR_DATE_MEM_SPACE_EXTRA - 6];
		strftime(cTemp, STR_DATE_MEM_SPACE_EXTRA - 6, "%Y-%m-%d %H:%M:%S.", &tm_gmt);
		std::string strTemp(cTemp);
		strTemp.append(std::to_string(tUSec));
		strcpy_s(cDateTime, STR_DATE_MEM_SPACE_EXTRA, strTemp.c_str());
	}
	else
	{
		strftime(cDateTime, STR_DATE_MEM_SPACE, "%Y-%m-%d %H:%M:%S ", &tm_gmt);
	}

}

void CICEPCapParser::PrintMsg(const CString szMsg)
{
	m_cs.Lock();

	std::cout << szMsg << "\n";

	m_cs.Unlock();
}

void CICEPCapParser::WaitUntilAllThreadDone()
{
	while (m_nHandle > 0)
	{
		Sleep(500);
	}
}

int CICEPCapParser::GetDestPortNum(const u_char* pucData)
{
	return hex2dec(&pucData[DEST_PORT_POSN], DEST_PORT_LEN);
}

int CICEPCapParser::hex2dec(const u_char* ucPort, int nNumOfByte)
{
	int dec = 0;

	for (int n = 0; n < nNumOfByte; n++)
	{
		dec += static_cast<int>(ucPort[n]) << 8 * (nNumOfByte - 1 - n);
	}

	return dec;
}

void CICEPCapParser::SetStartTimer()
{
	m_begin = std::chrono::system_clock::now();
	const auto _begin = std::chrono::system_clock::to_time_t(m_begin);
	tm now;
	localtime_s(&now, &_begin);
	
	std::cout << '\n';
	std::cout << "start time: " << std::put_time(const_cast<tm*>(&now), "%Y-%m-%d %H:%M:%S") << '\n';
}

void CICEPCapParser::SetEndTimer()
{
	m_end = std::chrono::system_clock::now();
	const auto _end = std::chrono::system_clock::to_time_t(m_end);
	tm now;
	localtime_s(&now, &_end);

	std::cout << '\n';
	std::cout << "end time: " << std::put_time(const_cast<tm*>(&now), "%Y-%m-%d %H:%M:%S") << '\n';

	std::chrono::duration<double> elapsed_seconds = m_end - m_begin;

	int h = static_cast<int>(elapsed_seconds.count() / 3600.0);
	int m = static_cast<int>((elapsed_seconds.count() - h * 3600.0) / 60.0);
	double s = elapsed_seconds.count() - h * 3600.0 - m * 60.0;
	std::cout << "elapsed time: "
			  << h << " hr "
		      << m << " min "
		      << s << " sec"
		      << "\n";
}
