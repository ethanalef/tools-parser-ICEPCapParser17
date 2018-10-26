#include "stdafx.h"
#include "PCapLog.h"

CPCapLog::CPCapLog()
{
}

CPCapLog::CPCapLog(const CString szPCapFile, const CString szLogPath, const int nDestPort, const long lLogSize)
{
	m_szPcapName = szPCapFile.Mid(szPCapFile.ReverseFind('\\') + 1);
	m_szLogPath = szLogPath;
	m_nDestPort = nDestPort;
	m_nPostfix = 0;
	m_bHit = false;
	m_lLogSize = lLogSize;

}

CPCapLog::~CPCapLog()
{
}

int CPCapLog::WriteBuff()
{
	int nRes = 0;
	m_vBuf.insert(m_vBuf.end(), m_vTemp.begin(), m_vTemp.end());

	if (GetBuffSize() > m_lLogSize)
	{
		nRes = WriteLog();
	}

	return nRes;
}

long CPCapLog::GetBuffSize()
{
	return m_vBuf.size();
}

int CPCapLog::WriteLog()
{
	int res = 0;

	if (!m_vBuf.empty())
	{
		CString szParseFileName;
		if (m_szLogPath.Right(1) == "\\")
		{
			szParseFileName.Format("%s%s_%d_parsed_%d.log", m_szLogPath, m_szPcapName, m_nDestPort, m_nPostfix++);
		}
		else
		{
			szParseFileName.Format("%s\\%s_%d_parsed_%d.log", m_szLogPath, m_szPcapName, m_nDestPort, m_nPostfix++);
		}

		CFile f(szParseFileName, CFile::modeCreate | CFile::modeWrite);

		try
		{
			f.Write(&m_vBuf[0], m_vBuf.size() * sizeof(u_char));
			m_vBuf.clear();
			res = 0;
		}
		catch (...)
		{
			//TRACE(e);
			f.Close();
			return res = 1;
		}
		f.Close();
	}

	return res;
}

void CPCapLog::PushBackTemp(const unsigned char* CharArray, const int size)
{
	for (int n = 0; n < size; n++)
	{
		m_vTemp.push_back(*(CharArray + n));
	}
}

void CPCapLog::PushBackTemp(const char* first, const char* last)
{
	m_vTemp.insert(m_vTemp.end(), first, last);
}

void CPCapLog::PushBackTemp(const char &c)
{
	m_vTemp.push_back(c);
}

void CPCapLog::ClearTemp()
{
	m_vTemp.clear();
}

bool CPCapLog::IsTempEmpty()
{
	return m_vTemp.empty();
}

bool CPCapLog::IsTempEndWithLineFeed()
{
	return m_vTemp.back() == char(10) ? true : false;
}

void CPCapLog::SetHit(const bool bHit)
{
	m_bHit = bHit;
}

bool CPCapLog::GetHit()
{
	return m_bHit;
}