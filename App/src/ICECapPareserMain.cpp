#include "stdafx.h"
#include "ICECapParserMain.h"

int main(int argc, char* argv[])
{
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

	CString szPcap;				// path or path of .pcap file
	CString szParsePath;
	CString szKeyword;

	// argument options
	std::set<std::string> _arg;
	_arg.insert("-k");		// find keywords or not
	_arg.insert("-a");		// log all data or only readable lines
	_arg.insert("-s");		// log all data or only readable lines 

	if (argc < 3)
	{
		std::cerr <<

			"///////////////////////////////////////////////////////////////////////////////////////////////////////////////////"
			"// \n"
			"// Function:\n"
			"// 1) Convert a .pcap file or all .pcap files in a folder to readable logs\n"
			"// 2) If any, print only the lines with keywords specified in the argument\n"
			"// \n"
			"// Usage:\n"
			"// ICEPCapParser.exe [FULL_PATH_OF_PCAP_FOLDER_OR_FILE] [FULL_PATH_OF_PARSED_FOLDER] [-k] [KEYWORD_1] [KEYWORD_2] ... [-a] [-s] [SIZE_IN_MB]\n"
			"// Optional param: \n"
			"// -k: enable keyword search \n"
			"// -a: log all bytes \n"
			"// -s: split size in MB \n"
			"// \n"
			"///////////////////////////////////////////////////////////////////////////////////////////////////////////////////"
			"\n";
			
		return -1;
	}

	// input: [pcap] [pcap_parse_path] [keyword_1] [keyword_2]...
	szPcap = argv[1];
	szParsePath = argv[2];
	CICEPCapParser parser(szPcap, szParsePath);

	for (int i = 3; i < argc; i++)
	{
		if (std::string(argv[i]) == "-a")
		{
			parser.SetLogAll(true);
		}
		else if (std::string(argv[i]) == "-k")
		{
			while (i + 1 < argc && _arg.find(argv[i + 1]) == _arg.end())
			{
				szKeyword = argv[++i];
				szKeyword += '\0';
				parser.AddKeyword(szKeyword);
			}
		}
		else if (i + 1 < argc && std::string(argv[i]) == "-s")
		{
			std::string::size_type st;
			const int nSize = std::stoi(std::string(argv[++i]), &st);
			parser.SetSplitSize(nSize);
		}
	}

	parser.StartParseProcess();

	return 0;
}