  //ЧТО СДЕЛАТЬ
        // - парсинг cookie names
        // - Добавить анализ не только траффика, но и LocalStorage
        // - если base64, то после декодирования можно поиск данных сделать
        // - IDOR не только по числовым значениям нужно искать но и если
        //1)фио, логин, емаил присутствуют в параметрах юрл, пост запросов, в хедерах и куки
        //+ если id не только числом может быть



        //СДЕЛАНО
        // - парсинг парметров из url
        // - Запись всех X-headers в лог
        // - инпут тегов из reponseBody (name) <input type="hidden" id="sourceCodeGated" name="sourceCode1" value="fdgbr5"/>
        // - парсинг reqBodyParam
        // - парсинг емаилов (потом можно ) из responseBody, respHeaders, respCookies

        //Добавить парсинг всех параметров из url в файл E:\Ptest\Testing\Attacks\Tools\Brute\parameters.txt

        //Входные данные

        string reqHeaders = "";
		reqHeaders = System.Text.RegularExpressions.Regex.Replace(reqHeaders, @"trafficRequestHeaders.*?:", "");
		string respHeaders = "";
		respHeaders = System.Text.RegularExpressions.Regex.Replace(respHeaders, @"trafficResponseHeaders.*?:", "");
		string reqCookies = "";
		reqCookies = System.Text.RegularExpressions.Regex.Replace(reqCookies, @"trafficRequestCookies.*?:", "");
		string respCookies = "";
		respCookies = System.Text.RegularExpressions.Regex.Replace(respCookies, @"trafficResponseCookies.*?:", "");
		string respBody = "";
		respBody = System.Text.RegularExpressions.Regex.Replace(respBody, @"trafficResponseBody.*?:", "");
		string reqBody = "";
		reqBody = System.Text.RegularExpressions.Regex.Replace(reqBody, @"trafficRequestBody.*?:", "");
		string meth = "";
		string resCode = "";
		string conType = "";
		string trUrl = "";
		string Counter1 = "";
		string getDirectories = "";
		string fileName = "";
		string getProfileName = "";
		//Нужно сделать проверку на наличие reqHeaders, respBody, respHeaders, т.к. в траффике могут пустые быть (только url)

		if (!string.IsNullOrEmpty(reqHeaders) && !string.IsNullOrEmpty(respHeaders) && !string.IsNullOrEmpty(respBody))
		{

			string login = project.Profile.Login;
			string pass = project.Profile.Password;
			string email = project.Profile.Email;
			//string hyattMember = "";
			string campaign = "";

			var list = "";

			//Паттерны
			string patSql =
				@"(sql|mysql|mssql|id_base|idname|idselect|idsite|idstring|idtype|id\b|select|report|role|update|query|user|name|sort|where|search|params|process|row|view|table|from|sel|results|sleep|fetch|order|keyword|count|column|input\b|key|code|field|delete|string|number|filter|aai_codigo|aal_aluno|aal_codigo|aap_codigo|abfrsql|about|acc_codice|access|accessori|accessorin|accno|accnt|accnts|activated|active|add_date|address|adm_nivel|admin|admin_pass|admin_passwd|admin_password|admin_psw|admin_pwd|admin_user|adminemail|administrateur|administrator|administrators|administratorzy|adminlogin|adminmail|adminpass|adminpassword|adminpaw|adminpsw|adminpwd|admins|adminupass|adminuser|adres|adres_e-mailowy|adrese-mail|adress|adressee-mail|advanced|affiliate|after|age|agent|aide|aim|ajar|akses|aktif|akun|alamat|alias|alliance1|alliance2|allno|allow|allowance|allowbanip|allowbanuser|allowcensorword|allowdelpost|alloweditpoll|alloweditpost|allowedituser|allowmassprune|allowmodpost|allowmoduser|allowpostannounce|allowrefund|allowstickthread|alu_matricula|ana_codice|and_xevento|anelli|anno|anyone|app|app_gruppo_e|app_title|app_utente_e|apply|apwd|arcade|arch|area|arial|article|assigned_to|att_codice|attachment|attention|auth|authenticate|authentication|authentification|authentifier|author|author_num|authstr|ava_codigo|ava_disciplina|ava_professor|avatar|avatarheight|avatarwidth|avi_codigo|avp_codigo|ba_date|ba_num_reads|ba_num_voted|ba_order_num|backlink|baglanti|ban_ip|bank|banner|banner_title|banner_url|bar|batas|bc_plugin|bcena|bdate|before|benutzer|beschreibung|bezeichnung|bijoux|bijouxn|bio|bloc_row|blog|blogcommentsaccess|blogcommentscc|blogcommentssub|blogger|blogmessagesaccess|blogpermissiongroup|blz|book_code|box|bracciali|branch_num|branchno|brend|bs_setting|bst_time|btn|cabang|cache|calendar|callend|callstart|campo_bol|can|can_codice|candidato|canoccupantschangesubject|canoccupantsinvite|cap|capital|cardno|caroline-du-nord|catarticles|categories|category|category_img|cavilha|cc_expires|cc_owner|cc_type|ccc|ccv|cdele|cel|cellulare|cerca|certificate|cfg|channel|charge|charms|charmsn|charttype|chave|chave_primaria|chaveta|checkbox|checking|chiave|chiavetta|child_cfg|chost|cifrario|cinsiyet|city|class|classcategory_id1|classcategory_id2|clave|cle|cleanurl|clef|client|client_desc|client_img|client_url|clientno|clientpassword|clients|clock|closed|cno|cod|cod_aplicacion|cod_art|cod_clifor|cod_dep|cod_utente_cre|cod_utente_mod|cod_valuta|codcliente|coddoc|code|codepostal|codi|codice|codice_comune|codicemedico|codicepaziente|codigo|codrappr|codusuario|cognome|col|collane|color|com|com_natur|comm|command|comment|comment1|comment2|comment3|comment4|comment5|comment6|commentpath|comments|community|company|complet|compte|comptes|comune|conf|config|config_item|config_key|config_owner|confirm_url|conkey|connexion|consommateur|consumidor|contact|contacts|content|contenuti|context|contrasena|converge_pass_hash|converge_pass_salt|cookie|coppermine|copy|copyright|core|corso|coste|coste_total|coupon|course_no|cpr|crack|create_date|created_at|created_by|creditcard|csc|css|cuna|currentindex|currval|curtopics|custno|customenu|customer|customers|customers_email_address|customers_password|customsettings|customstatus|cvd|cvv|cvv2|cvvc|dal|danych|dat_movimento|dat_utente_cre|dat_utente_mod|data|data_in|data_out|datacol|datadimissione|datanascita|dataricovero|datarow|datasource|dates|datum|db_password|db_value|debet|debug|decl_mail|decrip|del_flg|delay|deliv_fee|denominazione|department|dept_desc|deptno|desccompensa|desconto|descr|descrip|description|descrizione|desd_xdecisao|desd_xfase|desd_xforo|desd_xjurisdicao|deskripsi|dest|dico|digest|dipart|dipnome|dipsede|direct|direction|diritto|dis_codigo|disablepostctrl|disma|display|displayorder|distip|distmacaddr|dlocation|dni|dno|dnum|does_repeat|dogum|dogum_tarih|dogum_tarihi|dogumtarih|dogumtarihi|dorsal|dostawcy|download|downloads|drinker|dst|dummy|e-mail|e-posta|e-posta_adres|e-posta_adresi|e-postaadres|e-postaadresi|e_mail|e_posta|e_posta_adres|e_posta_adresi|e_postaadres|e_postaadresi|ecolo|edad|edate|edit_flg|editor|editors|ele_codice|email|emailaddress|emailcloak|emer|emissao|emni|emniplote|emp_num|empnbr|empno|empty_days|emri|enabled|end_date_time|eno|enter|entry|enugene|eposta|eposta_adres|eposta_adresi|epostaadres|epostaadresi|error|esquema|essn|eta|etertre|ev_adres|ev_adresi|ev_telefon|ev_telefonu|evadresi|event|evtelefon|evtelefonu|exclude_date|expiration|expression|extended|extension|family|fee|feed|feedback|few|fichier|fidlist|field2|field3|figlio|fissure|fix|fjalekalimi|fjalekalimin|fkidanagrafica|fkidannofdr|flag|fld_password|fldfunhref|fldfunindex|fldfuninfo|fldfunmemo|fldfunopen|fldfuntype|flg_fiscale|flg_prezzo_con_iva|flipper|flscrvpre|folder|fonte|format|former|forum|foto|fre_aluno|fre_codigo|fre_disciplina|freeway|freewaylogin|full|full_news|gab_codigo|gab_pergunta|gaia_codigo|gaip_codigo|gap_codigo|gcode|gender|genitore|geometry|geshi|get_ddl|gifi_accno|gift|giris|glmm|gmail|google|grade|grand|grcode|grfilt|grkntr|groesse|group|groupcodes|groupe|grtov|gru_codice|grupy|gtranslate|guest_ip|guid_email|guid_sessao|gun|guncel|guncelleme|guncelleme_tarih|guncelleme_tarihi|guncellemetarih|guncellemetarihi|guy|hachage|handle|harga|hash|hashsalt|hashtag|havabfragen|hdesc|header|height|help|helvetica|hidden|hidden_url|hide|highlight|hiredate|hk_value|home|homepage|host|how|html|i_end|i_tel|icmsinterno|icmssp|icon|icq|id1|id2|id_annuncio|id_answer|id_article|id_artpage|id_attivita|id_auteur|id_breve|id_cat|id_catalog|id_cidade|id_citta|id_comune|id_contact|id_customer|id_disciplina|id_document|id_enfermedad|id_estado|id_fatura|id_forum|id_fragment|id_group|id_groupe|id_ip|id_links|id_log|id_logho|id_member|id_message|id_mot|id_msg|id_nazione|id_news|id_paciente|id_page|id_palestra|id_paragraph|id_passwd|id_photo|id_poll|id_poll_ip|id_preventivo|id_product|id_provincia|id_refferer|id_regione|id_richiesta|id_rubrique|id_scheda|id_seq|id_servico|id_signature|id_syndic|id_syndic_article|id_tra|id_type|id_user|id_version|idaddome|idanagrafica|idanamnesifamil|idappargenit|idapparlocom|idarticolo|idasl|idatleta|idbocca|idcamera|idcapo|idcard|idcartellaclinica|idcategoria|idcategory|idciclo|idclassificatore|idcliente|idclinica|idcollo|idcomune|idcomuneresidenza|idconfig|idconn|idcorpo|idcuore|idcute|iddescrizionedocumento|iddesign|iddiscipline|iddistretto|iddocumento|ide|identifier|identify|idesameobiettivo|idevent|ideventcategory|idextra|idgara|idgroup|idgroupacl|idgrouppermission|idgruppe|idkontakt|idletto|idlinfonodi|idlocation|idmedicofamiglia|idmlattach|idmlgroup|idmlmail|idnaso|idnotsentmails|idocchi|idoggetto|idorecchie|idpagamento|idpaziente|idperiodo|idpersonale|idplugin|idprovenienza|idragsoc|idregistro|idreparto|idricovero|idricoverohatipologia|idruolo|idservizio|idsessione|idsesso|idsistemazione|idsistnerv|idsistresp|idsmaglog|idsocieta|idstatocivile|idstatogenerale|idstelle|idsubscription|idsubscriptiontickets|idticket|idtipociclo|idtipodimissione|idtipodocumento|idtipologiaricovero|idtipologiaservizio|idtiporicovero|idtiposervizio|idtipotrasferimento|idtipotrattamento|idtitolo|idtrasferimento|idtrattamento|idtype|idusuario|idutente|idutenti|idx|idx_item|idxatv|ignatiusj|ilce|image|images|ime|imenu|impiegato|inactive|include_date|ind_clifor|index|index_num|indice|indirizzo|installed|instanceof|int4|intro|inventory|invisible|invoice|ip_address|ipaddress|ipi|is_adres|is_adresi|is_telefon|is_telefonu|isadmin|isadresi|isbn|ishtml|istelefon|istelefonu|item|item_cd|itemno|iteration|jcode|jeda|jenis|jfalternative|jfcategories|jfcontacts|jfcontent|jfdatabase|jfnewsfeeds|jfrouter|jfsections|jiscode|jml|job|job_e_date|job_s_date|job_title|joomla|journals|jpg|judul|jumpmenu|kata_kunci|kata_sandi|katakunci|katasandi|kategori|kelas|ken_kanji|kennung|kennwort|keterangan|key|key_|keyword|keywords|kiyaku_title|klient|kljuc|knr|kod|kode|kodi|koef|konta|kontak|kontaklar|kontakt|konto|kontr60|kontr600|kontr620|korisnici|korisnik|korschet|korschetfilter|kosten|kpro_user|kre1|kredit|kullanici|kullanici_adi|kunci|kursnr|kwick|l_col_list|lahir|lang|langkey|langug_code|last_ip|last_login|lastactivity|lastexecuted|lastpost|lastposter|lastpostpmtime|lastposttime|lastsearchtime|lastupdated|lastupdatetime|layer|lbl_aom_unaccessible_shipmethod|ldap|lec_codigo|lec_disciplina|lec_professor|legacy|legacybots|level|license|lieferant|lingua|link|list|liste|llave|llogaria|load|loadmodule|loans|loc|local_spi|locale|localita|location|locked|log|logenabled|login|login_admin|login_pas|login_pass|login_passwd|login_password|login_pw|login_pwd|login_user|logini|loginkey|loginout|loginpas|loginpass|loginpasswd|loginpassword|loginpwd|logins|logo|logohu|logout|lokasyon|long|losung|losungswort|lozinka|luogonascita|lxmenu|macaddr|madre|magic|magic_string|mail|main|main2|main3|main_comment|main_image|main_large_image|main_list_comment|main_list_image|main_module|maker|manager|manufacturer|matcode|matkhau|matma|matr|matricola|matrnr|maxusers|mayank|mbpc|mbpp|md5hash|md5sum|medals|mem_login|mem_pass|mem_passwd|mem_password|mem_pwd|member|member_login_key|members|membersonly|membre|membres|memlogin|mempassword|menu|menutype|message|mf_category_desc|mf_desc|mgr|mgrssn|mima|mindk|mnr|mobile|mod_arcadebtn|mod_catarticles|mod_cd_login|mod_cpmfetch|mod_cssmenu|mod_custom|mod_customenu|mod_date|mod_enugene|mod_flashmod|mod_flipper_img_rotator|mod_freeway_admin|mod_freeway_events|mod_freeway_products|mod_freeway_services|mod_freeway_shoppingcart|mod_freeway_subscriptions|mod_freewaylogin|mod_gtranslate|mod_jt_slideshow|mod_jumplink|mod_kwick_sliding_menu|mod_lxmenu|mod_mainmenu|mod_ninja_simple_icons|mod_product_list|mod_sendcart|mod_sidebarmenuapplestyle|mod_signallogin|mod_translate|mod_virtuemart_currencies|mod_virtuemart_featureprod|mod_virtuemart_latestprod|mod_virtuemart_manufacturers|mod_virtuemart_randomprod|mod_virtuemart_search|mod_virtuemart_topten|mod_vm_cat_menu_specific|mod_vm_prod_cat_full|model|moderated|modhome|modify_date|module_addr|module_code|moduledir|modules|modulo_contatti|mon_mot_de_passe|monmotdepasse|mootoolnicemenu|mopc|mopp|morfeoshow|mos|moscode|mosemailcloak|mosimage|mosloadposition|mospaging|mossef|mosvote|mot|mot_de_passe_bdd|motto|mountcategory|mpassword|msg|msn|multilinestring|multipolygon|municipioprestador|municipiotomador|my_email|my_password|myexec|mypassword|n_agence|n_client|n_compte|n_dept|n_dir|n_type|nam|nama|nama_akun|nama_pengguna|namaakun|namapengguna|naresh|natureza|nazwisko|ndc|network|new|newcollection|newnotices|newpms|newrow|news|news_date|news_title|newsfeeds|newssummaryauthor|newssummarycategory|newyork|newyorkenglish|nextval|nguoidung|nick|ninja|niv_codigo|nivel|nlista|nom|nombre|nome|nome_agencia|nome_cliente|nomedip|nompuerto|none|nonnavigable|nota|note|noteaccettazione|notification_type|nouveau|nowy|nrcandi|nroarticolo|nroordine|nrsez|nsprefix|nsschema|num|num1|numara|numer|numero|nummer|nuova|object|object_type|objectif|obrazy|odate|offerte|office|oggettistica|oggettistican|oggetto|old|oldstate|olimg|ono|operation|operation_type|order_currency|orderdate|orderno|orecchini|org_code|orgcode|origem|origin|ort|ortnr|ost1|ostatki|ostatkii|ostdate|osvendor|our_loc|owner|ownerno|p_assword|p_word|padre|page|pagebreak|pagenavigation|params|parent|parigi|parola|part|partof|partstring|pas|pasif|pass|pass1word|pass_hash|pass_w|pass_word|passe|passer|passw|passwd|password|passwordsalt|passwort|passwrd|paswd|pasword|payment|payment_extrainfo|payment_image|payment_method|pcode|pe_aduser|pe_user|peer_cfg|pekerjaan|pendidikan|pengguna|penjelasan|per_codigo|perdorimi|perdoruesi|perm|permission|pers_id_registerer|pers_nr|persistent|persnr|personal_key|perusahaan|petty|phone|php|php_dir|picurl|pid1|pid2|piede|pin|pins|pinsn|pixsize|plan_table_output|platform|plugin_googlemap2|plz|pnds|pno|point|point_rate|pom|pomoc|portachiavi|portachiavin|pos|post_date|post_status|posta|postdatetime|poster|power|prazo_xevento|prc_magg1|prc_magg2|prc_sconto1|prc_sconto2|prc_sconto3|prc_sconto4|pref|prenom|prepend_digits|press|prg_art|prg_movimento|prg_movimento_riga|price|price01|price02|prih|priority|privacy|private_key|prix|pro_codice|pro_matricula|problem_code|product|product_code|product_flag|product_list|product_version|progetto|propertyno|propvalue|prova|provincial|prz_merce|prz_merce_fis|psw|pswd|publicroom|published|publisher|publisher_code|pulsante|punetoret|punonjes|pwd|pwd1|pword|pwrd|qagent|qno|qta_merce|qty|quanly|quantidade|quantitens|quantri|que|question|rachunki|rakesh|random|rank|rate|readmore|readperm|realiz|realiz_opt|reason|recherche|reddito|ref_url|referer_md5|referredby|regist_date|registered|registrationenabled|relationmessage|relationsub|remember|replace|replies|result|results|risultato|rol|rolle_nr|root|rpad|ruang|rule|rysa|saat|saida|sal|sale_date|sale_limit|sale_unlimited|salt|sandi|sb_pwd|schet|schl|schweiz|screen|search|search_term|searchbot|searchstring|secret|secret_code|secretanswer|secretcode|secretquestion|section_value|sections|sede|sef|semester|semo|send|sender|senha|sent|serial|serial_no|seryjny|session_ip|session_member_login_key|sessione|sesskey|sesso|setting|shared_secret|sheight|ship|shop|short_news|show|side|sifra|sifre|sightml|signallogin|signature|sin|sira|sistema|site|situacao|sklad|sklep1|sklep2|skype|slogan|smtp_email|smtp_helo|smtp_server|soal|sonst|sot_proposta_e|sot_utente_e|source|spacer|special|spis|splitstring|sql_text|src|ssn|ssschet|staffno|stan|standard|standort_nr|start|start_date|startnummer|state|statement|status|stdprice|stichwort|stock|stock_unlimited|stocker|stockno|store|store1|store2|store3|store4|strasse|string|sub|sub_class|sub_comment1|sub_comment2|sub_comment3|sub_comment4|sub_comment5|sub_comment6|sub_image1|sub_image2|sub_image3|sub_image4|sub_image5|sub_image6|sub_large_image1|sub_large_image2|sub_large_image3|sub_large_image4|sub_large_image5|sub_large_image6|sub_title1|sub_title2|sub_title3|sub_title4|sub_title5|sub_title6|subdomain|submitted_by|succ_rate|sumdatarow|summachp|summaprihod|super|superssn|surat_elektronik|surel|swf|swidth|sys_context|system|sysuser|tabella|table_prefix|tag|tags|tanggal|tanggal_lahir|tarih|tasto|tat|tecla|teilnehmernr|tekst|telefon|telefon_ev|telefon_is|telefonev|telefonis|telefono|telephone|temp_pass|temp_password|tempat|tempat_lahir|tempfidlist|template|template_code|temppass|temppasword|tempprovkredit|ten|tendangnhap|tendn|tennd|tennguoidung|tenquanly|tenquantri|terms_body|test|testq|text|texte|texto|tf_key|the|the_geom|this|threadorder|ticker|tidclasfiscais|tidcliente|tidfornecedor|tidproduto|tids|time_stamp|timeofmove|tinymce|tipo|titel|title|titre|tmp_lahir|today|token|tono|toorg|top|topics|topped|total|totpc|totpp|totpv|touche|tovar|tpl_dir|tpref|tukhoa|tutor|tvoti|txt|type|u_pass|udal|ulke|under_menu|unit|universitas|uno|upass|update_date|updated_at|upper_rule|uprdescricao|url|url_md5|urut|usager|user|user1|user_admin|user_alto|user_basso|user_email|user_group|user_icq|user_ip|user_level|user_login|user_n|user_nm|user_pass|user_passw|user_passwd|user_password|user_pw|user_pwd|user_pword|user_pwrd|user_un|user_usern|user_usernm|user_usernun|user_usrnm|useradmin|userip|userlogin|usern|usernm|userpass|userpasswd|userpassword|userpw|userpwd|users|usr|usr2|usr_n|usr_nusr|usr_pass|usr_pw|usrn|usrnam|usrnm|usrpass|usrs|ustawienie|usuario|usufrutuario|utente|utilisateur|utilisateurs|utilizzatore|uwierzytelnianie|uwierzytelnienia|val|valor2|valor3|valor4|valor5|valorcontabil|variable|vcode|vehicle|venc2|venc3|venc4|venc5|venue|ver_codice|vergi|vergi_no|vergino|verifycode|version|version_min|veteran|ville|villiam|vinod|virtuemart|vm_category|vm_manufacturer|vm_manufacturer_category|vm_payment_method|von|vorgaenger|vorlnr|vot_proposta_e|vot_utente_e|vote|waktu|walnut|warez|wdatarow|wdate|weblinks|website|whabfragen|what|whatsdom|white|who|width|wind|word|word_text|wp_users|wuser|xadverso|xadvogado|xar_pass|xcadastro|xcategoria|xclasse|xcliente|xcubo|xcustom1|xcustom2|xcustom3|xcustom4|xdecisao|xencerramento|xequipe|xequipe_padrao|xevento|xfase|xfase_de_vencimento|xforo|xgarantia|xgrupo|xjurisdicao|xlancamento|xmetodo_atualizacao|xmlrpc|xnatureza|xobjeto|xprocedimento|xprocesso|xprocesso_apensado|xprognostico|xproprietario|xrelatorio|xserie|xsituacao|xstandard|xtipo_de_acao|xusuario|yahoo|yas|yeartag|yetki|yhm|yhmm|yil|yonghu|yoologin|you|zaloguj|zenzaro|zip|zugang|zytk)";
			string patDirTrav =
				@"([^pro].*file|fn\b|controller|location|action|locale|path|display|load|read|retrieve|folder|style|doc|document|root|pdf|bpg|dpgn|pg\b|pgdb|pgport|pgsql|pgsqlcon|pgtId|pgtIou|pguser|startpga|stoppga|include|list|view|img\b|img_filename|imgpath|imgtype|imgurl|image)";
			string patSsrf =
				@"(type\b|rl\b|reverse|to\b|out\b|go=|goback|godashboard|godb|gomkf|goto|back|forward|previous|target|open|destination|link|ref\b|referer|referrer|dest|redir|uri|path|src|href|continue|url|window\b|next|data|reference|site|html|val\b|validate|domain|callback|return|page|feed|host|[^re|im|trans].*port\b|dxportscan|port1|portalauth|portbc|portbl|portbw|portscanner|radiusport2|radiusport3|radiusport4|seo_characteristic_catalog_apor|sqlport1|sqlport2|sqlport3|sqlport4|sqlportb1|sqlportb2|sqlportb3|sqlportb4|upports)";
			string patComInj =
				@"(daemon|cmd|tool|upload|dir\b|execute|download|cli\b|clear_log|clearlog|clearlogs|logentries|hotlog|inbindlog|inviewlogs|log\b|logall|logdefaultblock|logeraser|logf|logfile|logid|loglevel|loglighttpd|logpeer|logprivatenets|logs|logsys|logtype|nolog|resetlog|resetlogs|savelogs|spamlog|speciallogfile|spylog|sqlog|belog|verboselog|viewupgradelog|weblog|bingreverseip_onlytarget|bingreverseippostsettings|ip_add|ip_id|ipaddr|ipandport|ipexclude|iplist|iplogged|ipproto|iprestricted|ips|ipscanner|ipsecpsk|ipv4|ipv6|ipv6allow|msg_ip_address|radiusip|radiusissueips|smtpipaddress|ip\b)"; //ip, cli, log слишком много совпадений может быть
			string patIdor =
				@"(follow|show|navigation|state|user|account|number|order|no\b|doc|key|email|group|profile|edit|id_base|idname|idselect|idsite|idstring|idtype|id\b)"; //no много лишнего
			string patSsti =
				@"(template|content|preview|redir|id_base|idname|idselect|idsite|idstring|idtype|id\b|view|activity|name)";
			string patLogDeb =
				@"(access|fn\b|password|register|signin|server|login|passwd|require|func|admin|dbg\b|debug|edit|grant|test|alter|clone|create|delete|disable|enable|execute|exec|load|make|modify|rename|reset|shell|toggle|adm|root|cfg|config)"; //test, fn, dbg, edit
																																																											//test, fn, dbg, edit
																																																											//string patXss = "";
																																																											//string patOpenRed = "";
																																																										//var patRCE = "";

			//var  = "";
            //в cookies нужно до ; парсить, т.к. там практически всегда url будет
			string patUrl =
                @"^(?:(?:(?:https?|ftp|file|gopher|sftp|dict|ldap|tftp|shttp):)?\/\/)(?:\S+(?::\S*)?@)?(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))|(?:(?:[a-z0-9\u00a1-\uffff][a-z0-9\u00a1-\uffff_-]{0,62})?[a-z0-9\u00a1-\uffff]\.)+(?:[a-z\u00a1-\uffff]{2,}\.?))(?::\d{2,5})?(?:[/?#]\S*)?$|(?:\b[a-z\d.-]+://[^""<>\s]+|\b(?:(?:(?:[^\s!\\@#$%^&*()_=+[\]{}\|:'"",.<>/?]+)\.)+(?:ac|ad|aero|ae|af|ag|ai|al|am|an|ao|aq|arpa|ar|asia|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|biz|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|cat|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|coop|com|com.mx|co|cr|cu|cv|cx|cy|cz|de|dj|dk|dm|do|dz|ec|edu|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gov|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|info|int|in|io|iq|ir|is|it|je|jm|jobs|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mil|mk|ml|mm|mn|mobi|mo|mp|mq|mr|ms|mt|museum|mu|mv|mw|mx|my|mz|name|na|nc|net|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|org|pa|pe|pf|pg|ph|pk|pl|pm|pn|pro|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tel|tf|tg|th|tj|tk|tl|tm|tn|to|tp|travel|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|xn--0zwm56d|xn--11b5bs3a9aj6g|xn--80akhbyknj4f|xn--9t4b11yi5a|xn--deba0ad|xn--g6w251d|xn--hgbk6aj7f53bba|xn--hlcj6aya9esc7a|xn--jxalpdlp|xn--kgbechtv|xn--zckzah|ye|yt|yu|za|zm|zw)|(?:(?:[0-9]|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5])\.){3}(?:[0-9]|[1-9]\d|1\d{2}|2[0-4]\d|25[0-5]))(?:[?#/][^;'\\""#?<>\s]*)?(?:\?[^#<>\s]*)?(?:#[^<>\s]*)?(?!\w))|(?:""|')(((?:[a-zA-Z]{1,10}://|//)[^""'/]{1,}\.[a-zA-Z]{2,}[^""']{0,})|((?:/|\.\./|\./)[^""'><,;| *()(%%$^/\\\[\]][^""'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/|[a-zA-Z0-9_\-/][a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|/][^""|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\?[^""|']{0,}|)))(?:""|')";
			string patIp = @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}";
            //those who don't know if you find endpoints with .action, .do , .go that means the web application running struts2.
            //.cfm -adobe coldfusion
            string patExtensions =
                @"(\.action|\.ad|\.adprototype|\.apk|\.app|\.application|\.asax|\.ascx|\.ashx|\.asmx|\.asp|\.aspq|\.aspx|\.axd|\.bat|\.bin|\.browser|\.cd|\.cfm|\.cgi|\.cmd|\.com|\.command|\.config|\.cpl|\.cs|\.csh|\.cshtm|\.cshtml|\.csproj|\.dd|\.dll.config|\.do|\.doc|\.docm|\.dotm|\.exclude|\.exe|\.exe.config|\.gadget|\.go|\.hta|\.html|\.inf|\.inf1|\.ini|\.ins|\.inx|\.ipa|\.isu|\.jar|\.java|\.job|\.js|\.jse|\.jsl|\.json|\.jsp|\.ksh|\.ldb|\.ldd|\.lddprototype|\.ldf|\.licx|\.lnk|\.master|\.md|\.mdb|\.mdf|\.mkd|\.msc|\.msh|\.msh1|\.msh1xml|\.msh2|\.msh2xml|\.mshxml|\.msi|\.msp|\.mst|\.osx|\.out|\.paf|\.php|\.phtml|\.pif|\.pl|\.potm|\.ppam|\.ppsm|\.ppt|\.pptm|\.prg|\.ps1|\.ps1xml|\.ps2|\.ps2xml|\.psc1|\.psc2|\.py|\.rb|\.refresh|\.reg|\.rem|\.resources|\.resx|\.rgs|\.rules|\.run|\.scf|\.scr|\.sct|\.sd|\.sdm|\.sdmDocument|\.sh|\.shb|\.shs|\.sitemap|\.skin|\.sldm|\.soap|\.svc|\.toml|\.txt|\.u3p|\.vb|\.vbe|\.vbhtm|\.vbhtml|\.vbproj|\.vbs|\.vbscript|\.vjsproj|\.wadl|\.webinfo|\.workflow|\.ws|\.wsc|\.wsdl|\.wsf|\.wsh|\.xamlx|\.xlam|\.xls|\.xlsm|\.xltm|\.xml|\.xoml|\.xrd|\.yaml|\.yml)";

			string patBase64 = @"[^A-Za-z0-9+/](eyj|YTo|Tzo|PD[89])[%a-zA-Z0-9+/]+={0,2}";
			string patDebugPages = @"(Application-Trace|Routing Error|DEBUG = True|Caused by:)";
			string patSqlErrors =
                @"(SQL syntax.*?MySQL|Warning.*?\Wmysqli?_|MySQLSyntaxErrorException|valid MySQL result|check the manual that corresponds to your (MySQL|MariaDB) server version|Unknown column '[^ ]+' in 'field list'|MySqlClient\.|com\.mysql\.jdbc|Zend_Db_(Adapter|Statement)_Mysqli_Exception|Pdo[./_\\]Mysql|MySqlException|PostgreSQL.*?ERROR|Warning.*?\Wpg_|valid PostgreSQL result|Npgsql\.|PG::SyntaxError:|org\.postgresql\.util\.PSQLException|ERROR:\s\ssyntax error at or near|ERROR: parser: parse error at or near|PostgreSQL query failed|org\.postgresql\.jdbc|Pdo[./_\\]Pgsql|PSQLException|Driver.*? SQL[\-_\ ]*Server|OLE DB.*? SQL Server|\bSQL Server[^&lt;&quot;]+Driver|Warning.*?\W(mssql|sqlsrv)_|\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}|System\.Data\.SqlClient\.SqlException|(?s)Exception.*?\bRoadhouse\.Cms\.|Microsoft SQL Native Client error '[0-9a-fA-F]{8}|\[SQL Server\]|ODBC SQL Server Driver|ODBC Driver \d+ for SQL Server|SQLServer JDBC Driver|com\.jnetdirect\.jsql|macromedia\.jdbc\.sqlserver|Zend_Db_(Adapter|Statement)_Sqlsrv_Exception|com\.microsoft\.sqlserver\.jdbc|Pdo[./_\\](Mssql|SqlSrv)|SQL(Srv|Server)Exception|Microsoft Access (\d+ )?Driver|JET Database Engine|Access Database Engine|ODBC Microsoft Access|Syntax error \(missing operator\) in query expression|\bORA-\d{5}|Oracle error|Oracle.*?Driver|Warning.*?\W(oci|ora)_|quoted string not properly terminated|SQL command not properly ended|macromedia\.jdbc\.oracle|oracle\.jdbc|Zend_Db_(Adapter|Statement)_Oracle_Exception|Pdo[./_\\](Oracle|OCI)|OracleException|CLI Driver.*?DB2|DB2 SQL error|\bdb2_\w+\(|SQLSTATE.+SQLCODE|com\.ibm\.db2\.jcc|Zend_Db_(Adapter|Statement)_Db2_Exception|Pdo[./_\\]Ibm|DB2Exception|Warning.*?\Wifx_|Exception.*?Informix|Informix ODBC Driver|ODBC Informix driver|com\.informix\.jdbc|weblogic\.jdbc\.informix|Pdo[./_\\]Informix|IfxException|Dynamic SQL Error|Warning.*?\Wibase_|org\.firebirdsql\.jdbc|Pdo[./_\\]Firebird|SQLite/JDBCDriver|SQLite\.Exception|(Microsoft|System)\.Data\.SQLite\.SQLiteException|Warning.*?\W(sqlite_|SQLite3::)|\[SQLITE_ERROR\]|SQLite error \d+:|sqlite3.OperationalError:|SQLite3::SQLException|org\.sqlite\.JDBC|Pdo[./_\\]Sqlite|SQLiteException|SQL error.*?POS([0-9]+)|Warning.*?\Wmaxdb_|DriverSapDB|com\.sap\.dbtech\.jdbc|Warning.*?\Wsybase_|Sybase message|Sybase.*?Server message|SybSQLException|Sybase\.Data\.AseClient|com\.sybase\.jdbc|Warning.*?\Wingres_|Ingres SQLSTATE|Ingres\W.*?Driver|com\.ingres\.gcf\.jdbc|Exception (condition )?\d+\. Transaction rollback|com\.frontbase\.jdbc|Unexpected end of command in statement \[|Unexpected token.*?in statement \[|org\.hsqldb\.jdbc|org\.h2\.jdbc)";
            string patSecAws =
				@"(ListBucketResult|RSA PRIVATE|Index of|aws-|aws_)";
			string patPhpError =
				@"(php warning|php error|fatal error|uncaught exception|include_path|undefined index|undefined variable)";
			//https://stackoverflow.com/questions/3115559/exploitable-php-functions
			string patPhpSink = @"[^a-z0-9_](system|exec|echo|print|popen|pcntl_exec|eval|create_function|passthru|shell_exec|proc_open|assert|preg_replace|include|include_once|require|require_once)";//patPhpSink
			string patPhpCallback = @"[^a-z0-9_](ob_start|array_diff_uassoc|array_diff_ukey|array_filter|array_intersect_uassoc|array_intersect_ukey|array_map|array_reduce|array_udiff_assoc|array_udiff_uassoc|array_udiff|array_uintersect_assoc|array_uintersect_uassoc|array_uintersect|array_walk_recursive|array_walk|assert_options|uasort|uksort|usort|preg_replace_callback|spl_autoload_register|iterator_apply|call_user_func|call_user_func_array|register_shutdown_function|register_tick_function|set_error_handler|set_exception_handler|session_set_save_handler|sqlite_create_aggregate|sqlite_create_function)";
			string patPhpInformDisclosure = @"[^a-z0-9_](phpinfo|posix_mkfifo|posix_getlogin|posix_ttyname|getenv|get_current_user|proc_get_status|get_cfg_var|disk_free_space|disk_total_space|diskfreespace|getcwd|getlastmo|getmygid|getmyinode|getmypid|getmyuid)";
			string patPhpOther = @"[^a-z0-9_-](extract|parse_str|putenv|ini_set|mail|header|proc_nice|proc_terminate|proc_close|pfsockopen|fsockopen|apache_child_terminate|posix_kill|posix_mkfifo|posix_setpgid|posix_setsid|posix_setuid)";

			//https://stackoverflow.com/questions/4339611/exploitable-java-functions


			string patSession = @"(server|debug|admin|session)";
			string patApi = @"(v1\/|v2\/|v3\/|v4\/|v5\/|api|cgi|graphql)";
			string patInteger = @"(?<=\s|^)\d+(?=\s|$)";//\b[0-9][0-9,\.:;]+\b - но много 1.0 вариантов. (?<=\s|^)\d+(?=\s|$) . \b[0-9]{2,}\b - много с .
            string parOther = @"(ajax|jsonp|include|src\/|redirect|proxy)";
            string patInterest = @"(kafka_cluser_id)";
            //kafka_cluser_id - /connectors/{name}

            //Keys
            string keyAWSApi = @"([^A-Z0-9]|^)(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{12,}";
			string keyAWSAccess = @"AKIA[0-9A-Z]{16}";
			string keyFacebookAccessToken = @"EAACEdEose0cBA[0-9A-Za-z]+";
			string keyFacebookOAuth = @"[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\""][0-9a-f]{32}['|\""]";
			//string keyFacebookClientID = @"[0-9]{13,17}"; слишком много совпадений 
			string keyFacebookSecretKey = @"[0-9a-f]{32}";
			string keyGenericAPIKey = @"[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\""][0-9a-zA-Z]{12,45}['|\""]";
			string keyGenericSecret = @"[s|S][e|E][c|C][r|R][e|E][t|T].*['|\""][0-9a-zA-Z]{12,45}['|\""]";
			string keyGitHub = @"[g|G][i|I][t|T][h|H][u|U][b|B].*['|\""][0-9a-zA-Z]{35,40}['|\""]";
			string keyGoogleServiceAccount = @"\""type\"": \""service_account\""";
			string keyGoogleAPIKey = @"AIza[0-9A-Za-z\\-_]{35}";
			string keyGoogleCloudPlatformOAuth = @"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com";
			string keyGoogleDriveOAuth = @"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com";
			string keyGoogleOAuthAccessToken = @"ya29\\.[0-9A-Za-z\\-_]+";
			string keyGoogleOauth = @"(\""client_secret\"":\""[a-zA-Z0-9-_]{24}\"")";
			string keyHerokuAPIKey =
				@"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}";
			string keyMailChimpAPIKey = @"[0-9a-f]{32}-us[0-9]{1,2}";
			string keyMailgunAPIKey = @"key-[0-9a-zA-Z]{32}";
			string keyPGPkeyblock = @"-----BEGIN PGP PRIVATE KEY BLOCK-----";
			string keyPayPalBraintreeAccessToken = @"access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}";
			string keyPicaticAPIKey = @"sk_live_[0-9a-z]{32}";
			string keyRSAprivatekey = @"-----BEGIN RSA PRIVATE KEY-----";
			string keySSHprivatekey = @"-----BEGIN DSA PRIVATE KEY-----";
			string keySSHECkey = @"-----BEGIN EC PRIVATE KEY-----";
			string keyOPENSSHprivatekey = @"-----BEGIN OPENSSH PRIVATE KEY-----";
			string keySlackToken = @"(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})";
			string keySlackWebhook =
				@"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}";
			string keySquareOAuthAccess = @"sq0atp-[0-9A-Za-z\\-_]{22}|sq0csp-[0-9A-Za-z\\-_]{43}";
			string keyStripeAPIKey = @"sk_live_[0-9a-zA-Z]{24}";
			string keyStripeRestrictedAPIKey = @"rk_live_[0-9a-zA-Z]{24}";
			string keyTwilioAPIKey = @"SK[0-9a-fA-F]{32}|SK[a-z0-9]{32}";
			string keyTwitterAccessToken = @"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}";
			string keyTwitterOAuth = @"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\""][0-9a-zA-Z]{35,44}['|\""]";
            //string keyLinkedInClientID = @"[0-9a-z]{12}";
            //string keyLinkedInSecretKey = @"\b[0-9a-zA-Z]{16}\b";
            //string keyTwitterClientID = @"\b[0-9a-zA-Z]{18,25}\b";
            //string keyTwitterSecretKey = @"\b[0-9a-zA-Z]{35,44}\b";


            string keysTokens = @"\b(accept|acceso|access|account|aceso|admin|administartor|agfa|alarm|algolia|alias|anaconda|analytics|android|ansible|aos|api|apigw|app|argos|artifact|artifactory|artifacts|aurora|auth|auth0|author|aws|b2|bintray|bluemix|branch|browser|bulk|bundle|bucket|bx|bxiam|cacdc|cache|cargo|casc|casperjs|cdascsa|cdscasc|censys|cert|certificate|channelid|cheverny|chrome|chrome_refresh|ci|ci_user|claimr|cli|cli_e2e|client|clojars|cloud|clu|cocoapods|codacy|codeclimate|codesign|coding|com|component|configuration|consumer|contentful|conversation|core|cos|coveralls|coverity|cred|csac|danger|database|db|dbp|ddg|ddgc|deploy|dest|dh|digitalocean|docker|driver|dropbox|droplet|duration|e2e|encrypt|end|env|export|extension|fbtools|feedback|fi1|fi2|file|firebase|firefox|flickr|foo|ftp|fvdvd|gateway|gcloud|gcr|gh|ghb|git|github|gk|gpg|gradle|grgit|hab|handle|hb|heroku|host|hpmifls|hub|id|ij|image|index|integration|irc|isbooleangood|isdevelop|isparentallowed|iss|issuer|java|kafka|kube|leanplum|lektor|licenses|linode|ll|location|logname|logout|looker|magento|mailchimp|mailgun|manage|management|manifest|mapbox|marathon|marionette|maven|mesos|mongolab|multi|mysql|nativeevents|netlify|new_relic|nexus|nexuspassword|nexusurl|nexususername|ngrok|node|non|now|npm|nuget|numbers|nunit|oauth|object|oc|octest|ofta|okta|omise|org|organization|os|ossrh|packagecloud|pantheon|parse|parse_js|partner|pass|password|passwordtravis|pat|path|paypal|percy|personal|php|places|plotly|plugin|poll|port|prebuild|preferred|priv|private|prod|project|props.disabled|pub|publish|pushover|pypi|qiita|qq|query|quip|record|redirect|refresh|registry|repo|repotoken|ri|rnd|rotatable|rtd|rubygems|runscope|s3|salesforce|sandbox|sauce|scope|scrutinizer|sdm4|sdr-token|search|secret|security|selion|sendgrid|sentry|session|shared|signing|slack|slash|slate|snoowrap|snyk|socrata|some|somevar|sona|sonar|sonatype|spa|space|spotify|square|srcclr|ssh|sshpass|ssmtp|staging|star|subdomain|surge|svn|team|ted|test|testadmin|tester|testurl|thera|travis|trex|trigger|trunk|trv|twilio|twine|twitter|uielement|uk|unity|url|usabilla|use|user|username|usertosharetravis|usertravis|vault|vip|vscetoken|wakatime|watson|web|webhook|whisk|widget|wincert|workspace|wporg|wpt|xsax|y8|yangshun|zendesk|zensonatype|zhuliang).*?(account|access|alias|bucket|channel|client|config|connection|cron|database|dir|directory|email|endpoint|env|gnutls|hash|host|hub|id|issuer|iv|key|logname|oauth|orgurl|pass|passphrase|password|project|pwd|repo|runscope|secret|seed|server|snapshot|testdomain|token|travis|uri|url|username|workspace)\b";
			//1. Поиск json и xml запросов multipart
			if (Regex.IsMatch(conType, @"(json|xml|multipart)"))
			{
				list.Add("Reason:json/xml" + "|ContentType:" + conType + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}
			if (Regex.IsMatch(conType, @"(application.*javascript)"))//jsonp callback потестировать https://stackoverflow.com/questions/477816/what-is-the-correct-json-content-type
			{
				list.Add("Reason:application/javascript" + "|ContentType:" + conType + "|Url:" + trUrl +
				         "|RequestCounter:" + Counter1 + "|File:" +
				          fileName + "_traffic.txt" +
				         "|Profile:" + getProfileName);
			}

			//2. Методы не GET 
			if (Regex.IsMatch(meth, @"^((?!GET).)*$"))
			{
				list.Add("Reason:method" + "|ReqMethod:" + meth + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			//3. Ответ сервера не 200, 404
			if (Regex.IsMatch(resCode, @"(?!404)(3|4|5)[0-9]{2}"))
			{
				list.Add("Reason:code" + "|ResponseCode:" + resCode + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			//4. Aнализ url (path + query & parameters)

			//Uri req = new Uri(trUrl);
			//string linkHost = req.Scheme + "://" + req.Authority + "/";
			string linkQuery =
				System.Text.RegularExpressions.Regex.Match(trUrl, @"(?<=&|\?|;).*?(?=#|$)")
					.Value; //Trim( new Char[] { '?', '&', ';' } ); (?<=&|\?|;).*?(?=#|$) - от &|?|; и до конца строки или #
			string pathLink = System.Text.RegularExpressions.Regex.Match(trUrl, @"(?<!/)/(?!/).*?([^?;&#]+)").Value
				.Trim('/');

            int querySplitCount = linkQuery.Split(new Char[] { '&', ';' }).Count(); //считаем количество path частей
            string[] linkQuery0 = linkQuery.Split(new Char[] { '&', ';' });
		
            //4.1 query 
			if (Regex.IsMatch(linkQuery, @"(\{|\[|\/|\\\\|<|\(|eyj)"))
				list.Add("Reason:specCharsInQuery" + "|Query:" + linkQuery + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			if (Regex.IsMatch(linkQuery, @"(\.html|\.htm|\.jpg|\.jpeg|\.png|\.gif|\.svg)"))
				list.Add("Reason:FileInQuery" + "|Query:" + linkQuery + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);


            //4.2 параметры + значения
            if (!string.IsNullOrEmpty(linkQuery))
            {

                //что сделать
                // 1) кодировки разные для полных слов из файла E:\Ptest\Testing\Attacks\Programs\valve\ContentDiscovery\ParameterDiscovery\parameters.txt НО patBase64 не получится конвертить, т.к. разные значения
                // 2) данные/параметры из E:\Ptest\Testing\ExploitDB\ по разным уязвимостям
                //часть данных для sql из https://github.com/sqlmapproject/sqlmap/blob/ef7d4bb404b9bfe9b799a1491626cc7aab3fec91/data/txt/common-columns.txt

                StringBuilder strBuild = new StringBuilder();
                for (int i = 0; i < querySplitCount; i++)
                {
                    string pv1 = linkQuery0.ElementAtOrDefault(i);
                    string queryParam = pv1.Split('=').ElementAtOrDefault(0); //берем параметр
                    strBuild.Append(queryParam + ", ");//записывем все параметры
                    string queryParamValue = pv1.Split(new[] { '=' }, 2).ElementAtOrDefault(1); //берем значение параметра


                    string queryParamValueDecoded =
                        System.Net.WebUtility.UrlDecode(queryParamValue); //кодируем значение параметра

                    if (!string.IsNullOrEmpty(queryParamValueDecoded))
                    {
                        int value;
                        if (int.TryParse(queryParamValueDecoded, out value))
                        {
                            list.Add("Reason:IntegerInQueryValue" + "|queryParam:" + queryParam + "|queryParamValue:" +
                                     queryParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                      fileName +
                                     "_traffic.txt" + "|Profile:" + getProfileName);
                        }


                        if (Regex.IsMatch(queryParamValueDecoded, patUrl)) //url in query value -> SSRF
                            list.Add("Reason:UrlInQueryValue" + "|queryParam:" + queryParam + "|queryParamValue:" +
                                     queryParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);

                        if (Regex.IsMatch(queryParamValueDecoded, patExtensions)) //Extension in query value -> SSRF
                            list.Add("Reason:ExtensionInQueryValue" + "|queryParam:" + queryParam + "|queryParamValue:" +
                                     queryParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);

                        if (Regex.IsMatch(queryParamValueDecoded, patIp)) //Ip
                            list.Add("Reason:IpInQueryValue" + "|queryParam:" + queryParam + "|queryParamValue:" +
                                     queryParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);
                        if (Regex.IsMatch(queryParamValueDecoded, keysTokens)) //keysTokens
                            list.Add("Reason:KeysTokensInQueryValue" + "|queryParam:" + queryParam + "|queryParamValue:" +
                                     queryParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);

                        if (Regex.IsMatch(queryParamValueDecoded, patBase64)) //Base64
                        {
                            var base64EncodedBytes = System.Convert.FromBase64String(queryParamValueDecoded);
                            string queryParamValueDecodedb64 = System.Text.Encoding.UTF8.GetString(base64EncodedBytes);

                            list.Add("Reason:Base64InQueryValue" + "|QueryValue:" + queryParamValueDecodedb64 + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        }

                        if (Regex.IsMatch(queryParam, patSql)) //sql parameters
                            list.Add("Reason:SqlParameter" + "|queryParam:" + queryParam + "|queryParamValue:" +
                                     queryParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);

                        if (Regex.IsMatch(queryParam, patDirTrav)) //file includes/dir traversal
                            list.Add("Reason:DirTraversalParameter" + "|queryParam:" + queryParam + "|queryParamValue:" +
                                     queryParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);

                        if (Regex.IsMatch(queryParam, patSsrf)) //ssrf
                            list.Add("Reason:SsrfParameter" + "|queryParam:" + queryParam + "|queryParamValue:" +
                                     queryParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);

                        if (Regex.IsMatch(queryParam, patComInj)) //Command Injection
                            list.Add("Reason:CommandInjParameter" + "|queryParam:" + queryParam + "|queryParamValue:" +
                                     queryParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);

                        if (Regex.IsMatch(queryParam, patIdor)) //IDOR
                            list.Add("Reason:IDORParameter" + "|queryParam:" + queryParam + "|queryParamValue:" +
                                     queryParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);

                        if (Regex.IsMatch(queryParam, patSsti)) //SSTI
                            list.Add("Reason:SSTIParameter" + "|queryParam:" + queryParam + "|queryParamValue:" +
                                     queryParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);

                        if (Regex.IsMatch(queryParam, patLogDeb)) //Logic/Debug
                            list.Add("Reason:LogicDebParameter" + "|queryParam:" + queryParam + "|queryParamValue:" +
                                     queryParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                      fileName + "_traffic.txt" + "|Profile:" + getProfileName);
                    
                    }
                }
                string parameters = strBuild.ToString();
                list.Add("Reason:UrlParameters" + "|Parameters:" + parameters + "|Url:" +
                                 trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                 fileName + "_traffic.txt" + "|Profile:" + getProfileName);
            }

			//}

			//4.3 path

			//if (Uri.IsWellFormedUriString(trUrl, UriKind.Absolute))
			//{
			//Uri req1 = new Uri(trUrl);
			//string pathTrUrl = req1.AbsolutePath.Trim('/');
			//linkToVisitHost = req1.Scheme + "://" + req1.Authority + "/";
			//linkToVisitQuery = req1.Query;
			//string patExtensions = @"(\.php|\.phtml|\.asp|\.aspx|\.cgi|\.pl|\.json|\.xml|\.rb|\.py|\.sh|\.yaml|\.yml|\.toml|\.ini|\.md|\.mkd|\.do|\.jsp)";
			if (!string.IsNullOrEmpty(pathLink))
			{
				if (Regex.IsMatch(pathLink, patExtensions))
				{
					list.Add("Reason:ExtensionInUrlPath" + "|Path:" + pathLink + "|Url:" +
							 trUrl + "|RequestCounter:" +
							 Counter1 + "|File:" + 
							 fileName + "_traffic.txt" + "|Profile:" +
							 getProfileName);
				}

				if (Regex.IsMatch(pathLink, patInteger))
				{
					list.Add("Reason:IntegerInUrlPath" + "|Path:" + pathLink + "|Url:" +
							 trUrl + "|RequestCounter:" +
							 Counter1 + "|File:" + 
							 fileName + "_traffic.txt" + "|Profile:" +
							 getProfileName);
				}

				if (Regex.IsMatch(pathLink, patLogDeb))
				{
					list.Add("Reason:SensitiveDataInUrlPath" + "|Path:" + pathLink + "|Url:" +
							 trUrl + "|RequestCounter:" +
							 Counter1 + "|File:" + 
							 fileName + "_traffic.txt" + "|Profile:" +
							 getProfileName);
				}

				if (Regex.IsMatch(pathLink, patApi))
				{
					list.Add("Reason:ApiInUrlPath" + "|Path:" + pathLink + "|Url:" + trUrl +
							 "|RequestCounter:" + Counter1 + "|File:" +
							  fileName +
							 "_traffic.txt" + "|Profile:" + getProfileName);
				}

				if (Regex.IsMatch(pathLink, parOther))
				{
					list.Add("Reason:OtherInUrlPath" + "|Path:" + pathLink + "|Url:" +
							 trUrl + "|RequestCounter:" +
							 Counter1 + "|File:" + 
							 fileName + "_traffic.txt" + "|Profile:" +
							 getProfileName);
				}
			}


			//4.4 поиск query values в responseBody и respHeaders (если в куках query value, то crlf тестировать нужно) (мин 4 символа, urlDecoded нужно сравнивать)
			//если header в респонсе, то xss можно в stored превратить с помощью cache-poisoning (https://medium.com/@nahoragg/chaining-cache-poisoning-to-stored-xss-b910076bda4f)
			//+ ResponseSplitting http://projects.webappsec.org/w/page/13246931/HTTP%20Response%20Splitting
			if (!string.IsNullOrEmpty(linkQuery))
			{
				for (int i = 0; i < querySplitCount; i++)
				{
					string pv1 = linkQuery0.ElementAtOrDefault(i);
					string queryParamValueLink1 = pv1.Split(new[] { '=' }, 2).ElementAtOrDefault(1);
                    if (!string.IsNullOrEmpty(queryParamValueLink1))
                    {

                        int queryParamValueLink1Len = queryParamValueLink1.Length;
                        string queryParamValueLink1Dec = System.Net.WebUtility.UrlDecode(queryParamValueLink1);
                        if (queryParamValueLink1Len >= 4 && Regex.IsMatch(respBody, @queryParamValueLink1Dec))
                            list.Add("Reason:QueryValueInRespBody" + "|Value:" + queryParamValueLink1Dec + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                      fileName +
                                     "_traffic.txt" + "|Profile:" + getProfileName);
                        if (queryParamValueLink1Len >= 4 && Regex.IsMatch(respHeaders, @queryParamValueLink1Dec))
                            list.Add("Reason:QueryValueInRespHeaders" + "|Value:" + queryParamValueLink1Dec + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                      fileName +
                                     "_traffic.txt" + "|Profile:" + getProfileName);
                    }
				}
			}




            //5. Анализ reqBody
            // для коротких слов (ip, id, fn) как-то нужно количество символов до и после считать, т.к. в patBase64 - очень много может найтись
            //Нужно разбить на парам=значение + json (нужна регулярка)
            if (!string.IsNullOrEmpty(reqBody))
            {
                int reqBodySplitCount = reqBody.Split(new Char[] { '&', ';' }).Count();
				string[] reqBodySplit = reqBody.Split(new Char[] { '&', ';' });
				if (reqBodySplitCount == 0)
				{
					//разбиваем json
					reqBodySplitCount = reqBody.Split(new Char[] { ',' }).Count();
					reqBodySplit = reqBody.Split(new Char[] { ',' });
				}
                StringBuilder strBld = new StringBuilder();//собираем названия параметров   
                for (int i = 0; i < reqBodySplitCount; i++)
				{
					string pv1 = reqBodySplit.ElementAtOrDefault(i);
					string reqParam = pv1.Split('=').ElementAtOrDefault(0); //берем параметр
					string reqParamValue = pv1.Split(new[] { '=' }, 2).ElementAtOrDefault(1); //берем значение параметра

                    strBld.Append(reqParam + ", ");//записывем все параметры
                                                         //если json
                    if (reqParam == "")
					{
						pv1 = System.Text.RegularExpressions.Regex.Replace(pv1, @"""", "");
						reqParam = pv1.Split(':').ElementAtOrDefault(0); //берем параметр
						reqParamValue = pv1.Split(new[] { ':' }, 2).ElementAtOrDefault(1); //берем значение параметра
					}

					string reqParamValueDecoded = System.Net.WebUtility.UrlDecode(reqParamValue);
                    //Значения параметров
                    if (!string.IsNullOrEmpty(reqParamValueDecoded))
                    {
                        if (Regex.IsMatch(reqParamValueDecoded, patExtensions)) //Extensions
                            list.Add("Reason:ExtensionInReqBodyValue" + "|reqBodyParam:" + reqParam +
                                     "|reqBodyParamValue:" + reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (Regex.IsMatch(reqParamValueDecoded, patInteger)) //Integer
                            list.Add("Reason:IntegerInReqBodyValue" + "|reqBodyParam:" + reqParam + "|reqBodyParamValue:" +
                                     reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (Regex.IsMatch(reqParamValueDecoded, patUrl)) //Url
                            list.Add("Reason:UrlInReqBodyValue" + "|reqBodyParam:" + reqParam + "|reqBodyParamValue:" +
                                     reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (Regex.IsMatch(reqParamValueDecoded, patIp)) //Ip
                            list.Add("Reason:IpInReqBodyValue" + "|reqBodyParam:" + reqParam + "|reqBodyParamValue:" +
                                     reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);
                        if (Regex.IsMatch(reqParamValueDecoded, keysTokens)) //keysTokens
                            list.Add("Reason:KeysTokensInReqBodyValue" + "|reqBodyParam:" + reqParam + "|reqBodyParamValue:" +
                                     reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);
                        if (Regex.IsMatch(reqParamValueDecoded, patBase64)) //Base64
                        {
                            var base64EncodedBytes = System.Convert.FromBase64String(reqParamValueDecoded);
                            string reqParamValueDecodedb64 = System.Text.Encoding.UTF8.GetString(base64EncodedBytes);

                            list.Add("Reason:Base64InReqBodyValue" + "|reqBodyValue:" + reqParamValueDecodedb64 + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        }

                        //Имена параметров
                        if (Regex.IsMatch(reqParam, patSql)) //sql 
                            list.Add("Reason:SqlInReqBody" + "|reqBodyParam:" + reqParam + "|reqBodyParamValue:" +
                                     reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (Regex.IsMatch(reqParam, patDirTrav)) //file includes/dir traversal
                            list.Add("Reason:DirTraversalInReqBody" + "|reqBodyParam:" + reqParam + "|reqBodyParamValue:" +
                                     reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (Regex.IsMatch(reqParam, patSsrf)) //ssrf
                            list.Add("Reason:SsrfInReqBody" + "|reqBodyParam:" + reqParam + "|reqBodyParamValue:" +
                                     reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (Regex.IsMatch(reqParam, patComInj)) //Command Injection
                            list.Add("Reason:CommandInjInReqBody" + "|reqBodyParam:" + reqParam + "|reqBodyParamValue:" +
                                     reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (Regex.IsMatch(reqParam, patIdor)) //IDOR
                            list.Add("Reason:IDORInReqBody" + "|reqBodyParam:" + reqParam + "|reqBodyParamValue:" +
                                     reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (Regex.IsMatch(reqParam, patSsti)) //SSTI
                            list.Add("Reason:SSTIInReqBody" + "|reqBodyParam:" + reqParam + "|reqBodyParamValue:" +
                                     reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (Regex.IsMatch(reqParam, patLogDeb)) //Logic/Debug
                            list.Add("Reason:LogicDebInReqBody" + "|reqBodyParam:" + reqParam + "|reqBodyParamValue:" +
                                     reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);


                    }

                    string paramsReqBody = strBld.ToString();
                    list.Add("Reason:RequestBodyParameters" + "|Parameters:" + paramsReqBody + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);

                }
			}


			//6. Анализ respBody

			if (Regex.IsMatch(respBody, patIp)) //Ips
			{
				MatchCollection mList = Regex.Matches(respBody, patIp);
				string allMatches = string.Join(",", from Match match in mList select match.Value);
				list.Add("Reason:IpInRespBodyValue" + "|respBodyValues:" + allMatches + "|Url:" +
						 trUrl + "|RequestCounter:" +
						 Counter1 + "|File:" + 
						 fileName + "_traffic.txt" + "|Profile:" +
						 getProfileName);
			}

			if (Regex.IsMatch(respBody, patPhpSink)) //PhpSink
			{
				MatchCollection mList = Regex.Matches(respBody, patPhpSink);
                mList.OfType<Match>().Select(m => m.Groups[0].Value).Distinct();
                string allMatches = string.Join(",", from Match match in mList select match.Value);
                allMatches = Macros.TextProcessing.Replace(allMatches, "\r\n", ", ", "Regex", "All");
                list.Add("Reason:PhpSinkInRespBodyValue" + "|respBodyValues:" + allMatches + "|Url:" +
						 trUrl + "|RequestCounter:" +
						 Counter1 + "|File:" + 
						 fileName + "_traffic.txt" + "|Profile:" +
						 getProfileName);
			}

			if (Regex.IsMatch(respBody, patPhpCallback)) //PhpCallback
			{
				MatchCollection mList = Regex.Matches(respBody, patPhpCallback);
				string allMatches = string.Join(",", from Match match in mList select match.Value);
				list.Add("Reason:PhpCallbackInRespBodyValue" + "|respBodyValues:" + allMatches + "|Url:" +
				         trUrl + "|RequestCounter:" +
				         Counter1 + "|File:" + 
				         fileName + "_traffic.txt" + "|Profile:" +
				         getProfileName);
			}

			if (Regex.IsMatch(respBody, patPhpInformDisclosure)) //patPhpInformDisclosure
			{
				MatchCollection mList = Regex.Matches(respBody, patPhpInformDisclosure);
				string allMatches = string.Join(",", from Match match in mList select match.Value);
				list.Add("Reason:PhpInformDisclosureInRespBodyValue" + "|respBodyValues:" + allMatches + "|Url:" +
				         trUrl + "|RequestCounter:" +
				         Counter1 + "|File:" + 
				         fileName + "_traffic.txt" + "|Profile:" +
				         getProfileName);
			}

			if (Regex.IsMatch(respBody, patPhpOther)) //patPhpOther
			{
				MatchCollection mList = Regex.Matches(respBody, patPhpOther);
				string allMatches = string.Join(",", from Match match in mList select match.Value);
				list.Add("Reason:PhpOtherInRespBodyValue" + "|respBodyValues:" + allMatches + "|Url:" +
				         trUrl + "|RequestCounter:" +
				         Counter1 + "|File:" + 
				         fileName + "_traffic.txt" + "|Profile:" +
				         getProfileName);
			}

			if (Regex.IsMatch(respBody, patPhpError)) //PhpError
			{
				MatchCollection mList = Regex.Matches(respBody, patPhpError);
				string allMatches = string.Join(",", from Match match in mList select match.Value);
				list.Add("Reason:PhpErrorInRespBodyValue" + "|respBodyValue:" + allMatches + "|Url:" +
						 trUrl + "|RequestCounter:" +
						 Counter1 + "|File:" + 
						 fileName + "_traffic.txt" + "|Profile:" +
						 getProfileName);
			}

			if (Regex.IsMatch(respBody, patSecAws)) //SecAws
			{
				MatchCollection mList = Regex.Matches(respBody, patSecAws);
				string allMatches = string.Join(",", from Match match in mList select match.Value);
				list.Add("Reason:SecAwsInRespBodyValue" + "|respBodyValue:" + allMatches + "|Url:" +
						 trUrl + "|RequestCounter:" +
						 Counter1 + "|File:" + 
						 fileName + "_traffic.txt" + "|Profile:" +
						 getProfileName);
			}

			if (Regex.IsMatch(respBody, patDebugPages)) //DebugPages
			{
				MatchCollection mList = Regex.Matches(respBody, patDebugPages);
				string allMatches = string.Join(",", from Match match in mList select match.Value);
				list.Add("Reason:DebugPagesInRespBodyValue" + "|respBodyValue:" + allMatches + "|Url:" +
						 trUrl + "|RequestCounter:" +
						 Counter1 + "|File:" + 
						 fileName + "_traffic.txt" + "|Profile:" +
						 getProfileName);
			}

			if (Regex.IsMatch(respBody, patSqlErrors)) //SqlErrors
			{
				MatchCollection mList = Regex.Matches(respBody, patSqlErrors);
				string allMatches = string.Join(",", from Match match in mList select match.Value);
				list.Add("Reason:SqlErrorsInRespBodyValue" + "|respBodyValue:" + allMatches + "|Url:" +
						 trUrl + "|RequestCounter:" +
						 Counter1 + "|File:" + 
						 fileName + "_traffic.txt" + "|Profile:" +
						 getProfileName);
			}
            if (Regex.IsMatch(respBody, patInterest)) //patInterest
            {
                MatchCollection mList = Regex.Matches(respBody, patInterest);
                string allMatches = string.Join(",", from Match match in mList select match.Value);
                list.Add("Reason:InterestingPatterns" + "|respBodyValue:" + allMatches + "|Url:" +
                         trUrl + "|RequestCounter:" +
                         Counter1 + "|File:" + 
                         fileName + "_traffic.txt" + "|Profile:" +
                         getProfileName);
            }

            if (Regex.IsMatch(respBody, keysTokens)) //keysTokens
            {
                MatchCollection mList = Regex.Matches(respBody, keysTokens);
                string allMatches = string.Join(",", from Match match in mList select match.Value);
                list.Add("Reason:keysTokens" + "|respBodyValue:" + allMatches + "|Url:" +
                         trUrl + "|RequestCounter:" +
                         Counter1 + "|File:" +
                         fileName + "_traffic.txt" + "|Profile:" +
                         getProfileName);
            }





            //7. Анализ reqCookies
            //проверитьь если base64, то деление на название и значение из-за = . ДА обрезает последний = (new[] { '=' }, 2)
            if (!string.IsNullOrEmpty(reqCookies))
            {

                int reqCookiesSplitCount = reqCookies.Split(new Char[] { ';' }).Count();
                string[] reqCookiesSplit = reqCookies.Split(new Char[] { ';' });
                for (int i = 0; i < reqCookiesSplitCount; i++)
                {
                    string pv1 = reqCookiesSplit.ElementAtOrDefault(i);
                    string reqParam = pv1.Split('=').ElementAtOrDefault(0); //берем параметр
                    string reqParamValue = pv1.Split(new[] { '=' }, 2).ElementAtOrDefault(1); //берем значение параметра
                    //если base64 то bm_sv=am3efedJjMOqvkWwY7Ih1Oa4Q== в конце равно несколько
                    string reqParamValueDecoded = System.Net.WebUtility.UrlDecode(reqParamValue);
                    //Значения параметров
                    if (!string.IsNullOrEmpty(reqParamValueDecoded))
                    {
                        if (Regex.IsMatch(reqParamValueDecoded, patExtensions)) //Extensions
                            list.Add("Reason:ExtensionInReqCookiesValue" + "|reqCookies:" + reqParam + "|reqCookiesValue:" +
                                     reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (reqParamValueDecoded.Length > 5 && Regex.IsMatch(reqParamValueDecoded, patInteger)) //Integer
                            list.Add("Reason:IntegerInReqCookiesValue" + "|reqCookies:" + reqParam + "|reqCookiesValue:" +
                                     reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (Regex.IsMatch(reqParamValueDecoded, patUrl)) //Url
                            list.Add("Reason:UrlInReqCookiesValue" + "|reqCookies:" + reqParam + "|reqCookiesValue:" +
                                     reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (Regex.IsMatch(reqParamValueDecoded, patIp)) //Ip
                            list.Add("Reason:IpInReqCookiesValue" + "|reqCookies:" + reqParam + "|reqCookiesValue:" +
                                     reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);
                        if (Regex.IsMatch(reqParamValueDecoded, keysTokens)) //keysTokens
                            list.Add("Reason:keysTokensInReqCookiesValue" + "|reqCookies:" + reqParam + "|reqCookiesValue:" +
                                     reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);
                        if (Regex.IsMatch(reqParamValueDecoded, patBase64)) //Base64
                        {
                            var base64EncodedBytes = System.Convert.FromBase64String(reqParamValueDecoded);
                            string reqParamValueDecodedb64 = System.Text.Encoding.UTF8.GetString(base64EncodedBytes);

                            list.Add("Reason:Base64InReqCookiesValue" + "|reqCookiesValue:" + reqParamValueDecodedb64 +
                                     "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        }

                        if (reqParamValueDecoded.Length > 4 && Regex.IsMatch(respBody, @reqParamValueDecoded)) //CookieInRespBody
                        {
                            list.Add("Reason:CookieInRespBody" + "|reqCookies:" + reqParam + "|reqCookiesValue:" +
                                     reqParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        }
                    }
                    //хз искать ли в Имена параметров

                }
            }

            //8. Анализ respCookies (это строки Set-Cookie в Headers)
            if (!string.IsNullOrEmpty(respCookies))
            {
                int respCookiesSplitCount = respCookies.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries).Count();
                string[] respCookiesSplit = respCookies.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                for (int i = 0; i < respCookiesSplitCount; i++)
                {
                    string pv1 = respCookiesSplit.ElementAtOrDefault(i);
                    string respParam = pv1.Split('=').ElementAtOrDefault(0); //берем параметр
                    string respParamValue = pv1.Split(new[] { '=' }, 2).ElementAtOrDefault(1); //берем значение параметра
                    string respParamValueDecoded = System.Net.WebUtility.UrlDecode(respParamValue);
                    //Значения параметров
                    if (!string.IsNullOrEmpty(respParamValueDecoded))
                    {
                        if (Regex.IsMatch(respParamValueDecoded, patExtensions)) //Extensions
                            list.Add("Reason:ExtensionInRespCookiesValue" + "|respCookies:" + respParam + "|respCookiesValue:" +
                                     respParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (respParamValueDecoded.Length > 5 && Regex.IsMatch(respParamValueDecoded, patInteger)) //Integer
                            list.Add("Reason:IntegerInRespCookiesValue" + "|respCookies:" + respParam + "|respCookiesValue:" +
                                     respParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (Regex.IsMatch(respParamValueDecoded, patUrl)) //Url
                            list.Add("Reason:UrlInRespCookiesValue" + "|respCookies:" + respParam + "|respCookiesValue:" +
                                     respParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (Regex.IsMatch(respParamValueDecoded, patIp)) //Ip
                            list.Add("Reason:IpInRespCookiesValue" + "|respCookies:" + respParam + "|respCookiesValue:" +
                                     respParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);
                        if (Regex.IsMatch(respParamValueDecoded, keysTokens)) //keysTokens
                            list.Add("Reason:keysTokensInRespCookiesValue" + "|respCookies:" + respParam + "|respCookiesValue:" +
                                     respParamValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);
                        if (Regex.IsMatch(respParamValueDecoded, patBase64)) //Base64
                        {
                            var base64EncodedBytes = System.Convert.FromBase64String(respParamValueDecoded);
                            string respParamValueDecodedb64 = System.Text.Encoding.UTF8.GetString(base64EncodedBytes);

                            list.Add("Reason:Base64InRespCookiesValue" + "|respCookiesValue:" + respParamValueDecodedb64 +
                                     "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        }
                    }
                    //хз искать ли в Имена параметров

                }
            }

            //9. Анализ reqHeaders (исключить Host и Referer, может и нет)
            if (!string.IsNullOrEmpty(reqHeaders))
            {
                int reqHeadersSplitCount = reqHeaders.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries).Count();
                string[] reqHeadersSplit = reqHeaders.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                for (int i = 0; i < reqHeadersSplitCount; i++)
                {
                    string pv1 = reqHeadersSplit.ElementAtOrDefault(i);
                    string reqHeader = pv1.Split(':').ElementAtOrDefault(0); //берем header
                    string reqHeaderValue = pv1.Split(new[] { ':' }, 2).ElementAtOrDefault(1); //берем значение header
                    string reqHeaderValueDecoded = System.Net.WebUtility.UrlDecode(reqHeaderValue);
                    if (!string.IsNullOrEmpty(reqHeaderValueDecoded))
                    {
                        //Значения параметров
                        if (Regex.IsMatch(reqHeaderValueDecoded, @"XMLHttpRequest")) //XMLHttpRequest
                            list.Add("Reason:XMLHttpRequestInReqHeadersValue" + "|reqHeader:" + reqHeader + "|reqHeaderValue:" +
                                     reqHeaderValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (Regex.IsMatch(reqHeaderValueDecoded, patExtensions)) //Extensions
                            list.Add("Reason:ExtensionInReqHeadersValue" + "|reqHeader:" + reqHeader + "|reqHeaderValue:" +
                                     reqHeaderValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (reqHeaderValueDecoded.Length > 5 && Regex.IsMatch(reqHeaderValueDecoded, patInteger)) //Integer
                            list.Add("Reason:IntegerInReqHeadersValue" + "|reqHeader:" + reqHeader + "|reqHeaderValue:" +
                                     reqHeaderValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (Regex.IsMatch(reqHeaderValueDecoded, patUrl)) //Url
                            list.Add("Reason:UrlInReqHeadersValue" + "|reqHeader:" + reqHeader + "|reqHeaderValue:" +
                                     reqHeaderValue + "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        if (Regex.IsMatch(reqHeaderValueDecoded, patIp)) //Ip
                            list.Add("Reason:IpInReqHeadersValue" + "|reqHeader:" + reqHeader + "|reqHeaderValue:" +
                                     reqHeaderValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);
                        if (Regex.IsMatch(reqHeaderValueDecoded, keysTokens)) //keysTokens
                            list.Add("Reason:keysTokensInReqHeadersValue" + "|reqHeader:" + reqHeader + "|reqHeaderValue:" +
                                     reqHeaderValue + "|Url:" +
                                     trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" + getProfileName);
                        if (Regex.IsMatch(reqHeaderValueDecoded, patBase64)) //Base64
                        {
                            var base64EncodedBytes = System.Convert.FromBase64String(reqHeaderValueDecoded);
                            string reqHeaderValueDecodedb64 = System.Text.Encoding.UTF8.GetString(base64EncodedBytes);

                            list.Add("Reason:Base64InReqHeadersValue" + "|reqHeaderValue:" + reqHeaderValueDecodedb64 +
                                     "|Url:" +
                                     trUrl + "|RequestCounter:" +
                                     Counter1 + "|File:" +
                                     fileName + "_traffic.txt" + "|Profile:" +
                                     getProfileName);
                        }

                    }
                }

                //Парсинг X-Headers 
                MatchCollection matchList2 = Regex.Matches(respBody, @"X-.*?(?=:)");
                matchList2.OfType<Match>().Select(m => m.Groups[0].Value).Distinct();//регулярка с удалением дублей
                                                                                     //здесь ошибка может быть MatchCollection заменить на var или OfType на Cast
                                                                                     //matchList1.Cast<Match>().Select(match => match.Value).ToList().ForEach(s => list.Add(s + "|trafficRequestHeaders" + "|notHidden|" + "RequestNum:" + Counter1 + "|"));
                string allMatchesUnitedz = string.Join(",", from Match match in matchList2 select match.Value);
                string allMatchesUnited1 = Macros.TextProcessing.Replace(allMatchesUnitedz, "\r\n", ", ", "Regex", "All");

                if (!string.IsNullOrEmpty(allMatchesUnited1))
                {
                    list.Add("Reason:X-Headers" + "|List:" + allMatchesUnited1 + "|Url:" +
                             trUrl + "|RequestCounter:" + Counter1 +
                             "|File:" + fileName +
                             "_traffic.txt" + "|Profile:" + getProfileName);
                }

            }

            //10. Анализ respHeaders
            if (!string.IsNullOrEmpty(respHeaders))
            {
                int respHeadersSplitCount = respHeaders.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries).Count();
                string[] respHeadersSplit = respHeaders.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                for (int i = 0; i < respHeadersSplitCount; i++)
                {
                    string pv1 = respHeadersSplit.ElementAtOrDefault(i);
                    string respHeader = pv1.Split(':').ElementAtOrDefault(0); //берем header
                    string respHeaderValue = pv1.Split(new[] { ':' }, 2).ElementAtOrDefault(1); //берем значение header
                    string respHeaderValueDecoded = System.Net.WebUtility.UrlDecode(respHeaderValue);
                    if (!string.IsNullOrEmpty(respHeaderValueDecoded))
                    {
                        if (!respHeader.Contains("Cookie:")) //пропускаем куки
                        {
                            //Значения параметров
                            if (Regex.IsMatch(respHeaderValueDecoded, patExtensions)) //Extensions
                                list.Add("Reason:ExtensionInRespHeadersValue" + "|respHeader:" + respHeader +
                                         "|respHeaderValue:" + respHeaderValue + "|Url:" +
                                         trUrl + "|RequestCounter:" +
                                         Counter1 + "|File:" +
                                         fileName + "_traffic.txt" + "|Profile:" +
                                         getProfileName);
                            if (respHeaderValueDecoded.Length > 5 && Regex.IsMatch(respHeaderValueDecoded, patInteger)) //Integer
                                list.Add("Reason:IntegerInRespHeadersValue" + "|respHeader:" + respHeader +
                                         "|respHeaderValue:" + respHeaderValue + "|Url:" +
                                         trUrl + "|RequestCounter:" +
                                         Counter1 + "|File:" +
                                         fileName + "_traffic.txt" + "|Profile:" +
                                         getProfileName);
                            if (Regex.IsMatch(respHeaderValueDecoded, patUrl)) //Url
                                list.Add("Reason:UrlInRespHeadersValue" + "|respHeader:" + respHeader + "|respHeaderValue:" +
                                         respHeaderValue + "|Url:" +
                                         trUrl + "|RequestCounter:" +
                                         Counter1 + "|File:" +
                                         fileName + "_traffic.txt" + "|Profile:" +
                                         getProfileName);
                            if (Regex.IsMatch(respHeaderValueDecoded, patIp)) //Ip
                                list.Add("Reason:IpInRespHeadersValue" + "|respHeader:" + respHeader + "|respHeaderValue:" +
                                         respHeaderValue + "|Url:" +
                                         trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                         fileName + "_traffic.txt" + "|Profile:" + getProfileName);
                            if (Regex.IsMatch(respHeaderValueDecoded, keysTokens)) //keysTokens
                                list.Add("Reason:keysTokensInRespHeadersValue" + "|respHeader:" + respHeader + "|respHeaderValue:" +
                                         respHeaderValue + "|Url:" +
                                         trUrl + "|RequestCounter:" + Counter1 + "|File:" +
                                         fileName + "_traffic.txt" + "|Profile:" + getProfileName);
                            if (Regex.IsMatch(respHeaderValueDecoded, patBase64)) //Base64
                            {
                                var base64EncodedBytes = System.Convert.FromBase64String(respHeaderValueDecoded);
                                string respHeaderValueDecodedb64 = System.Text.Encoding.UTF8.GetString(base64EncodedBytes);

                                list.Add("Reason:Base64InRespHeadersValue" + "|respHeaderValue:" + respHeaderValueDecodedb64 +
                                         "|Url:" +
                                         trUrl + "|RequestCounter:" +
                                         Counter1 + "|File:" +
                                         fileName + "_traffic.txt" + "|Profile:" +
                                         getProfileName);
                            }
                        }
                    }

                }
                //Парсинг X-Headers 
                MatchCollection matchList3 = Regex.Matches(respBody, @"X-.*?(?=:)");
                matchList3.OfType<Match>().Select(m => m.Groups[0].Value).Distinct();//регулярка с удалением дублей
                                                                                     //здесь ошибка может быть MatchCollection заменить на var или OfType на Cast
                                                                                     //matchList1.Cast<Match>().Select(match => match.Value).ToList().ForEach(s => list.Add(s + "|trafficRequestHeaders" + "|notHidden|" + "RequestNum:" + Counter1 + "|"));
                string allMatchesUnited_p = string.Join(",", from Match match in matchList3 select match.Value);
                string allMatchesUnited3 = Macros.TextProcessing.Replace(allMatchesUnited_p, "\r\n", ", ", "Regex", "All");

                if (!string.IsNullOrEmpty(allMatchesUnited3))
                {
                    list.Add("Reason:X-Headers" + "|List:" + allMatchesUnited3 + "|Url:" +
                             trUrl + "|RequestCounter:" + Counter1 +
                             "|File:" + fileName +
                             "_traffic.txt" + "|Profile:" + getProfileName);
                }
            }
			//11. поиск ключей aws, git и пр в respBody
			//E:\Ptest\Testing\Attacks\Tools\Analysis\secret_keys.txt
			//добавлять по мере нахождения новые ключи
			// нужно добавлять в лог .value
			//добавить поиск по respHeaders

			//respBody
			if (Regex.IsMatch(respBody, keyAWSApi))
			{
				Match match = Regex.Match(respBody, keyAWSApi);
				list.Add("Reason:KeyInRespBody" + "|Type:AWSApi|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyAWSAccess))
			{
				Match match = Regex.Match(respBody, keyAWSAccess);
				list.Add("Reason:KeyInRespBody" + "|Type:AWSAccess|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyFacebookAccessToken))
			{
				Match match = Regex.Match(respBody, keyFacebookAccessToken);
				list.Add("Reason:KeyInRespBody" + "|Type:Facebook Access Token|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyFacebookOAuth))
			{
				Match match = Regex.Match(respBody, keyFacebookOAuth);
				list.Add("Reason:KeyInRespBody" + "|Type:Facebook OAuth|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyFacebookSecretKey))
			{
				Match match = Regex.Match(respBody, keyFacebookSecretKey);
				list.Add("Reason:KeyInRespBody" + "|Type:FacebookSecretKey|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyGenericAPIKey))
			{
				Match match = Regex.Match(respBody, keyGenericAPIKey);
				list.Add("Reason:KeyInRespBody" + "|Type:Generic API Key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyGenericSecret))
			{
				Match match = Regex.Match(respBody, keyGenericSecret);
				list.Add("Reason:KeyInRespBody" + "|Type:Generic Secret|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyGitHub))
			{
				Match match = Regex.Match(respBody, keyGitHub);
				list.Add("Reason:KeyInRespBody" + "|Type:GitHub|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyGoogleServiceAccount))
			{
				Match match = Regex.Match(respBody, keyGoogleServiceAccount);
				list.Add("Reason:KeyInRespBody" + "|Type:Google (GCP) Service-account|Key:" + match.Value + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyGoogleAPIKey))
			{
				Match match = Regex.Match(respBody, keyGoogleAPIKey);
				list.Add("Reason:KeyInRespBody" + "|Type:Google API Key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyGoogleCloudPlatformOAuth))
			{
				Match match = Regex.Match(respBody, keyGoogleCloudPlatformOAuth);
				list.Add("Reason:KeyInRespBody" + "|Type:Google Cloud Platform OAuth|Key:" + match.Value + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyGoogleDriveOAuth))
			{
				Match match = Regex.Match(respBody, keyGoogleDriveOAuth);
				list.Add("Reason:KeyInRespBody" + "|Type:Google Drive OAuth|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyGoogleOAuthAccessToken))
			{
				Match match = Regex.Match(respBody, keyGoogleOAuthAccessToken);
				list.Add("Reason:KeyInRespBody" + "|Type:Google OAuth Access Token|Key:" + match.Value + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyGoogleOauth))
			{
				Match match = Regex.Match(respBody, keyGoogleOauth);
				list.Add("Reason:KeyInRespBody" + "|Type:Google Oauth|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyHerokuAPIKey))
			{
				Match match = Regex.Match(respBody, keyHerokuAPIKey);
				list.Add("Reason:KeyInRespBody" + "|Type:Heroku API Key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyMailChimpAPIKey))
			{
				Match match = Regex.Match(respBody, keyMailChimpAPIKey);
				list.Add("Reason:KeyInRespBody" + "|Type:MailChimp API Key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyMailgunAPIKey))
			{
				Match match = Regex.Match(respBody, keyMailgunAPIKey);
				list.Add("Reason:KeyInRespBody" + "|Type:Mailgun API Key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyPGPkeyblock))
			{
				Match match = Regex.Match(respBody, keyPGPkeyblock);
				list.Add("Reason:KeyInRespBody" + "|Type:PGP private key block|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyPayPalBraintreeAccessToken))
			{
				Match match = Regex.Match(respBody, keyPayPalBraintreeAccessToken);
				list.Add("Reason:KeyInRespBody" + "|Type:PayPal Braintree Access Token|Key:" + match.Value + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyPicaticAPIKey))
			{
				Match match = Regex.Match(respBody, keyPicaticAPIKey);
				list.Add("Reason:KeyInRespBody" + "|Type:Picatic API Key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyRSAprivatekey))
			{
				Match match = Regex.Match(respBody, keyRSAprivatekey);
				list.Add("Reason:KeyInRespBody" + "|Type:RSA private key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keySSHprivatekey))
			{
				Match match = Regex.Match(respBody, keySSHprivatekey);
				list.Add("Reason:KeyInRespBody" + "|Type:SSH (DSA) private key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keySSHECkey))
			{
				Match match = Regex.Match(respBody, keySSHECkey);
				list.Add("Reason:KeyInRespBody" + "|Type:SSH (EC) private key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyOPENSSHprivatekey))
			{
				Match match = Regex.Match(respBody, keyOPENSSHprivatekey);
				list.Add("Reason:KeyInRespBody" + "|Type:SSH (OPENSSH) private key|Key:" + match.Value + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keySlackToken))
			{
				Match match = Regex.Match(respBody, keySlackToken);
				list.Add("Reason:KeyInRespBody" + "|Type:Slack Token|Key:" + match.Value + "|Profile:" + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keySlackWebhook))
			{
				Match match = Regex.Match(respBody, keySlackWebhook);
				list.Add("Reason:KeyInRespBody" + "|Type:Slack Webhook|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keySquareOAuthAccess))
			{
				Match match = Regex.Match(respBody, keySquareOAuthAccess);
				list.Add("Reason:KeyInRespBody" + "|Type:Square OAuth/Access|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyStripeAPIKey))
			{
				Match match = Regex.Match(respBody, keyStripeAPIKey);
				list.Add("Reason:KeyInRespBody" + "|Type:Stripe API Key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyStripeRestrictedAPIKey))
			{
				Match match = Regex.Match(respBody, keyStripeRestrictedAPIKey);
				list.Add("Reason:KeyInRespBody" + "|Type:Stripe Restricted API Key|Key:" + match.Value + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyTwilioAPIKey))
			{
				Match match = Regex.Match(respBody, keyTwilioAPIKey);
				list.Add("Reason:KeyInRespBody" + "|Type:Twilio API Key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyTwitterAccessToken))
			{
				Match match = Regex.Match(respBody, keyTwitterAccessToken);
				list.Add("Reason:KeyInRespBody" + "|Type:Twitter Access Token|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, keyTwitterOAuth))
			{
				Match match = Regex.Match(respBody, keyTwitterOAuth);
				list.Add("Reason:KeyInRespBody" + "|Type:Twitter OAuth|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			//respHeaders
			if (Regex.IsMatch(respHeaders, keyAWSApi))
			{
				Match match = Regex.Match(respHeaders, keyAWSApi);
				list.Add("Reason:KeyInRespHeaders" + "|Type:AWSApi|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyAWSAccess))
			{
				Match match = Regex.Match(respHeaders, keyAWSAccess);
				list.Add("Reason:KeyInRespHeaders" + "|Type:AWSAccess|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyFacebookAccessToken))
			{
				Match match = Regex.Match(respHeaders, keyFacebookAccessToken);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Facebook Access Token|Key:" + match.Value + "|Url:" +
						 trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyFacebookOAuth))
			{
				Match match = Regex.Match(respHeaders, keyFacebookOAuth);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Facebook OAuth|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyFacebookSecretKey))
			{
				Match match = Regex.Match(respHeaders, keyFacebookSecretKey);
				list.Add("Reason:KeyInRespHeaders" + "|Type:FacebookSecretKey|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyGenericAPIKey))
			{
				Match match = Regex.Match(respHeaders, keyGenericAPIKey);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Generic API Key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyGenericSecret))
			{
				Match match = Regex.Match(respHeaders, keyGenericSecret);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Generic Secret|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyGitHub))
			{
				Match match = Regex.Match(respHeaders, keyGitHub);
				list.Add("Reason:KeyInRespHeaders" + "|Type:GitHub|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyGoogleServiceAccount))
			{
				Match match = Regex.Match(respHeaders, keyGoogleServiceAccount);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Google (GCP) Service-account|Key:" + match.Value + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyGoogleAPIKey))
			{
				Match match = Regex.Match(respHeaders, keyGoogleAPIKey);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Google API Key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyGoogleCloudPlatformOAuth))
			{
				Match match = Regex.Match(respHeaders, keyGoogleCloudPlatformOAuth);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Google Cloud Platform OAuth|Key:" + match.Value + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyGoogleDriveOAuth))
			{
				Match match = Regex.Match(respHeaders, keyGoogleDriveOAuth);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Google Drive OAuth|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyGoogleOAuthAccessToken))
			{
				Match match = Regex.Match(respHeaders, keyGoogleOAuthAccessToken);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Google OAuth Access Token|Key:" + match.Value + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyGoogleOauth))
			{
				Match match = Regex.Match(respHeaders, keyGoogleOauth);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Google Oauth|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyHerokuAPIKey))
			{
				Match match = Regex.Match(respHeaders, keyHerokuAPIKey);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Heroku API Key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyMailChimpAPIKey))
			{
				Match match = Regex.Match(respHeaders, keyMailChimpAPIKey);
				list.Add("Reason:KeyInRespHeaders" + "|Type:MailChimp API Key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyMailgunAPIKey))
			{
				Match match = Regex.Match(respHeaders, keyMailgunAPIKey);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Mailgun API Key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyPGPkeyblock))
			{
				Match match = Regex.Match(respHeaders, keyPGPkeyblock);
				list.Add("Reason:KeyInRespHeaders" + "|Type:PGP private key block|Key:" + match.Value + "|Url:" +
						 trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyPayPalBraintreeAccessToken))
			{
				Match match = Regex.Match(respHeaders, keyPayPalBraintreeAccessToken);
				list.Add("Reason:KeyInRespHeaders" + "|Type:PayPal Braintree Access Token|Key:" + match.Value +
						 "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyPicaticAPIKey))
			{
				Match match = Regex.Match(respHeaders, keyPicaticAPIKey);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Picatic API Key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyRSAprivatekey))
			{
				Match match = Regex.Match(respHeaders, keyRSAprivatekey);
				list.Add("Reason:KeyInRespHeaders" + "|Type:RSA private key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keySSHprivatekey))
			{
				Match match = Regex.Match(respHeaders, keySSHprivatekey);
				list.Add("Reason:KeyInRespHeaders" + "|Type:SSH (DSA) private key|Key:" + match.Value + "|Url:" +
						 trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keySSHECkey))
			{
				Match match = Regex.Match(respHeaders, keySSHECkey);
				list.Add("Reason:KeyInRespHeaders" + "|Type:SSH (EC) private key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyOPENSSHprivatekey))
			{
				Match match = Regex.Match(respHeaders, keyOPENSSHprivatekey);
				list.Add("Reason:KeyInRespHeaders" + "|Type:SSH (OPENSSH) private key|Key:" + match.Value + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keySlackToken))
			{
				Match match = Regex.Match(respHeaders, keySlackToken);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Slack Token|Key:" + match.Value + "|Profile:" + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keySlackWebhook))
			{
				Match match = Regex.Match(respHeaders, keySlackWebhook);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Slack Webhook|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keySquareOAuthAccess))
			{
				Match match = Regex.Match(respHeaders, keySquareOAuthAccess);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Square OAuth/Access|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyStripeAPIKey))
			{
				Match match = Regex.Match(respHeaders, keyStripeAPIKey);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Stripe API Key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyStripeRestrictedAPIKey))
			{
				Match match = Regex.Match(respHeaders, keyStripeRestrictedAPIKey);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Stripe Restricted API Key|Key:" + match.Value + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyTwilioAPIKey))
			{
				Match match = Regex.Match(respHeaders, keyTwilioAPIKey);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Twilio API Key|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyTwitterAccessToken))
			{
				Match match = Regex.Match(respHeaders, keyTwitterAccessToken);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Twitter Access Token|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, keyTwitterOAuth))
			{
				Match match = Regex.Match(respHeaders, keyTwitterOAuth);
				list.Add("Reason:KeyInRespHeaders" + "|Type:Twitter OAuth|Key:" + match.Value + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}


			//12. поиск конфид данных (логин, пароль, емаил)
			//кодировка в hex
			//string everything = string.Join("", input.ToCharArray().Select(c =>((int)c).ToString("x2")).ToArray());

			var log = System.Text.Encoding.UTF8.GetBytes(login);
			var log64 = System.Convert.ToBase64String(log);
			var em = System.Text.Encoding.UTF8.GetBytes(email);
			var em64 = System.Convert.ToBase64String(em);
			var logPass0 = System.Text.Encoding.UTF8.GetBytes(login + ":" + pass);
			var logPass064 = System.Convert.ToBase64String(logPass0);
			var emailPass0 = System.Text.Encoding.UTF8.GetBytes(email + ":" + pass);
			var emailPass064 = System.Convert.ToBase64String(emailPass0);
			var logPass1 = System.Text.Encoding.UTF8.GetBytes(login + "_" + pass);
			var logPass164 = System.Convert.ToBase64String(logPass1);
			var emailPass1 = System.Text.Encoding.UTF8.GetBytes(email + "_" + pass);
			var emailPass164 = System.Convert.ToBase64String(emailPass1);
			//if (campaign.ToString().Equals("hyatt"))
			//{

			//	var hyatt = System.Text.Encoding.UTF8.GetBytes(hyattMember);
			//	var hyatt64 = System.Convert.ToBase64String(hyatt);

			//	var hyattPass0 = System.Text.Encoding.UTF8.GetBytes(hyattMember + ":" + pass);
			//	var hyattPass064 = System.Convert.ToBase64String(hyattPass0);

			//	var hyattPass1 = System.Text.Encoding.UTF8.GetBytes(hyattMember + "_" + pass);
			//	var hyattPass164 = System.Convert.ToBase64String(hyattPass1);

			//	//if (Regex.IsMatch(dom, @login) || Regex.IsMatch(dom, @pass) || Regex.IsMatch(dom, @hyattMember) || Regex.IsMatch(dom, @email))
			//	//{
			//	//	list.Add("Reason:Credential" + "|FoundIn:Dom" + "|Profile:" +
			//	//			 getProfileName +
			//	//			 "|File:" + 
			//	//			 fileName + "_traffic.txt" + "|Url:" +
			//	//			 trUrl + "|RequestCounter:" +
			//	//			 Counter1);
			//	//}
			//	//if (Regex.IsMatch(dom, @log64) || Regex.IsMatch(dom, @hyatt64) || Regex.IsMatch(dom, @em64) || Regex.IsMatch(dom, @logPass064) || Regex.IsMatch(dom, @hyattPass064) || Regex.IsMatch(dom, @emailPass064) || Regex.IsMatch(dom, @logPass164) || Regex.IsMatch(dom, @hyattPass164) || Regex.IsMatch(dom, @emailPass164))
			//	//{
			//	//	list.Add("Reason:CredentialEncoded64" + "|FoundIn:Dom" + "|Profile:" +
			//	//			 getProfileName +
			//	//			 "|File:" + 
			//	//			 fileName + "_traffic.txt" + "|Url:" +
			//	//			 trUrl + "|RequestCounter:" +
			//	//			 Counter1);
			//	//}
			//	if (Regex.IsMatch(respHeaders, @login) || Regex.IsMatch(respHeaders, @pass) ||
			//		Regex.IsMatch(respHeaders, @hyattMember) || Regex.IsMatch(respHeaders, @email))
			//	{
			//		list.Add("Reason:Credential" + "|FoundIn:respHeaders" + "|Url:" +
			//				 trUrl + "|RequestCounter:" +
			//				 Counter1 + "|File:" + 
			//				 fileName + "_traffic.txt" + "|Profile:" +
			//				 getProfileName);
			//	}

			//	if (Regex.IsMatch(respHeaders, @log64) || Regex.IsMatch(respHeaders, @hyatt64) ||
			//		Regex.IsMatch(respHeaders, @em64) || Regex.IsMatch(respHeaders, @logPass064) ||
			//		Regex.IsMatch(respHeaders, @hyattPass064) || Regex.IsMatch(respHeaders, @emailPass064) ||
			//		Regex.IsMatch(respHeaders, @logPass164) || Regex.IsMatch(respHeaders, @hyattPass164) ||
			//		Regex.IsMatch(respHeaders, @emailPass164))
			//	{
			//		list.Add("Reason:CredentialEncoded64" + "|FoundIn:respHeaders" + "|Url:" +
			//				 trUrl + "|RequestCounter:" +
			//				 Counter1 + "|File:" + 
			//				 fileName + "_traffic.txt" + "|Profile:" +
			//				 getProfileName);
			//	}

			//	if (Regex.IsMatch(respCookies, @login) || Regex.IsMatch(respCookies, @pass) ||
			//		Regex.IsMatch(respCookies, @hyattMember) || Regex.IsMatch(respCookies, @email))
			//	{
			//		list.Add("Reason:Credential" + "|FoundIn:respCookies" + "|Url:" +
			//				 trUrl + "|RequestCounter:" +
			//				 Counter1 + "|File:" + 
			//				 fileName + "_traffic.txt" + "|Profile:" +
			//				 getProfileName);
			//	}

			//	if (Regex.IsMatch(respCookies, @log64) || Regex.IsMatch(respCookies, @hyatt64) ||
			//		Regex.IsMatch(respCookies, @em64) || Regex.IsMatch(respCookies, @logPass064) ||
			//		Regex.IsMatch(respCookies, @hyattPass064) || Regex.IsMatch(respCookies, @emailPass064) ||
			//		Regex.IsMatch(respCookies, @logPass164) || Regex.IsMatch(respCookies, @hyattPass164) ||
			//		Regex.IsMatch(respCookies, @emailPass164))
			//	{
			//		list.Add("Reason:CredentialEncoded64" + "|FoundIn:respCookies" + "|Url:" +
			//				 trUrl + "|RequestCounter:" +
			//				 Counter1 + "|File:" + 
			//				 fileName + "_traffic.txt" + "|Profile:" +
			//				 getProfileName);
			//	}

			//	if (Regex.IsMatch(respBody, @login) || Regex.IsMatch(respBody, @pass) ||
			//		Regex.IsMatch(respBody, @hyattMember) || Regex.IsMatch(respBody, @email))
			//	{
			//		list.Add("Reason:Credential" + "|FoundIn:respBody" + "|Url:" + trUrl +
			//				 "|RequestCounter:" + Counter1 + "|File:" +
			//				  fileName +
			//				 "_traffic.txt" + "|Profile:" + getProfileName);
			//	}

			//	if (Regex.IsMatch(respBody, @log64) || Regex.IsMatch(respBody, @hyatt64) ||
			//		Regex.IsMatch(respBody, @em64) || Regex.IsMatch(respBody, @logPass064) ||
			//		Regex.IsMatch(respBody, @hyattPass064) || Regex.IsMatch(respBody, @emailPass064) ||
			//		Regex.IsMatch(respBody, @logPass164) || Regex.IsMatch(respBody, @hyattPass164) ||
			//		Regex.IsMatch(respBody, @emailPass164))
			//	{
			//		list.Add("Reason:CredentialEncoded64" + "|FoundIn:respBody" + "|Url:" +
			//				 trUrl + "|RequestCounter:" +
			//				 Counter1 + "|File:" + 
			//				 fileName + "_traffic.txt" + "|Profile:" +
			//				 getProfileName);
			//	}

			//	if (Regex.IsMatch(trUrl, @login) || Regex.IsMatch(trUrl, @pass) || Regex.IsMatch(trUrl, @hyattMember) ||
			//		Regex.IsMatch(trUrl, @email))
			//	{
			//		list.Add("Reason:Credential" + "|FoundIn:trUrl" + "|Url:" + trUrl +
			//				 "|RequestCounter:" + Counter1 + "|File:" +
			//				  fileName +
			//				 "_traffic.txt" + "|Profile:" + getProfileName);
			//	}

			//	if (Regex.IsMatch(trUrl, @log64) || Regex.IsMatch(trUrl, @hyatt64) || Regex.IsMatch(trUrl, @em64) ||
			//		Regex.IsMatch(trUrl, @logPass064) || Regex.IsMatch(trUrl, @hyattPass064) ||
			//		Regex.IsMatch(trUrl, @emailPass064) || Regex.IsMatch(trUrl, @logPass164) ||
			//		Regex.IsMatch(trUrl, @hyattPass164) || Regex.IsMatch(trUrl, @emailPass164))
			//	{
			//		list.Add("Reason:CredentialEncoded64" + "|FoundIn:trUrl" + "|Url:" +
			//				 trUrl + "|RequestCounter:" +
			//				 Counter1 + "|File:" + 
			//				 fileName + "_traffic.txt" + "|Profile:" +
			//				 getProfileName);
			//	}
			//}

			//else
			//dom нужно убрать, т.к. одно и то же будет постоянно
			//	if (Regex.IsMatch(dom, @login) || Regex.IsMatch(dom, @pass) || Regex.IsMatch(dom, @email))
			//{
			//	list.Add("Reason:Credential" + "|FoundIn:Dom" + "|Profile:" +
			//			 getProfileName +
			//			 "|File:" + 
			//			 fileName + "_traffic.txt" + "|Url:" +
			//			 trUrl + "|RequestCounter:" +
			//			 Counter1);
			//}
			//if (Regex.IsMatch(dom, @log64) || Regex.IsMatch(dom, @em64) || Regex.IsMatch(dom, @logPass064) || Regex.IsMatch(dom, @emailPass064) || Regex.IsMatch(dom, @logPass164) || Regex.IsMatch(dom, @emailPass164))
			//	{
			//	list.Add("Reason:CredentialEncoded64" + "|FoundIn:Dom" + "|Profile:" +
			//			 getProfileName +
			//			 "|File:" + 
			//			 fileName + "_traffic.txt" + "|Url:" +
			//			 trUrl + "|RequestCounter:" +
			//			 Counter1);
			//}
			if (Regex.IsMatch(respHeaders, @login) || Regex.IsMatch(respHeaders, @pass) ||
				Regex.IsMatch(respHeaders, @email))
			{
				list.Add("Reason:Credential" + "|FoundIn:respHeaders" + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respHeaders, @log64) || Regex.IsMatch(respHeaders, @em64) ||
				Regex.IsMatch(respHeaders, @logPass064) || Regex.IsMatch(respHeaders, @emailPass064) ||
				Regex.IsMatch(respHeaders, @logPass164) || Regex.IsMatch(respHeaders, @emailPass164))
			{
				list.Add("Reason:CredentialEncoded64" + "|FoundIn:respHeaders" + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respCookies, @login) || Regex.IsMatch(respCookies, @pass) ||
				Regex.IsMatch(respCookies, @email))
			{
				list.Add("Reason:Credential" + "|FoundIn:respCookies" + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respCookies, @log64) || Regex.IsMatch(respCookies, @em64) ||
				Regex.IsMatch(respCookies, @logPass064) || Regex.IsMatch(respCookies, @emailPass064) ||
				Regex.IsMatch(respCookies, @logPass164) || Regex.IsMatch(respCookies, @emailPass164))
			{
				list.Add("Reason:CredentialEncoded64" + "|FoundIn:respCookies" + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, @login) || Regex.IsMatch(respBody, @pass) || Regex.IsMatch(respBody, @email))
			{
				list.Add("Reason:Credential" + "|FoundIn:respBody" + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(respBody, @log64) || Regex.IsMatch(respBody, @em64) ||
				Regex.IsMatch(respBody, @logPass064) ||
				Regex.IsMatch(respBody, @emailPass064) || Regex.IsMatch(respBody, @logPass164) ||
				Regex.IsMatch(respBody, @emailPass164))
			{
				list.Add("Reason:CredentialEncoded64" + "|FoundIn:respBody" + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(trUrl, @login) || Regex.IsMatch(trUrl, @pass) || Regex.IsMatch(trUrl, @email))
			{
				list.Add("Reason:Credential" + "|FoundIn:trUrl" + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}

			if (Regex.IsMatch(trUrl, @log64) || Regex.IsMatch(trUrl, @em64) || Regex.IsMatch(trUrl, @logPass064) ||
				Regex.IsMatch(trUrl, @emailPass064) || Regex.IsMatch(trUrl, @logPass164) ||
				Regex.IsMatch(trUrl, @emailPass164))
			{
				list.Add("Reason:CredentialEncoded64" + "|FoundIn:trUrl" + "|Url:" + trUrl +
						 "|RequestCounter:" + Counter1 + "|File:" +
						  fileName + "_traffic.txt" +
						 "|Profile:" + getProfileName);
			}



            //13. парсим переменные из responseBody для фаззинга параметров, например. (?<=const|let|var)\s+(\w+?)(?=[;.=\s])
            MatchCollection matchList1 = Regex.Matches(respBody, @"(?<=const|let|var)\s+(\w+?)(?=[;.=\s])");
            matchList1.OfType<Match>().Select(m => m.Groups[0].Value).Distinct();//регулярка с удалением дублей
			//здесь ошибка может быть MatchCollection заменить на var или OfType на Cast
            //matchList1.Cast<Match>().Select(match => match.Value).ToList().ForEach(s => list.Add(s + "|trafficRequestHeaders" + "|notHidden|" + "RequestNum:" + Counter1 + "|"));
			string allMatchesUnited0 = string.Join(",", from Match match in matchList1 select match.Value);
			string allMatchesUnited = Macros.TextProcessing.Replace(allMatchesUnited0, "\r\n", ", ", "Regex", "All");

			if (!string.IsNullOrEmpty(allMatchesUnited))
			{
				list.Add("Reason:varInRespBody" + "|Variables:" + allMatchesUnited + "|Url:" +
						 trUrl + "|RequestCounter:" + Counter1 +
						 "|File:" +  fileName +
						 "_traffic.txt" + "|Profile:" + getProfileName);
			}
            //14. парсим названия тегов из responseBody для фаззинга параметров, например. (?<=\ name=").*?(?=")
            MatchCollection matchList11 = Regex.Matches(respBody, @"(?<=<input.*name=)[""']?((?:.(?![""']?\\s+(?:\S+)=|[>""']))+.)[""']?.*?>");
            matchList11.OfType<Match>().Select(m => m.Groups[0].Value).Distinct();//регулярка с удалением дублей
                                                                                 //здесь ошибка может быть MatchCollection заменить на var или OfType на Cast
                                                                                 //matchList1.Cast<Match>().Select(match => match.Value).ToList().ForEach(s => list.Add(s + "|trafficRequestHeaders" + "|notHidden|" + "RequestNum:" + Counter1 + "|"));
            string allMatchesUnited0_q = string.Join(",", from Match match in matchList11 select match.Value);
            string allMatchesUnited_q = Macros.TextProcessing.Replace(allMatchesUnited0_q, "\r\n", ", ", "Regex", "All");
            allMatchesUnited_q = Macros.TextProcessing.Replace(allMatchesUnited0_q, @"""|'", "", "Regex", "All");

            if (!string.IsNullOrEmpty(allMatchesUnited_q))
            {
                list.Add("Reason:inputTagNamesInRespBody" + "|TagNames:" + allMatchesUnited_q + "|Url:" +
                         trUrl + "|RequestCounter:" + Counter1 +
                         "|File:" + fileName +
                         "_traffic.txt" + "|Profile:" + getProfileName);
            }

            //15.1 парсим емаилы из responseBody
            MatchCollection matchListEmails = Regex.Matches(respBody, @"[\.\-_A-Za-z0-9]+?@[\.\-A-Za-z0-9-]+?[-\.A-Za-z0-9]{2,}");
            matchListEmails.OfType<Match>().Select(m => m.Groups[0].Value).Distinct();
            string allMatchesUnitedEmails = string.Join(",", from Match match in matchListEmails select match.Value);
            allMatchesUnitedEmails = Macros.TextProcessing.Replace(allMatchesUnitedEmails, "\r\n", ", ", "Regex", "All");

            if (!string.IsNullOrEmpty(allMatchesUnitedEmails))
            {
                list.Add("Reason:emailInRespBody" + "|Emails:" + allMatchesUnitedEmails + "|Url:" +
                         trUrl + "|RequestCounter:" + Counter1 +
                         "|File:" + fileName +
                         "_traffic.txt" + "|Profile:" + getProfileName);
            }

            //15.2 парсим емаилы из responseHeaders
            MatchCollection matchListEmailsH = Regex.Matches(respHeaders, @"[\.\-_A-Za-z0-9]+?@[\.\-A-Za-z0-9-]+?[-\.A-Za-z0-9]{2,}");
            matchListEmailsH.OfType<Match>().Select(m => m.Groups[0].Value).Distinct();
            string allMatchesUnitedEmailsH = string.Join(",", from Match match in matchListEmailsH select match.Value);
            allMatchesUnitedEmailsH = Macros.TextProcessing.Replace(allMatchesUnitedEmailsH, "\r\n", ", ", "Regex", "All");

            if (!string.IsNullOrEmpty(allMatchesUnitedEmailsH))
            {
                list.Add("Reason:emailInRespHeaders" + "|Emails:" + allMatchesUnitedEmailsH + "|Url:" +
                         trUrl + "|RequestCounter:" + Counter1 +
                         "|File:" + fileName +
                         "_traffic.txt" + "|Profile:" + getProfileName);
            }

            //15.3 парсим емаилы из responseCookies
            MatchCollection matchListEmailsC = Regex.Matches(respCookies, @"[\.\-_A-Za-z0-9]+?@[\.\-A-Za-z0-9-]+?[-\.A-Za-z0-9]{2,}");
            matchListEmailsC.OfType<Match>().Select(m => m.Groups[0].Value).Distinct();
            string allMatchesUnitedEmailsC = string.Join(",", from Match match in matchListEmailsC select match.Value);
            allMatchesUnitedEmailsC = Macros.TextProcessing.Replace(allMatchesUnitedEmailsC, "\r\n", ", ", "Regex", "All");

            if (!string.IsNullOrEmpty(allMatchesUnitedEmailsC))
            {
                list.Add("Reason:emailInRespCookies" + "|Emails:" + allMatchesUnitedEmailsC + "|Url:" +
                         trUrl + "|RequestCounter:" + Counter1 +
                         "|File:" + fileName +
                         "_traffic.txt" + "|Profile:" + getProfileName);
            }

        }




