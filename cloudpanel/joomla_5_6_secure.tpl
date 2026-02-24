server {
  listen 80;
  listen [::]:80;
  listen 443 quic;
  listen 443 ssl;
  listen [::]:443 quic;
  listen [::]:443 ssl;
  http2 on;
  http3 off;
  {{ssl_certificate_key}}
  {{ssl_certificate}}
  {{server_name}}
  {{root}}

  {{nginx_access_log}}
  {{nginx_error_log}}

  if ($scheme != "https") {
    rewrite ^ https://$host$request_uri permanent;
  }

  ######################################################################
  ## Protect against common file injection attacks
  ######################################################################
  set $file_injection 0;
  if ($query_string ~ "[a-zA-Z0-9_]=http://") {set $file_injection 1;}
  if ($query_string ~ "[a-zA-Z0-9_]=(\.\.//?)+") {set $file_injection 1;}
  if ($query_string ~ "[a-zA-Z0-9_]=/([a-z0-9_.]//?)+") {set $file_injection 1;}
  if ($file_injection = 1) {return 403;}

  ######################################################################
  ## Protect against common exploits in query strings in NginX
  ######################################################################
  set $common_exploit 0;
  if ($query_string ~ "proc/self/environ") {set $common_exploit 1;}
  if ($query_string ~ "mosConfig_[a-zA-Z_]{1,21}(=|\%3D)") {set $common_exploit 1;}
  if ($query_string ~ "base64_(en|de)code\(.*\)") {set $common_exploit 1;}
  if ($query_string ~ "(<|%3C).*script.*(>|%3E)") {set $common_exploit 1;}
  if ($query_string ~ "GLOBALS(=|\[|\%[0-9A-Z]{0,2})") {set $common_exploit 1;}
  if ($query_string ~ "_REQUEST(=|\[|\%[0-9A-Z]{0,2})") {set $common_exploit 1;}
  if ($common_exploit = 1) {return 403;}

  ######################################################################
  ## Block access from specific user agents
  ######################################################################
  set $bad_ua 0;
  if ($http_user_agent ~ "acapbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "acoonbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "acunetix") {set $bad_ua 1;}
  if ($http_user_agent ~ "ahrefs") {set $bad_ua 1;}
  if ($http_user_agent ~ "alexibot") {set $bad_ua 1;}
  if ($http_user_agent ~ "archiver") {set $bad_ua 1;}
  if ($http_user_agent ~ "asterias") {set $bad_ua 1;}
  if ($http_user_agent ~ "attackbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "awario") {set $bad_ua 1;}
  if ($http_user_agent ~ "backdor") {set $bad_ua 1;}
  if ($http_user_agent ~ "base64_decode") {set $bad_ua 1;}
  if ($http_user_agent ~ "becomebot") {set $bad_ua 1;}
  if ($http_user_agent ~ "bin/bash") {set $bad_ua 1;}
  if ($http_user_agent ~ "binlar") {set $bad_ua 1;}
  if ($http_user_agent ~ "blackwidow") {set $bad_ua 1;}
  if ($http_user_agent ~ "blekkobot") {set $bad_ua 1;}
  if ($http_user_agent ~ "blex") {set $bad_ua 1;}
  if ($http_user_agent ~ "blowfish") {set $bad_ua 1;}
  if ($http_user_agent ~ "bolt 0") {set $bad_ua 1;}
  if ($http_user_agent ~ "bot for jce") {set $bad_ua 1;}
  if ($http_user_agent ~ "bot mailto:craftbot@yahoo.com") {set $bad_ua 1;}
  if ($http_user_agent ~ "bullseye") {set $bad_ua 1;}
  if ($http_user_agent ~ "bunnys") {set $bad_ua 1;}
  if ($http_user_agent ~ "butterfly") {set $bad_ua 1;}
  if ($http_user_agent ~ "c99shell") {set $bad_ua 1;}
  if ($http_user_agent ~ "careerbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "casper") {set $bad_ua 1;}
  if ($http_user_agent ~ "cazoodlebot") {set $bad_ua 1;}
  if ($http_user_agent ~ "checkpriv") {set $bad_ua 1;}
  if ($http_user_agent ~ "checkprivacy") {set $bad_ua 1;}
  if ($http_user_agent ~ "cheesebot") {set $bad_ua 1;}
  if ($http_user_agent ~ "cherrypick") {set $bad_ua 1;}
  if ($http_user_agent ~ "chinaclaw") {set $bad_ua 1;}
  if ($http_user_agent ~ "choppy") {set $bad_ua 1;}
  if ($http_user_agent ~ "clshttp") {set $bad_ua 1;}
  if ($http_user_agent ~ "cmsworld") {set $bad_ua 1;}
  if ($http_user_agent ~ "cmsworldmap") {set $bad_ua 1;}
  if ($http_user_agent ~ "comodo") {set $bad_ua 1;}
  if ($http_user_agent ~ "companyspotter") {set $bad_ua 1;}
  if ($http_user_agent ~ "copernic") {set $bad_ua 1;}
  if ($http_user_agent ~ "copyrightcheck") {set $bad_ua 1;}
  if ($http_user_agent ~ "cosmos") {set $bad_ua 1;}
  if ($http_user_agent ~ "crescent") {set $bad_ua 1;}
  if ($http_user_agent ~ "custo") {set $bad_ua 1;}
  if ($http_user_agent ~ "datacha") {set $bad_ua 1;}
  if ($http_user_agent ~ "default browser 0") {set $bad_ua 1;}
  if ($http_user_agent ~ "demon") {set $bad_ua 1;}
  if ($http_user_agent ~ "diavol") {set $bad_ua 1;}
  if ($http_user_agent ~ "diibot") {set $bad_ua 1;}
  if ($http_user_agent ~ "disco") {set $bad_ua 1;}
  if ($http_user_agent ~ "discobot") {set $bad_ua 1;}
  if ($http_user_agent ~ "disconnect") {set $bad_ua 1;}
  if ($http_user_agent ~ "dittospyder") {set $bad_ua 1;}
  if ($http_user_agent ~ "dotbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "dotnetdotcom") {set $bad_ua 1;}
  if ($http_user_agent ~ "download demon") {set $bad_ua 1;}
  if ($http_user_agent ~ "dumbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "ecatch") {set $bad_ua 1;}
  if ($http_user_agent ~ "econtext") {set $bad_ua 1;}
  if ($http_user_agent ~ "ecxi") {set $bad_ua 1;}
  if ($http_user_agent ~ "eirgrabber") {set $bad_ua 1;}
  if ($http_user_agent ~ "emailcollector") {set $bad_ua 1;}
  if ($http_user_agent ~ "emailsiphon") {set $bad_ua 1;}
  if ($http_user_agent ~ "emailwolf") {set $bad_ua 1;}
  if ($http_user_agent ~ "eolasbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "eval") {set $bad_ua 1;}
  if ($http_user_agent ~ "eventures") {set $bad_ua 1;}
  if ($http_user_agent ~ "express webpictures") {set $bad_ua 1;}
  if ($http_user_agent ~ "extract") {set $bad_ua 1;}
  if ($http_user_agent ~ "extractorpro") {set $bad_ua 1;}
  if ($http_user_agent ~ "eyenetie") {set $bad_ua 1;}
  if ($http_user_agent ~ "feedfinder") {set $bad_ua 1;}
  if ($http_user_agent ~ "fhscan") {set $bad_ua 1;}
  if ($http_user_agent ~ "flaming") {set $bad_ua 1;}
  if ($http_user_agent ~ "flashget") {set $bad_ua 1;}
  if ($http_user_agent ~ "flicky") {set $bad_ua 1;}
  if ($http_user_agent ~ "foobot") {set $bad_ua 1;}
  if ($http_user_agent ~ "fuck") {set $bad_ua 1;}
  if ($http_user_agent ~ "g00g1e") {set $bad_ua 1;}
  if ($http_user_agent ~ "getright") {set $bad_ua 1;}
  if ($http_user_agent ~ "getweb!") {set $bad_ua 1;}
  if ($http_user_agent ~ "gigabot") {set $bad_ua 1;}
  if ($http_user_agent ~ "go!zilla") {set $bad_ua 1;}
  if ($http_user_agent ~ "go-ahead-got") {set $bad_ua 1;}
  if ($http_user_agent ~ "go-ahead-got-it") {set $bad_ua 1;}
  if ($http_user_agent ~ "gozilla") {set $bad_ua 1;}
  if ($http_user_agent ~ "grab") {set $bad_ua 1;}
  if ($http_user_agent ~ "grabnet") {set $bad_ua 1;}
  if ($http_user_agent ~ "grafula") {set $bad_ua 1;}
  if ($http_user_agent ~ "gt::www") {set $bad_ua 1;}
  if ($http_user_agent ~ "harvest") {set $bad_ua 1;}
  if ($http_user_agent ~ "heritrix") {set $bad_ua 1;}
  if ($http_user_agent ~ "hmview") {set $bad_ua 1;}
  if ($http_user_agent ~ "http::lite") {set $bad_ua 1;}
  if ($http_user_agent ~ "httrack") {set $bad_ua 1;}
  if ($http_user_agent ~ "httracks") {set $bad_ua 1;}
  if ($http_user_agent ~ "ia_archiver") {set $bad_ua 1;}
  if ($http_user_agent ~ "icarus6j") {set $bad_ua 1;}
  if ($http_user_agent ~ "id-search") {set $bad_ua 1;}
  if ($http_user_agent ~ "id-search.org") {set $bad_ua 1;}
  if ($http_user_agent ~ "idbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "image stripper") {set $bad_ua 1;}
  if ($http_user_agent ~ "image sucker") {set $bad_ua 1;}
  if ($http_user_agent ~ "indy library") {set $bad_ua 1;}
  if ($http_user_agent ~ "interget") {set $bad_ua 1;}
  if ($http_user_agent ~ "internet ninja") {set $bad_ua 1;}
  if ($http_user_agent ~ "internetseer.com") {set $bad_ua 1;}
  if ($http_user_agent ~ "irlbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "isc systems irc search 2.1") {set $bad_ua 1;}
  if ($http_user_agent ~ "jakarta") {set $bad_ua 1;}
  if ($http_user_agent ~ "java") {set $bad_ua 1;}
  if ($http_user_agent ~ "jetbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "jetcar") {set $bad_ua 1;}
  if ($http_user_agent ~ "jikespider") {set $bad_ua 1;}
  if ($http_user_agent ~ "joc web spider") {set $bad_ua 1;}
  if ($http_user_agent ~ "kmccrew") {set $bad_ua 1;}
  if ($http_user_agent ~ "larbin") {set $bad_ua 1;}
  if ($http_user_agent ~ "leechftp") {set $bad_ua 1;}
  if ($http_user_agent ~ "libweb") {set $bad_ua 1;}
  if ($http_user_agent ~ "libwww") {set $bad_ua 1;}
  if ($http_user_agent ~ "libwww-perl") {set $bad_ua 1;}
  if ($http_user_agent ~ "liebaofast") {set $bad_ua 1;}
  if ($http_user_agent ~ "linkscan") {set $bad_ua 1;}
  if ($http_user_agent ~ "linksmanager.com_bot") {set $bad_ua 1;}
  if ($http_user_agent ~ "linkwalker") {set $bad_ua 1;}
  if ($http_user_agent ~ "loader") {set $bad_ua 1;}
  if ($http_user_agent ~ "lwp-download") {set $bad_ua 1;}
  if ($http_user_agent ~ "lwp-trivial") {set $bad_ua 1;}
  if ($http_user_agent ~ "majestic") {set $bad_ua 1;}
  if ($http_user_agent ~ "mass downloader") {set $bad_ua 1;}
  if ($http_user_agent ~ "masscan") {set $bad_ua 1;}
  if ($http_user_agent ~ "maxthon") {set $bad_ua 1;}
  if ($http_user_agent ~ "mechanize") {set $bad_ua 1;}
  if ($http_user_agent ~ "mfc_tear_sample") {set $bad_ua 1;}
  if ($http_user_agent ~ "microsoft url control") {set $bad_ua 1;}
  if ($http_user_agent ~ "microsoft.url") {set $bad_ua 1;}
  if ($http_user_agent ~ "midown tool") {set $bad_ua 1;}
  if ($http_user_agent ~ "miner") {set $bad_ua 1;}
  if ($http_user_agent ~ "missigua locator") {set $bad_ua 1;}
  if ($http_user_agent ~ "mister pix") {set $bad_ua 1;}
  if ($http_user_agent ~ "mj12bot") {set $bad_ua 1;}
  if ($http_user_agent ~ "morfeus") {set $bad_ua 1;}
  if ($http_user_agent ~ "moveoverbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "msfrontpage") {set $bad_ua 1;}
  if ($http_user_agent ~ "navroad") {set $bad_ua 1;}
  if ($http_user_agent ~ "nearsite") {set $bad_ua 1;}
  if ($http_user_agent ~ "net vampire") {set $bad_ua 1;}
  if ($http_user_agent ~ "netants") {set $bad_ua 1;}
  if ($http_user_agent ~ "netmechanic") {set $bad_ua 1;}
  if ($http_user_agent ~ "netspider") {set $bad_ua 1;}
  if ($http_user_agent ~ "netzip") {set $bad_ua 1;}
  if ($http_user_agent ~ "newt") {set $bad_ua 1;}
  if ($http_user_agent ~ "nicerspro") {set $bad_ua 1;}
  if ($http_user_agent ~ "nikto") {set $bad_ua 1;}
  if ($http_user_agent ~ "ninja") {set $bad_ua 1;}
  if ($http_user_agent ~ "nominet") {set $bad_ua 1;}
  if ($http_user_agent ~ "nutch") {set $bad_ua 1;}
  if ($http_user_agent ~ "octopus") {set $bad_ua 1;}
  if ($http_user_agent ~ "offline explorer") {set $bad_ua 1;}
  if ($http_user_agent ~ "offline navigator") {set $bad_ua 1;}
  if ($http_user_agent ~ "pagegrabber") {set $bad_ua 1;}
  if ($http_user_agent ~ "panscient.com") {set $bad_ua 1;}
  if ($http_user_agent ~ "papa foto") {set $bad_ua 1;}
  if ($http_user_agent ~ "pavuk") {set $bad_ua 1;}
  if ($http_user_agent ~ "pcbrowser") {set $bad_ua 1;}
  if ($http_user_agent ~ "pecl::http") {set $bad_ua 1;}
  if ($http_user_agent ~ "peoplepal") {set $bad_ua 1;}
  if ($http_user_agent ~ "petalbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "phpcrawl") {set $bad_ua 1;}
  if ($http_user_agent ~ "phpshell") {set $bad_ua 1;}
  if ($http_user_agent ~ "planetwork") {set $bad_ua 1;}
  if ($http_user_agent ~ "pleasecrawl") {set $bad_ua 1;}
  if ($http_user_agent ~ "postrank") {set $bad_ua 1;}
  if ($http_user_agent ~ "proximic") {set $bad_ua 1;}
  if ($http_user_agent ~ "psbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "purebot") {set $bad_ua 1;}
  if ($http_user_agent ~ "queryn") {set $bad_ua 1;}
  if ($http_user_agent ~ "queryseeker") {set $bad_ua 1;}
  if ($http_user_agent ~ "radian6") {set $bad_ua 1;}
  if ($http_user_agent ~ "radiation") {set $bad_ua 1;}
  if ($http_user_agent ~ "realdownload") {set $bad_ua 1;}
  if ($http_user_agent ~ "reget") {set $bad_ua 1;}
  if ($http_user_agent ~ "remoteview") {set $bad_ua 1;}
  if ($http_user_agent ~ "rippers 0") {set $bad_ua 1;}
  if ($http_user_agent ~ "rogerbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "sbider") {set $bad_ua 1;}
  if ($http_user_agent ~ "scan") {set $bad_ua 1;}
  if ($http_user_agent ~ "scooter") {set $bad_ua 1;}
  if ($http_user_agent ~ "seamonkey") {set $bad_ua 1;}
  if ($http_user_agent ~ "seekerspid") {set $bad_ua 1;}
  if ($http_user_agent ~ "semalt") {set $bad_ua 1;}
  if ($http_user_agent ~ "siclab") {set $bad_ua 1;}
  if ($http_user_agent ~ "sindice") {set $bad_ua 1;}
  if ($http_user_agent ~ "sistrix") {set $bad_ua 1;}
  if ($http_user_agent ~ "sitebot") {set $bad_ua 1;}
  if ($http_user_agent ~ "sitecheck.internetseer.com") {set $bad_ua 1;}
  if ($http_user_agent ~ "sitecopier") {set $bad_ua 1;}
  if ($http_user_agent ~ "siteexplorer") {set $bad_ua 1;}
  if ($http_user_agent ~ "sitesnagger") {set $bad_ua 1;}
  if ($http_user_agent ~ "skygrid") {set $bad_ua 1;}
  if ($http_user_agent ~ "smartdownload") {set $bad_ua 1;}
  if ($http_user_agent ~ "snoopy") {set $bad_ua 1;}
  if ($http_user_agent ~ "sosospider") {set $bad_ua 1;}
  if ($http_user_agent ~ "spankbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "spbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "sqlmap") {set $bad_ua 1;}
  if ($http_user_agent ~ "stackrambler") {set $bad_ua 1;}
  if ($http_user_agent ~ "steeler") {set $bad_ua 1;}
  if ($http_user_agent ~ "stripper") {set $bad_ua 1;}
  if ($http_user_agent ~ "sucker") {set $bad_ua 1;}
  if ($http_user_agent ~ "superbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "superhttp") {set $bad_ua 1;}
  if ($http_user_agent ~ "surfbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "surftbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "sux0r") {set $bad_ua 1;}
  if ($http_user_agent ~ "suzukacz") {set $bad_ua 1;}
  if ($http_user_agent ~ "suzuran") {set $bad_ua 1;}
  if ($http_user_agent ~ "takeout") {set $bad_ua 1;}
  if ($http_user_agent ~ "teleport") {set $bad_ua 1;}
  if ($http_user_agent ~ "teleport pro") {set $bad_ua 1;}
  if ($http_user_agent ~ "telesoft") {set $bad_ua 1;}
  if ($http_user_agent ~ "toata dragostea mea pentru diavola") {set $bad_ua 1;}
  if ($http_user_agent ~ "true_robots") {set $bad_ua 1;}
  if ($http_user_agent ~ "turingos") {set $bad_ua 1;}
  if ($http_user_agent ~ "turnit") {set $bad_ua 1;}
  if ($http_user_agent ~ "turnitinbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "unserializ") {set $bad_ua 1;}
  if ($http_user_agent ~ "uri::fetch") {set $bad_ua 1;}
  if ($http_user_agent ~ "urllib") {set $bad_ua 1;}
  if ($http_user_agent ~ "vampire") {set $bad_ua 1;}
  if ($http_user_agent ~ "vikspider") {set $bad_ua 1;}
  if ($http_user_agent ~ "voideye") {set $bad_ua 1;}
  if ($http_user_agent ~ "web image collector") {set $bad_ua 1;}
  if ($http_user_agent ~ "web sucker") {set $bad_ua 1;}
  if ($http_user_agent ~ "webalta") {set $bad_ua 1;}
  if ($http_user_agent ~ "webauto") {set $bad_ua 1;}
  if ($http_user_agent ~ "webbandit") {set $bad_ua 1;}
  if ($http_user_agent ~ "webcollage") {set $bad_ua 1;}
  if ($http_user_agent ~ "webcopier") {set $bad_ua 1;}
  if ($http_user_agent ~ "webfetch") {set $bad_ua 1;}
  if ($http_user_agent ~ "webgo is") {set $bad_ua 1;}
  if ($http_user_agent ~ "webleacher") {set $bad_ua 1;}
  if ($http_user_agent ~ "webreaper") {set $bad_ua 1;}
  if ($http_user_agent ~ "websauger") {set $bad_ua 1;}
  if ($http_user_agent ~ "webshell") {set $bad_ua 1;}
  if ($http_user_agent ~ "website extractor") {set $bad_ua 1;}
  if ($http_user_agent ~ "website quester") {set $bad_ua 1;}
  if ($http_user_agent ~ "webstripper") {set $bad_ua 1;}
  if ($http_user_agent ~ "webvac") {set $bad_ua 1;}
  if ($http_user_agent ~ "webviewer") {set $bad_ua 1;}
  if ($http_user_agent ~ "webwhacker") {set $bad_ua 1;}
  if ($http_user_agent ~ "webzip") {set $bad_ua 1;}
  if ($http_user_agent ~ "wells search ii") {set $bad_ua 1;}
  if ($http_user_agent ~ "wep search") {set $bad_ua 1;}
  if ($http_user_agent ~ "widow") {set $bad_ua 1;}
  if ($http_user_agent ~ "winhttp") {set $bad_ua 1;}
  if ($http_user_agent ~ "woxbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "www-mechanize") {set $bad_ua 1;}
  if ($http_user_agent ~ "wwwoffle") {set $bad_ua 1;}
  if ($http_user_agent ~ "xaldon") {set $bad_ua 1;}
  if ($http_user_agent ~ "xaldon webspider") {set $bad_ua 1;}
  if ($http_user_agent ~ "xxxyy") {set $bad_ua 1;}
  if ($http_user_agent ~ "yamanalab") {set $bad_ua 1;}
  if ($http_user_agent ~ "yioopbot") {set $bad_ua 1;}
  if ($http_user_agent ~ "youda") {set $bad_ua 1;}
  if ($http_user_agent ~ "zermelo") {set $bad_ua 1;}
  if ($http_user_agent ~ "zeus") {set $bad_ua 1;}
  if ($http_user_agent ~ "zmeu") {set $bad_ua 1;}
  if ($http_user_agent ~ "zune") {set $bad_ua 1;}
  if ($http_user_agent ~ "zyborg") {set $bad_ua 1;}
  if ($bad_ua = 1) {return 403;}

  ######################################################################
  ## Block AI Bots from accessing the site based on user agent strings
  ## https://perishablepress.com/ultimate-ai-block-list/
  ######################################################################
  set $ai_bot 0;
  if ($http_user_agent ~* "(\.ai|-ai|_ai|ai\.|ai-|ai_|ai=|AddSearchBot|Agentic|AgentQL|Agent\ 3|Agent\ API|Agent-|AI\ Agent|AI\ Article\ Writer|AI\ Assistant|AI\ Chat|AI\ Content\ Detector|AI\ Detection|AI\ Dungeon)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(AI\ Journalist|AI\ Legion|AI\ RAG|AI\ Search|AI\ SEO\ Crawler|AI\ Training|AI\ Web|AI\ Writer|AI2|AIBot|aiHitBot|AIMatrix|Airesearch|AISearch|AITraining|Alexa|Alice\ Yandex|AliGenie|AliyunSec|Alpha\ AI)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(AlphaAI|Amazon|Amelia|AndersPinkBot|AndiBot|Anomura|Anonymous\ AI|Anthropic|AnyPicker|Anyword|Applebot|Aria\ AI|Aria\ Browse|Articoolo|Ask\ AI|Atlassian|AutoGen|Automated\ Writer|AutoML|Autonomous\ RAG)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(AutoRAG|Awario|AWS\ Trainium|Azure|BabyAGI|BabyCatAGI|BardBot|Basic\ RAG|Bedrock|Big\ Sur|Bigsur|Botsonic|Brightbot|Browser\ MCP\ Agent|Browser\ Use|BuddyBot|Bytebot|ByteDance|Bytespider|CarynAI)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(CatBoost|CC-Crawler|CCBot|Chai|Channel3Bot|Character|Charstar\ AI|Chatbot|Chatsonic|ChatUser|Chinchilla|Claude|ClearScope|Clearview|Cognitive\ AI|Cohere|Common\ Crawl|CommonCrawl|Compass|Content\ Harmony)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(Content\ King|Content\ Optimizer|Content\ Samurai|ContentAtScale|ContentBot|Contentedge|ContentShake|Conversion\ AI|Copilot|CopyAI|Copymatic|Copyscape|CoreWeave|Corrective\ RAG|Cotoyogi|CRAB|Crawl4AI|CrawlQ\ AI|Crawlspace|Crew\ AI)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(CrewAI|Crushon\ AI|Cypex|DALL-E|DarkBard|DarkBERT|DataFor|DataProvider|Datenbank\ Crawler|DeepAI|Deep\ AI|DeepL|DeepMind|Deep\ Research|DeepResearch|DeepSeek|Devin|Diffbot|Dolma|Doubao\ AI)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(DuckAssistBot|DuckDuckGo\ Chat|DuckDuckGo-Enhanced|Echobot|Echobox|Elixir|FacebookBot|FacebookExternalHit|Factset|Falcon|FIRE-1|Firebase|Firecrawl|Flyriver|Frase\ AI|FriendlyCrawler|Gato|Gemini|Gemma|Gen\ AI)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(GenAI|Generative|Genspark|Gentoo-chat|Ghostwriter|GigaChat|GLM|GodMode|Goose|GPT|Grammarly|Grendizer|Grok|Groq|GT\ Bot|GTBot|GTP|Hemingway\ Editor|Hetzner|Hugging)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(Hunyuan|Hybrid\ Search\ RAG|Hypotenuse\ AI|iAsk|IbouBot|ICC-Crawler|Ideogram|ImageGen|Imagen|ImagesiftBot|ImageSpider|img2dataset|imgproxy|INK\ Editor|INKforall|Instructor|IntelliSeek|Inferkit|ISSCyberRiskCrawler|Janitor\ AI)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(Jasper|Jenni\ AI|Julius\ AI|Kafkai|Kaggle|Kangaroo|Keyword\ Density\ AI|Kimi|Klaviyo|Knowledge|KomoBot|Kruti|KunatoCrawler|LAIONDownloader|LangChain|Langfuse|Language\ AI|Le\ Chat|Lensa|Leonardo)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(Lightpanda|LightRAG|LinerBot|LinkupBot|LLaMA|LCC|LLM|Local\ RAG\ Agent|Lovable|Magistral|magpie-crawler|MAI-Image|Manus|MarketMuse|MBZUAI|Meltwater|Meta-AI|Meta-External|Meta-Webindexer|Meta\ AI)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(MetaAI|MetaTagBot|Middleware|Midjourney|Mini\ AGI|MiniMax|Mintlify|Mistral|Mixtral|model-training|Molmo|Monica|Nano|Narrative|NeevaBot|netEstate|Neural\ Text|NeuralSEO|NinjaAI|NodeZero)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(NotebookLM|Nova\ Act|NovaAct|Nytheon|OAI-SearchBot|OAI\ SearchBot|OASIS|Olivia|OLM|Omgili|Onyx|Open\ AI|Open\ Interpreter|OpenAGI|OpenAI|OpenBot|OpenInterpreter|OpenPi|OpenRouter|OpenText\ AI)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(Operator|Outwrite|OVHcloud|Owlin|Page\ Analyzer\ AI|PaLM\ 2|PanguBot|Panscient|Paperlibot|Paraphraser\.io|peer39_crawler|Perflexity|Perplexity|Petal|Phind|PiplBot|Pixmo|Playwright|PoeBot|PoeSearchBot)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(Poggio|Poseidon|ProWritingAid|Proximic|PulsarRPA|Puppeteer|Python\ AI|Python\ lxml|PyTorch|Qualified|Quark|QuillBot|Qopywriter|Qwen|RAG\ Agent|RAG\ Azure\ AI|RAG\ Chatbot|RAG\ Database|RAG\ IS|RAG\ Pipeline)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(RAG\ Search|RAG\ with|RAG-|RAG_|Raptor|React\ Agent|Reasoning|Redis\ AI\ RAG|Reka\ Flash|Replicate|RobotSpider|RunPod|Rytr|SaplingAI|SBIntuitionsBot|Scala|Scalenut|Scrap|ScriptBook|Seekr)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(SEObot|SEO\ Content\ Machine|SEO\ Robot|SemrushBot|Sentibot|Serper|ShapBot|Sidetrade|Simplified\ AI|Sitefinity|Skydancer|Skyvern|SlickWrite|SmartBot|Sonic|Sora|Spider/2|SpiderCreator|Spin\ Rewrite|Spinbot)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(Stability|Stable\ Diffusion|StableDiffusionBot|Stagehand|Stealth|Sudowrite|SummalyBot|Super\ Agent|Superagent|SuperAGI|Surfer\ AI|Taiko|TavilyBot|TerraCotta|Text\ Blaze|TextCortex|Thinkbot|Thordata|TikTokSpider|Timpibot)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(Tinybird|Together|Traefik|Tulu|Tülu|TurnitinBot|TwinAgent|uAgents|UI-TARS|VelenPublicWebCrawler|Venus\ Chub\ AI|Vidnami\ AI|Vision\ RAG|WARDBot|WebSurfer|WebText|WebVoyager|Webzio|WeChat|Whisper)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(WordAI|Wordtune|WPBot|Writecream|WriterZen|Writescope|Writesonic|WRTNBot|xAI|Xanthorox|xBot|XLNet|YaK|YaML|YandexAdditional|YouBot|Zanista|Zendesk|Zero|Zhipu)") {set $ai_bot 1;}
  if ($http_user_agent ~* "(Zhuque\ AI|Zimm)") {set $ai_bot 1;}
  if ($bad_ua = 1) {return 403;}

  location ~ /.well-known {
    auth_basic off;
    allow all;
  }

  {{settings}}

  include /etc/nginx/global_settings;

  ######################################################################
  ## Block access to common Joomla sensitive files in NginX
  ######################################################################
  location = /configuration.php {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /configuration.php-dist {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /CONTRIBUTING.md {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /htaccess.txt {
      log_not_found off;
      deny all;
      return 404;
  }
  location = /joomla.xml {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /LICENSE.txt {
    log_not_found off;
    deny all;
    return 404;
  }
  location /phpunit.xml {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /README.txt {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /web.config {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /language/en-GB/install.xml {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /language/en-GB/langmetadata.xml {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /language/nl-NL/install.xml {
    log_not_found off;
    deny all;
    return 404;
  }
  location = /language/nl-NL/langmetadata.xml {
    log_not_found off;
    deny all;
    return 404;
  }

  ######################################################################
  ## Block access to common Joomla sensitive folders
  ######################################################################
  location ^~ /logs/ {
    log_not_found off;
    deny all;
    return 404;
  }

  location ^~ /administrator/logs/ {
    log_not_found off;
    deny all;
    return 404;
  }

  try_files $uri $uri/ /index.php?$args;
  index index.php index.html;

  location ~ \.php$ {
    include fastcgi_params;
    fastcgi_intercept_errors on;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    try_files $uri =404;
    fastcgi_read_timeout 3600;
    fastcgi_send_timeout 3600;
    fastcgi_param HTTPS $fastcgi_https;
    fastcgi_pass 127.0.0.1:{{php_fpm_port}};
    fastcgi_param PHP_VALUE "{{php_settings}}";
  }

  location ~* ^.+\.(css|js|jpg|jpeg|gif|png|ico|gz|svg|svgz|ttf|otf|woff|woff2|eot|mp4|ogg|ogv|webm|webp|zip|swf)$ {
    add_header Access-Control-Allow-Origin "*";
    add_header alt-svc 'h3=":443"; ma=86400';
    expires max;
    access_log off;
  }

  location /api/ {
    try_files $uri $uri/ /api/index.php?$args;
  }

  if (-f $request_filename) {
    break;
  }
}
