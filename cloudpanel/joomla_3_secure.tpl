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

  # -- Maximum client body size set to 1 Gigabyte
  client_max_body_size 1G;

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
  ## Disable PHP Easter Eggs
  ######################################################################
  if ($query_string ~ "\=PHP[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}") {return 403;}
  
  # add global x-content-type-options header
  add_header X-Content-Type-Options nosniff;

  ######################################################################
  ## Block Bad Bots from accessing the site based on user agent strings
  ## https://perishablepress.com/ultimate-htaccess-blacklist/
  ######################################################################
  set $bad_bot 0;
  if ($http_user_agent ~* "(almaden|^Anarchie|^ASPSeek|^attach|^autoemailspider|^BackWeb|^Bandit|^BatchFTP|^BlackWidow|^Bot\ mailto:craftbot@yahoo\.com|^Buddy|^bumblebee|^CherryPicker|^ChinaClaw|^CICC|^Collector|^Copier|^Crescent|^Custo|^DA)") {set $bad_bot 1;}
  if ($http_user_agent ~* "(^DIIbot|^DISCo\ Pump|^DISCo|^Download\ Demon|^Download\ Wonder|^Downloader|^Drip|^DSurf15a|^eCatch|^EasyDL/2\.99|^EirGrabber|email|^EmailCollector|^EmailSiphon|^EmailWolf|^Express\ WebPictures|^ExtractorPro|^EyeNetIE|^FileHound|^FlashGet)") {set $bad_bot 1;}
  if ($http_user_agent ~* "(FrontPage|^GetRight|^GetSmart|^GetWeb!|^gigabaz|^Go!Zilla|^Go-Ahead-Got-It|^gotit|^Grabber|^GrabNet|^Grafula|^grub-client|^HMView|^HTTrack|^httpdown|httrack|^ia_archiver|^Image\ Stripper|^Image\ Sucker|^Indy.*Library)") {set $bad_bot 1;}
  if ($http_user_agent ~* "(Indy\ Library|^InterGET|^InternetLinkagent|^Internet\ Ninja|^InternetSeer\.com|^Iria|^JBH.*agent|^JetCar|^JOC\ Web\ Spider|^JustView|^larbin|^LeechFTP|^LexiBot|^lftp|^Link.*Sleuth|^likse|^Link|^LinkWalker|^Mag-Net|^Magnet)") {set $bad_bot 1;}
  if ($http_user_agent ~* "(^Mass\ Downloader|^Memo|^Microsoft\.URL|^MIDown\ tool|^Mirror|^Mister\ PiX|^Mozilla.*Indy|^Mozilla.*NEWT|^Mozilla.*MSIECrawler|^MS\ FrontPage|^MSFrontPage|^MSIECrawler|^MSProxy|^Navroad|^NearSite|^NetAnts|^NetMechanic|^NetSpider|^Net\ Vampire|^NetZIP)") {set $bad_bot 1;}
  if ($http_user_agent ~* "(^NICErsPRO|^Ninja|^Octopus|^Offline\ Explorer|^Offline\ Navigator|^Openfind|^PageGrabber|^Papa\ Foto|^pavuk|^pcBrowser|^Ping|^PingALink|^Pockey|^psbot|^Pump|^QRVA|^RealDownload|^Reaper|^Recorder|^ReGet)") {set $bad_bot 1;}
  if ($http_user_agent ~* "(^Scooter|^Seeker|^Siphon|^sitecheck\.internetseer\.com|^SiteSnagger|^SlySearch|^SmartDownload|^Snake|^SpaceBison|^sproose|^Stripper|^Sucker|^SuperBot|^SuperHTTP|^Surfbot|^Szukacz|^tAkeOut|^Teleport\ Pro|^URLSpiderPro|^Vacuum)") {set $bad_bot 1;}
  if ($http_user_agent ~* "(^VoidEYE|^Web\ Image\ Collector|^Web\ Sucker|^WebAuto|^[Ww]eb[Bb]andit|^webcollage|^WebCopier|^Web\ Downloader|^WebEMailExtrac|^WebFetch|^WebGo\ IS|^WebHook|^WebLeacher|^WebMiner|^WebMirror|^WebReaper|^WebSauger|^Website\ eXtractor|^Website\ Quester|^Website)") {set $bad_bot 1;}
  if ($http_user_agent ~* "(^Webster|^WebStripper|WebWhacker|^WebZIP|^Wget|^Whacker|^Widow|^WWWOFFLE|^x-Tractor|^Xaldon\ WebSpider|^Xenu|^Zeus.*Webster|^Zeus)") {set $bad_bot 1;}
  if ($bad_bot = 1) {return 403;}

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
  if ($ai_bot = 1) {return 403;}

  location ~ /.well-known {
    auth_basic off;
    allow all;
  }

  {{settings}}

  include /etc/nginx/global_settings;

  ######################################################################
  ## Block access to common Joomla sensitive files in NginX
  ######################################################################
  # Block sensitive root-level files
  location ~* ^/(configuration\.php(-dist)?|CONTRIBUTING\.md|htaccess\.txt|joomla\.xml|LICENSE\.txt|phpunit\.xml|README\.txt|robots\.txt\.dist|web\.config)$ {
    log_not_found off;
    deny all;
    return 404;
  }

  # Block access to language metadata files
  location ~* ^/language/[a-z][a-z]-[A-Z][A-Z]/(install|langmetadata)\.xml$ {
    log_not_found off;
    deny all;
    return 404;
  }

  ######################################################################
  ## Block access to common Joomla sensitive folders
  ######################################################################
  location ~* ^/(administrator/)?logs/ {
    log_not_found off;
    deny all;
    return 404;
  }

  ######################################################################
  ## Password protect access to /administrator
  ## Uncomment the lines below if you want to prevent access
  ######################################################################
  # location /administrator {
  #   satisfy any;
  #
  #   # Add ip addresses here you want to whitelist
  #   # First IP
  #   allow 1.2.3.4
  #   # Second ip
  #   allow 5.6.6.7.8
  #   deny all;
  #
  #   auth_basic "Restricted Area";
  #   # Add path here to .htpasswd file
  #   # See https://www.cyberciti.biz/faq/create-update-user-authentication-files/
  #   auth_basic_user_file /path/to/your/.htpasswd;
  # }

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

  if (-f $request_filename) {
    break;
  }
}
