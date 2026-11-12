# Product-role classifier for any CVE record. Same rules for every CVE (no use of exploitation data).
# Order: source-based plug-in rule -> vendor table (exact CPE/CNA vendor) -> bounded keyword rules on product names + description head -> fallbacks.
import re
WP_SRC={'security@wordfence.com','audit@patchstack.com','contact@wpscan.com'}
OSS_SRC={'security-advisories@github.com','security@huntr.dev','security@huntr.com','report@snyk.io','security@apache.org','security@golang.org','security@python.org','security@php.net','cna@python.org','security@nodejs.org','openssl-security@openssl.org','security@eclipse.org','cve@kernel.org'}
ICS_SRC={'ics-cert@hq.dhs.gov','productcert@siemens.com','cybersecurity@se.com','psirt@moxa.com','cybersecurity@ch.abb.com','info@cert.vde.com','psirt@bosch.com','psirt@rockwellautomation.com','cybersecurity@hitachienergy.com','ot-cert@dragos.com','psirt@honeywell.com','security@codesys.com','productsecurity@jci.com','psirt@emerson.com','security@selinc.com','psirt@sick.de','cert@ncsc.nl-ics'}
def B(alts): return re.compile(r"(?<![a-z0-9])(?:"+alts+r")(?![a-z0-9])")
def S(s): return set(x.strip() for x in s.split('|') if x.strip())

# ---------- vendor table (exact match on CPE vendor / CNA vendor, lowercased, underscores->spaces)
IOT=S("plex|emby|jellyfin|thecus|goabode|abode|ip-com|raspap|nec|dd-wrt|netis|tenda|tendacn|d-link|dlink|netgear|tp-link|tplink|totolink|linksys|wavlink|lb-link|trendnet|edimax|belkin|buffalo|buffalo inc|comfast|cudy|mercusys|phicomm|jcg|intelbras|dasan|dasannetworks|nexxt|digisol|iball|sagemcom|arris|technicolor|actiontec|teltonika|teltonika-networks|teltonika networks|four-faith|fourfaith|sierrawireless|sierra wireless|inhandnetworks|inhand networks|hikvision|dahuasecurity|dahua|reolink|wyze|uniview|avtech|tvt|nuuo|geovision|foscam|amcrest|vivotek|qnap|qnap systems inc.|synology|westerndigital|western digital|wdc|seagate|terra-master|terramaster|asustor|netis-systems|netis|zioncom|utt|h3c|ruijie|ruijienetworks|ruijie networks|mikrotik|ubiquiti|ui|ubnt|ubiquiti inc|draytek|netcore|kguard|lilin|meritlilin|tbkvision|zavio|ezviz|swann|lorex|annke|axis|axis communications ab|hanwhavision|hanwha vision|grandstream|yealink|polycom|poly|snom|fanvil|akuvox|2n|sonos|roku|ecobee|meross|tuya|shelly|sonoff|govee|eufy|anker|ecovacs|roborock|dji|garmin|fitbit|epson|brother|lexmark|xerox|kyocera|ricoh|konicaminolta|konica minolta|fujifilm|fujixerox|toshibatec|zebra|planet|cdatatec|c-data|zte|vstarcam|wansview|raisecom|billion|comtrend|zhone|dzs|calix|adtran|optilink|arlo|nest|ring|wemo|imou|xiongmai|jooan|sricam|engenius|airlive|level1|levelone|digitus|iodata|i-o data|i-o data device, inc.|elecom|elecom co.,ltd.|logitec|planex|corega|pantum|oki|olivetti|flir|mobotix|pelco|verkada|avigilon|milesight|tiandy|provision-isr|hichip|chamberlain|somfy|netatmo|signify|xiaomi|canon|canon inc.|sharp|sony|panasonic|yamaha|lg|lge|vizio|tcl|hisense|philips|tenda technology|shenzhen tenda technology co.,ltd.|ctek|ctekproducts|kalay|throughtek|cp plus|cpplus|d-view|edgecore|iptime|efm|efm-networks|zioncom|totolink|tp-link systems inc.|d-link corporation|netgear, inc.|linksys holdings|gl-inet|gl.inet|glinet|glidnet|openwrt|dd-wrt|tomato|asuswrt-merlin|padavan|keenetic|zyxel-keenetic|tenda|nexxt solutions|blink|cradlepoint|peplink|pepwave|ruckuswireless|ruckus|ruckus wireless|commscope|tp-link technologies|motorola|binatone|hubble|owlet|furbo|petcube|wyze labs|simplisafe|abode|vivint|adt|august|yale|schlage|kwikset|ultraloq|nuki|tapo|kasa|aqara|switchbot|broadlink|insteon|hubitat|smartthings|wink|lutron|leviton|ge appliances|whirlpool|miele|bosch home|ikea|sengled|lifx|nanoleaf|wiz|yeelight")
EDGE=S("paloaltonetworks|palo alto networks|f5|juniper|juniper networks|watchguard|barracuda|barracuda networks|arista|arista networks|versa-networks|versa|arraynetworks|array networks|aviatrix|sangfor|hillstone|hillstonenet|stormshield|netgate|pfsense|opnsense|a10networks|radware|kemptechnologies|kemp|brocade|extremenetworks|extreme networks|arubanetworks|aruba|silver-peak|riverbed|infoblox|bluecoat|clavister|untangle|endian|ipfire|vyos|netmotion|lancom|lancom-systems|bintec|mimecast|ironport|squid-cache|haproxy|envoyproxy|traefik|konghq|kong|nginx|f5 networks|zscaler|netskope|cato networks|fatpipe|fatpipeinc|alliedtelesis|allied telesis|allied-telesis|netscaler|pulsesecure|pulse secure|sonicwall|fortinet|check point|checkpoint|sophos|cisco|citrix|ivanti|zyxel|securepoint|kerio|gfi|smoothwall|sonicwall inc.|hpe aruba networking|silverpeak|akamai|imperva|netography|nokia|ericsson|ciena|infinera|adva|ribbon|casa systems|casa|mavenir|parallel wireless|airspan|baicells|kyland|h3c technologies")
CLIENT=S("arm|tonybybell|gtkwave|freerdp|ansys|dassault|dassault systemes|dassault systèmes|apple|mozilla|opera|whatsapp|rarlab|7-zip|videolan|foxit|foxitsoftware|foxit software|telemessage|zoom|teamviewer|anydesk|slack|discord|signal|telegram|viber|line|linecorp|wechat|skype|libreoffice|the document foundation|openoffice|kingsoft|wps|hancom|irfanview|xnview|autodesk|bentley|ashlar|ashlar-vellum|luxion|tracker-software|pdf-xchange|pdf-xchange co. ltd|kofax|tungsten|tungstenautomation|tungsten automation|nitro|gonitro|corel|sketchup|opendesign|open design alliance|santesoft|nikon|gimp|inkscape|blender|vim|notepad-plus-plus|putty|winscp|thunderbird|valvesoftware|valve|epicgames|mojang|obsidian|typora|marktext|joplin|joplinapp|notion|evernote|cursor|anysphere|anthropic|openai|windsurf|codeium|sublimetext|brave|vivaldi|kakao|acer|msi|gigabyte|asrock|razer|logitech|corsair|steelseries|synaptics|realtek|wacom|parallels|qemu|malwarebytes|avast|avg|avira|norton|nortonlifelock|gen digital|f-secure|panda|pandasecurity|comodo|360totalsecurity|qihoo|webroot|zonealarm|1password|agilebits|lastpass|keepass|dashlane|nordvpn|expressvpn|protonvpn|proton|surfshark|mullvad|wireguard|tunnelblick|qualcomm|mediatek|imaginationtech|amd|android|samsung mobile|google|microsoft|adobe|samsung|intel|nvidia|lenovo|dell|hp|asus|huawei|oracle|vmware|eset|kaspersky|bitdefender|mcafee|trendmicro|trend micro|symantec|broadcom|jetbrains|naver|tencent|bytedance|baidu|sogou|iobit|ccleaner|piriform|glarysoft|wondershare|tenorshare|easeus|aomei|minitool|cyberlink|nero|ashampoo|winzip|peazip|bandisoft|bandizip|winamp|foobar2000|audacity|obsproject|handbrake|kodi|xbmc|steam|ea|electronicarts|ubisoft|blizzard|riotgames|rockstargames|unity3d|nomachine|xmind|freemind|drawio|jgraph|postman|insomnia|kong insomnia|gitkraken|sourcetree|tortoisegit|tortoisesvn|github desktop|termius|mobatek|mobaxterm|securecrt|vandyke|xshell|netsarang|bitvise|wireshark|nmap|fiddler|charles|burp|zotero|calibre|sumatrapdf|okular|evince|xpdfreader|soda pdf|pdfforge|pdf24|pdfsam|icecream|iskysoft|movavi|camtasia|techsmith|snagit|greenshot|sharex|lightshot|flameshot|paint.net|krita|affinity|serif|figma|sketch|zeplin|invision|canva")
SRVX=S("nextgen|nextgen healthcare|openclaw|wwbn|dokploy|coollabsio|coolify|github|byzoro|hgiga|sap se|pi-hole|onlyoffice|teclib|glpi-project|sugarcrm|dotcms|thinkphp|micro focus|wso2|zimbra|synacor|roundcube|exim|smartertools|sendmail|postfix|mdaemon|icewarp|squirrelmail|horde|rainloop|snappymail|afterlogic|axigen|mailenable|hmailserver|mailcow|dovecot|sogo|open-xchange|kopano|zarafa|progress|ipswitch|fortra|helpsystems|accellion|kiteworks|crushftp|cleo|solarwinds-servu|wftpserver|gladinet|owncloud|nextcloud|soliton|rejetto|southrivertech|cerberusftp|globalscape|filecloud|codelathe|seafile|pydio|atlassian|sitecore|kentico|craftcms|wordpress|drupal|joomla|dnnsoftware|telerik|vbulletin|magento|liferay|umbraco|typo3|octobercms|cyberpanel|centos-webpanel|control-webpanel|plesk|cpanel|webmin|zoneminder|opencart|prestashop|gitea|gogs|forgejo|discourse|xwiki|boltcms|concretecms|concrete5|silverstripe|contao|modx|pimcore|shopware|oscommerce|zen-cart|cs-cart|nopcommerce|strapi|directus|ghost|getgrav|getkirby|statamic|textpattern|s9y|b2evolution|e107|phpbb|mybb|simplemachines|xenforo|invisioncommunity|flarum|nodebb|vanillaforums|xoops|cmsmadesimple|pluck-cms|wondercms|get-simple|intelliants|fuelcms|pagekit|backdropcms|processwire|expressionengine|ibexa|dedecms|phpcms|ecshop|wuzhicms|seacms|zzcms|eyoucms|emlog|typecho|zblogcn|pbootcms|metinfo|jeecg|ruoyi|weaver|yonyou|seeyon|tongda2000|tongda|kingdee|landray|fanruan|jeesite|halo|maccms|74cms|niushop|thinkcmf|fastadmin|yzmcms|xunruicms|ourphp|beescms|sdcms|tpshop|shopxo|crmeb|rockoa|zentao|easycorp|chanzhi|discuz|comsenz|phpwind|phome|empirecms|dotcms|magnolia-cms|alkacon|jahia|hestiacp|vestacp|aapanel|bt|ispconfig|directadmin|froxlor|whmcs|ajenti|litespeedtech|caddyserver|lighttpd|php|rubyonrails|djangoproject|laravel|symfony|codeigniter|cakephp|yiiframework|thinkphp|topthink|zend|laminas|pivotal software|pivotal|vercel|palletsprojects|odoo|frappe|erpnext|dolibarr|vtiger|sugarcrm|salesagility|espocrm|civicrm|orangehrm|akaunting|invoiceninja|kimai|leantime|kanboard|redmine|mantisbt|bugzilla|phacility|openproject|osticket|otrs|znuny|zammad|freescout|glpi-project|teclib-edition|combodo|ocsinventory-ng|snipeitapp|librenms|observium|cacti|nagios|zabbix|icinga|centreon|pandorafms|artica|opsview|netdata|grafana|phpmyadmin|adminer|pgadmin|moodle|chamilo|instructure|sakailms|ilias|mahara|koha|dspace|pkp|mediawiki|dokuwiki|bookstackapp|requarks|tiki|bludit|pixelfed|joinmastodon|misskey|peertube|matrix|rocket.chat|mattermost|zulip|jitsi|bigbluebutton|igniterealtime|ejabberd|jenkins|gitlab|sonarsource|sonatype|jfrog|goharbor|rundeck|pagerduty|argoproj|n8n|nodered|budibase|appsmith|tooljet|nocodb|supabase|appwrite|pocketbase|metabase|redash|jupyter|rstudio|posit|mlflow|lfprojects|kubeflow|anyscale|langflow|langflow-ai|litellm|berriai|langgenius|flowiseai|openwebui|open-webui|ollama|mudler|parisneo|oobabooga|comfy|comfyanonymous|automatic1111|invoke|gradio|gradio-app|streamlit|chainlit|mintplexlabs|lobehub|danny-avila|librechat|infiniflow|maxkb|1panel|fit2cloud|quivr|h2o|h2oai|bentoml|zenml|mage|prefect|dagster|humansignal|clearml|allegroai|qdrant|weaviate|milvus|vllm|skypilot|xorbits|significant-gravitas|geekan|crewai|binary-husky|khoj|onyx|vanna-ai|sinaptik|connectwise|simple-help|simplehelp|kaseya|beyondtrust|n-able|bomgar|rustdesk|splashtop|logmein|dameware|meshcentral|netsupport|realvnc|uvnc|tightvnc|tigervnc|sysaid|zohocorp|manageengine|zoho|tibco|pega|pegasystems|opentext|microfocus|micro focus|novell|netiq|hcltech|hcl software|hclsoftware|bmc|infor|epicor|sage|hyland|alfresco|nuxeo|m-files|docuware|laserfiche|mitel|freepbx|sangoma|trueconf|3cx|asterisk|digium|avaya|freeswitch|signalwire|kamailio|issabel|elastix|vicidial|fusionpbx|unify|atos|alcatel-lucent|al-enterprise|audiocodes|genesys|yeastar|geoserver|osgeo|geosolutionsgroup|apache-superset|samsung magicinfo|trimble|papercut|commvault command|sitefinity|whatsupgold|qlik|servicenow|salesforce|oracle e-business|pentaho|hitachi vantara|ibm|redhat|red hat|suse|craft cms|cms made simple|october|wbce|pluxml|dotclear|spip|jorani|piwigo|chevereto|lychee|photoprism|immich|nextcloud gmbh|mailpit|mailhog|postal|listmonk|mautic|acquia|phplist|limesurvey|formtools|formalms|opensis|os4ed|rosariosis|fedena|gibbon|gibbonedu|openeclass|gunet|webid|classcms|feehicms|icms|idreamsoft|jizhicms|lmxcms|semcms|zzzcms|bagecms|taogogo|kitecms|myucms|duxcms|xyhcms|mipcms|qibosoft|sscms|siteserver|dtcms|foosun|kesion|aspcms|pageadmin|powereasy|hdwiki|wcms|baigo|inxedu|jspxcms|jfinalcms|jpress|publiccms|ujcms|mingsoft|mcms|jeecms|jeewms|jflow|ccflow|oa systems|oasys|o2oa|zhiyuan|ezoffice|wanhu|tongweb|tongtech|dahua icc|hikvision ivms|springblade|bladex|ruoyi-vue|yudao|pig4cld|lilishop|macrozheng|mall|newbee-mall|litemall|jshop|jshERP|jsherp|huaxia|erpnext|nacos|dolphinscheduler|xxl-job|xuxueli|powerjob|datax|datagear|datart|dataease|davinci|kkfileview|keking|onlyoffice|ascensio|collabora|etherpad|hedgedoc|outline|affine|appflowy|trilium|siyuan|b3log|solo|symphony|wekan|planka|focalboard|vikunja|plane|makeplane|taiga|kanboard|leantime|orangescrum|qdpm|projeqtor|web2project|rukovoditel|dotproject|phprojekt|egroupware|group-office|intermesh|kopano|tine20|tine|sogo|inverse|opencrx|vtiger|yetiforce|x2engine|zurmo|corebos|fatfreecrm|krayin|monica|twenty|erxes|chatwoot|papercups|tawk|livehelperchat|livezilla|mibew|osticket|hesk|phpmyfaq|thorsten|faqforge|bolt|lime|limesurvey gmbh")
SRVI=S("veeam|veritas|commvault|nakivo|acronis|arcserve|ahsay|rubrik|cohesity|unitrends|bacula|bareos|druva|quest|emc|rsa|netapp|hitachi|hitachivantara|purestorage|hpe|hewlett packard enterprise|supermicro|inspur|ami|aten|raritan|vertiv|apc|eaton|cyberpower|solarwinds|paessler|elastic|elasticsearch|splunk|mongodb|redis|couchbase|postgresql|mysql|mariadb|percona|influxdata|clickhouse|cockroachlabs|neo4j|arangodb|orientdb|memcached|etcd|hashicorp|docker|mobyproject|containerd|linuxfoundation|kubernetes|rancher|helm|istio|minio|ceph|rabbitmq|nats|emqx|eclipse mosquitto|hazelcast|prestodb|trino|airbyte|talend|informatica|saltstack|saltproject|ansible|puppet|chef|theforeman|cobbler|lansweeper|jamf|soti|42gears|baramundi|matrix42|tanium|qualys|tenable|rapid7|portswigger|acunetix|invicti|greenbone|wazuh|ossec|alienvault|graylog|logpoint|logrhythm|exabeam|datadog|newrelic|dynatrace|sentry|sciencelogic|checkmk|tribe29|crowdstrike|sentinelone|cylance|blackberry|cybereason|forescout|cyberark|thycotic|delinea|centrify|okta|pingidentity|forgerock|keycloak|gluu|wso2|auth0|goauthentik|authelia|casdoor|zitadel|freeipa|samba|openldap|openssl|openssh|libssh|imprivata|onelogin|entrust|thalesgroup|gemalto|hid|yubico|digicert|venafi|keyfactor|primekey|printerlogic|vasion|ysoft|nuance|3ds|dassault|ptc|tableau|microstrategy|sisense|domo|thoughtspot|yellowfin|jaspersoft|sas|alteryx|knime|dataiku|databricks|cloudera|teradata|vertica|snowflake|nutanix|xen|xenproject|proxmox|libvirt|ovirt|openstack|opennebula|carbonblack|trellix|fireeye|kaseya unitrends|zerto|datto|storagecraft|synology active|open-emr|openemr|cacti group|pandora|op5|nagios enterprises|ivanti epm|landesk|microsoft sql|oracle database|sap hana|vmware vcenter|jetbrains teamcity|teamcity|gocd|thoughtworks|drone|buildkite|octopus|octopusdeploy|spinnaker|concourse|harness|circleci|travis-ci|bamboo|argo|flux|fluxcd|tekton|crossplane|pulumi|terraform|vault|consul|nomad|boundary|waypoint|packer|vagrant|virtualbox|kvm|qemu-kvm|hyperv|esxi|vsphere")
ICS=S("ni|national instruments|siretta|silabs|silicon labs|solarview|contec|siemens|schneider-electric|schneider electric|rockwellautomation|rockwell automation|deltaww|delta electronics|advantech|mitsubishielectric|mitsubishi electric|omron|abb|ge|gevernova|ge vernova|ge digital|emerson|honeywell|moxa|wago|phoenixcontact|phoenix contact|codesys|openplcproject|unitronics|aveva|inductiveautomation|inductive automation|iconics|fujielectric|fuji electric|fatek|we-con|wecon|weintek|wellintech|yokogawa|hitachienergy|hitachi energy|beckhoff|br-automation|b&r|pilz|sick|festo|lenze|keyence|hornerautomation|redlion|red lion|prosoft-technology|hms-networks|hms|ewon|westermo|korenix|lantronix|perle|digi|opto22|automationdirect|ecava|progea|copadata|copa-data|trihedral|johnsoncontrols|johnson controls|tridium|carrier|automatedlogic|distech-controls|trane|opcfoundation|softing|matrikon|kepware|trianglemicroworks|osisoft|aspentech|bently|bakerhughes|selinc|schweitzer engineering laboratories|medtronic|baxter|bd|philips healthcare|gehealthcare|ge healthcare|siemens-healthineers|hologic|abbott|bostonscientific|biotronik|draeger|hillrom|welchallyn|dcm4che|orthanc-server|osirix|softneta|microdicom|autel|chargepoint|wallbox|enelx|tesla|bmw|mercedes-benz|volkswagen|toyota|nissan|hyundai|kia|ford|harman|alpine|pioneer|kenwood|blackberry qnx|windriver|wind river|freertos|zephyrproject|zephyrproject-rtos|contiki-ng|riot-os|arm mbed|apache nuttx|rt-thread|treck|interniche|oryx-embedded|lwip|denx|u-boot|tianocore|insyde|phoenixtechnologies|circutor|sma|solaredge|growatt|sungrow|enphase|fronius|goodwe|deye|solarman|solarview|contec|solar-log|socomec|riello|janitza|landis+gyr|itron|elster|kamstrup|iskra|carlo gavazzi|carlogavazzi|loytec|saia|sbc|sauter|priva|kieback|kieback&peter|wago kontakttechnik|turck|ifm|pepperl+fuchs|balluff|baumer|endress+hauser|krohne|vega|samson|metso|valmet|andritz|kuka|fanuc|yaskawa|universal robots|abb robotics|staubli|denso|epson robots|kawasaki|nachi|comau|doosan|techman|mir|mobile industrial robots|fetch robotics|boston dynamics|unitree|dji enterprise|zebra technologies|honeywell intelligent|datalogic|cognex|sato|tsc|bixolon|citizen|star micronics|epson pos|ncr|diebold|diebold nixdorf|verifone|ingenico|pax|pax technology|nayax|crane|cantaloupe|gilbarco|veeder-root|dover|wayne|franklin fueling|opw|orpak|dresser|tokheim|tatsuno|bennett|petrovend|fuelmaster|syntech|trak|e.j. ward|multiforce|piusi")
COMP=S("langchain|langchain-ai|llamaindex|run-llama|cloudflare|xstream project|picklescan|accusoft|libbiosig project|libbiosig|axiosys|gpac|swftools|cgal|democritus|color|vm2 project|nostromo|webrtc|webrtc project|ajax.net professional|laravel|apache|linux|gnu|debian|canonical|fedoraproject|opensuse|freebsd|netbsd|openbsd|nodejs|python|perl|ruby-lang|golang|rust-lang|eclipse|imagemagick|graphicsmagick|artifex|libpng|libtiff|zlib|busybox|thekelleys|isc|nlnetlabs|powerdns|haxx|curl|git|git-scm|git for windows project|sudo project|polkit project|systemd|freedesktop|x.org|freetype|gnome|kde|qt|libxml2|xmlsoft|sqlite|ffmpeg|gstreamer|webmproject|struktur|openjpeg|uclouvain|libraw|exiv2|exiftool project|poppler|mupdf|opencv|pillow|numpy|pytorch|tensorflow|keras|onnx|huggingface|scikit-learn|jquery|facebook|meta|angular|angularjs|vuejs|lodash|momentjs|axios|webpack|vitejs|babeljs|eslint|npmjs|yarnpkg|pypa|jenkins-x|gradle|xstream|x-stream|fastjson|alibaba|fasterxml|snakeyaml project|protobuf|grpc|netty|undertow|vertx|akka|lightbend|quarkus|micronaut|dropwizard|commons|hibernate|mybatis|electronjs|electron|tauri|flutter|unity|godotengine|openssl project|wolfssl|mbed|arm|mbedtls|gnutls|libgcrypt|gnupg|libssh2|libuv|libevent|boost|poco|protobuf-c|msgpack|capnproto|flatbuffers|rapidjson|nlohmann|jsoncpp|yaml|libyaml|pyyaml|ruamel|tomlplusplus|expat|libexpat project|tinyxml|pugixml|xerces|libarchive|bzip|xz|tukaani|lz4|zstd|snappy|brotli|c-ares|nghttp2|quiche|ngtcp2|lsquic|h2o|http-parser|llhttp|uwebsockets|websocketpp|libwebsockets|civetweb|mongoose|cesanta|lighttpd project|thttpd|boa|goahead|embedthis|appweb|mini_httpd|acme|uhttpd|micro_httpd|shttpd|monkey|nostromo|nazgul|hiawatha|cherokee|abyss|xitami|zeus|resin|caucho|glassfish|payara|tomee|geronimo|jonas|jrun|orion|weblogic|websphere|jboss|wildfly|undertow|jetty|grizzly|tomcat")
def microsoft(p):
    if B("exchange|exchange server|sharepoint[a-z ]*|internet information services|iis").search(p): return 'srv_exposed'
    if re.search(r"windows(?! server update)|defender(?! for (identity|iot))|office|365 apps|edge|internet explorer|visual studio|\.net|excel|word|outlook|powerpoint|teams|onenote|access|publisher|visio|project(?! server)|malware protection|security essentials|xbox|surface|hololens|paint|photos|media|codecs|raw image|hevc|vp9|av1|webp|3d (viewer|builder)|print 3d|remote desktop client|authenticator|onedrive|skype(?! for business server)|chakracore|powershell|sysinternals|pc manager|bing (search|app)|copilot (app|for (ios|android))",p): return 'client_os'
    if B("azure (?!devops server|stack|sphere|rtos|iot edge|connected machine|cli|powershell|sdk|uamqp|file sync|cyclecloud|arc|linux|monitor agent|network watcher|site recovery|storage explorer|data studio|service fabric|kubernetes|ad connect|migrate|hdinsight|open management)[a-z ]*|365 copilot|copilot studio|power platform|power apps|dataverse|purview|entra|bing|office online|dynamics 365 (?!.*on-prem)[a-z ()]*").search(p): return 'cloud'
    if re.search(r"sql server|active directory|system center|open management infrastructure|\bomi\b|windows server update services|wsus|dynamics|configuration manager|power pages|azure devops server|team foundation server|biztalk|skype for business server|lync server|identity manager|project server|host integration server|forefront|on-premises data gateway|power bi report server|hpc pack|service fabric|defender for identity|operations manager|azure",p): return 'srv_internal'
    return 'client_os'
def cisco(p):
    if B("anyconnect|secure client|webex(?! meetings server)[a-z ]*|jabber|duo|proximity|umbrella roaming|packet tracer").search(p): return 'client_os'
    if B("ip phone[a-z0-9 ]*|spa[0-9a-z ]*|ata [0-9a-z ]*|video phone[a-z0-9 ]*|telepresence[a-z0-9 ]*|wireless ip phone[a-z0-9 ]*|roomos|desk phone[a-z0-9 ]*").search(p): return 'iot'
    if re.search(r"identity services|\bise\b|hyperflex|data center network|dcnm|prime |unified c|unity|smart software manager|firepower management|firewall management center|\bfmc\b|\bucs\b|nexus dashboard|emergency responder|secure email and web manager|content security management|vmanage|sd-wan manager|dna center|catalyst center|epn manager|evolved programmable|crosswork|network services orchestrator|security manager|integrated management controller|intersight|cloud services platform|enterprise nfv|elastic services|policy suite|finesse|contact center|unified intelligence|meeting server|broadworks|virtualized voice|common services platform|cyber vision|industrial network director|modeling labs|appdynamics|thousandeyes|tetration|secure workload|stealthwatch|secure network analytics|application policy infrastructure|\bapic\b|ucs director|unified computing|container platform|meetings server|video surveillance|wide area application|energy management|license manager|packaged contact|virtualized infrastructure|managed services accelerator|network level service|connected mobile|mobility services|digital media manager|show and share|tidal|workload automation|process orchestrator|cloud portal|network analysis module|configuration assistant|firesight|sourcefire|registered envelope|vision dynamic signage|data center analytics|nexus insights|application services engine|iot field network director|iot operations dashboard|edge intelligence|kinetic|socialminer|mediasense|remote expert|unified sip proxy|telepresence (management|conductor|video communication)|expressway|hosted collaboration|prime$",p): return 'srv_internal'
    return 'edge'
def fortinet(p):
    if 'forticlient' in p: return 'client_os'
    if re.search(r"fortimanager|fortisiem|fortinac|fortisandbox|fortivoice|fortianalyzer|fortiwlm|fortiswitchmanager|fortiportal|fortiedr|fortisoar|fortiauthenticator|fortiisolator|fortideceptor|fortitester|fortindr|fortirecorder|fortiextender|fortiap|fortiswitch|fortiddos|fortipam|forticamera|fortitoken|forticloud|fortiaiops|fortiai\b|fortiguest|fortipresence|forticonverter|fortinet tools|fortiwan",p): return 'srv_internal'
    return 'edge'
def citrix(p):
    if re.search(r"workspace|receiver|secure access client|gotomeeting|gotomypc",p): return 'client_os'
    if re.search(r"sharefile|content collaboration|storefront|session recording|xenmobile|endpoint management|virtual apps|xenapp|xendesktop|virtual delivery|provisioning|licens|hypervisor|xenserver|director|studio|application delivery management|\badm\b|analytics|cloud connector|federated authentication",p): return 'srv_internal'
    return 'edge'
def ivanti(p):
    if re.search(r"endpoint manager mobile|epmm|mobileiron|\bcore\b",p): return 'srv_exposed'
    if re.search(r"connect secure|policy secure|cloud services appliance|\bcsa\b|sentry|neurons for (zta|secure access)|zta gateway|secure access(?! client)|virtual traffic manager|pulse (connect|policy)",p): return 'edge'
    if re.search(r"secure access client|pulse (secure )?(desktop|client)",p): return 'client_os'
    return 'srv_internal'
def sonicwall(p):
    if re.search(r"netextender|global vpn|capture client|connect tunnel|directory services",p): return 'client_os'
    if re.search(r"gms|global management|analytics|on-prem|\bnsm\b|network security manager",p): return 'srv_internal'
    return 'edge'
def sophos(p):
    if re.search(r"firewall|\bxg\b|sfos|utm|\bsg\b|unified threat|web appliance|cyberoam|email appliance|secure web|mobile(?! security)|connect|\bap\b|access point|redos|\bred\b",p): return 'edge'
    if re.search(r"intercept|endpoint|home|anti-virus|safeguard|hitmanpro",p): return 'client_os'
    return 'srv_internal'
def checkpoint(p):
    if re.search(r"smartconsole|endpoint|zonealarm|harmony|identity agent|ssl network extender|capsule|remote access vpn client|endpoint security",p): return 'client_os' if not 'smartconsole' in p else 'srv_internal'
    return 'edge'
def zyxel(p):
    if re.search(r"usg|atp\d|\batp\b|vpn\d|zywall|flex|zld|firewall|nxc|\bnsg\b|\bsbg\b|uos",p): return 'edge'
    return 'iot'
def adobe(p):
    if re.search(r"coldfusion|commerce|magento|experience manager|blazeds|connect|campaign|livecycle|flash media server|jrun|workfront|marketo",p): return 'srv_exposed'
    return 'client_os'
def oracle(p):
    if re.search(r"\bjre\b|\bjdk\b|java se|graalvm|virtualbox|openjdk",p): return 'client_os'
    if re.search(r"solaris|zfs|mysql|database|essbase|goldengate|timesten|berkeley|secure backup|enterprise manager|coherence|nosql|big data|exadata|ilom|integrated lights|sparc|x86 server|financial services|retail|hospitality|health sciences|utilities|insurance|primavera|jd edwards|siebel|agile|demantra|hyperion|data integrator|outside in|tuxedo|communications|linux|vm server|sun |storagetek|hospitality|micros|banking|flexcube",p): return 'srv_internal'
    return 'srv_exposed'
def google(p):
    if re.search(r"chrome|android|chromium|chromeos|pixel|wear os|fuchsia|gboard|play|drive for desktop|earth|web designer|quick share|nearby|\bv8\b|angle|skia|libwebp|libvpx|nest|home|chromecast|fitbit|tv|glass|gemini cli|antigravity|android studio|flutter",p):
        return 'iot' if re.search(r"nest|home|chromecast|fitbit|\btv\b",p) and 'chrome' not in p else 'client_os'
    if re.search(r"cloud|vertex|looker|apigee|workspace|gmail|docs|bigquery|firebase|kubernetes engine|gke|compute engine|app engine|dialogflow|chronicle|mandiant|security operations|agentspace",p): return 'cloud'
    return 'component'
def samsung(p):
    if re.search(r"magicinfo|data management server|knox manager|samsung dms",p): return 'srv_exposed'
    if re.search(r"smartthings|smart tv|\btv\b|camera|snh|wisenet|printer|syncthru|router|refrigerator|galaxy buds|galaxy watch|gear|hub|soundbar|tizen",p): return 'iot'
    if re.search(r"escargot|tizenrt|one-nn|walrus|rlottie|libtpms",p): return 'component'
    return 'client_os'
def huawei(p):
    if re.search(r"hg\d|echolife|ws\d|ax\d|\bb\d\d\d|\be\d\d\d\d|router|home gateway|hilink|cpe|mate|\bp\d\d|nova|harmonyos|emui|magic ui|band|watch|smart|honor|phone|pad|matebook|pc manager|hisuite|ont|hi ?link|freebuds|vision|ideahub|mobile",p): return 'iot' if re.search(r"hg\d|echolife|ws\d|ax\d|\bb\d\d\d|\be\d\d\d\d|router|home gateway|hilink|cpe|ont|vision|ideahub",p) else 'client_os'
    if re.search(r"usg|eudemon|secospace|firewall|\bar\d|\bne\d|\bce\d|switch|s\d\d\d\d|cloudengine|netengine|access controller|\bac\d",p): return 'edge'
    return 'srv_internal'
def asus(p):
    if re.search(r"rt-|gt-|zenwifi|dsl-|rp-|tuf-|4g-|lyra|blue cave|asuswrt|router|rog rapture|\bxt\d|\bbq\d|\bet\d|ebm|expertwifi|aicloud|download master|firmware|rt ac|rt ax|gt ax|gt ac|zenwifi",p): return 'iot'
    if re.search(r"control center|asmb|bmc|server|ipmi",p): return 'srv_internal'
    return 'client_os'
def hp(p):
    if re.search(r"laserjet|officejet|printer|pagewide|designjet|deskjet|envy|futuresmart|smart tank|ink tank|scanjet|digital sender|multifunction|\bmfp\b",p): return 'iot'
    if re.search(r"integrated lights|\bilo\b|oneview|system management|data protector|intelligent management|\bimc\b|operations|universal cmdb|service manager|network node|sitescope|loadrunner|arcsight|fortify|storeonce|3par|nimble|primera|simplivity|superdome|proliant|moonshot|insight|matrix|web jetadmin|device manager|teradici|anyware|officeconnect|procurve|comware|aruba|access manager|ucmdb|project and portfolio|application lifecycle|quality center|performance center|diagnostics|storage|msa|xp\d|nonstop|hp-ux|openvms|tru64|thin client management|thinpro management",p): return 'srv_internal'
    return 'client_os'
def dell(p):
    if re.search(r"supportassist|command|bios|alienware|peripheral|display manager|digital delivery|update package|optimizer|precision|latitude|inspiron|xps|wyse (?!management)|thinos|dock|encryption|trusted device|power manager|client platform|inventory collector|pair|dbutil|update|foundation services|rugged control|mobile connect|premier color|cinema|killer",p): return 'client_os'
    return 'srv_internal'
def vmware(p):
    if re.search(r"workstation|fusion|player|horizon client|tools|remote console|thinapp|view client",p): return 'client_os'
    if re.search(r"spring|rabbitmq|tanzu spring|pivotal",p): return 'srv_exposed' if 'spring' in p else 'srv_internal'
    if re.search(r"sd-wan|velocloud|nsx|avi|load balancer|unified access gateway|\buag\b|horizon (?!client)|workspace one access|identity manager|vrealize automation|aria automation|cloud director|vcloud director",p):
        return 'edge' if re.search(r"sd-wan|velocloud|nsx|avi|load balancer|unified access gateway|\buag\b",p) else 'srv_exposed'
    return 'srv_internal'
def apache(p):
    if re.search(r"http server|httpd|tomcat|ofbiz|struts|solr|superset|airflow|activemq|druid|nifi|shiro|roller|jspwiki|openmeetings|guacamole|unomi|kylin|skywalking|hertzbeat|dolphinscheduler|streampark|inlong|linkis|zeppelin|answer|seatunnel|shenyu|apisix|couchdb|tapestry|wicket|sling|karaf|archiva|continuum|syncope|fineract|cocoon|axis|cxf|jetspeed|cloudstack|allura|ambari|ranger|atlas|knox|oozie|nutch|manifoldcf|rocketmq|dubbo|spark|flink|kafka|hadoop|hive|hbase|zookeeper|pulsar|cassandra|ignite|geode|storm|camel|james|traffic server|traffic control|tika server|submarine|iotdb|doris|pinot|hugegraph|seata|servicecomb|brpc|bookkeeper|ozone|openoffice|pdfbox|poi|commons|log4j|xmlbeans|mina|velocity|freemarker|groovy|ant|maven|ivy|derby|lucene|tika|uima|opennlp|mxnet|tvm|singa|thrift|avro|parquet|orc|arrow|calcite|santuario|xerces|xalan|batik|fop|httpclient|httpcomponents|bcel|portable runtime|apr|subversion|netbeans|cordova|royale|flex",p):
        if 'openoffice' in p: return 'client_os'
        if re.search(r"commons|log4j|xmlbeans|mina|velocity|freemarker|groovy|\bant\b|maven|ivy|derby|lucene|tika(?! server)|uima|opennlp|mxnet|tvm|singa|thrift|avro|parquet|\borc\b|arrow|calcite|santuario|xerces|xalan|batik|\bfop\b|httpclient|httpcomponents|bcel|portable runtime|\bapr\b|subversion|netbeans|cordova|royale|flex|pdfbox|\bpoi\b|struts|shiro|tapestry|wicket|sling|karaf|cxf|axis|camel|dubbo|brpc|servicecomb|cocoon|seata",p): return 'component'
        if re.search(r"spark|flink|kafka|hadoop|hive|hbase|zookeeper|pulsar|cassandra|ignite|geode|storm|iotdb|doris|pinot|hugegraph|bookkeeper|ozone|ambari|ranger|atlas|knox|oozie|kylin|druid|linkis|inlong|seatunnel|streampark|dolphinscheduler|submarine|rocketmq",p): return 'srv_internal'
        return 'srv_exposed'
    return 'component'
def ibm(p):
    if re.search(r"websphere|maximo|cognos|domino|notes|sametime|connections|filenet|datapower|api connect|aspera|sterling|b2b|business automation|curam|control desk|content navigator|mobilefirst|urbancode|tririga|openpages|planning analytics|watson|engineering|jazz|rational|security verify access|security access manager|langflow|i2|mq appliance|app connect|integration bus|operational decision|robotic|case manager|datacap|commerce|marketing|campaign|unica|emptoris|kenexa|forms|lotus|inotes|quickr|rational",p): return 'srv_exposed'
    if re.search(r"\bi\b|aix|z/os|db2|informix|client access|personal communications|trusteer|notes client|sdk, java|java sdk|semeru",p): return 'srv_internal'
    return 'srv_internal'
def siemens(p):
    if re.search(r"jt2go|teamcenter visualization|solid edge|simcenter|tecnomatix|parasolid|jt open|jt utilities|pads |xpedition|nx\b|femap|cadra|star-ccm",p): return 'client_os'
    return 'ics'
def trend(p):
    if re.search(r"maximum security|internet security|antivirus\+?|housecall|password manager|consumer|premium security|security 20\d\d|vpn proxy",p): return 'client_os'
    if re.search(r"interscan|iwsva|imsva|tippingpoint|deep discovery (email|inspector)|smart protection server",p): return 'edge'
    return 'srv_internal'
def lenovo(p):
    return 'srv_internal' if re.search(r"xclarity|thinkagile|thinksystem|storage|bmc|imm|system x|flex system|server",p) else 'client_os'
def intel(p):
    return 'srv_internal' if re.search(r"data center manager|\bdcm\b|openvino|neural compressor|server board|one ?api|manageability commander|bmc|server system",p) else 'client_os'
def nvidia(p):
    return 'srv_internal' if re.search(r"triton|riva|nemo|megatron|container toolkit|bluefield|cumulus|dgx|base command|aistore|apex|isaac|nvflare|merlin|morpheus|rapids|omniverse|clara|jetson|mellanox|onyx|ufm|nvdebug|redfish|bmc|tao|dali|nvtabular|resiliency|run:ai|runai|nim\b",p) else 'client_os'
def av_vendor(p):
    return 'client_os' if re.search(r"internet security|anti-?virus(?! (for|server))|total security|safe kids|password manager|vpn|home|consumer|free|premium|smart security|nod32|cyber security|mobile security|livesafe|total protection|safe connect|true key|family|endpoint security(?! (for linux|server|cloud))",p) else 'srv_internal'
def broadcom(p):
    if re.search(r"wi-?fi|bluetooth|chip|bcm\d",p): return 'client_os'
    if re.search(r"messaging gateway|proxysg|web gateway|advanced secure gateway|ssl visibility|content analysis|sd-wan|velocloud|nsx|avi ",p): return 'edge'
    return 'srv_internal'
def jetbrains(p):
    return 'srv_internal' if re.search(r"teamcity|youtrack|hub|space|upsource|qodana",p) else 'client_os'
def redhat(p):
    return 'srv_exposed' if re.search(r"jboss|keycloak|single sign|3scale|satellite|quay|cloudforms|mobile application platform|process automation|decision manager|fuse|amq|data grid",p) else 'component'
def progress(p):
    return 'edge' if re.search(r"loadmaster|multi-tenant hypervisor|flowmon",p) else 'srv_exposed'
def realtek(p):
    return 'iot' if re.search(r'sdk|router|rtl819|rtl8|jungle|luna|ap-router|ecos',p) else 'client_os'
def sap(p):
    return 'client_os' if re.search(r'3d visual enterprise viewer|sap ?gui|business client|sapcar|crystal reports|analysis for (microsoft )?office|powerdesigner',p) else 'srv_exposed'
def aruba(p):
    return 'srv_internal' if re.search(r'clearpass|airwave|central|fabric composer|netedit|analytics',p) else 'edge'
def hpe(p):
    return 'edge' if re.search(r'arubaos|aruba (instant|access|cx|networking (switch|access|gateway|edgeconnect))|aos-cx|aos-8|aos-10|edgeconnect|comware|procurve|officeconnect|instant on',p) else 'srv_internal'
def f5(p):
    return 'component' if re.search(r'\bnjs\b|nginx (open source|unit|javascript)',p) else 'edge'
VFN={'sap':sap,'sap se':sap,'arubanetworks':aruba,'aruba':aruba,'hpe':hpe,'hewlett packard enterprise':hpe,'f5':f5,'realtek':realtek,'microsoft':microsoft,'cisco':cisco,'fortinet':fortinet,'citrix':citrix,'netscaler':citrix,'ivanti':ivanti,'pulsesecure':ivanti,'pulse secure':ivanti,'mobileiron':ivanti,'sonicwall':sonicwall,'sophos':sophos,'checkpoint':checkpoint,'check point':checkpoint,'zyxel':zyxel,'zyxel communications corporation':zyxel,'adobe':adobe,'oracle':oracle,'google':google,'samsung':samsung,'samsung mobile':samsung,'samsung electronics':samsung,'huawei':huawei,'asus':asus,'asustek':asus,'asustek computer inc.':asus,'hp':hp,'hp inc.':hp,'dell':dell,'vmware':vmware,'apache':apache,'apache software foundation':apache,'ibm':ibm,'siemens':siemens,'trendmicro':trend,'trend micro':trend,'trend micro, inc.':trend,'lenovo':lenovo,'intel':intel,'nvidia':nvidia,'eset':av_vendor,'kaspersky':av_vendor,'bitdefender':av_vendor,'mcafee':av_vendor,'symantec':broadcom,'broadcom':broadcom,'jetbrains':jetbrains,'redhat':redhat,'red hat':redhat,'progress':progress,'progress software corporation':progress,'progress software':progress}
VROLE={}
for names,ro in ((COMP,'component'),(ICS,'ics'),(SRVI,'srv_internal'),(SRVX,'srv_exposed'),(CLIENT,'client_os'),(EDGE,'edge'),(IOT,'iot')):
    for n in names: VROLE[n]=ro
HOBBY_V=S("sourcecodester|code-projects|phpgurukul|campcodes|itsourcecode|projectworlds|kashipara|1000projects|oretnom23|carmelogarcia|mayurik|fabianros|razormist|janobe|tamparongj|codeastro|anisha|remyandrade|sourcecodehero|codezips|phpjabbers|kashipara group|1000 projects|code4berry|angeljudesuarez|adonesevangelista|nikhil-bhalerao|pianolab|pushpam02|rems|ganesh|senior-walter|lerouxyxchire|argie|walterjnr1|emoblazz|hemedy99|donbermoy|bdtask|projectworlds|sinamjackson|hemant|code-projects.org")
# ---------- bounded keyword rules on product strings + description head (distinctive names only)
KW=[
 (B(r"wordpress (plugin|theme)s?|plugin for wordpress|theme for wordpress|wp (plugin|theme)|joomla!? ?(extension|component|module|plugin|template)s?|(extension|component|module|plugin) for joomla!?|drupal (module|theme)|(module|theme) for drupal|prestashop (module|addon)s?|module for prestashop|opencart (extension|module)|magento ?2? (extension|module)|typo3 extension|extension for typo3|nextcloud app|moodle plugin|plugin for moodle|mediawiki extension|plugin for jenkins|vs ?code extension|visual studio code extension|(chrome|firefox|browser) extension|roundcube plugin|grafana plugin|redmine plugin|discourse plugin|backstage plugin|obsidian plugin|craft cms plugin|woocommerce"),'plugin'),
 (re.compile(r"jenkins [^.|;]{0,60}plugin"),'plugin'),
 (B(r"sourcecodester|code-projects|phpgurukul|campcodes|itsourcecode|projectworlds|kashipara|1000 ?projects|oretnom23|codeastro|sourcecodehero|codezips|phpjabbers|code4berry"),'hobby'),
 (B(r"fortios|fortigate|fortiproxy|fortiweb|fortimail|fortiadc|pan-os|globalprotect|netscaler|citrix adc|citrix gateway|pulse connect secure|ivanti connect secure|connect secure|policy secure|sonicos|sma ?[0-9]+[a-z0-9 ]*|secure mobile access|big-ip|big-iq|junos|junos os|ios xe|ios xr|nx-os|adaptive security appliance|firepower threat defense|firepower|asa software|meraki|rv[0-9]{3}[a-z0-9]*|small business rv[a-z0-9 ]*|fireware|firebox|email security gateway|barracuda [a-z ]{0,30}(firewall|gateway|waf)|loadmaster|sd-wan|arubaos|aruba instant|edgeconnect|clearpass|zywall|usg flex|usg[0-9]+[a-z0-9-]*|atp[0-9]+|sophos firewall|sophos xg|cyberoam|sangfor|hillstone|stormshield|pfsense|opnsense|vyos|openvpn access server|checkpoint gaia|gaia os|quantum security gateway|secure web gateway|web application firewall|vpn gateway|ssl[- ]vpn|next-generation firewall|ngfw|firewall appliance|load balancer|application delivery controller|wan optimi[sz]\w*|session border controller"),'edge'),
 (B(r"router|routers|access point|range extender|ip camera|network camera|nvr|dvr|nas|smart (plug|bulb|tv|home|lock|speaker)|set-top box|modem|home gateway|wi-?fi (extender|mesh|router|repeater)|ip phone|printer|printers|baby monitor|doorbell|thermostat|wearable|drone|cpe|ont|gpon|repeater|webcam|intercom|video recorder|media player|smart ?watch|dir-[0-9a-z]+|dsl-[0-9a-z]+|dap-[0-9a-z]+|dcs-[0-9a-z]+|dns-[0-9a-z]+|ac[0-9]{1,4}[a-z]?|ax[0-9]{1,5}[a-z]?|a[0-9]{4}r[a-z]*|n[0-9]{3}r[a-z0-9]*|x[0-9]{4}r|ex[0-9]{3,4}|wn[0-9a-z]+|archer [a-z0-9]+|tl-[a-z0-9]+|nighthawk|orbi|readynas|vigor ?[0-9a-z]*|routeros|unifi|edgerouter|airos|my cloud|mycloud|diskstation|dsm|qts|quts hero|qutscloud"),'iot'),
 (B(r"internet explorer|microsoft (office|excel|word|outlook|windows|edge|teams)|macos|ipados|watchos|safari|webkit|google chrome|chromium|firefox|thunderbird|acrobat|foxit (pdf )?(reader|editor|phantompdf)|winrar|7-zip|vlc media player|autocad|libreoffice|wps office|desktop app(lication)?|desktop client|mobile app(lication)?|android app(lication)?|ios app(lication)?|electron app|visual studio code|claude code|gemini cli|codex cli"),'client_os'),
 (B(r"exchange server|sharepoint|confluence|jira|bitbucket|zimbra|roundcube|moveit|goanywhere|crushftp|serv-u|ws_ftp|filecatalyst|kiteworks|accellion|screenconnect|simplehelp|sysaid|manageengine [a-z ]+|servicedesk plus|adselfservice plus|opmanager|desktop central|endpoint central|netweaver|e-business suite|weblogic|peoplesoft|websphere|jboss|wildfly|coldfusion|tomcat|struts|drupal|joomla!?|wordpress|magento|typo3|craft cms|sitecore|telerik|liferay|vbulletin|phpmyadmin|webmin|cpanel|plesk|gitlab|jenkins|grafana|nextcloud|owncloud|freepbx|asterisk|3cx|mitel"),'srv_exposed'),
 (B(r"web application|web portal|web interface|content management system|cms|e-commerce|webmail|mail server|ftp server|file transfer|help ?desk|ticketing system|erp|crm|lms|learning management|forum|wiki|web server|application server|api server|admin panel|dashboard|php application|web app|php"),'other_web'),
 (B(r"vcenter|esxi|vsphere|vrealize|aria operations|workspace one|horizon|veeam|backup exec|netbackup|commvault|nakivo|acronis|solarwinds|orion platform|whatsup gold|prtg|papercut|qlik sense|elasticsearch|kibana|splunk|mongodb|redis|postgresql|mysql|mariadb|sql server|oracle database|active directory|domain controller|kubernetes|docker|openshift|rancher|hadoop|kafka|zookeeper|rabbitmq|saltstack|ansible|puppet|teamcity|artifactory|nexus repository|sonarqube|zabbix|nagios|cacti|centreon|librenms|endpoint manager|sccm|kace|lansweeper|bmc|idrac|ilo|ipmi|hypervisor|backup (server|software)|monitoring (server|software|platform)|database server|management server|management console|orchestrator|siem|edr|antivirus server|identity provider|ldap|kerberos|print server|license server"),'srv_internal'),
 (B(r"scada|plc|hmi|rtu|dcs|industrial|ics|opc ua|modbus|bacnet|dnp3|simatic|sinumerik|scalance|ruggedcom|wincc|tia portal|factorytalk|studio 5000|rslogix|controllogix|compactlogix|micrologix|ecostruxure|modicon|triconex|diascreen|cncsoft|dopsoft|diaenergie|webaccess|melsec|gx works|cx-one|sysmac|ignition|codesys|building automation|building management|medical device|infusion pump|patient monitor|dicom|pacs|ev charg\w+|charging station|inverter|solar|smart meter|vehicle|automotive|infotainment|telematics|robot\w*|firmware for [a-z ]*controller"),'ics'),
]
HOBBY2=re.compile(r"\b(online|simple|free|best|advanced|responsive|complete|modern|basic)\b[^.|]{0,60}\b(management|booking|reservation|ordering|voting|billing|inventory|pos|shopping|enrollment|examination|exam|portal|tracking|record|rental|ticketing|attendance|payroll|library|hospital|school|student|restaurant|hotel|pharmacy|clinic|gym|store|shop|blog|forum|chat|quiz|grading|scheduling|appointment|e-?commerce|food|courier|parking|complaint|leave|loan|insurance|job|event|news|music|movie)\b[^.|]{0,40}\b(system|site|website|app|application|project|portal|php)\b")
def keys(r):
    vp=[]
    for c in r.get('cpe') or []:
        p=c.split(':')
        if len(p)>=3: vp.append((p[1].replace('_',' ').replace('\\',''),p[2].replace('_',' ').replace('\\','')))
    for a in r.get('aff') or []:
        p=a.split('|')
        if len(p)>=2: vp.append((p[0].lower().strip(),p[1].lower().strip()))
    return vp
SUF=re.compile(r"(\s*\(.*?\))|[,.]?\s+(inc|llc|ltd|corp|corporation|co|gmbh|ag|sa|se|bv|plc|limited|company|technologies|technology|software|systems|networks|project|foundation|group|labs|team|international|electronics|communications|holdings)\.?$")
def norm(v):
    v=v.strip().strip('.').strip()
    for _ in range(3):
        n=SUF.sub('',v).strip(' ,.')
        if n==v or not n: break
        v=n
    return v
def lookup(v, prodtext):
    for cand in (v, norm(v)):
        if cand in VFN: return VFN[cand](prodtext)
        if cand in VROLE: return VROLE[cand]
    w=norm(v).split(' ')[0] if v else ''
    if len(w)>=5:
        if w in VFN: return VFN[w](prodtext)
        if w in VROLE and w not in AMBIG: return VROLE[w]
    return None
def src_label(src):
    if '@' not in src: return ''
    dom=src.split('@')[1].split('.')
    lab=dom[-2] if len(dom)>=2 else ''
    if lab in ('com','co','org','net','ac','gov') and len(dom)>=3: lab=dom[-3]
    return {'emc':'dell','us':'ibm','hq':'','googlegroups':'','hackerone':'','mitre':'','vuldb':'','github':'','trendmicro':'trendmicro','se':'schneider-electric'}.get(lab,lab)
def role2(r):
    src=(r.get('src') or '').lower()
    vp=keys(r)
    d=(r.get('desc') or '').lower()
    head=d[:240]; lead=head[:200]
    if src in WP_SRC: return 'plugin'
    prods=' ; '.join(p for v,p in vp[:8])
    if KW[0][0].search(prods+' ; '+head) or KW[1][0].search(prods+' ; '+head): return 'plugin'
    for v,p in vp[:8]:
        if v in HOBBY_V or norm(v) in HOBBY_V: return 'hobby'
    if KW[2][0].search(head): return 'hobby'
    if vp:
        lab=src_label(src)
        byv={}
        for v,p in vp: byv.setdefault(v,[]).append(p)
        def score(v):
            sc=0.0; w=re.sub(r'[^a-z0-9]','',norm(v))
            if lab and (w==lab or w.startswith(lab) or lab.startswith(w) and len(w)>=4): sc+=3
            first=norm(v).split(' ')[0]
            if len(first)>=3 and re.search(r"(?<![a-z0-9])"+re.escape(first)+r"(?![a-z0-9])",lead): sc+=2
            sc+=len(byv[v])/len(vp)
            return sc
        order=sorted(byv,key=lambda v:-score(v))
        for v in order[:6]:
            named=[q for q in byv[v] if len(q)>=4 and q in lead]
            ptxt=' ; '.join((named or byv[v])[:12])
            if not ptxt.strip(' ;-') or ptxt in ('n/a','-'): ptxt=lead[:140]
            ro=lookup(v,ptxt)
            if ro: return ro
    if src in ICS_SRC: return 'ics'
    if src in ('cna@vuldb.com','cve@mitre.org') and HOBBY2.search(prods+' ; '+head): return 'hobby'
    m=LEAD_RX.search(head[:110])
    if m:
        v=m.group(0)
        if v in VFN: return VFN[v](head[:110])
        return VROLE[v]
    t=prods+' ; '+head
    for rx,ro in KW[3:]:
        if rx.search(t): return ro
    if src in OSS_SRC: return 'component'
    if re.search(r"github\.com|npm package|pypi|python package|\bgem\b|go module|rust crate|\blibrary\b|open[- ]source|\bsdk\b|\bframework\b",d): return 'component'
    return 'other'
AMBIG=S("planet|canon|brother|sharp|zebra|motorola|philips|august|chamberlain|signify|garmin|fitbit|billion|comtrend|digitus|corega|olivetti|pelco|verkada|insteon|hubble|kasa|express|element|matrix|outline|october|commons|python|eclipse|golang|facebook|angular|electron|flutter|pillow|webpack|systemd|google|oracle|apache|intel|nvidia|progress|siemens|symantec|broadcom|lenovo|redhat|vmware|sophos|ivanti|citrix|adobe|huawei|samsung|microsoft|fortinet|sonicwall|checkpoint|jetbrains|kaspersky|bitdefender|mcafee|trendmicro|netscaler|mobileiron|pulsesecure|carrier|emerson|honeywell|pioneer|kenwood|alpine|harman|abbott|baxter|toyota|nissan|hyundai|tesla|volkswagen|contec|crane|dover|wayne|bennett|citizen|datalogic|cognex|doosan|kawasaki|denso|comau|fanuc|yaskawa|baumer|balluff|samson|metso|valmet|andritz|sauter|turck|sungrow|growatt|fronius|goodwe|enphase|solarman|itron|elster|kamstrup|janitza|riello|socomec|circutor|insyde|treck|perle|westermo|korenix|lantronix|festo|lenze|keyence|beckhoff|yokogawa|unitronics|advantech|rockwellautomation|mitsubishielectric|schneider-electric|phoenixcontact|inductiveautomation|fujielectric|hitachienergy|johnsoncontrols|automatedlogic|distech-controls|opcfoundation|trianglemicroworks|bakerhughes|aspentech|osisoft|softing|matrikon|kepware|tridium|codesys|omron|aveva|iconics|fatek|wecon|weintek|wellintech|medtronic|hologic|biotronik|draeger|hillrom|welchallyn|nextgen|softneta|microdicom|chargepoint|wallbox|autel")

_names=sorted([v for v in VFN if len(v)>=4]+[v for v in VROLE if len(v)>=6 and v not in AMBIG and v not in VFN],key=len,reverse=True)
LEAD_RX=re.compile(r"(?<![a-z0-9])(?:"+"|".join(re.escape(v) for v in _names)+r")(?![a-z0-9])")

def primary_vendor(r):
    """Vendor used for prominence counts: same scoring as role2 (CNA domain, named in description, share of CPEs)."""
    src=(r.get('src') or '').lower(); vp=keys(r)
    if not vp: return ''
    lead=(r.get('desc') or '').lower()[:200]; lab=src_label(src); byv={}
    for v,p in vp: byv.setdefault(v,[]).append(p)
    def score(v):
        sc=0.0; w=re.sub(r'[^a-z0-9]','',norm(v))
        if lab and (w==lab or w.startswith(lab) or lab.startswith(w) and len(w)>=4): sc+=3
        first=norm(v).split(' ')[0]
        if len(first)>=3 and re.search(r"(?<![a-z0-9])"+re.escape(first)+r"(?![a-z0-9])",lead): sc+=2
        return sc+len(byv[v])/len(vp)
    return norm(sorted(byv,key=lambda v:-score(v))[0])
