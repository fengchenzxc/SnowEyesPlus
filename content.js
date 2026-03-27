// SnowEyesPlus: flattened from modular source
// 日志工具模块
const logger = (function() {
  return {
    // 调试级别日志
    debug: (...args) => console.debug('[Scanner]', ...args),
    
    // 信息级别日志
    info: (...args) => console.info('[Scanner]', ...args),
    
    // 警告级别日志
    warn: (...args) => console.warn('[Scanner]', ...args),
    
    // 错误级别日志
    error: (...args) => console.error('[Scanner]', ...args)
  };
})();

// 将日志工具暴露到全局作用域
window.logger = logger; 
const REPORT_SCHEMA = globalThis.SNOWEYES_REPORT_SCHEMA || {};
const REPORT_FIELD_LIMITS = REPORT_SCHEMA.REPORT_FIELD_LIMITS || {};
const REPORT_UTILS = REPORT_SCHEMA.utils || {};
const FINGERPRINT_CORE = globalThis.SNOWEYES_FINGERPRINT || {};
const FINGERPRINT_UTILS = FINGERPRINT_CORE.utils || {};
function getReportFieldLimit(field, fallback) {
  const value = Number(REPORT_FIELD_LIMITS?.[field]);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}
function normalizeReportSeverity(value, fallback = 'medium') {
  if (typeof REPORT_UTILS.normalizeSeverity === 'function') {
    return REPORT_UTILS.normalizeSeverity(value, {
      allowed: ['high', 'medium', 'low'],
      fallback
    });
  }
  const normalized = String(value || fallback).toLowerCase();
  return ['high', 'medium', 'low'].includes(normalized) ? normalized : fallback;
}
// 统一的扫描器配置
const SCANNER_CONFIG = {
  // API 相关配置
  API: {
    PATTERN: /['"`](?:\/|\.\.\/|\.\/)[^\/\>\< \)\(\}\,\'\"\\](?:[^\^\>\< \)\(\,\'\"\\])*?['"`]|['"`][a-zA_Z0-9]+(?<!text|application)\/(?:[^\^\>\< \)\(\{\}\,\'\"\\])*?["'`]/g,
    // 图片文件模式
    IMAGE_PATTERN: /\.(jpg|jpeg|png|gif|bmp|webp|svg|ico|mp3|mp4|m4a|wav|swf)(?:\?[^'"]*)?$/i,
    // JS文件模式
    JS_PATTERN: /\.(js|jsx|ts|tsx|less)(?:\?[^'"]*)?$/i,
    // 文档文件模式
    DOC_PATTERN: /\.(pdf|doc|docx|xls|xlsx|ppt|exe|apk|zip|7z|dll|dmg|pptx|txt|rar|md|csv)(?:\?[^'"]*)?$/i,
    // css字体模式
    FONT_PATTERN: /\.(ttf|eot|woff|woff2|otf|css)(?:\?[^'"]*)?$/i,
    // 需要跳过的第三方JS库正则匹配规则
    SKIP_JS_PATTERNS: [
      // jQuery相关
      /^jquery([.-]?\d*\.?\d*\.?\d*)?(?:[\.-]cookie)?(?:[\.-]fancybox)?(?:[\.-]validate)?(?:[\.-]artDialog)?(?:[\.-]blockui)?(?:[\.-]pack)?(?:[\.-]base64)?(?:[\.-]md5)?(?:[\.-]min)?\.js$/i,
      /^(?:vue|vue-router|vuex)[.-]?\d*\.?\d*\.?\d*(?:\.min)?\.js$/i,
      // React相关
      /^(react|react-dom)[.-]?\d*\.?\d*\.?\d*(?:\.min)?\.js$/i,
      // Bootstrap相关
      /^bootstrap(?:\.bundle)?[.-]?\d*\.?\d*\.?\d*(?:[\.-]datepicker|datetimepicker)?(?:[\.-]zh-CN)?(?:[\.-]min)?\.js$/i,
      // UI框架相关
      /^(layui|lay|layer|liger|h-ui|element-ui|ueditor|kindeditor|ant-design)[.-]?\d*\.?\d*\.?\d*(?:[\.-]all)?(?:\.admin)?(?:[\.-]config)?(?:[\.-]min)?\.js$/i,
      // 图表相关
      /^(echarts|chart|highcharts)[.-]?\d*\.?\d*\.?\d*(?:\.min)?\.js$/i,     
      // 工具库相关
      /^(lodash|moment|katex|tableexport|axios|plupload|pqgrid|md5)[.-]?\d*\.?\d*\.?\d*(?:\.full)?(?:\.min)?\.js$/i,     
      // 其他常用库
      /^(polyfill|modernizr|device|less|isotope.pkgd|lhgdialog|kendo.web|dataTables|editor|seajs-style|seajs-text|tinymce|jsencrypt|backbone|select2|underscore|ext-all|ext-unigui-min|exporter|buttons|v5_float_4)[.-]?\d*\.?\d*\.?\d*(?:[\.-]dev)?(?:[\.-]html5|bootstrap|print|full)?(?:[\.-]min)?\.js$/i,      
      // 日期选择器
      /^(datepicker|datetimepicker|wdatepicker|laydate)[.-]?\d*\.?\d*\.?\d*(?:\.min)?\.js$/i,   
      // 语言包
      /^(?:zh|en|zh-cn|zh-tw|ja|ko)[.-]?\d*\.?\d*\.?\d*(?:\.min)?\.js$/i,
    ],
    // 需要过滤的内容类型
    FILTERED_CONTENT_TYPES: [  
      'multipart/form-data',
      'node_modules/',
      'pause/break',
      'partial/ajax',
      'chrome/',
      'firefox/',
      'edge/',
      'examples/element-ui',
      'static/js/',
      'static/css/',
      'stylesheet/less',
      'jpg/jpeg/png/pdf',
      //日期类型
      'yyyy/mm/dd',
      'dd/mm/yyyy',
      'mm/dd/yy',
      'yy/mm/dd',
      'm/d/Y',
      'm/d/y',
      'xx/xx',
      'zrender/vml/vml'
    ]
  },
  THIRD_PARTY_LIBS: [
    /^jquery(?:[\.-](?:cookie|fancybox|validate|artDialog|blockui|pack|base64|md5|dataTables|corner|enPlaceholder))?(?:[\.-]min)?(?:[.-]?\d*\.?\d*\.?\d*)?\.js$/i,
    /^(?:vue|vue-router|vuex|react|react-dom|angular|core-js)[.-]?\d*\.?\d*\.?\d*(?:\.min)?\.js$/i,
    /^(?:bootstrap|layui|layer|element-ui|ant-design|liger|h-ui|uview|vant|iview|mui|flat-ui|pure-css|metisMenu)[.-]?\d*\.?\d*\.?\d*(?:[\.-]bundle)?(?:[\.-]all)?(?:[\.-]min)?\.js$/i,
    /^(?:datepicker|datetimepicker|wdatepicker|laydate|select2|swiper|slick|fancybox|magnific-popup)[.-]?\d*\.?\d*\.?\d*(?:[\.-]zh-CN)?(?:\.min)?\.js$/i,
    /^(?:handlebars|lodash|moment|axios|qs|md5|jsencrypt|crypto-js|base64|uuid|rxjs|immutable|underscore|backbone|require|seajs)[.-]?[v]?\d*\.?\d*\.?\d*(?:\.min)?\.js$/i,
    /^(?:polyfill|modernizr|device|js-cookie|nprogress|pace|fingerprintjs|isotope|webuploader)[.-]?\d*\.?\d*\.?\d*(?:\.min)?\.js$/i,
    /^(?:echarts|chart|highcharts|d3|v-charts|antv|viz|markmap|mermaid|plantuml-encoder|flowchart|abcjs-basic|smiles-drawer)[.-]?\d*\.?\d*\.?\d*(?:[\.-]all)?(?:\.min)?\.js$/i,
    /^(?:ueditor|kindeditor|tinymce|ckeditor|wangEditor|quill|monaco-editor|lute|highlight)[.-]?\d*\.?\d*\.?\d*(?:[\.-]config)?(?:[\.-]all)?(?:\.min)?\.js$/i,
    /^(?:plupload|pqgrid|lhgdialog|kendo|dataTables|editor|exporter|buttons|v5_float_4|full\.render|method)[.-]?\d*\.?\d*\.?\d*(?:\.min)?\.js$/i,
    /^(?:zh|en|zh-cn|zh-tw|ja|ko|i18n|third-languages)[.-]?\d*\.?\d*\.?\d*(?:\.min)?\.js$/i
  ],
  DOMAIN: {
    // 域名黑名单：不会展示以下域名
    BLACKLIST: [
      'el.datepicker.today',
      'obj.style.top',
      'window.top',
      'mydragdiv.style.top',
      'container.style.top',
      'location.host',
      'page.info',
      'res.info',
      'item.info'
    ]
  },

    // IP 相关配置
  IP: {
    // 特殊 IP 范围（保留地址和特殊用途地址）
    SPECIAL_RANGES: [
      /^0\.0\.0\.0$/,          // 当前网络
      /^255\.255\.255\.255$/   // 广播地址
    ]
  },
  PATTERNS: {
// 域名匹配 - HTML页面
    DOMAIN: /\b(?:(?!this)[a-z0-9%-]+\.)*?(?:(?!this)[a-z0-9%-]{2,}\.)(?:wang|club|xyz|vip|top|beer|work|ren|technology|fashion|luxe|yoga|red|love|online|ltd|chat|group|pub|run|city|live|kim|pet|space|site|tech|host|fun|store|pink|ski|design|ink|wiki|video|email|company|plus|center|cool|fund|gold|guru|life|team|today|world|zone|social|bio|black|blue|green|lotto|organic|poker|promo|vote|archi|voto|fit|cn|website|press|icu|art|law|shop|band|media|cab|cash|cafe|games|link|fan|net|cc|com|fans|cloud|info|pro|mobi|asia|studio|biz|vin|news|fyi|tax|tv|market|shopping|mba|sale|co|org)(?:\:\d{1,5})?(?![a-zA-Z0-9._=>\(\);!}-])\b/g,
    // 域名匹配 - 资源文件
    DOMAIN_RESOURCE: /["'](?:(?:[a-z0-9]+:)?\/\/)?(?:(?!this)[a-z0-9%-]+\.)*?(?:[a-z0-9%-]{2,}\.)(?:wang|club|xyz|vip|top|beer|work|ren|technology|fashion|luxe|yoga|red|love|online|ltd|chat|group|pub|run|city|live|kim|pet|space|site|tech|host|fun|store|pink|ski|design|ink|wiki|video|email|company|plus|center|cool|fund|gold|guru|life|team|today|world|zone|social|bio|black|blue|green|lotto|organic|poker|promo|vote|archi|voto|fit|cn|website|press|icu|art|law|shop|band|media|cab|cash|cafe|games|link|fan|net|cc|com|fans|cloud|info|pro|mobi|asia|studio|biz|vin|news|fyi|tax|tv|market|shopping|mba|sale|co|org)(?![a-zA-Z0-9.])(?:\:\d{1,5})?\S*?["']/g,
    DOMAIN_FILTER: /\b(?:[a-zA-Z0-9%-]+\.)+[a-z]{2,10}(?:\:\d{1,5})?\b/,
    // IP 地址匹配 - HTML页面
    IP: /(?<!\.|\d)(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?::\d{1,5})?(?!\.|[0-9])/g,
    // IP 地址匹配 - 资源文件
    IP_RESOURCE: /["'](?:(?:[a-zA-Z0-9%-]+\:)?\/\/)?(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?::\d{1,5}|\/)?\S*?["']/g,
    get API() {
      return SCANNER_CONFIG.API.PATTERN;
    },
    PHONE: /(?<!\d|\.)(?:13[0-9]|14[01456879]|15[0-35-9]|16[2567]|17[0-8]|18[0-9]|19[0-35-9]|198|199)\d{8}(?!\d)/g,
    EMAIL: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+(?!\.png)\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?/g,
    IDCARD: /(?:\d{6}(?:19|20)(?:0\d|10|11|12)(?:[0-2]\d|30|31)\d{3}$)|(?:\d{6}(?:18|19|20)\d{2}(?:0[1-9]|10|11|12)(?:[0-2]\d|30|31)\d{3}(?:\d|X|x))(?!\d)/g,
    URL: /(?:https?|wss?|ftp):\/\/(?:(?:[\w-]+\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3})(?::\d{2,5})?(?:\/[^\s\>\)\}\<'"]*)?/gi,
    JWT: /["'](?:ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|ey[A-Za-z0-9_\/+-]{10,}\.[A-Za-z0-9._\/+-]{10,})["']/g,
    COMPANY: /(?:[\u4e00-\u9fa5\（\）]{4,15}[^的](?:公司|中心)|[\u4e00-\u9fa5\（\）]{2,10}[^的](?:软件)|[\u4e00-\u9fa5]{2,15}(?:科技|集团))(?!法|点|与|查)/g,
    GITHUB: /(?:https?:\/\/)?(?:www\.)?github\.com\/[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+/gi,
    WINDOWS_PATH: /(?:c|d|e|f|g):(?:\\\\[\w\u4e00-\u9fa5_@.-]+)+/gi,
    get CREDENTIALS() {
      return {
        type: 'CREDENTIALS',
        patterns: SCANNER_CONFIG.CREDENTIALS.PATTERNS
      };
    },
    COOKIE: /\b\w*(?:token|PHPSESSID|JSESSIONID)\s*[:=]\s*["']?(?!localStorage)(?:[a-zA-Z0-9-._]{4,})["']?/ig,
    get ID_KEY() {
      return {
        type: 'ID_KEY',
        patterns: SCANNER_CONFIG.ID_KEY.PATTERNS
      };
    },
    get FINGER() {
      return {
        type: 'FINGER',
        patterns: SCANNER_CONFIG.FINGER.PATTERNS
      };
    }
  },
  // 统一的黑名单配置
  BLACKLIST: {
    // 值黑名单 - 从 ID_KEY 配置中移出
    SHORT_VALUES: new Set([
      'up','in','by','of','is','on','to','no',
      'age','all','app','ang','bar','bea','big','bug','can','com','con','cry','dom',
      'dow','emp','ent','eta','eye','for','get','gen','has','hei','hid','ing','int',
      'ken','key','lea','log','low','met','mod','new','nor','not','num','red','obj',
      'old','out','pic','pre','pro','pop','pun','put','rad','ran','ref','red','reg',
      'ren','rig','row','sea','set','seq','shi','str','sub','sup','sun','tab','tan',
      'tip','top','uri','url','use','ver','via','rce','sum','bit','kit','uid'
    ]),
    MEDIUM_VALUES: new Set([
      'null','node','when','face','read','load','body','left','mark','down',
      'ctrl','play','ntal','head','item','init','hand','next','nect','json',
      'long','slid','less','view','html','tion','rect','link','char','core',
      'turn','atom','tech','type','main','size','time','full','card','more',
      'wrap','this','tool','late','note','leng','area','bool','pick','parm',
      'axis','high','true','date','tend','work','lang','func','able','dark',
      'term','info','data','opts','self','void','pace','list','brac','cret',
      'tive','sult','text','stor','back','port','case','pare','dent','blot',
      'fine','reif','cord','else','fail','rend','leav','hint','coll','move',
      'with','base','rate','name','hile','lete','post','pect','icon','auth',
      'jump','wave','land','wood','lize','room','chat','user','vice','ress',
      'line','send','mess','calc','http','rame','rest','last','guar','iate',
      'ment','task','stat','fill','coun','faul','rece','arse','exam','good',
      'gest','word','cast','lock','slot','fund','plus','thre','sign','pack',
      'reak','code','tent','math','lect','draw','lend','glow','past','blue',
      'dial','purp'
    ]),
    LONG_VALUES: new Set([
      'about','alias','apply','array','basic','beare','begin','black','break',
      'broad','catch','class','close','clear','click','clude','color','count',
      'cover','croll','crypt','error','false','fault','fetch','final','found',
      'gener','green','group','guard','index','inner','input','inter','light',
      'login','opera','param','parse','panel','place','print','phony','radio',
      'range','right','refer','serve','share','shift','style','tance','title',
      'token','tract','trans','trave','valid','video','white','write',

      'button','cancel','create','double','finger','global','insert','module',
      'normal','object','popper','triple','search','select','simple','single',
      'status','statis','switch','system','visual','verify','detail','screen',
      'member','change','buffer','grade'
    ]),
    CHINESE_BLACKLIST: new Set([
      '请','输入','前往','整个','常用','咨询','为中心','是否','以上','目前','任务',
      '或者','推动','需要','直接','识别','获取','用于','清除','遍历','使用','是由',
      '您','用户','一家','项目','等','造价','判断','通过','为了','可以','掌握',
      '传统','杀毒','允许','分析','包括','很多','接','未经','方式','些','的','第三方',
      '因此','形式','任何','提交','多数','其他','执行','操作','维护','或','其它',
      '分享','导致','一概','所有','及其','以及','应当','条件','除非','否则','违反',
      '将被','提供','无法','建立','打造','帮助','依法','鉴于','快速','构建','是','在',
      '去','恶意','挖矿','流氓','勒索','依靠','基于','通常','这','个','没有','并','、',
      '，','查看','确保','提高','减少','检查','更新','卸载','常见','依赖','进行','测试',
      '作弊',' '
    ])
  },
  

    // ID密钥相关配置
  ID_KEY: {
    PATTERNS: [
      {name: '微信开放平台密钥', pattern: /wx[a-z0-9]{15,18}/g},
      {name: 'AWS密钥', pattern: /AKIA[0-9A-Z]{16}/g},  
      {name: '阿里云密钥', pattern: /LTAI[A-Za-z\d]{12,30}/g},
      {name: 'Google API密钥', pattern: /AIza[0-9A-Za-z_\-]{35}/g},
      {name: '腾讯云密钥', pattern: /AKID[A-Za-z\d]{13,40}/g},
      {name: '京东云密钥', pattern: /JDC_[0-9A-Z]{25,40}/g},
      {name: '其他AWS密钥', pattern: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g},
      {name: '支付宝开放平台密钥', pattern: /(?:AKLT|AKTP)[a-zA-Z0-9]{35,50}/g},
      {name: 'GitLab Token1', pattern: /glpat-[a-zA-Z0-9\-=_]{20,22}/g},
      {name: 'GitHub Token2', pattern: /(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255}/g},
      {name: 'Apple开发者密钥', pattern: /APID[a-zA-Z0-9]{32,42}/g},
      {name: '企业微信密钥', pattern: /ww[a-z0-9]{15,18}/g},
      {name: 'key1', pattern: /(?:['"]?(?:[\w-]*(?:secret|oss|bucket|key)[\w-]*)|ak["']?)\s*[:=]\s*(?:"(?!\+)[^\,\s\"\(\>\<]{6,}"|'(?!\+)[^\,\s\'\(\>\<]{6,}'|[0-9a-zA-Z_-]{16,})/ig},
      {name: 'key2', pattern: /["'][a-zA-Z0-9]{32}["']/g}
    ],

    // 关键词黑名单
    KEY_BLACKLIST: new Set([
      'size', 'row', 'dict', 'up', 'highlight', 'cabin', 'cross','time'
    ])
  },
  CREDENTIALS: {
    PATTERNS: [
      {pattern: /['"]\w*(?:pwd|pass|user|member|account|password|passwd|admin|root|system)[_-]?(?:id|name)?[0-9]*["']\s*[:=]\s*(?:['"][^\,\s\"\(]*["'])/gi},
      {pattern: /\w*(?:pwd|pass|user|member|account|password|passwd|admin|root|system)[_-]?(?:id|name)?[0-9]*\s*[:=]\s*(?:['"][^\,\s\"\(]*["'])/gi},
      {pattern: /['"]\w*(?:pwd|pass|user|member|account|password|passwd|admin|root|system)[_-]?(?:id|name)?[0-9]*\s*[:=]\s*(?:[^\,\s\"\(]*)["']/gi},
    ]
  },
  DOM_XSS: {
    SOURCES: [
      { name: 'location.hash', pattern: /\blocation\.hash\b/i },
      { name: 'location.search', pattern: /\blocation\.search\b/i },
      { name: 'searchParams.get', pattern: /\bsearchParams\.get\s*\(/i },
      { name: 'URLSearchParams', pattern: /\bURLSearchParams\s*\(/i },
      { name: 'window.location', pattern: /\bwindow\.location\b/i },
      { name: 'location', pattern: /\blocation\b/i },
      { name: 'location.href', pattern: /\blocation\.href\b/i },
      { name: 'document.URL', pattern: /\bdocument\.(?:url|URL|documentURI)\b/i },
      { name: 'document.URLUnencoded', pattern: /\bdocument\.URLUnencoded\b/i },
      { name: 'document.baseURI', pattern: /\bdocument\.baseURI\b/i },
      { name: 'document.cookie', pattern: /\bdocument\.cookie\b/i },
      { name: 'document.referrer', pattern: /\bdocument\.referrer\b/i },
      { name: 'window.name', pattern: /\bwindow\.name\b/i },
      { name: 'postMessage', pattern: /\b(?:event|e)\.data\b/i },
      { name: 'storage', pattern: /\b(?:localStorage|sessionStorage)\.getItem\b/i },
      { name: 'dom input value', pattern: /\bdocument\.(?:getElementById|getElementsByName|querySelector|querySelectorAll)\s*\([^)]*\)\s*(?:\[\s*\d+\s*\]\s*)?\.value\b/i },
      { name: 'event target value', pattern: /\b(?:event|e|evt)\.(?:target|currentTarget)\.value\b/i },
      { name: 'jquery val()', pattern: /\b(?:jQuery|\$)\s*\([^)]*\)\.val\s*\(\s*\)/i },
      { name: 'history.state', pattern: /\bhistory\.state\b/i },
      { name: 'history.pushState/replaceState', pattern: /\bhistory\.(?:pushState|replaceState)\b/i },
      { name: 'indexedDB', pattern: /\b(?:indexedDB|mozIndexedDB|webkitIndexedDB|msIndexedDB)\b/i },
      { name: 'openDatabase', pattern: /\bopenDatabase\s*\(/i },
      { name: 'route.params/query', pattern: /\b(?:route|router)\.(?:query|params)\b/i },
      { name: 'hash route fragment', pattern: /\b(?:Backbone\.history\.getFragment|location\.hash\.slice\s*\(|location\.hash\.substring\s*\(|decodeURIComponent\s*\(\s*location\.hash)\b/i },
      { name: 'framework route object', pattern: /\b(?:\$route|currentRoute)\.(?:query|params|path|hash)\b/i },
      { name: 'location.pathname', pattern: /\blocation\.pathname\b/i }
    ],
    SINKS: [
      { name: 'innerHTML', pattern: /\.\s*innerHTML\s*=/i, severity: 'high' },
      { name: 'outerHTML', pattern: /\.\s*outerHTML\s*=/i, severity: 'high' },
      { name: 'insertAdjacentHTML', pattern: /\.\s*insertAdjacentHTML\s*\(/i, severity: 'high' },
      { name: 'jquery html()', pattern: /\.\s*html\s*\(/i, severity: 'high' },
      { name: 'jquery append()', pattern: /\.\s*append\s*\(/i, severity: 'medium' },
      { name: 'jquery prepend()', pattern: /\.\s*prepend\s*\(/i, severity: 'medium' },
      { name: 'jquery before()', pattern: /\.\s*before\s*\(/i, severity: 'medium' },
      { name: 'jquery after()', pattern: /\.\s*after\s*\(/i, severity: 'medium' },
      { name: 'jquery replaceWith()', pattern: /\.\s*replaceWith\s*\(/i, severity: 'medium' },
      { name: 'jquery insertAfter()', pattern: /\.\s*insertAfter\s*\(/i, severity: 'medium' },
      { name: 'jquery insertBefore()', pattern: /\.\s*insertBefore\s*\(/i, severity: 'medium' },
      { name: 'jquery replaceAll()', pattern: /\.\s*replaceAll\s*\(/i, severity: 'medium' },
      { name: 'jquery wrap()', pattern: /\.\s*wrap\s*\(/i, severity: 'medium' },
      { name: 'jquery wrapInner()', pattern: /\.\s*wrapInner\s*\(/i, severity: 'medium' },
      { name: 'jquery wrapAll()', pattern: /\.\s*wrapAll\s*\(/i, severity: 'medium' },
      { name: 'jquery add()', pattern: /\.\s*add\s*\(/i, severity: 'low', requireSource: true, requireJqueryContext: true },
      { name: 'jquery has()', pattern: /\.\s*has\s*\(/i, severity: 'low', requireSource: true, requireJqueryContext: true },
      { name: 'jquery index()', pattern: /\.\s*index\s*\(/i, severity: 'low', requireSource: true, requireJqueryContext: true },
      { name: 'jquery animate()', pattern: /\.\s*animate\s*\(/i, severity: 'low', requireSource: true, requireJqueryContext: true },
      { name: 'jquery attr(href/src/action)', pattern: /\.\s*attr\s*\(\s*['"`](?:href|src|action|formaction|xlink:href)['"`]\s*,/i, severity: 'high' },
      { name: 'jQuery.parseHTML', pattern: /\b(?:jQuery|\$)\.parseHTML\s*\(/i, severity: 'high' },
      { name: 'jQuery $() selector', pattern: /\$\s*\(\s*(?!function\s*\(|document\b|window\b|this\b|['"`][.#\w-]+['"`]\s*\))/i, severity: 'low', requireSource: true },
      { name: 'element.onevent', pattern: /\.\s*on[a-z]{3,20}\s*=/i, severity: 'high', requireDomReceiver: true },
      { name: 'setAttribute(on*)', pattern: /\.\s*setAttribute\s*\(\s*['"`]on[a-z]{3,20}['"`]\s*,/i, severity: 'high' },
      { name: 'document.write', pattern: /\bdocument\.(?:write|writeln)\s*\(/i, severity: 'high' },
      { name: 'eval', pattern: /\beval\s*\(/i, severity: 'high' },
      { name: 'new Function', pattern: /\bnew\s+Function\s*\(/i, severity: 'high' },
      { name: 'setTimeout(string)', pattern: /\bsetTimeout\s*\(\s*['"`]/i, severity: 'medium' },
      { name: 'setInterval(string)', pattern: /\bsetInterval\s*\(\s*['"`]/i, severity: 'medium' },
      { name: 'dangerous href', pattern: /\b(?:href|location)\s*=\s*['"`]\s*javascript:/i, severity: 'high' },
      { name: 'vue v-html', pattern: /\bv-html\s*=/i, severity: 'medium' },
      { name: 'react dangerouslySetInnerHTML', pattern: /\bdangerouslySetInnerHTML\b/i, severity: 'high' }
    ],
    SANITIZERS: [
      /\bDOMPurify\.sanitize\s*\(/i,
      /\bsanitizeHtml\s*\(/i,
      /\bxss(?:\.|_)?filter\s*\(/i,
      /\bescapeHtml\s*\(/i,
      /\bvalidator\.escape\s*\(/i,
      /\bhe\.encode\s*\(/i
    ],
    LOW_FP_TEMPLATES: [
      // 纯静态字面量写入（无变量拼接）
      /\.\s*(?:innerHTML|outerHTML)\s*=\s*(?![^;\n]*\+)\s*(?:['"`])[\s\S]*?(?:['"`])\s*;?$/i,
      /\.\s*(?:html|append|prepend|before|after|replaceWith|insertAfter|insertBefore|replaceAll|wrap|wrapInner|wrapAll|add|has|index|animate)\s*\(\s*(?![^)\n]*\+)\s*(?:['"`])[\s\S]*?(?:['"`])\s*\)\s*;?$/i,
      /\.\s*attr\s*\(\s*['"`](?:href|src|action|formaction|xlink:href)['"`]\s*,\s*['"`][\s\S]*?['"`]\s*\)\s*;?$/i,
      /\b(?:jQuery|\$)\.parseHTML\s*\(\s*['"`][\s\S]*?['"`]\s*\)\s*;?$/i,
      // 常见 i18n 文本渲染链路
      /\bpolyglot\.t\s*\(/i,
      /\b(?:i18n|translate|localize|intl)\s*\(/i,
      /(?:\b(?:textContent|innerText)\b|\.text\s*\()/i
    ],
    VUE_SOURCE_HINT: /\b(?:location|route|router|query|params|hash|search|url|href|message|payload|content)\b/i,
    MAX_FINDINGS_PER_CHUNK: 120,
    MAX_SINK_ONLY_PER_CHUNK: 20,
    MAX_REPORTS_PER_FILE: 16,
    MAX_SINK_ONLY_PER_FILE: 3
  },
  ROUTE: {
    MAX_MATCHES_PER_CHUNK: 120,
    EXCLUDE_EXT: /\.(?:js|jsx|ts|tsx|css|less|scss|sass|map|json|xml|txt|md|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|otf|mp3|mp4|wav|pdf|zip|rar|7z|exe|dll|apk)(?:[?#].*)?$/i,
    RULES: [
      { name: 'router.push/replace', pattern: /\b(?:router|this\.\$router)\.(?:push|replace)\s*\(\s*(['"`])([^'"`\n]{1,220})\1/gi },
      { name: 'history.pushState/replaceState', pattern: /\bhistory\.(?:pushState|replaceState)\s*\([^)]*?(['"`])([^'"`\n]{1,220})\1\s*\)/gi },
      { name: 'location.hash assignment', pattern: /\b(?:window\.)?location\.hash\s*=\s*(['"`])([^'"`\n]{1,220})\1/gi },
      { name: 'route object path', pattern: /\b(?:path|route|to|from)\s*:\s*(['"`])([^'"`\n]{1,220})\1/gi },
      { name: 'window.open/location.assign', pattern: /\b(?:window\.open|location\.(?:assign|replace))\s*\(\s*(['"`])([^'"`\n]{1,220})\1/gi }
    ]
  },

  // 添加构建工具配置
  FINGER: {
    PATTERNS: [
      {class: 'Webpack', name: 'Webpack页面特征', pattern: /(?:webpackJsonp|__webpack_require__|webpack-dev-server)/i, description: '构建工具，用于前端资源打包', type: 'builder'},
      {class: 'Webpack', name: 'Webpack文件特征', pattern: /(?:chunk|main|app|vendor|common)s?(?:[-.][a-f0-9]{8,20})+.(?:css|js)/i, description: '构建工具，用于前端资源打包', type: 'builder'},
      {class: 'VisualStudio', name: 'Visual Studio页面特征', pattern: /visual\sstudio/i, description: '开发工具，用于网页开发', type: 'builder'},
      {class: 'Cloudflare CDN', name: '页面特征', pattern: /cdnjs.cloudflare.com/i, description: '服务，用于网页加速', type: 'cdn'},
      {class: 'jsDelivr CDN', name: '页面特征', pattern: /cdn.jsdelivr.net/i, description: '服务，用于网页加速', type: 'cdn'},
      {class: 'Django', name: '页面特征', pattern: /csrfmiddlewaretoken/i, description: '框架', type: 'framework',extType: 'technology',extName: 'Python'},
    ]
  },
};

// 导出配置
window.SCANNER_CONFIG = SCANNER_CONFIG;
window.API_CONFIG = SCANNER_CONFIG.API;
window.DOMAIN_CONFIG = SCANNER_CONFIG.DOMAIN;
window.IP_CONFIG = SCANNER_CONFIG.IP; 

// 正则表达式缓存
const regexCache = {
  coordPattern: /^coord/,
  valuePattern: /^(?:\/|true|false|null|undefined|register|signup|basic|http|https)$/i,
  chinesePattern: /^[\u4e00-\u9fa5]+$/,
  camelCasePattern: /\b[_a-z]+(?:[A-Z][a-z]+)+\b/,
};
const COMPANY_NOISE_PATTERNS = [
  /^(?:或|和|及|与|由|在|按|根据|通过|对于|针对|为|对|向|将|可|能|应|需|请|若|如|本|该|我|你|其|此)/,
  /(?:本公司|该公司|我公司|贵公司|所属公司|关联公司|第三方公司|任何公司|其他公司|其它公司|合作公司|相关公司)/,
  /(?:常用软件|应用软件|系统软件|软件工具|软件服务|用户中心|个人中心|帮助中心|登录中心|服务中心)/,
  /(?:协议|条款|政策|免责声明|用户服务|隐私|法律|争议|法院|不得|应当|以及|或者|为了|通过|包括)/
];
const COMPANY_SHORT_NOISE_WORDS = new Set([
  '使用', '根据', '通过', '提供', '用户', '平台', '系统', '服务',
  '方式', '进行', '包括', '相关', '其他', '任何', '可以'
]);
function normalizeCompanyCandidate(name = '') {
  let compact = String(name || '').replace(/\s+/g, '');
  if (!compact) return '';

  const suffixMatch = compact.match(/(?:有限责任公司|股份有限公司|有限公司)/);
  if (suffixMatch) {
    const suffix = suffixMatch[0];
    const endIndex = compact.indexOf(suffix) + suffix.length;
    compact = compact.slice(0, endIndex);
  }

  compact = compact.replace(/^(?:本公司与|该公司与|我公司与|本公司|该公司|我公司|贵公司|悦花积分是|平台是|网站是|系统是|是)/, '');
  compact = compact.replace(/^(?:与|和|及|或)+/, '');
  return compact;
}
function isLikelyCompanyName(name = '') {
  const compact = String(name || '').replace(/\s+/g, '');
  if (!compact || compact.length < 4 || compact.length > 26) return false;
  if (/[、，。；：！？,.!?]/.test(compact)) return false;

  if (COMPANY_NOISE_PATTERNS.some((pattern) => pattern.test(compact))) {
    const hasStrongOrgSuffix = /(?:有限责任公司|股份有限公司|有限公司|集团有限公司|集团|银行|信用社|研究院|研究所|大学|学院|医院|委员会)/.test(compact);
    if (!hasStrongOrgSuffix) return false;
  }

  if (!/(?:公司|集团|中心|软件|科技|有限责任公司|股份有限公司|有限公司)$/.test(compact)) {
    return false;
  }

  if (/(?:中心|软件|科技)$/.test(compact) && compact.length < 6) {
    return false;
  }
  if (/(?:中心|软件|科技)$/.test(compact) && /(?:常用|应用|系统|相关|服务|用户|帮助|登录|支付|平台|工具)/.test(compact)) {
    return false;
  }

  return true;
}
// 统一的扫描过滤器
const SCANNER_FILTER = {
  // API 过滤器
  api: (function() {
    return function(match, url, resultsSet) {
      match = match.slice(1, -1);
      if (SCANNER_CONFIG.API.FONT_PATTERN.test(match)) {
        return false;
      }
      if (match.endsWith('.vue')) {
        resultsSet?.vueFiles?.set(match, url);
        return true;
      }
      if (SCANNER_CONFIG.API.IMAGE_PATTERN.test(match)) {
        resultsSet?.imageFiles?.set(match, url);
        return true;
      }
      if (SCANNER_CONFIG.API.DOC_PATTERN.test(match)) {
        resultsSet?.docFiles?.set(match, url);
        return true;
      }
      const lcMatch = match.toLowerCase();
      const shouldFilter = SCANNER_CONFIG.API.FILTERED_CONTENT_TYPES.some(type => 
        lcMatch==type.toLowerCase()
      );
      if (shouldFilter) {
        return false;
      }
      // 与 v0.3.0 对齐：相对模块路径优先归入 moduleFiles，避免被 JS_PATTERN 抢先命中。
      if (match.startsWith('./') && !resultsSet?.moduleFiles?.has(`${match}.js`)) {
        resultsSet?.moduleFiles?.set(match, url);
        if (isUseWebpack) {
          if (resultsSet?.jsFiles?.has(`${match}.js`)) {
            resultsSet.jsFiles.delete(`${match}.js`);
          }
          if (match.endsWith('.js') && resultsSet?.moduleFiles?.has(match.slice(0, -3))) {
            resultsSet.moduleFiles.delete(match.slice(0, -3));
          }
        }
        return true;
      }
      if (SCANNER_CONFIG.API.JS_PATTERN.test(match)) {
        resultsSet?.jsFiles?.set(match, url);
        return true;
      }
      if (match.startsWith('/')) {
        // 绝对路径
        if(match.length<=4&&/[A-Z\.\/\#\+\?23]/.test(match.slice(1))) return false;
        resultsSet?.absoluteApis?.set(match, url);
      } else {
        // 相对路径
        if (/^(audio|blots|core|ace|icon|css|formats|image|js|modules|text|themes|ui|video|static|attributors|application)/.test(match)) return false;
        if(match.length<=4) return false;
        resultsSet?.apis?.set(match, url);
      }
      return true;
    };
  })(),

  // 域名过滤器
  domain: (function() {
    // URL解码缓存
    const decodeCache = new Map();
    const validate = {
      // 清理和标准化域名
      clean(domain) {
        try {
          // 1. 处理引号
          domain = domain.replace(/^['"]|['"]$/g, '');
          // 2. 转小写
          domain = domain.toLowerCase();
          // 3. URL解码（使用缓存）
          if (decodeCache.has(domain)) {
            domain = decodeCache.get(domain);
          } else {
            try {
              const decoded = decodeURIComponent(domain.replace(/\+/g, ' '));
              decodeCache.set(domain, decoded);
              domain = decoded;
            } catch {
              decodeCache.set(domain, domain);
            }
          }
          // 4. 使用过滤规则提取域名
          const filterMatch = domain.match(SCANNER_CONFIG.PATTERNS.DOMAIN_FILTER);
          if (/\b[a-z]+\.(?:top|bottom)-[a-z]+\.top\b/.test(filterMatch[0])) return false;
          if (filterMatch && filterMatch[0].split('.')[0]!="el" && filterMatch[0].split('.')[0]!="e") {
            domain = filterMatch[0];
          } else {
            return false;
          }
          
          return domain;
        } catch {
          return false;
        }
      },

      // 检查是否在黑名单中
      notInBlacklist(domain) {
        return !SCANNER_CONFIG.DOMAIN.BLACKLIST.some(blacklisted => 
          domain.includes(blacklisted)
        );
      }
    };

    return function(match, url, resultsSet) {
      // 清理和标准化域名
      match = validate.clean(match);
      if (!match) return false;

      // 检查是否在黑名单中
      if (!validate.notInBlacklist(match)) {
        return false;
      }

      // 添加到结果集
      resultsSet?.domains?.set(match, url);
      return true;
    };
  })(),

  // IP 过滤器
  ip: (function() {
    const validate = {
      notSpecial(ip) {
        return !SCANNER_CONFIG.IP.SPECIAL_RANGES.some(range => range.test(ip));
      }
    };

    return function(match, url, resultsSet) {
      // 提取纯IP地址（带端口）
      match = match.replace(/^[`'"]|[`'"]$/g, '');
      const ipMatches = match.match(SCANNER_CONFIG.PATTERNS.IP) || [];
      let added = false;
      ipMatches.forEach((extractedIp) => {
        if (!validate.notSpecial(extractedIp)) return;
        resultsSet?.ips?.set(extractedIp, url);
        added = true;
      });
      return added;
    };
  })(),

  // 其他敏感信息过滤器
  phone: (match, url, resultsSet) => {
    resultsSet?.phones?.set(match, url);
    return true;
  },

  email: (match, url, resultsSet) => {
    resultsSet?.emails?.set(match, url);
    return true;
  },

  idcard: (match, url, resultsSet) => {
    resultsSet?.idcards?.set(match, url);
    return true;
  },

  url: (match, url, resultsSet) => {
    try {
      // 检查是否是GitHub URL
      if (match.toLowerCase().includes('github.com/')) {  
        resultsSet?.githubUrls?.set(match, url);
        return true;
      }
      resultsSet?.urls?.set(match, url);
      // 解析URL
      const matchUrl = new URL(match);
      const currentHost = window.location.host;
      // 检查是否是当前域名或IP
      if (matchUrl.host === currentHost) {
        // 获取路径部分
        const path = matchUrl.pathname;
        if (SCANNER_CONFIG.API.FONT_PATTERN.test(path)) {
          return false;
        }
        if (SCANNER_CONFIG.API.IMAGE_PATTERN.test(path)) {
          resultsSet?.imageFiles?.set(path, url);
          return true;
        }
        if (SCANNER_CONFIG.API.JS_PATTERN.test(path)) {
          resultsSet?.jsFiles?.set(path, url);
          return true;
        }
        if (SCANNER_CONFIG.API.DOC_PATTERN.test(path)) {
          resultsSet?.docFiles?.set(path, url);
          return true;
        }
        
        // 如果不是特定类型文件，则当作API处理
        if (!path.match(/\.[a-zA-Z0-9]+$/)) {
          // 区分绝对路径和相对路径
          if (path.startsWith('/')) {
            resultsSet?.absoluteApis?.set(path, url);
          } else {
            resultsSet?.apis?.set(path, url);
          }
          return true;
        }
      }
    } catch (e) {
      console.error('Error processing URL:', e);
    }
    
    return true;
  },

  jwt: (match, url, resultsSet) => {
    resultsSet?.jwts?.set(match, url);
    return true;
  },

  aws_key: (match, url, resultsSet) => {
    resultsSet?.awsKeys?.set(match, url);
    return true;
  },

  company: (match, url, resultsSet) => {
    const cleanMatch = String(match || '').trim();
    if (!cleanMatch) return false;
    const normalizedCompany = normalizeCompanyCandidate(cleanMatch);
    if (!normalizedCompany) return false;
    if (!isLikelyCompanyName(normalizedCompany)) return false;
    if (/[（）]/.test(normalizedCompany) && !normalizedCompany.match(/（\S*）/)) return false;
    const compactMatch = normalizedCompany.replace(/\s+/g, '');
    for (const blackWord of SCANNER_CONFIG.BLACKLIST.CHINESE_BLACKLIST) {
      if (!blackWord) continue;
      if (blackWord.length <= 2) {
        if (compactMatch === blackWord) return false;
        if (COMPANY_SHORT_NOISE_WORDS.has(blackWord) && compactMatch.includes(blackWord)) return false;
        continue;
      }
      if (compactMatch.includes(blackWord)) return false;
    }
    resultsSet?.companies?.set(normalizedCompany, url);
    return true;
  },

  credentials: (match, url, resultsSet) => {
    const normalizedMatch = match.replace(/\s+/g, '');
    const splitIndex = normalizedMatch.search(/[:=]/);
    if (splitIndex <= 0) return false;
    const key = normalizedMatch.slice(0, splitIndex).replace(/['"]/g, '').toLowerCase();
    const value = normalizedMatch.slice(splitIndex + 1).replace(/['"\{\}\[\]\，\：\。\？\、\?\!\>\<]/g, '').toLowerCase();
    if (!value.length) {
      return false; 
    }
    if (regexCache.coordPattern.test(key) || value.length <= 1) return false;
    if (regexCache.valuePattern.test(value)) return false;
    if (regexCache.chinesePattern.test(value) && value.length <= 4) return false;
    
    resultsSet?.credentials?.set(match, url);
    return true;
  },

  cookie: (match, url, resultsSet) => {
    // 检查是否是空值
    const valueMatch = match.replace(/\s+/g,'').split(/[:=]/);
    if (valueMatch[1].replace(/['"]/g,'').length<4) {
      return false;
    }
    var key = valueMatch[0].replace(/['"<>]/g,'').toLowerCase();
    var value = valueMatch[1].replace(/['"<>]/g,'').toLowerCase();
    if (!value.length||key==value) {
      return false; 
    }
    if (value.length<12){
      if(Array.from(SCANNER_CONFIG.BLACKLIST.SHORT_VALUES).some(blackWord=>value.includes(blackWord))){
        return false;
      }
    }else{
      if(Array.from(SCANNER_CONFIG.BLACKLIST.MEDIUM_VALUES).some(blackWord=>value.includes(blackWord))){
        return false;
      }
    }
    resultsSet?.cookies?.set(match, url);
    return true;
  },

  id_key: (match, url, resultsSet) => {
    // 先检查是否包含分隔符
    const hasDelimiter = match.match(/[:=]/);
    
    if (hasDelimiter || match.length >= 32) {
      // 只有在有分隔符的情况下才进行分割
      if (hasDelimiter) {
        const valueMatch = match.replace(/\s+/g,'').split(/[:=]/);
        var key = valueMatch[0].replace(/['"<>]/g,'');
        var value = valueMatch[1].replace(/['"><]/g,'');
        const keyLower = key.toLowerCase();
        const valueLower = value.toLowerCase();
        
        if (!value.length || keyLower === valueLower) {
          return false;
        }
        // 检查key是否在黑名单中
        if(Array.from(SCANNER_CONFIG.ID_KEY.KEY_BLACKLIST).some(blackWord=>keyLower.includes(blackWord))){
          return false;
        }
        // 检查value是否在统一黑名单中
        if(value.length<16){
          if(Array.from(SCANNER_CONFIG.BLACKLIST.SHORT_VALUES).some(blackWord=>valueLower.includes(blackWord))){
            return false;
          }
          if(Array.from(SCANNER_CONFIG.BLACKLIST.MEDIUM_VALUES).some(blackWord=>valueLower.includes(blackWord))){
            return false;
          }
        }else{
          if(Array.from(SCANNER_CONFIG.BLACKLIST.MEDIUM_VALUES).some(blackWord=>valueLower.includes(blackWord))){
            return false;
          }
          if(Array.from(SCANNER_CONFIG.BLACKLIST.LONG_VALUES).some(blackWord=>valueLower.includes(blackWord))){
            return false;
          }
        }
        // 其他检查
        if (key === "key" && (value.length <= 8 || regexCache.camelCasePattern.test(value))) {
          return false;
        }
        if (value.length <= 3) {
          return false;
        }
      } else {
        // 处理长度大于等于32的情况
        if (/^[a-zA-Z]+$/.test(match.slice(1,-1))) {
          return false;
        }
        // 检查value是否在统一黑名单中
        if(Array.from(SCANNER_CONFIG.BLACKLIST.MEDIUM_VALUES).some(blackWord=>match.includes(blackWord))){
          return false;
        }
        if(Array.from(SCANNER_CONFIG.BLACKLIST.LONG_VALUES).some(blackWord=>match.includes(blackWord))){
          return false;
        }
      }
      resultsSet?.idKeys?.set(match, url);
      return true;
    }
    return false;
  },
  windows_path: (match, url, resultsSet) => {
    resultsSet?.windowsPaths?.set(match, url);
    return true;
  },

  // 构建工具检测过滤器
  finger: (fingerName, fingerClass, fingerType, fingerDescription, url, resultsSet, fingerExtType, fingerExtName) => {
    var fingerprint = {};
    fingerprint.type = fingerType;
    fingerprint.name = fingerClass;
    fingerprint.description = `通过${fingerName}识别到${fingerClass}${fingerDescription}`;
    fingerprint.version = fingerClass;
    if(fingerExtType){
      fingerprint.extType = fingerExtType;
      fingerprint.extName = fingerExtName;
    }
    chrome.runtime.sendMessage({
      type: 'UPDATE_BUILDER',
      from: 'content',
      to: 'background',
      tabId: currentTabId,
      frameId: currentFrameId,
      finger: fingerprint
    });
    resultsSet?.fingers?.set(fingerClass, url);
    return true;
  }
};
SCANNER_FILTER.github = SCANNER_FILTER.url;

// 导出过滤器
window.SCANNER_FILTER = SCANNER_FILTER;
window.apiFilter = SCANNER_FILTER.api;
window.domainFilter = SCANNER_FILTER.domain;
window.ipFilter = SCANNER_FILTER.ip; 
let dynamicScanEnabled = false; 
let deepScanEnabled = false;
let currentTabId = null;
let currentFrameId = '0';
const isInIframe = window.self !== window.top;
let scanTimeout = null;
let observerInitialized = false;
let maxDepth = 3;
let tabJs = new Set();
let isWhitelisted = false;
let hostname = null;
let isUseWebpack = false;
const tree = {};
const jsQueue = [];
const queueSet = new Set();
const jsFileMap = new Map();
const inFlightSet = new Set();
const tabResults = new Map();
const reportedVulnIds = new Set();
const domXssFileStats = new Map();
const MAX_CONCURRENT = 10;
const MAX_CHUNK_SIZE = 50000;
const MAX_DEBUG_ITEMS = 1200;
const VUE_ROUTE_SCANNER_FILE = 'snow_x25.js';
const EXTERNAL_FINGERPRINT_LIBRARY_FILES = Array.isArray(FINGERPRINT_CORE.constants?.FINGERPRINT_LIBRARY_FILES)
  ? FINGERPRINT_CORE.constants.FINGERPRINT_LIBRARY_FILES
  : ['finger.json', 'kscan_fingerprint.json', 'webapp.json', 'apps.json'];
const EXTERNAL_FINGERPRINT_SCORE_THRESHOLD = Number(FINGERPRINT_CORE.constants?.FINGERPRINT_SCORE_THRESHOLD || 72);
const EXTERNAL_FINGERPRINT_STORE_CACHE_KEY = 'snoweyes_unified_fingerprint_store_v2';
const EXTERNAL_FINGERPRINT_STORE_CACHE_VERSION = Number(FINGERPRINT_CORE.constants?.FINGERPRINT_RULE_CACHE_VERSION || 5);
const EXTERNAL_FINGERPRINT_BODY_SCAN_LIMIT = 480000;
const EXTERNAL_FINGERPRINT_MAX_FAVICON_URLS = 6;
const EXTERNAL_FINGERPRINT_MIN_INTERVAL_MS = 3500;
let vueRouteListenerBound = false;
let vueRouteScriptInjected = false;
let externalFingerprintLibrary = null;
let externalFingerprintLibraryPromise = null;
let externalFingerprintScanRunning = false;
let externalFingerprintLastDomSignature = '';
let externalFingerprintLastRunAt = 0;

async function initSettings() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['dynamicScan', 'deepScan', 'customWhitelist'], async (result) => {
      hostname = window.location.hostname.toLowerCase();
      dynamicScanEnabled = result.dynamicScan === true;
      deepScanEnabled = result.deepScan === true;
      isWhitelisted = result.customWhitelist?.some(domain => hostname === domain || hostname.endsWith(`.${domain}`));
      chrome.runtime.sendMessage({
        type: 'REGISTER_CONTENT',
        from: 'content',
        to: 'background',
        frameId: currentFrameId
      }, (response) => {
        if(isWhitelisted) return;
        currentFrameId = String(response?.frameId ?? currentFrameId ?? '0');
        tabJs = Array.isArray(response?.tabJs) ? response.tabJs : [];
        currentTabId = response?.tabId;
        if (!currentTabId) return;
        getTabResults(currentTabId);
        const resultsSet = tabResults.get(currentTabId);
        incrementDebugCounter(resultsSet, 'background_initial_js_count', tabJs.length);
        tabJs.forEach(url => {
          enqueueJsUrl(url, 'background:init', '', 'background');
        });
      });
      resolve();
    });
  });
}
const waitForDependencies = () => {
  const deps = [
    'SCANNER_CONFIG',
    'SCANNER_FILTER',
    'logger'
  ];
  return new Promise(resolve => {
    (function check() {
      deps.every(dep => window[dep]) ? resolve() : setTimeout(check, 20);
    })();
  });
};
const getTabId = () => {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ type: 'GET_TAB_ID', from: 'content', to: 'background'}, response => {
      currentTabId = response.tabId;
      resolve(currentTabId);
    });
  });
};
const isThirdPartyLib = (url) => {
  const fileName = url.split('/').pop()?.split('?')[0]?.toLowerCase() || '';
  const patterns = Array.isArray(SCANNER_CONFIG.THIRD_PARTY_LIBS) && SCANNER_CONFIG.THIRD_PARTY_LIBS.length
    ? SCANNER_CONFIG.THIRD_PARTY_LIBS
    : SCANNER_CONFIG.API.SKIP_JS_PATTERNS;
  return patterns.some(pattern => pattern.test(fileName));
};
function getBasePath(url){
  const filePath = new URL(url).pathname;
  let pathArray = filePath.split('/');
  pathArray.pop();
  return pathArray.join('/')+'/';
}
function getJsDisplayPath(url = '') {
  try {
    const parsed = new URL(url);
    const path = decodeURIComponent(parsed.pathname || '/');
    return `${path}${parsed.search || ''}`;
  } catch {
    return String(url || '');
  }
}
function buildTree(path) {
  const parts = path.split('/').filter(Boolean);
    let current = tree;
    parts.forEach(part => {
      if (!current[part]) current[part] = {};
      current = current[part];
    });
  return tree;
}
function findFullPath(tree, target, currentPath = '') {
  for (const key in tree) {
    const nextPath = currentPath + '/' + key;
    if (key === target.split('/')[1]) {
      return nextPath;
    }
    const result = findFullPath(tree[key], target, nextPath);
    if (result) return result;
  }
  return '';
}
function enqueueJsUrl(url, source = 'page', basePath = '', sourceRef = '') {
  const resultsSet = tabResults.get(currentTabId);
  if (isWhitelisted) return;

  let queuedUrl = '';
  try {
    const parsed = new URL(url, document.baseURI || window.location.href);
    if (!/^https?:$/i.test(parsed.protocol)) return;
    if (parsed.hostname.toLowerCase() !== hostname) return;
    queuedUrl = parsed.href;
  } catch {
    return;
  }
  const sourceLabel = String(sourceRef || (source.startsWith('background') ? 'background' : document.location.href));

  if (isThirdPartyLib(queuedUrl)) {
    resultsSet?.thirdPartyLibs?.set(getJsDisplayPath(queuedUrl), sourceLabel);
    incrementDebugCounter(resultsSet, 'js_skipped_third_party', 1);
    setDebugInfo(resultsSet, 'debugFetchFailedJs', queuedUrl, `skip: third-party(${source})`);
    return;
  }

  if (!queueSet.has(queuedUrl)) {
    const fileName = queuedUrl.split('/').pop()?.split('?')[0];
    const filePath = new URL(queuedUrl).pathname;
    const fileBasePath = getBasePath(queuedUrl);
    const existFilePath = jsFileMap.get(fileName);
    if (source === 'page' && deepScanEnabled) {
      if (existFilePath && existFilePath.includes(filePath)) {
        return;
      }
      if (!existFilePath && basePath) {
        let fullPathParts = findFullPath(tree, fileBasePath)?.split('/');
        if (fullPathParts) {
          fullPathParts.pop();
          let fullPath = fullPathParts.join('/') + fileBasePath;
          queuedUrl = queuedUrl.replace(fileBasePath, fullPath);
        }
      }
    }
    buildTree(fileBasePath);
    jsFileMap.set(fileName, filePath);
    queueSet.add(queuedUrl);
    jsQueue.push(queuedUrl);
    if (resultsSet) {
      resultsSet.jsFiles.set(getJsDisplayPath(queuedUrl), sourceLabel);
    }
    incrementDebugCounter(resultsSet, 'js_discovered_total', 1);
    setDebugInfo(resultsSet, 'debugDiscoveredJs', queuedUrl, `source=${source}`);
    processJsQueue();
  } else {
    incrementDebugCounter(resultsSet, 'js_discovered_duplicate', 1);
  }
}
function* splitIntoChunks(text) {
  if (text.length <= MAX_CHUNK_SIZE) {
    yield text;
    return;
  }
  const lines = text.split(/\r?\n/);
  let currentLines = [];
  let currentSize = 0;

  for (const line of lines) {
    const lineSize = line.length + 1;

    if (currentSize + lineSize > MAX_CHUNK_SIZE) {
      if (currentSize > 0) {
        yield currentLines.join('\n') + '\n';
        currentLines = [];
        currentSize = 0;
      }
      if (line.length > MAX_CHUNK_SIZE) {
        for (let i = 0; i < line.length; i += MAX_CHUNK_SIZE) {
          yield line.slice(i, i + MAX_CHUNK_SIZE);
        }
      } else {
        currentLines.push(line);
        currentSize = lineSize;
      }
    } else {
      currentLines.push(line);
      currentSize += lineSize;
    }
  }

  if (currentLines.length > 0) {
    yield currentLines.join('\n') + '\n';
  }
}
const normalizeText = (value = '') => value.replace(/\s+/g, ' ').trim();
const truncate = (value = '', maxLen = 120) => value.length > maxLen ? `${value.slice(0, maxLen)}...` : value;
const stableHash = (value = '') => {
  if (typeof REPORT_UTILS.stableHash === 'function') {
    return REPORT_UTILS.stableHash(value);
  }
  let hash = 0;
  const text = String(value || '');
  for (let i = 0; i < text.length; i++) {
    hash = ((hash << 5) - hash) + text.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash).toString(36);
};
async function readCachedUnifiedFingerprintStore() {
  try {
    const cache = await chrome.storage.session.get(EXTERNAL_FINGERPRINT_STORE_CACHE_KEY);
    const payload = cache?.[EXTERNAL_FINGERPRINT_STORE_CACHE_KEY];
    if (!payload || payload.version !== EXTERNAL_FINGERPRINT_STORE_CACHE_VERSION) return null;
    const rules = payload?.normalizedStore?.rules;
    if (!Array.isArray(rules) || rules.length === 0) return null;
    return {
      normalizedStore: payload.normalizedStore,
      wappalyzerCatalog: payload.wappalyzerCatalog && typeof payload.wappalyzerCatalog === 'object'
        ? payload.wappalyzerCatalog
        : null
    };
  } catch {
    return null;
  }
}
async function writeCachedUnifiedFingerprintStore(normalizedStore, wappalyzerCatalog) {
  try {
    await chrome.storage.session.set({
      [EXTERNAL_FINGERPRINT_STORE_CACHE_KEY]: {
        version: EXTERNAL_FINGERPRINT_STORE_CACHE_VERSION,
        normalizedStore,
        wappalyzerCatalog: wappalyzerCatalog && typeof wappalyzerCatalog === 'object' ? wappalyzerCatalog : null
      }
    });
  } catch {}
}
async function fetchFingerprintPayload(fileName = '') {
  const target = String(fileName || '').trim();
  if (!target) return null;
  try {
    const url = chrome.runtime.getURL(target);
    const response = await fetch(url, { cache: 'no-cache' });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    window.logger.warn(`[Scanner] 指纹文件加载失败(${target}):`, error?.message || error);
    return null;
  }
}
async function loadExternalFingerprintLibrary() {
  if (externalFingerprintLibrary) return externalFingerprintLibrary;
  if (externalFingerprintLibraryPromise) return externalFingerprintLibraryPromise;

  externalFingerprintLibraryPromise = (async () => {
    const cachedStore = await readCachedUnifiedFingerprintStore();
    let normalizedStore = cachedStore?.normalizedStore || null;
    let cachedWappalyzerCatalog = cachedStore?.wappalyzerCatalog || null;
    if (!normalizedStore) {
      const payloadMap = Object.create(null);
      await Promise.all(EXTERNAL_FINGERPRINT_LIBRARY_FILES.map(async (fileName) => {
        payloadMap[fileName] = await fetchFingerprintPayload(fileName);
      }));
      if (typeof FINGERPRINT_UTILS.buildUnifiedCompiledFingerprintStore === 'function') {
        externalFingerprintLibrary = FINGERPRINT_UTILS.buildUnifiedCompiledFingerprintStore(payloadMap);
        if (externalFingerprintLibrary?.normalizedRuleStore?.rules?.length > 0) {
          void writeCachedUnifiedFingerprintStore(
            externalFingerprintLibrary.normalizedRuleStore,
            null
          );
        }
        window.logger.info(
          `[Scanner] 外部统一指纹库已加载: rules=${externalFingerprintLibrary?.rules?.length || 0}, wappalyzer=${externalFingerprintLibrary?.wappalyzerCatalog?.apps?.length || 0}`
        );
        return externalFingerprintLibrary;
      }
      if (typeof FINGERPRINT_UTILS.buildNormalizedRuleStore !== 'function') {
        throw new Error('buildNormalizedRuleStore 不可用');
      }
      normalizedStore = FINGERPRINT_UTILS.buildNormalizedRuleStore(payloadMap);
      const wappPayload = payloadMap['apps.json'] || payloadMap['wappalyzer_apps.json'] || payloadMap.wappalyzer || {};
      cachedWappalyzerCatalog = typeof FINGERPRINT_UTILS.normalizeWappalyzerCatalog === 'function'
        ? FINGERPRINT_UTILS.normalizeWappalyzerCatalog(wappPayload)
        : { apps: [], categories: {} };
      if (normalizedStore?.rules?.length > 0) {
        void writeCachedUnifiedFingerprintStore(normalizedStore, null);
      }
    }

    if (!cachedWappalyzerCatalog) {
      const wappPayload = await fetchFingerprintPayload('apps.json');
      cachedWappalyzerCatalog = typeof FINGERPRINT_UTILS.normalizeWappalyzerCatalog === 'function'
        ? FINGERPRINT_UTILS.normalizeWappalyzerCatalog(wappPayload || {})
        : { apps: [], categories: {} };
    }

    const compiled = typeof FINGERPRINT_UTILS.compileNormalizedRuleStore === 'function'
      ? FINGERPRINT_UTILS.compileNormalizedRuleStore(normalizedStore)
      : { rules: [] };
    const wappalyzerCatalog = cachedWappalyzerCatalog || (
      typeof FINGERPRINT_UTILS.normalizeWappalyzerCatalog === 'function'
        ? FINGERPRINT_UTILS.normalizeWappalyzerCatalog({})
        : { apps: [], categories: {} }
    );
    externalFingerprintLibrary = {
      ...compiled,
      normalizedRuleStore: normalizedStore,
      wappalyzerCatalog
    };
    window.logger.info(
      `[Scanner] 外部统一指纹库已加载: rules=${externalFingerprintLibrary?.rules?.length || 0}, wappalyzer=${externalFingerprintLibrary?.wappalyzerCatalog?.apps?.length || 0}`
    );
    return externalFingerprintLibrary;
  })().catch((error) => {
    window.logger.warn('外部统一指纹库加载失败:', error?.message || error);
    externalFingerprintLibrary = {
      rules: [],
      wappalyzerCatalog: { apps: [], categories: {} },
      stats: {}
    };
    return externalFingerprintLibrary;
  }).finally(() => {
    externalFingerprintLibraryPromise = null;
  });

  return externalFingerprintLibraryPromise;
}
function sampleBodyHtmlForFingerprint(rawHtml = '') {
  if (typeof FINGERPRINT_UTILS.sampleBodyHtmlForFingerprint === 'function') {
    return FINGERPRINT_UTILS.sampleBodyHtmlForFingerprint(rawHtml, EXTERNAL_FINGERPRINT_BODY_SCAN_LIMIT);
  }
  return String(rawHtml || '');
}
function toAbsoluteUrl(rawUrl = '') {
  try {
    return new URL(String(rawUrl || ''), document.baseURI || window.location.href).href;
  } catch {
    return '';
  }
}
function collectFaviconCandidateUrls() {
  const urls = new Set();
  const links = Array.from(document.querySelectorAll('link[rel]'));
  links.forEach((link) => {
    const rel = String(link.getAttribute('rel') || '').toLowerCase();
    if (!rel.includes('icon')) return;
    const href = toAbsoluteUrl(link.getAttribute('href') || '');
    if (href) urls.add(href);
  });
  const fallback = toAbsoluteUrl('/favicon.ico');
  if (fallback) urls.add(fallback);
  return Array.from(urls).slice(0, EXTERNAL_FINGERPRINT_MAX_FAVICON_URLS);
}
function fetchBinaryViaBackground(url = '') {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({
      type: 'FETCH_BINARY',
      from: 'content',
      to: 'background',
      url: String(url || '')
    }, (response) => {
      resolve(response || null);
    });
  });
}
function computeFaviconHashCandidates(base64 = '') {
  if (typeof FINGERPRINT_UTILS.computeFaviconHashCandidates === 'function') {
    return FINGERPRINT_UTILS.computeFaviconHashCandidates(base64);
  }
  return [];
}
function emitFingerprintHit(resultsSet, fingerprint) {
  if (!resultsSet?.fingers) return false;
  const name = String(fingerprint?.name || '').trim();
  if (!name || resultsSet.fingers.has(name)) return false;
  chrome.runtime.sendMessage({
    type: 'UPDATE_BUILDER',
    from: 'content',
    to: 'background',
    tabId: currentTabId,
    frameId: currentFrameId,
    finger: fingerprint
  });
  resultsSet.fingers.set(name, document.location.href);
  return true;
}
function applyExternalFingerprintMatch(resultsSet, match = {}, sourceName = '') {
  if (!resultsSet?.fingers) return false;
  const name = String(match?.name || '').trim();
  if (!name || resultsSet.fingers.has(name)) return false;
  const type = String(match?.type || 'component').trim() || 'component';
  const score = Number(match?.score || 0);
  const confidence = String(match?.confidence || (score >= 90 ? 'high' : score >= 75 ? 'medium' : 'low'));
  const version = String(match?.version || name);
  const fields = Array.isArray(match?.matchedFields) ? match.matchedFields.filter(Boolean).join(',') : '';
  const source = String(match?.source || sourceName || 'external');
  const description = `通过${sourceName || source}识别到网站使用${name}（置信度:${confidence}${score ? `/${score}` : ''}${fields ? `，字段:${fields}` : ''}）`;
  return emitFingerprintHit(resultsSet, {
    type,
    name,
    version,
    score,
    confidence,
    source,
    matchedFields: Array.isArray(match?.matchedFields) ? match.matchedFields : [],
    evidence: Array.isArray(match?.traces) ? match.traces : [],
    description
  });
}
async function collectFaviconHashCandidatesForScan() {
  const hashSet = new Set();
  const urls = collectFaviconCandidateUrls();
  if (!urls.length) return [];
  for (const faviconUrl of urls) {
    const response = await fetchBinaryViaBackground(faviconUrl);
    if (!response?.success || !response.base64) continue;
    computeFaviconHashCandidates(response.base64).forEach((hash) => hashSet.add(String(hash)));
    if (hashSet.size >= 6) break;
  }
  return Array.from(hashSet);
}
function collectMetaMapForFingerprint() {
  const map = new Map();
  document.querySelectorAll('meta[name],meta[property],meta[http-equiv]').forEach((meta) => {
    const key = String(meta.getAttribute('name') || meta.getAttribute('property') || meta.getAttribute('http-equiv') || '').trim().toLowerCase();
    if (!key || map.has(key)) return;
    const value = String(meta.getAttribute('content') || '').trim();
    if (value) map.set(key, value);
  });
  return map;
}
function collectCookieMapForFingerprint(cookieText = '') {
  const map = new Map();
  String(cookieText || '')
    .split(';')
    .forEach((rawPart) => {
      const part = String(rawPart || '').trim();
      if (!part) return;
      const equalIndex = part.indexOf('=');
      if (equalIndex > 0) {
        const key = String(part.slice(0, equalIndex) || '').trim().toLowerCase();
        if (!key) return;
        const value = String(part.slice(equalIndex + 1) || '').trim();
        if (!map.has(key)) {
          map.set(key, value);
        }
        return;
      }
      const key = part.toLowerCase();
      if (/^[a-z0-9_.-]{1,120}$/.test(key) && !map.has(key)) {
        map.set(key, '');
      }
    });
  return map;
}
function collectScriptUrlsForFingerprint() {
  const urls = new Set();
  document.querySelectorAll('script[src]').forEach((node) => {
    const src = String(node.getAttribute('src') || '').trim();
    if (!src) return;
    const full = toAbsoluteUrl(src);
    if (full) urls.add(full);
  });
  return Array.from(urls).slice(0, 220);
}
function collectEnvKeysForFingerprint(max = 420) {
  const result = [];
  try {
    Object.keys(window).forEach((key) => {
      if (result.length < max) result.push(String(key || ''));
    });
  } catch {}
  return result;
}
async function runExternalFingerprintScan() {
  if (isInIframe) return false;
  if (externalFingerprintScanRunning) return false;
  const now = Date.now();
  if (now - externalFingerprintLastRunAt < EXTERNAL_FINGERPRINT_MIN_INTERVAL_MS) return false;
  const resultsSet = tabResults.get(currentTabId);
  if (!resultsSet) return false;

  externalFingerprintScanRunning = true;
  externalFingerprintLastRunAt = now;
  try {
    const library = await loadExternalFingerprintLibrary();
    const titleSource = String(document.title || '');
    const htmlSource = sampleBodyHtmlForFingerprint(document.documentElement?.innerHTML || '');
    const cookieText = String(document.cookie || '').trim();
    const signature = stableHash(`${window.location.href}|${titleSource}|${htmlSource.length}|${htmlSource.slice(0, 12000)}|${cookieText.length}|${cookieText.slice(0, 1200)}`);
    if (signature === externalFingerprintLastDomSignature) {
      return false;
    }
    externalFingerprintLastDomSignature = signature;

    const headersMap = new Map();
    const metaMap = collectMetaMapForFingerprint();
    const cookiesMap = collectCookieMapForFingerprint(cookieText);
    const scripts = collectScriptUrlsForFingerprint();
    const env = collectEnvKeysForFingerprint();
    const iconHashes = await collectFaviconHashCandidatesForScan();
    const jsProbe = typeof FINGERPRINT_UTILS.collectWappalyzerJsProbeValues === 'function'
      ? FINGERPRINT_UTILS.collectWappalyzerJsProbeValues(library?.wappalyzerCatalog || { apps: [] }, window, 180)
      : {};
    const hits = typeof FINGERPRINT_UTILS.detectFingerprintsWithUnifiedStore === 'function'
      ? FINGERPRINT_UTILS.detectFingerprintsWithUnifiedStore(library, {
        url: window.location.href,
        title: titleSource,
        body: htmlSource,
        headersMap,
        metaMap,
        cookieText,
        cookiesMap,
        scripts,
        env,
        iconHashes,
        jsProbe
      }, {
        threshold: EXTERNAL_FINGERPRINT_SCORE_THRESHOLD
      })
      : [];

    let updated = false;
    hits.forEach((hit) => {
      if (applyExternalFingerprintMatch(resultsSet, hit, hit?.source || 'unified-fingerprint-engine')) {
        updated = true;
      }
    });
    return updated;
  } catch (error) {
    window.logger.warn('外部统一指纹扫描失败:', error?.message || error);
    return false;
  } finally {
    externalFingerprintScanRunning = false;
  }
}
function setLimitedMapEntry(map, key, value, limit = MAX_DEBUG_ITEMS) {
  if (!(map instanceof Map)) return;
  const safeKey = String(key || '').trim().slice(0, 220);
  if (!safeKey) return;
  if (map.has(safeKey)) return;
  if (map.size >= limit) {
    const firstKey = map.keys().next().value;
    if (firstKey) map.delete(firstKey);
  }
  map.set(safeKey, String(value || '').slice(0, 520));
}
function incrementDebugCounter(resultsSet, key, delta = 1) {
  if (!resultsSet?.debugSummary) return;
  const currentValue = Number(resultsSet.debugSummary.get(key) || 0);
  resultsSet.debugSummary.set(key, currentValue + delta);
}
function setDebugInfo(resultsSet, mapKey, key, value) {
  if (!resultsSet) return;
  const map = resultsSet[mapKey];
  if (!(map instanceof Map)) return;
  setLimitedMapEntry(map, key, value);
}
function isLikelyHtmlDocument(text = '') {
  const head = String(text || '').slice(0, 2200).toLowerCase();
  if (!head) return false;
  return head.includes('<!doctype') || head.includes('<html') || head.includes('<body');
}
function getDomXssFileStatKey(url = '') {
  return `${currentTabId || 0}|${String(url || '')}`;
}
function getOrCreateDomXssFileStat(url = '') {
  const key = getDomXssFileStatKey(url);
  if (!domXssFileStats.has(key)) {
    domXssFileStats.set(key, { total: 0, sinkOnly: 0 });
  }
  return domXssFileStats.get(key);
}
const testRegex = (regex, text) => {
  if (!(regex instanceof RegExp)) return false;
  regex.lastIndex = 0;
  return regex.test(text);
};
function findRuleName(text, rules = []) {
  for (const rule of rules) {
    if (testRegex(rule.pattern, text)) {
      return rule.name;
    }
  }
  return '';
}
const JS_RESERVED_WORDS = new Set([
  'var', 'let', 'const', 'function', 'return', 'if', 'else', 'for', 'while', 'switch',
  'case', 'break', 'continue', 'new', 'this', 'true', 'false', 'null', 'undefined',
  'try', 'catch', 'finally', 'class', 'extends', 'super', 'import', 'export', 'default',
  'await', 'async', 'typeof', 'instanceof', 'in', 'of', 'delete', 'void', 'yield',
  'window', 'document', 'location', 'decodeURIComponent', 'encodeURIComponent',
  'URLSearchParams', 'Math', 'JSON', 'Object', 'Array', 'String', 'Number', 'Boolean',
  'Date', 'RegExp', 'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval'
]);
function stripQuotedLiterals(text = '') {
  return String(text).replace(/(["'`])(?:\\.|(?!\1)[^\\])*\1/g, ' ');
}
function extractIdentifiers(expression = '') {
  const source = stripQuotedLiterals(expression);
  const matches = source.match(/\b[$A-Za-z_][$\w]*\b/g) || [];
  return matches.filter((token) => !JS_RESERVED_WORDS.has(token));
}
function parseAssignment(line = '') {
  const trimmed = String(line).trim();
  if (!trimmed || trimmed.startsWith('//')) return null;

  const declareMatch = trimmed.match(/^(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*([\s\S]+?);?\s*$/);
  if (declareMatch) {
    return { varName: declareMatch[1], expression: declareMatch[2] };
  }
  const assignMatch = trimmed.match(/^([A-Za-z_$][\w$]*)\s*=\s*([\s\S]+?);?\s*$/);
  if (assignMatch) {
    return { varName: assignMatch[1], expression: assignMatch[2] };
  }
  const thisPropMatch = trimmed.match(/^(?:this|self|vm|ctx)\.([A-Za-z_$][\w$]*)\s*=\s*([\s\S]+?);?\s*$/);
  if (thisPropMatch) {
    return { varName: thisPropMatch[1], expression: thisPropMatch[2] };
  }
  const objectPropMatch = trimmed.match(/^(?:[A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)\s*=\s*([\s\S]+?);?\s*$/);
  if (objectPropMatch) {
    return { varName: objectPropMatch[1], expression: objectPropMatch[2] };
  }
  return null;
}
function extractSourceParam(text = '') {
  const normalized = String(text || '');
  if (!normalized) return '';

  const patterns = [
    /(?:searchParams|get)\s*\(\s*['"`]([A-Za-z0-9_.-]{1,60})['"`]\s*\)/i,
    /split\(\s*['"`]([A-Za-z0-9_.-]{1,60})=/i,
    /[?&]([A-Za-z0-9_.-]{1,60})=/,
    /(?:query|params)\.([A-Za-z0-9_$]{1,60})/i
  ];
  for (const regex of patterns) {
    const match = normalized.match(regex);
    if (match?.[1]) {
      return match[1];
    }
  }
  return '';
}
function extractSinkExpression(line = '', sinkName = '') {
  const sourceLine = String(line || '');
  if (!sourceLine) return '';

  if (sinkName === 'insertAdjacentHTML') {
    const match = sourceLine.match(/insertAdjacentHTML\s*\(([\s\S]+)\)\s*;?/i);
    if (!match?.[1]) return sourceLine;
    const args = match[1].split(',');
    return args.slice(1).join(',') || match[1];
  }
  if (sinkName === 'document.write') {
    const match = sourceLine.match(/document\.(?:write|writeln)\s*\(([\s\S]+)\)\s*;?/i);
    return match?.[1] || sourceLine;
  }
  if (
    sinkName === 'jquery html()' ||
    sinkName === 'jquery append()' ||
    sinkName === 'jquery prepend()' ||
    sinkName === 'jquery before()' ||
    sinkName === 'jquery after()' ||
    sinkName === 'jquery replaceWith()' ||
    sinkName === 'jquery insertAfter()' ||
    sinkName === 'jquery insertBefore()' ||
    sinkName === 'jquery replaceAll()' ||
    sinkName === 'jquery wrap()' ||
    sinkName === 'jquery wrapInner()' ||
    sinkName === 'jquery wrapAll()' ||
    sinkName === 'jquery add()' ||
    sinkName === 'jquery has()' ||
    sinkName === 'jquery index()' ||
    sinkName === 'jquery animate()'
  ) {
    const match = sourceLine.match(/\.\s*(?:html|append|prepend|before|after|replaceWith|insertAfter|insertBefore|replaceAll|wrap|wrapInner|wrapAll|add|has|index|animate)\s*\(([\s\S]+)\)\s*;?/i);
    return match?.[1] || sourceLine;
  }
  if (sinkName === 'jquery attr(href/src/action)') {
    const match = sourceLine.match(/\.attr\s*\(\s*['"`](?:href|src|action|formaction|xlink:href)['"`]\s*,\s*([\s\S]+?)\)\s*;?/i);
    return match?.[1] || sourceLine;
  }
  if (sinkName === 'jQuery.parseHTML') {
    const match = sourceLine.match(/(?:jQuery|\$)\.parseHTML\s*\(([\s\S]+)\)\s*;?/i);
    return match?.[1] || sourceLine;
  }
  if (sinkName === 'setAttribute(on*)') {
    const match = sourceLine.match(/setAttribute\s*\(\s*['"`]on[a-z]{3,20}['"`]\s*,\s*([\s\S]+?)\)\s*;?/i);
    return match?.[1] || sourceLine;
  }
  const equalIndex = sourceLine.indexOf('=');
  if (equalIndex > -1) {
    return sourceLine.slice(equalIndex + 1);
  }
  return sourceLine;
}
function parseParamList(raw = '') {
  const params = [];
  String(raw || '').split(',').forEach((rawParam) => {
    const cleaned = rawParam.split('=')[0].trim().replace(/^\.\.\./, '');
    if (/^[A-Za-z_$][\w$]*$/.test(cleaned) && !params.includes(cleaned)) {
      params.push(cleaned);
    }
  });
  return params;
}
function getNearestFunctionSignature(lines = [], index = 0) {
  const maxLookBack = 30;
  for (let j = index; j >= Math.max(0, index - maxLookBack); j--) {
    const line = String(lines[j] || '');
    let match = line.match(/^\s*([A-Za-z_$][\w$]*)\s*:\s*function\s*\(([^)]*)\)/);
    if (match) {
      return {
        lineNo: j + 1,
        line,
        functionName: match[1],
        params: parseParamList(match[2])
      };
    }
    match = line.match(/^\s*function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)/);
    if (match) {
      return {
        lineNo: j + 1,
        line,
        functionName: match[1],
        params: parseParamList(match[2])
      };
    }
    match = line.match(/^\s*([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{/);
    if (match) {
      return {
        lineNo: j + 1,
        line,
        functionName: match[1],
        params: parseParamList(match[2])
      };
    }
    match = line.match(/\bfunction\s*\(([^)]*)\)/);
    if (match) {
      return {
        lineNo: j + 1,
        line,
        functionName: '',
        params: parseParamList(match[1])
      };
    }
  }
  return null;
}
function isLikelyUserControlledParamName(param = '') {
  const name = String(param || '').trim();
  if (!name) return false;
  if (/^(?:req|res|ctx|event|e|evt|payload|data|input|value|html|text|content|message|msg|url|href|src|query|params?|route|hash|search|path|keyword|q|id|name|code|token)$/i.test(name)) {
    return true;
  }
  if (name.length <= 1) return false;
  return /(?:url|href|src|html|text|content|message|msg|payload|query|param|route|hash|search|path|code|token|input|value|keyword|data|body)/i.test(name);
}
function inferSourceFromFunctionArgs(lines = [], index = 0, context = '', sinkExpression = '') {
  const signature = getNearestFunctionSignature(lines, index);
  if (!signature?.params?.length) return null;
  const usedIdentifiers = extractIdentifiers(sinkExpression);
  const matchedParam = signature.params.find(param => usedIdentifiers.includes(param));
  if (!matchedParam) return null;

  const functionName = String(signature.functionName || '');
  const routeHintPattern = /\b(route|router|backbone\.router|history|fragment|hash|showtestparam|testhandler|lessoncontent|showlesson)\b/i;
  const hasRouteHint = routeHintPattern.test(`${context}\n${functionName}`);
  if (!hasRouteHint && !isLikelyUserControlledParamName(matchedParam)) {
    return null;
  }
  return {
    sourceName: hasRouteHint ? 'route parameter' : 'function argument',
    sourceParam: matchedParam,
    functionContextLine: {
      lineNo: signature.lineNo,
      line: signature.line
    }
  };
}
function isGenericVariableOnlyExpression(expression = '') {
  const trimmed = String(expression || '').trim().replace(/;$/, '').trim();
  if (!trimmed) return false;
  const identifiers = extractIdentifiers(trimmed);
  if (identifiers.length !== 1) return false;
  return /^(html|content|template|tpl|markup|msg|message|text|result|output|body)$/i.test(identifiers[0]);
}
function isOnlyStaticLiteralExpression(expression = '') {
  const trimmed = String(expression || '').trim().replace(/;$/, '').trim();
  if (!trimmed) return false;
  const tokens = extractIdentifiers(trimmed);
  if (tokens.length > 0) return false;
  return /^['"`][\s\S]*['"`]$/.test(trimmed);
}
function hitLowFalsePositiveTemplate(context = '', sinkExpression = '', sourceName = '', domXssConfig = {}) {
  if (sourceName) return false;
  if (isOnlyStaticLiteralExpression(sinkExpression)) return true;
  if (isGenericVariableOnlyExpression(sinkExpression)) return true;
  const templates = Array.isArray(domXssConfig.LOW_FP_TEMPLATES) ? domXssConfig.LOW_FP_TEMPLATES : [];
  const text = `${context}\n${sinkExpression}`;
  return templates.some(regex => testRegex(regex, text));
}
function resolveSourceFromTaint(expression = '', taintMap = new Map()) {
  const identifiers = extractIdentifiers(expression);
  for (const name of identifiers) {
    if (taintMap.has(name)) {
      return taintMap.get(name);
    }
  }
  return null;
}
function updateJqueryState(line = '', jqueryVarMap = new Map()) {
  const text = String(line || '');
  if (!text) return;
  const direct = text.match(/\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*(?:window\.)?(?:jQuery|\$)\s*\(/);
  if (direct?.[1]) {
    jqueryVarMap.set(direct[1], true);
    return;
  }
  const thisDirect = text.match(/\b(?:this|self|vm|ctx)\.\s*([A-Za-z_$][\w$]*)\s*=\s*(?:window\.)?(?:jQuery|\$)\s*\(/);
  if (thisDirect?.[1]) {
    jqueryVarMap.set(thisDirect[1], true);
    return;
  }
  const alias = text.match(/\b(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*)\s*;?/);
  if (alias?.[1] && alias?.[2] && jqueryVarMap.has(alias[2])) {
    jqueryVarMap.set(alias[1], true);
  }
}
function getJqueryMethodNameFromSink(sinkName = '') {
  const match = String(sinkName || '').match(/^jquery\s+([A-Za-z_$][\w$]*)\(\)$/i);
  return match?.[1] || '';
}
function hasLikelyJqueryContext(line = '', sinkName = '', jqueryVarMap = new Map()) {
  const method = getJqueryMethodNameFromSink(sinkName);
  if (!method) return false;
  const text = String(line || '');
  if (!text) return false;
  if (/(?:window\.)?(?:jQuery|\$)\s*\(/.test(text)) {
    return true;
  }
  if (hasJqueryChainHint(text, method)) {
    return true;
  }
  const receiverRegex = new RegExp(String.raw`([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\.\s*${method}\s*\(`);
  const receiverMatch = text.match(receiverRegex);
  if (receiverMatch?.[1]) {
    const chain = receiverMatch[1];
    const segments = chain.split('.');
    if (segments.some((seg) => jqueryVarMap.has(seg))) {
      return true;
    }
    if (segments.some((seg) => /^\$[A-Za-z_$][\w$]*$/.test(seg))) {
      return true;
    }
    if (/^(?:this|self|vm|view|ctx)\.\$[A-Za-z_$][\w$]*$/i.test(chain)) {
      return true;
    }
  }
  return false;
}
function hasJqueryChainHint(line = '', methodName = '') {
  const text = String(line || '');
  const method = String(methodName || '').trim();
  if (!text || !method) return false;

  if (/(?:window\.)?(?:jQuery|\$)\s*\(/.test(text)) {
    return true;
  }
  if (/(?:^|[^A-Za-z0-9_])\$[A-Za-z_$][\w$]*\s*\./.test(text)) {
    return true;
  }
  if (/\b(?:this|self|vm|view|ctx)\s*\.\s*\$[A-Za-z_$][\w$]*/i.test(text)) {
    return true;
  }

  const chainHintRegex = new RegExp(
    String.raw`\.\s*(?:find|closest|children|child|parent|parents|siblings|next|prev|filter|not|eq|first|last|end)\s*\([^)]*\)\s*\.\s*${escapeRegexLiteral(method)}\s*\(`,
    'i'
  );
  return chainHintRegex.test(text);
}
function hasLikelyJqueryAttrContext(line = '', jqueryVarMap = new Map()) {
  const text = String(line || '');
  if (!text) return false;
  if (/(?:window\.)?(?:jQuery|\$)\s*\(/.test(text)) {
    return true;
  }
  const receiverMatch = text.match(/\b([A-Za-z_$][\w$]*)\s*\.\s*attr\s*\(/);
  if (receiverMatch?.[1] && jqueryVarMap.has(receiverMatch[1])) {
    return true;
  }
  return false;
}
const RECEIVER_TYPES = Object.freeze({
  UNKNOWN: 'unknown',
  DOM: 'dom',
  JQUERY: 'jquery',
  XHR: 'xhr',
  OTHER: 'other'
});
function inferExpressionReceiverType(expression = '', receiverTypeMap = new Map(), jqueryVarMap = new Map()) {
  const expr = String(expression || '').trim();
  if (!expr) return RECEIVER_TYPES.UNKNOWN;

  if (/\bnew\s+XMLHttpRequest\s*\(/i.test(expr) || /\bXMLHttpRequest\b/i.test(expr)) {
    return RECEIVER_TYPES.XHR;
  }
  if (/(?:window\.)?(?:jQuery|\$)\s*\(/.test(expr)) {
    return RECEIVER_TYPES.JQUERY;
  }
  if (/\b(?:document\.(?:getElementById|getElementsByClassName|getElementsByTagName|getElementsByName|querySelector|querySelectorAll|createElement|body|head|documentElement)|window|document|this\.\$el|(?:event|e|evt)\.(?:target|currentTarget)|[A-Za-z_$][\w$]*\.current)\b/i.test(expr)) {
    return RECEIVER_TYPES.DOM;
  }

  const aliasMatch = expr.match(/^([A-Za-z_$][\w$]*)(?:\.[A-Za-z_$][\w$]*)?\s*;?$/);
  if (aliasMatch?.[1]) {
    const alias = aliasMatch[1];
    if (receiverTypeMap.has(alias)) {
      return receiverTypeMap.get(alias);
    }
    if (jqueryVarMap.has(alias)) {
      return RECEIVER_TYPES.JQUERY;
    }
  }
  return RECEIVER_TYPES.UNKNOWN;
}
function updateReceiverTypeState(line = '', receiverTypeMap = new Map(), jqueryVarMap = new Map()) {
  const assignment = parseAssignment(line);
  if (!assignment?.varName) return;
  const inferredType = inferExpressionReceiverType(assignment.expression, receiverTypeMap, jqueryVarMap);
  if (inferredType !== RECEIVER_TYPES.UNKNOWN) {
    receiverTypeMap.set(assignment.varName, inferredType);
    return;
  }
  if (jqueryVarMap.has(assignment.varName)) {
    receiverTypeMap.set(assignment.varName, RECEIVER_TYPES.JQUERY);
  }
}
function escapeRegexLiteral(value = '') {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
function extractMethodReceiver(line = '', methodName = '') {
  const text = String(line || '');
  const method = String(methodName || '').trim();
  if (!text || !method) return '';
  const methodRegex = new RegExp(String.raw`\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\.\s*${escapeRegexLiteral(method)}\s*\(`, 'i');
  return text.match(methodRegex)?.[1] || '';
}
function extractPropertyReceiver(line = '', propertyName = '') {
  const text = String(line || '');
  const prop = String(propertyName || '').trim();
  if (!text || !prop) return '';
  const propRegex = new RegExp(String.raw`\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\.\s*${escapeRegexLiteral(prop)}\s*=`, 'i');
  return text.match(propRegex)?.[1] || '';
}
function resolveReceiverType(receiver = '', line = '', context = '', receiverTypeMap = new Map(), jqueryVarMap = new Map()) {
  const normalizedReceiver = String(receiver || '').trim();
  if (!normalizedReceiver) return RECEIVER_TYPES.UNKNOWN;
  if (/^(?:window|document|self|globalThis)$/i.test(normalizedReceiver)) return RECEIVER_TYPES.DOM;
  if (/^(?:window|document)\.[A-Za-z_$][\w$]*$/i.test(normalizedReceiver)) return RECEIVER_TYPES.DOM;
  if (/xmlhttprequest/i.test(normalizedReceiver)) return RECEIVER_TYPES.XHR;

  const baseReceiver = normalizedReceiver.split('.')[0] || normalizedReceiver;
  if (!baseReceiver) return RECEIVER_TYPES.UNKNOWN;

  if (/^(?:xhr|xmlhttp|request|req|response|resp|client|http|ajax)$/i.test(baseReceiver)) {
    return RECEIVER_TYPES.XHR;
  }
  if (jqueryVarMap.has(baseReceiver)) {
    return RECEIVER_TYPES.JQUERY;
  }
  if (receiverTypeMap.has(normalizedReceiver)) {
    return receiverTypeMap.get(normalizedReceiver);
  }
  if (receiverTypeMap.has(baseReceiver)) {
    return receiverTypeMap.get(baseReceiver);
  }

  const merged = `${line}\n${context}`;
  const escapedBase = escapeRegexLiteral(baseReceiver);
  const xhrPattern = new RegExp(String.raw`\b${escapedBase}\s*=\s*new\s+XMLHttpRequest\s*\(`, 'i');
  if (xhrPattern.test(merged)) {
    return RECEIVER_TYPES.XHR;
  }
  const domPattern = new RegExp(
    String.raw`\b${escapedBase}\s*=\s*(?:document\.(?:getElementById|getElementsByClassName|getElementsByTagName|getElementsByName|querySelector|querySelectorAll|createElement|body|head|documentElement)|window|document|this\.\$el|(?:event|e|evt)\.(?:target|currentTarget)|(?:[A-Za-z_$][\w$]*\.)?(?:querySelector|getElementById|getElementsByClassName|getElementsByTagName|getElementsByName|createElement)\s*\()`,
    'i'
  );
  if (domPattern.test(merged)) {
    return RECEIVER_TYPES.DOM;
  }
  return RECEIVER_TYPES.UNKNOWN;
}
function extractOneventReceiver(line = '') {
  const text = String(line || '');
  if (!text) return '';
  const match = text.match(/([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\.\s*on[a-z]{3,20}\s*=/i);
  return match?.[1] || '';
}
function hasLikelyDomOneventContext(line = '', context = '') {
  const receiver = extractOneventReceiver(line);
  if (!receiver) return false;

  const normalizedReceiver = receiver.trim();
  const baseReceiver = normalizedReceiver.split('.')[0] || normalizedReceiver;
  if (!baseReceiver) return false;

  if (/^(?:window|document|self|globalThis)$/i.test(normalizedReceiver)) {
    return true;
  }
  if (/^(?:window|document)\.[A-Za-z_$][\w$]*$/i.test(normalizedReceiver)) {
    return true;
  }
  if (/^(?:this|vm|ctx)\.\$el$/i.test(normalizedReceiver)) {
    return true;
  }
  if (/^(?:el|elem|element|node|target|currentTarget)$/i.test(baseReceiver)) {
    return true;
  }

  if (/xmlhttprequest/i.test(normalizedReceiver)) {
    return false;
  }
  if (/^(?:xhr|xmlhttp|request|req|response|resp|client|http|ajax)$/i.test(baseReceiver)) {
    return false;
  }

  const merged = `${line}\n${context}`;
  const escapedReceiver = escapeRegexLiteral(normalizedReceiver);
  const escapedBase = escapeRegexLiteral(baseReceiver);

  const xhrConstructPatterns = [
    new RegExp(String.raw`\b${escapedReceiver}\s*=\s*new\s+XMLHttpRequest\s*\(`, 'i'),
    new RegExp(String.raw`\b${escapedBase}\s*=\s*new\s+XMLHttpRequest\s*\(`, 'i'),
    new RegExp(String.raw`\b${escapedReceiver}\s*\.\s*open\s*\(`, 'i'),
    new RegExp(String.raw`\b${escapedBase}\s*\.\s*open\s*\(`, 'i')
  ];
  if (xhrConstructPatterns.some((regex) => regex.test(merged))) {
    return false;
  }

  const domInitPattern = new RegExp(
    String.raw`\b${escapedBase}\s*=\s*(?:document\.(?:getElementById|getElementsByClassName|getElementsByTagName|getElementsByName|querySelector|querySelectorAll|createElement|body|head|documentElement)|window|document|(?:event|e|evt)\.(?:target|currentTarget)|this\.\$el|(?:[A-Za-z_$][\w$]*\.)?(?:querySelector|getElementById|getElementsByClassName|getElementsByTagName|getElementsByName|createElement)\s*\()`,
    'i'
  );
  if (domInitPattern.test(merged)) {
    return true;
  }

  return false;
}
function runDomXssSemanticCheck({ line = '', context = '', sinkRule = {}, receiverTypeMap = new Map(), jqueryVarMap = new Map() }) {
  const sinkName = String(sinkRule?.name || '');
  if (!sinkName) {
    return { passed: true, reason: '' };
  }

  const jqueryMethod = getJqueryMethodNameFromSink(sinkName);
  if (jqueryMethod) {
    if (hasLikelyJqueryContext(line, sinkName, jqueryVarMap)) {
      return { passed: true, reason: '' };
    }
    if (hasJqueryChainHint(line, jqueryMethod)) {
      return { passed: true, reason: '' };
    }
    const receiver = extractMethodReceiver(line, jqueryMethod);
    const receiverType = resolveReceiverType(receiver, line, context, receiverTypeMap, jqueryVarMap);
    if (receiverType === RECEIVER_TYPES.XHR) {
      return { passed: false, reason: 'jquery method on xhr receiver' };
    }
    const strictJqueryMethods = new Set(['add', 'has', 'index', 'animate']);
    if (strictJqueryMethods.has(jqueryMethod.toLowerCase())) {
      return { passed: false, reason: 'jquery method without jquery context' };
    }
    // 对 html/append/prepend 等高风险 sink，语义不确定时保留候选，避免漏报
    return { passed: true, reason: '' };
  }

  if (sinkName === 'jquery attr(href/src/action)') {
    if (hasLikelyJqueryAttrContext(line, jqueryVarMap)) {
      return { passed: true, reason: '' };
    }
    const receiver = extractMethodReceiver(line, 'attr');
    const receiverType = resolveReceiverType(receiver, line, context, receiverTypeMap, jqueryVarMap);
    if (receiverType === RECEIVER_TYPES.DOM) {
      return { passed: false, reason: 'jquery attr on dom receiver' };
    }
    if (receiverType === RECEIVER_TYPES.XHR) {
      return { passed: false, reason: 'jquery attr on xhr receiver' };
    }
    return { passed: false, reason: 'jquery attr without jquery context' };
  }

  if (sinkName === 'innerHTML' || sinkName === 'outerHTML') {
    const receiver = extractPropertyReceiver(line, sinkName);
    const receiverType = resolveReceiverType(receiver, line, context, receiverTypeMap, jqueryVarMap);
    if (receiverType === RECEIVER_TYPES.XHR) {
      return { passed: false, reason: 'html assignment on xhr receiver' };
    }
  }

  return { passed: true, reason: '' };
}
function updateTaintState(line = '', domXssConfig = {}, taintMap = new Map(), lineNo = 0) {
  const assignment = parseAssignment(line);
  if (!assignment) return;

  const { varName, expression } = assignment;
  const sourceName = findRuleName(expression, domXssConfig.SOURCES || []);
  const sourceParam = extractSourceParam(expression);
  if (sourceName) {
    taintMap.set(varName, {
      sourceName,
      sourceParam,
      trace: [{
        lineNo,
        variable: varName,
        expression: truncate(normalizeText(expression), 180),
        sourceName,
        sourceParam
      }]
    });
    return;
  }

  const inherited = resolveSourceFromTaint(expression, taintMap);
  if (inherited?.sourceName) {
    const inheritedTrace = Array.isArray(inherited.trace) ? inherited.trace.slice(-6) : [];
    taintMap.set(varName, {
      sourceName: inherited.sourceName,
      sourceParam: sourceParam || inherited.sourceParam || '',
      trace: [
        ...inheritedTrace,
        {
          lineNo,
          variable: varName,
          expression: truncate(normalizeText(expression), 180),
          sourceName: inherited.sourceName,
          sourceParam: sourceParam || inherited.sourceParam || ''
        }
      ]
    });
    return;
  }
  taintMap.delete(varName);
}
function getContextByLine(lines = [], index = 0, radius = 8) {
  const start = Math.max(0, index - radius);
  const end = Math.min(lines.length, index + radius + 1);
  return lines.slice(start, end).join('\n');
}
function addVulnerability(resultsSet, report) {
  if (!resultsSet || !report) return false;
  const normalizedSeverity = normalizeReportSeverity(report.severity, 'medium');
  const reportId = report.id || `${report.category || 'GENERIC'}_${stableHash([
    report.title || '',
    report.source || '',
    report.sourceSinkChain || '',
    normalizedSeverity
  ].join('|'))}`;

  if (resultsSet.vulnReports.has(reportId)) {
    return false;
  }

  const normalizedReport = {
    id: reportId,
    category: report.category || 'GENERIC',
    type: report.type || report.category || 'GENERIC',
    title: report.title || '未命名漏洞',
    severity: normalizedSeverity,
    source: report.source || document.location.href,
    pageUrl: report.pageUrl || document.location.href,
    evidence: '',
    advice: report.advice || '',
    sourcePoint: report.sourcePoint || '',
    sourceParam: report.sourceParam || '',
    sinkPoint: report.sinkPoint || '',
    sourceSinkChain: report.sourceSinkChain || '',
    exp: report.exp || '',
    payloadHint: String(report.payloadHint || '').slice(0, getReportFieldLimit('payloadHint', 3000)),
    payloadReason: String(report.payloadReason || '').slice(0, getReportFieldLimit('payloadReason', 3000)),
    payloadProfile: String(report.payloadProfile || '').slice(0, getReportFieldLimit('payloadProfile', 300)),
    hasSanitizer: Boolean(report.hasSanitizer),
    detectedAt: report.detectedAt || new Date().toISOString()
  };
  resultsSet.vulnReports.set(reportId, normalizedReport);

  if (normalizedReport.category === 'DOM_XSS') {
    const label = `[${normalizedReport.severity.toUpperCase()}] ${normalizedReport.title}`;
    resultsSet.domxssVulns.set(label, normalizedReport.source);
  }
  return true;
}
function formatSourceSinkChain({ fileUrl, sourceName, sourceParam, sinkName, sinkLineNo, sinkLine, taint, functionContextLine }) {
  const chain = [];
  if (fileUrl) {
    chain.push(`FILE: ${fileUrl}`);
  }
  const sourceLabel = sourceName ? `${sourceName}${sourceParam ? `(${sourceParam})` : ''}` : '未明确';
  chain.push(`SOURCE: ${sourceLabel}`);
  if (functionContextLine?.lineNo) {
    chain.push(`  -> [L${functionContextLine.lineNo}] ${truncate(normalizeText(functionContextLine.line), 520)}`);
  }

  const trace = Array.isArray(taint?.trace) ? taint.trace : [];
  trace.slice(-40).forEach((step) => {
    const snippet = step?.expression ? ` = ${step.expression}` : '';
    const lineText = step?.lineNo ? `[L${step.lineNo}] ` : '';
    chain.push(`  -> ${lineText}${step?.variable || 'var'}${snippet}`);
  });

  chain.push(`SINK[L${sinkLineNo}]: ${sinkName}`);
  chain.push(`  -> ${truncate(normalizeText(sinkLine), 1200)}`);
  return chain.join('\n');
}
function lowerFirstChar(value = '') {
  if (!value) return '';
  return value[0].toLowerCase() + value.slice(1);
}
function dedupeStringList(items = []) {
  const list = [];
  (Array.isArray(items) ? items : []).forEach((item) => {
    const value = String(item || '').trim();
    if (!value || list.includes(value)) return;
    list.push(value);
  });
  return list;
}
function extractSinkLineFromSourceSinkChain(sourceSinkChain = '') {
  const lines = String(sourceSinkChain || '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    if (/^\s*SINK\[L\d+\]\s*:/i.test(lines[i] || '')) {
      const nextLine = String(lines[i + 1] || '').trim();
      if (nextLine.startsWith('->')) {
        return nextLine.replace(/^->\s*/, '').trim();
      }
      return nextLine;
    }
  }
  return '';
}
function inferRouteNameFromFunctionName(functionName = '') {
  const name = String(functionName || '').trim();
  if (!name) return '';
  const showParamMatch = name.match(/^show([A-Za-z0-9_]+)Param$/i);
  if (showParamMatch?.[1]) return lowerFirstChar(showParamMatch[1]);
  const handlerMatch = name.match(/^([A-Za-z0-9_]+)Handler$/i);
  if (handlerMatch?.[1]) return lowerFirstChar(handlerMatch[1]);
  if (/^test/i.test(name)) return 'test';
  return '';
}
function inferDomXssPayloadProfile({ sinkPoint = '', sourcePoint = '', sourceParam = '', sinkLine = '', sourceSinkChain = '' }) {
  const sink = String(sinkPoint || '').toLowerCase();
  const source = String(sourcePoint || '').toLowerCase();
  const sinkSnippet = String(sinkLine || '').trim();
  const merged = `${sinkSnippet}\n${String(sourceSinkChain || '')}`.toLowerCase();
  const payloadProfiles = {
    html: '<svg/onload=alert(document.domain)>',
    href: 'javascript:alert(document.domain)',
    js: 'alert(document.domain)',
    attrBreakout: 'x" autofocus onfocus=alert(document.domain) x="'
  };
  if (sink.includes('eval') || sink.includes('function') || sink.includes('settimeout') || sink.includes('setinterval')) {
    return { payload: payloadProfiles.js, reason: '代码执行型 sink（eval/function/timer）', profile: 'code' };
  }
  if (sink.includes('href') || sink.includes('location') || /(?:href|src|action|formaction|xlink:href)\s*=/.test(merged)) {
    return { payload: payloadProfiles.href, reason: '链接协议上下文（href/src/action）', profile: 'href' };
  }
  if (sink.includes('element.onevent') || sink.includes('setattribute(on*)')) {
    return { payload: payloadProfiles.js, reason: '事件处理器上下文（on*）', profile: 'event-handler' };
  }

  const htmlSink =
    sink.includes('html') ||
    sink.includes('innerhtml') ||
    sink.includes('outerhtml') ||
    sink.includes('insertadjacenthtml') ||
    sink.includes('parsehtml') ||
    sink.includes('append') ||
    sink.includes('prepend') ||
    sink.includes('before') ||
    sink.includes('after') ||
    sink.includes('replacewith');
  if (htmlSink) {
    const escapedParam = escapeRegexLiteral(String(sourceParam || '').trim());
    const hasAttrInjectionPattern = escapedParam
      ? new RegExp(String.raw`(?:href|src|action|formaction|xlink:href|on[a-z]{3,20})\s*=\s*['"][\s\S]{0,120}\+\s*${escapedParam}`, 'i').test(merged)
      : /(?:href|src|action|formaction|xlink:href|on[a-z]{3,20})\s*=\s*['"`][\s\S]{0,120}\+\s*[A-Za-z_$][\w$]*/i.test(merged);
    if (hasAttrInjectionPattern && /(?:href|src|action|formaction|xlink:href)\s*=/.test(merged)) {
      return { payload: payloadProfiles.href, reason: 'HTML 属性中的 URL 上下文', profile: 'href-attr' };
    }
    if (hasAttrInjectionPattern) {
      return { payload: payloadProfiles.attrBreakout, reason: 'HTML 属性拼接场景，优先属性逃逸 payload', profile: 'attr' };
    }
    if (source.includes('route parameter') || source.includes('location.hash') || /\+\s*[A-Za-z_$][\w$]*\s*$/.test(sinkSnippet)) {
      return { payload: payloadProfiles.html, reason: 'HTML 文本插入场景（最贴近可执行标签注入）', profile: 'html-text' };
    }
    return { payload: payloadProfiles.html, reason: '默认 HTML 注入场景', profile: 'html-default' };
  }

  return { payload: payloadProfiles.html, reason: '默认通用 XSS payload', profile: 'generic' };
}
function inferJsQuotePreferenceForExp(sourceSinkChain = '', sinkLine = '') {
  const merged = `${String(sourceSinkChain || '')}\n${String(sinkLine || '')}`;
  const hasDouble = /["][^"\n]{0,200}\+\s*[A-Za-z_$][\w$]*\s*\+[^"\n]{0,200}["]/.test(merged);
  const hasSingle = /'][^'\n]{0,200}\+\s*[A-Za-z_$][\w$]*\s*\+[^'\n]{0,200}'/.test(merged);
  if (hasDouble && !hasSingle) return 'double';
  return 'single';
}
function buildDomXssProbePayloadForExp({ profile = '', sinkPoint = '', sourceSinkChain = '', sinkLine = '' }) {
  const marker = `DOM_PROBE_${Math.random().toString(36).slice(2, 5)}`.toUpperCase();
  const safeProfile = String(profile || '').toLowerCase();
  const sink = String(sinkPoint || '').toLowerCase();
  const codeLike = safeProfile.includes('code') || safeProfile.includes('event-handler') || sink.includes('eval') || sink.includes('function') || sink.includes('settimeout') || sink.includes('setinterval') || sink.includes('onevent') || sink.includes('setattribute(on*)');
  const urlLike = safeProfile.includes('href') || sink.includes('href') || sink.includes('src') || sink.includes('location') || sink.includes('action');
  const attrLike = safeProfile.includes('attr') && !urlLike;
  const htmlLike = safeProfile.includes('html') || safeProfile === 'generic' || sink.includes('innerhtml') || sink.includes('outerhtml') || sink.includes('insertadjacenthtml') || sink.includes('document.write') || sink.includes('jquery');

  if (codeLike) {
    const quotePref = inferJsQuotePreferenceForExp(sourceSinkChain, sinkLine);
    const single = `';window.__SE_DOM_PROBE='${marker}';//`;
    const double = `";window.__SE_DOM_PROBE='${marker}';//`;
    return {
      payload: quotePref === 'double' ? double : single,
      altPayload: quotePref === 'double' ? single : double,
      reason: 'JS 字符串上下文探针，仅验证输入能否进入可执行字符串拼接点。'
    };
  }
  if (urlLike) {
    return {
      payload: `#${marker}`,
      reason: 'URL 上下文探针，仅验证可控值是否写入 URL 相关 sink。'
    };
  }
  if (attrLike) {
    return {
      payload: `x' data-se="${marker}" x='`,
      reason: 'HTML 属性上下文探针，仅验证是否可控属性边界。'
    };
  }
  if (htmlLike) {
    return {
      payload: `<domprobe data-se="${marker}"></domprobe>`,
      reason: 'HTML 标签上下文探针，仅验证标签是否真实进入 DOM。'
    };
  }
  return {
    payload: marker,
    reason: '通用文本探针，仅验证可控输入是否回流到页面。'
  };
}
function buildDomXssExploitCandidatesForExp({ profile = '', sinkPoint = '', defaultPayload = '' }) {
  const safeProfile = String(profile || '').toLowerCase();
  const sink = String(sinkPoint || '').toLowerCase();
  const list = [];
  const push = (value = '') => {
    const payload = String(value || '').trim();
    if (!payload || list.includes(payload)) return;
    list.push(payload);
  };
  if (defaultPayload) push(defaultPayload);

  const codeLike = safeProfile.includes('code') || safeProfile.includes('event-handler') || sink.includes('eval') || sink.includes('function') || sink.includes('settimeout') || sink.includes('setinterval') || sink.includes('onevent') || sink.includes('setattribute(on*)');
  const urlLike = safeProfile.includes('href') || sink.includes('href') || sink.includes('src') || sink.includes('location') || sink.includes('action');
  const attrLike = safeProfile.includes('attr') && !urlLike;
  const htmlLike = safeProfile.includes('html') || safeProfile === 'generic' || sink.includes('innerhtml') || sink.includes('outerhtml') || sink.includes('insertadjacenthtml') || sink.includes('document.write') || sink.includes('jquery');

  if (codeLike) {
    push("';alert(document.domain);//");
    push('";alert(document.domain);//');
    push('`);alert(document.domain);//');
  } else if (urlLike) {
    push('javascript:alert(document.domain)');
    push('data:text/html,<svg/onload=alert(document.domain)>');
  } else if (attrLike) {
    push("x' onclick='alert(document.domain)' x='");
    push('x" onmouseover="alert(document.domain)" x="');
  } else if (htmlLike) {
    push('<svg/onload=alert(document.domain)>');
    push('"><svg/onload=alert(document.domain)>');
    push('</script><svg/onload=alert(document.domain)>');
  } else {
    push('<svg/onload=alert(document.domain)>');
  }
  return list.slice(0, 6);
}
function buildRouteCandidatesForExp(sourceParam = '', sourceSinkChain = '', sourcePoint = '') {
  const candidates = [];
  const chainText = String(sourceSinkChain || '');
  const functionMatch = chainText.match(/->\s*\[L\d+\]\s*([A-Za-z_$][\w$]*)\s*:\s*function\s*\(/);
  const fromFunction = inferRouteNameFromFunctionName(functionMatch?.[1] || '');
  if (fromFunction) candidates.push(fromFunction);

  try {
    const decodedHash = decodeURIComponent(window.location.hash.replace(/^#/, ''));
    const hashParts = decodedHash.split('/').filter(Boolean);
    const firstSeg = hashParts[0];
    if (firstSeg && !firstSeg.includes('=')) {
      candidates.push(firstSeg.replace(/^#/, '').replace(/^\//, ''));
    }
  } catch {}

  const sourceText = String(sourcePoint || '').toLowerCase();
  if (sourceText.includes('route')) {
    candidates.push('test');
  }
  candidates.push('lesson', 'test', 'start');
  const cleanParam = String(sourceParam || '').trim();
  if (cleanParam && cleanParam !== 'param') {
    candidates.push(cleanParam);
  }
  return dedupeStringList(candidates).slice(0, 6);
}
function buildDomXssExp(sinkPoint, sourcePoint, sourceParam = '', evidence = '', sourceSinkChain = '') {
  const sink = String(sinkPoint || '').toLowerCase();
  const source = String(sourcePoint || '');
  const paramName = String(sourceParam || '').trim() || 'xss';
  const sinkLine = evidence || extractSinkLineFromSourceSinkChain(sourceSinkChain);
  const payloadProfile = inferDomXssPayloadProfile({
    sinkPoint,
    sourcePoint,
    sourceParam: paramName,
    sinkLine,
    sourceSinkChain
  });
  const probeDetail = buildDomXssProbePayloadForExp({
    profile: payloadProfile.profile,
    sinkPoint,
    sourceSinkChain,
    sinkLine
  });
  const exploitCandidates = buildDomXssExploitCandidatesForExp({
    profile: payloadProfile.profile,
    sinkPoint,
    defaultPayload: payloadProfile.payload
  });
  const primaryExploit = exploitCandidates[0] || payloadProfile.payload;
  const lines = [
    `验证Payload(低噪声): ${probeDetail.payload}`,
    probeDetail.altPayload ? `验证Payload(备选): ${probeDetail.altPayload}` : '',
    `验证依据: ${probeDetail.reason}`,
    `利用Payload(参考): ${primaryExploit}`,
    `利用依据: ${payloadProfile.reason}`
  ].filter(Boolean);

  if (source.includes('location.hash')) {
    const hashPayload = String(probeDetail.payload || '').replace(/^#/, '');
    const verifyUrl = `${window.location.origin}${window.location.pathname}#${encodeURIComponent(hashPayload)}`;
    lines.push(`验证URL: ${verifyUrl}`);
    lines.push('# 先用验证Payload确认可控输入进入上下文，再切换利用Payload做人工可利用性确认。');
    return lines.join('\n');
  }
  if (source.includes('route') || source.includes('function argument')) {
    const targetUrl = new URL(window.location.href);
    const routeNames = buildRouteCandidatesForExp(paramName, sourceSinkChain, source);
    const hashPayload = String(probeDetail.payload || '').replace(/^#/, '');
    const candidateVerifyUrls = routeNames.map((routeName) => {
      const url = new URL(targetUrl.toString());
      url.hash = `${routeName}/${encodeURIComponent(hashPayload)}`;
      return url.toString();
    });
    const fallbackQuery = new URL(targetUrl.toString());
    fallbackQuery.searchParams.set(paramName, probeDetail.payload);
    lines.push('验证URL候选（Hash路由参数场景）:');
    candidateVerifyUrls.forEach((value) => lines.push(value));
    lines.push(`备用Query(验证): ${fallbackQuery.toString()}`);
    lines.push('# 验证命中后，将 URL 中验证Payload 替换为利用Payload 做人工确认。');
    return lines.join('\n');
  }
  if (source.includes('location.search') || source.includes('query')) {
    const verifyUrl = new URL(window.location.href);
    verifyUrl.searchParams.set(paramName, probeDetail.payload);
    lines.push(`验证URL: ${verifyUrl.toString()}`);
    lines.push('# 验证命中后，可将参数改为利用Payload进行人工确认。');
    return lines.join('\n');
  }
  lines.push('# 将验证Payload注入 Source，确认命中后再切换利用Payload。');
  return lines.join('\n');
}
function detectDomXss(chunk, isHtmlContent, url, resultsSet) {
  const domXssConfig = SCANNER_CONFIG.DOM_XSS;
  if (!domXssConfig || !Array.isArray(domXssConfig.SINKS)) return false;

  incrementDebugCounter(resultsSet, 'domxss_chunks_scanned', 1);
  let update = false;
  let findingCount = 0;
  let sinkOnlyCount = 0;
  const maxFindings = domXssConfig.MAX_FINDINGS_PER_CHUNK || 30;
  const maxSinkOnlyFindings = domXssConfig.MAX_SINK_ONLY_PER_CHUNK || 15;
  const maxReportsPerFile = domXssConfig.MAX_REPORTS_PER_FILE || 20;
  const maxSinkOnlyPerFile = domXssConfig.MAX_SINK_ONLY_PER_FILE || 4;
  const lines = chunk.split(/\r?\n/);
  const taintMap = new Map();
  const jqueryVarMap = new Map();
  const receiverTypeMap = new Map();
  const shortSource = String(url || '').split('/').slice(-2).join('/');
  const fileStat = getOrCreateDomXssFileStat(url);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line || line.length > 2500) continue;
    updateTaintState(line, domXssConfig, taintMap, i + 1);
    updateJqueryState(line, jqueryVarMap);
    updateReceiverTypeState(line, receiverTypeMap, jqueryVarMap);

    const sinkRule = domXssConfig.SINKS.find(sink => testRegex(sink.pattern, line));
    if (!sinkRule) continue;
    if (fileStat.total >= maxReportsPerFile) {
      incrementDebugCounter(resultsSet, 'domxss_filtered_file_total_limit', 1);
      setDebugInfo(resultsSet, 'debugDomxssFiltered', `${shortSource}:L${i + 1}:${sinkRule.name}`, 'file total over limit');
      break;
    }
    incrementDebugCounter(resultsSet, 'domxss_sink_hits', 1);
    setDebugInfo(resultsSet, 'debugDomxssCandidates', `${shortSource}:L${i + 1}:${sinkRule.name}`, truncate(normalizeText(line), 260));

    const context = getContextByLine(lines, i, 8);

    if (sinkRule.requireJqueryContext && !hasLikelyJqueryContext(line, sinkRule.name, jqueryVarMap)) {
      incrementDebugCounter(resultsSet, 'domxss_filtered_jquery_context', 1);
      setDebugInfo(resultsSet, 'debugDomxssFiltered', `${shortSource}:L${i + 1}:${sinkRule.name}`, 'not likely jQuery context');
      continue;
    }
    if (sinkRule.requireDomReceiver && !hasLikelyDomOneventContext(line, context)) {
      incrementDebugCounter(resultsSet, 'domxss_filtered_receiver_type', 1);
      setDebugInfo(resultsSet, 'debugDomxssFiltered', `${shortSource}:L${i + 1}:${sinkRule.name}`, 'not dom receiver or xhr context');
      continue;
    }
    const semanticResult = runDomXssSemanticCheck({
      line,
      context,
      sinkRule,
      receiverTypeMap,
      jqueryVarMap
    });
    if (!semanticResult.passed) {
      incrementDebugCounter(resultsSet, 'domxss_filtered_semantic', 1);
      setDebugInfo(resultsSet, 'debugDomxssFiltered', `${shortSource}:L${i + 1}:${sinkRule.name}`, semanticResult.reason || 'semantic check failed');
      continue;
    }

    const sinkExpr = extractSinkExpression(line, sinkRule.name);
    let sourceName = findRuleName(sinkExpr, domXssConfig.SOURCES || []);
    let sourceParam = extractSourceParam(sinkExpr);
    let taint = null;
    let functionContextLine = null;

    if (!sourceName) {
      const nearContext = lines.slice(Math.max(0, i - 2), i + 1).join('\n');
      sourceName = findRuleName(nearContext, domXssConfig.SOURCES || []);
      sourceParam = sourceParam || extractSourceParam(nearContext);
    }
    if (!sourceName) {
      taint = resolveSourceFromTaint(sinkExpr, taintMap);
      if (taint?.sourceName) {
        sourceName = taint.sourceName;
        sourceParam = sourceParam || taint.sourceParam || '';
      }
    }
    if (!sourceName) {
      const inferred = inferSourceFromFunctionArgs(lines, i, context, sinkExpr);
      if (inferred?.sourceName) {
        sourceName = inferred.sourceName;
        sourceParam = sourceParam || inferred.sourceParam || '';
        functionContextLine = inferred.functionContextLine || null;
      }
    }
    if (!sourceName && sinkRule.requireSource === true) {
      incrementDebugCounter(resultsSet, 'domxss_filtered_require_source', 1);
      setDebugInfo(resultsSet, 'debugDomxssFiltered', `${shortSource}:L${i + 1}:${sinkRule.name}`, 'require source rule');
      continue;
    }
    if (sourceName) {
      incrementDebugCounter(resultsSet, 'domxss_source_resolved', 1);
      const sourceLabel = sourceParam ? `${sourceName}(${sourceParam})` : sourceName;
      setDebugInfo(resultsSet, 'debugSourceInference', `${shortSource}:L${i + 1}:${sinkRule.name}`, sourceLabel);
    }
    if (hitLowFalsePositiveTemplate(context, sinkExpr, sourceName, domXssConfig)) {
      incrementDebugCounter(resultsSet, 'domxss_filtered_low_fp', 1);
      setDebugInfo(resultsSet, 'debugDomxssFiltered', `${shortSource}:L${i + 1}:${sinkRule.name}`, 'low-fp template');
      continue;
    }

    const sourcePointDisplay = sourceName
      ? (sourceParam ? `${sourceName}(${sourceParam})` : sourceName)
      : '未明确';
    const hasSanitizer = (domXssConfig.SANITIZERS || []).some(regex => testRegex(regex, context));
    let severity = String(sinkRule.severity || 'medium').toLowerCase();

    if (sourceName && !hasSanitizer) {
      severity = sourceName === 'function argument' ? 'medium' : 'high';
    } else if (sourceName && hasSanitizer) {
      severity = 'low';
    } else if (sinkRule.name === 'vue v-html' && isHtmlContent && testRegex(domXssConfig.VUE_SOURCE_HINT, context)) {
      severity = 'high';
    } else if (sinkRule.name === 'react dangerouslySetInnerHTML' && !hasSanitizer) {
      severity = sourceName ? 'high' : 'medium';
    } else if (hasSanitizer) {
      severity = 'low';
    } else if (!sourceName) {
      severity = sinkRule.severity === 'high' ? 'medium' : 'low';
    }

    if (!sourceName && hasSanitizer && sinkRule.name !== 'vue v-html') {
      incrementDebugCounter(resultsSet, 'domxss_filtered_sanitized', 1);
      setDebugInfo(resultsSet, 'debugDomxssFiltered', `${shortSource}:L${i + 1}:${sinkRule.name}`, 'sanitizer without source');
      continue;
    }
    if (!sourceName) {
      if (fileStat.sinkOnly >= maxSinkOnlyPerFile) {
        incrementDebugCounter(resultsSet, 'domxss_filtered_sink_only_file_limit', 1);
        setDebugInfo(resultsSet, 'debugDomxssFiltered', `${shortSource}:L${i + 1}:${sinkRule.name}`, 'sink-only file over limit');
        continue;
      }
      sinkOnlyCount++;
      if (sinkOnlyCount > maxSinkOnlyFindings) {
        incrementDebugCounter(resultsSet, 'domxss_filtered_sink_only_limit', 1);
        setDebugInfo(resultsSet, 'debugDomxssFiltered', `${shortSource}:L${i + 1}:${sinkRule.name}`, 'sink-only over limit');
        continue;
      }
    }

    const title = sourceName ? `${sinkRule.name} <- ${sourceName}` : `${sinkRule.name} 可疑调用`;
    const sourceSinkChain = formatSourceSinkChain({
      sourceName,
      sourceParam,
      fileUrl: url,
      sinkName: sinkRule.name,
      sinkLineNo: i + 1,
      sinkLine: line,
      taint,
      functionContextLine
    });
    const payloadSelection = inferDomXssPayloadProfile({
      sinkPoint: sinkRule.name,
      sourcePoint: sourcePointDisplay,
      sourceParam: sourceParam || '',
      sinkLine: line,
      sourceSinkChain
    });
    const saved = addVulnerability(resultsSet, {
      category: 'DOM_XSS',
      type: 'DOM_XSS',
      title,
      severity,
      source: url,
      pageUrl: document.location.href,
      evidence: '',
      advice: '检查是否存在用户可控输入流入该 sink，并在写入前进行严格净化。',
      sourcePoint: sourcePointDisplay,
      sourceParam: sourceParam || '',
      sinkPoint: sinkRule.name,
      sourceSinkChain,
      payloadHint: payloadSelection.payload,
      payloadReason: payloadSelection.reason,
      payloadProfile: payloadSelection.profile,
      hasSanitizer,
      exp: buildDomXssExp(sinkRule.name, sourcePointDisplay, sourceParam, line, sourceSinkChain)
    });
    if (saved) {
      update = true;
      findingCount++;
      fileStat.total += 1;
      if (!sourceName) {
        fileStat.sinkOnly += 1;
      }
      incrementDebugCounter(resultsSet, 'domxss_reports_added', 1);
      setDebugInfo(resultsSet, 'debugDomxssTrace', `${shortSource}:L${i + 1}:${sinkRule.name}`, `${sourcePointDisplay} -> ${sinkRule.name}`);
    }
    if (findingCount >= maxFindings) break;
  }

  return update;
}
function safeDecodeURIComponent(value = '') {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
function normalizeRouteCandidate(rawValue = '', routeConfig = {}) {
  let value = String(rawValue || '').trim();
  if (!value) return '';
  value = value.replace(/\\\//g, '/').replace(/^['"`]|['"`]$/g, '').trim();
  if (!value || value.length > 220) return '';
  if (/\$\{|\{\{/.test(value)) return '';
  if (/^(?:javascript|data|mailto|tel|file):/i.test(value)) return '';
  if (/^(?:[a-z][a-z0-9+.-]*:)?\/\//i.test(value)) return '';
  if (/^[A-Za-z]:\\/.test(value)) return '';
  value = safeDecodeURIComponent(value);
  if (/\s/.test(value)) return '';
  if (routeConfig.EXCLUDE_EXT instanceof RegExp && testRegex(routeConfig.EXCLUDE_EXT, value)) {
    return '';
  }
  const isRouteLike =
    value.startsWith('/') ||
    value.startsWith('#/') ||
    value.startsWith('#!/') ||
    value.startsWith('./') ||
    value.startsWith('../') ||
    /^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_:@!$&'()*+,;=.-]+)+$/.test(value);
  if (!isRouteLike) return '';
  return value.slice(0, 220);
}
function resolveRouteTarget(routeValue = '') {
  const base = document.baseURI || document.location.href;
  try {
    if (routeValue.startsWith('#')) {
      const url = new URL(base);
      url.hash = routeValue.replace(/^#/, '');
      return url.toString();
    }
    return new URL(routeValue, base).toString();
  } catch {
    return base;
  }
}
function collectIframeResults(resultsSet, options = {}) {
  if (!resultsSet?.iframes) return false;
  const { replace = true } = options;
  const nextMap = new Map();
  const sourceUrl = document.location.href;

  try {
    document.querySelectorAll('iframe').forEach((iframeNode) => {
      let frameSrc = String(iframeNode.getAttribute('src') || '').trim();
      if (!frameSrc) {
        frameSrc = 'about:blank';
      } else {
        try {
          frameSrc = new URL(frameSrc, document.baseURI || sourceUrl).toString();
        } catch {
          frameSrc = frameSrc || 'about:blank';
        }
      }
      if (!nextMap.has(frameSrc)) {
        nextMap.set(frameSrc, sourceUrl);
      }
    });
  } catch (error) {
    window.logger.warn('收集 iframe 结果失败:', error);
    return false;
  }

  if (!replace) {
    let updated = false;
    nextMap.forEach((source, iframeUrl) => {
      if (!resultsSet.iframes.has(iframeUrl)) {
        resultsSet.iframes.set(iframeUrl, source);
        updated = true;
      }
    });
    return updated;
  }

  let changed = resultsSet.iframes.size !== nextMap.size;
  if (!changed) {
    for (const [iframeUrl, source] of nextMap.entries()) {
      if (resultsSet.iframes.get(iframeUrl) !== source) {
        changed = true;
        break;
      }
    }
  }
  if (!changed) return false;

  resultsSet.iframes.clear();
  nextMap.forEach((source, iframeUrl) => {
    resultsSet.iframes.set(iframeUrl, source);
  });
  return true;
}
function injectVueRuntimeRouteScanner(retry = 0) {
  if (vueRouteScriptInjected) return;
  const parentNode = document.head || document.documentElement;
  if (!parentNode) {
    if (retry < 8) {
      setTimeout(() => injectVueRuntimeRouteScanner(retry + 1), 40);
    }
    return;
  }
  const scriptNode = document.createElement('script');
  scriptNode.src = chrome.runtime.getURL(VUE_ROUTE_SCANNER_FILE);
  scriptNode.async = false;
  scriptNode.onload = () => {
    scriptNode.remove();
  };
  scriptNode.onerror = () => {
    scriptNode.remove();
    vueRouteScriptInjected = false;
    if (retry < 3) {
      setTimeout(() => injectVueRuntimeRouteScanner(retry + 1), 100);
    }
  };
  parentNode.appendChild(scriptNode);
  vueRouteScriptInjected = true;
}
function triggerVueRuntimeRouteScan() {
  window.postMessage({ type: 'TRIGGER_VUE_SCAN', source: 'content' }, '*');
}
function mergeVueRuntimeRoutes(payload = {}) {
  const resultsSet = tabResults.get(currentTabId);
  if (!resultsSet) return false;
  const routeConfig = SCANNER_CONFIG.ROUTE || {};
  const version = String(payload.version || '').trim();
  const runtimeRoutes = Array.isArray(payload.routes) ? payload.routes : [];
  let update = false;
  let normalizedCount = 0;

  runtimeRoutes.forEach((rawRoute) => {
    const routeValue = normalizeRouteCandidate(rawRoute, routeConfig);
    if (!routeValue) return;
    const routeTarget = resolveRouteTarget(routeValue);
    normalizedCount++;
    if (resultsSet.pageRoutes.get(routeValue) !== routeTarget) {
      // 运行时路由优先：同 key 时覆盖静态规则结果。
      resultsSet.pageRoutes.set(routeValue, routeTarget);
      update = true;
    }
  });

  if (version && !resultsSet.fingers.has(`Vue${version}`)) {
    const marked = SCANNER_FILTER.finger(
      'Vue特征',
      `Vue${version}`,
      'framework',
      `已获取${normalizedCount}个路由`,
      '',
      resultsSet
    );
    if (marked) update = true;
  }
  return update;
}
function bindVueRuntimeRouteListener() {
  if (vueRouteListenerBound) return;
  window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.type !== 'VUE_HOOKED' || data.source !== 'inject') return;
    if (mergeVueRuntimeRoutes(data.data || {})) {
      sendUpdate();
    }
  });
  vueRouteListenerBound = true;
}
function detectPageRoutes(chunk, isHtmlContent, url, resultsSet) {
  const routeConfig = SCANNER_CONFIG.ROUTE || {};
  const rules = Array.isArray(routeConfig.RULES) ? routeConfig.RULES : [];
  if (!rules.length) return false;

  let update = false;
  let totalMatches = 0;
  const maxMatches = routeConfig.MAX_MATCHES_PER_CHUNK || 120;

  for (const rule of rules) {
    if (!(rule.pattern instanceof RegExp)) continue;
    const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : `${rule.pattern.flags}g`;
    const regex = new RegExp(rule.pattern.source, flags);
    let match;
    while ((match = regex.exec(chunk)) !== null) {
      if (regex.lastIndex === match.index) {
        regex.lastIndex += 1;
      }
      const captured = match[2] || match[1] || match[0];
      const routeValue = normalizeRouteCandidate(captured, routeConfig);
      if (!routeValue) continue;
      const routeTarget = resolveRouteTarget(routeValue);
      if (!resultsSet?.pageRoutes?.has(routeValue)) {
        resultsSet.pageRoutes.set(routeValue, routeTarget);
        update = true;
      }
      totalMatches++;
      if (totalMatches >= maxMatches) {
        return update;
      }
    }
  }
  return update;
}
function syncVulnReportsToBackground(resultsSet) {
  if (!resultsSet?.vulnReports) return;
  const pendingReports = [];
  resultsSet.vulnReports.forEach((report, reportId) => {
    if (reportedVulnIds.has(reportId)) return;
    reportedVulnIds.add(reportId);
    pendingReports.push(report);
  });
  if (!pendingReports.length) return;

  chrome.runtime.sendMessage({
    type: 'ADD_VULN_REPORTS',
    from: 'content',
    to: 'background',
    reports: pendingReports
  }).catch(() => {
  });
}
//匹配函数
const matchPatterns = async (chunk, isHtmlContent = false, url) => {
  const patterns = Object.entries(SCANNER_CONFIG.PATTERNS);
  const resultsSet = tabResults.get(currentTabId);
  let update = false;
  for (const [key, pattern] of patterns) {
    const filter = SCANNER_FILTER[key.toLowerCase()];
    if (!filter) continue;
    if (pattern instanceof RegExp) {
      pattern.lastIndex = 0;
    }

    let match;
    let lastIndex = 0;
    let maxIterations = 10000;
    
    try {
      if (key === 'FINGER') {
        for (const {pattern: fingerPattern, name: fingerName, class: fingerClass, type: fingerType, description: fingerDescription, extType: fingerExtType, extName: fingerExtName} of pattern.patterns) {
          if (resultsSet.fingers.has(fingerClass)) continue;
          const matches = chunk.match(fingerPattern);
          if (matches && filter(fingerName, fingerClass, fingerType, fingerDescription, url, resultsSet, fingerExtType, fingerExtName)) {
            update = true;
          }
        }
        continue;
      }
      if (key === 'IP') {
        const ipPatterns = isHtmlContent
          ? [pattern]
          : [SCANNER_CONFIG.PATTERNS.IP_RESOURCE, SCANNER_CONFIG.PATTERNS.IP];
        ipPatterns.forEach((ipPattern) => {
          if (!(ipPattern instanceof RegExp)) return;
          const flags = ipPattern.flags.includes('g') ? ipPattern.flags : `${ipPattern.flags}g`;
          const regex = new RegExp(ipPattern.source, flags);
          const matches = chunk.match(regex);
          if (!matches) return;
          matches.forEach((matchValue) => {
            if (filter(matchValue, url, resultsSet)) {
              update = true;
            }
          });
        });
        continue;
      }
      if (key === 'DOMAIN') {
        const domainPattern = isHtmlContent ? pattern : SCANNER_CONFIG.PATTERNS.DOMAIN_RESOURCE;
        while ((match = domainPattern.exec(chunk)) !== null) {
          if (domainPattern.lastIndex <= lastIndex) {
            window.logger.warn(`检测到可能的无限循环: ${key}`);
            break;
          }
          lastIndex = domainPattern.lastIndex;
          
          if (--maxIterations <= 0) {
            window.logger.warn(`达到最大迭代次数: ${key}`);
            break;
          }
          
          if (filter(match[0], url, resultsSet)) {
            update = true;
          }
        }
        continue;
      }
      if (key === 'API') {
        const apiPattern = SCANNER_CONFIG.API.PATTERN;
        apiPattern.lastIndex = 0;
        while ((match = apiPattern.exec(chunk)) !== null) {
          if (apiPattern.lastIndex <= lastIndex) {
            window.logger.warn(`检测到可能的无限循环: API Pattern`);
            break;
          }
          lastIndex = apiPattern.lastIndex;
          
          if (--maxIterations <= 0) {
            window.logger.warn(`达到最大迭代次数: API`);
            break;
          }
          if (filter(match[0], url, resultsSet)) {
              update = true;
          }
        }
        continue;
      }
      if (key === 'CREDENTIALS' || key === 'ID_KEY' || key === 'EMAIL') {
        let patterns = [];
        if (key === 'EMAIL') {
          patterns = [{"pattern": SCANNER_CONFIG.PATTERNS.EMAIL.toString()}];
        }else{
          patterns = pattern.patterns.map(p => ({
            pattern: p.pattern.toString(),
          }));
        }
        try {
          const response = await new Promise((resolve) => {
            chrome.runtime.sendMessage({
              type: 'REGEX_MATCH',
              from: 'content',
              to: 'background',
              chunk: chunk,
              patterns: patterns,
              patternType: key
            }, resolve);
          });
          
          if (response && response.matches) {
            response.matches.forEach(({match}) => {
              if (filter(match, url, resultsSet)) {
                update = true;
              }
            });
          }
        } catch (e) {
          window.logger.error('CREDENTIALS匹配出错:', e);
        }
        continue;
      }
      while ((match = pattern.exec(chunk)) !== null) {
        if (pattern.lastIndex <= lastIndex) {
          window.logger.warn(`检测到可能的无限循环: ${pattern}`);
          break;
        }
        lastIndex = pattern.lastIndex;
        
        if (--maxIterations <= 0) {
          window.logger.warn(`达到最大迭代次数: ${key}`);
          break;
        }
        
        if (filter(match[0], url, resultsSet)) {
          update = true;
        }
        if (!pattern.global) break;
      }
    } catch (e) {
      window.logger.error(`匹配${key}出错:`, e);
    }
  }
  return update;
};
const collectJsUrls = (content, isHtmlContent = false, referenceUrl = '') => {
  const jsUrls = new Set();
  const resultsSet = tabResults.get(currentTabId);
  let baseHref = '';
  try {
    const fallbackBase = document.baseURI || window.location.href;
    baseHref = new URL(referenceUrl || fallbackBase, fallbackBase).href;
  } catch {
    baseHref = window.location.href;
  }
  const baseOrigin = (() => {
    try {
      return new URL(baseHref).origin;
    } catch {
      return window.location.origin;
    }
  })();
  const appBasePath = (() => {
    try {
      const pathname = new URL(baseHref).pathname || '/';
      const markerIndex = pathname.toLowerCase().indexOf('/static/js/');
      if (markerIndex > -1) {
        return pathname.slice(0, markerIndex + 1);
      }
      return pathname.replace(/\/[^/]*$/, '/') || '/';
    } catch {
      return '/';
    }
  })();

  const markerPattern = /!\*\*\*\s(?:\/|\.\/|\.\.\/)*[\w_~./-]*\s\*\*\*!/g;
  const objectChunkPattern = /{(?:"\.\/[\w._-]*\.js":\d{0,4},?){1,}}/g;
  const quotedJsPattern = /['"](?:[^?'"]+\.js(?:\?[^'"\s]*)?)['"]/g;
  const dynamicChunkPattern = /(?:(?<base>"[a-z-_/]*")\+)?(?<name_struct>(?:(?:\(\{(?<name>[^{};=]*?:"[^{},;=]*?")?\}\[[a-z]\]\|\|[a-z]\))||[\w])\+)?(?<add>"."\+)?(?<hash_struct>\{(?<hash>[^{}=]*?:"[\w]*")?\}\[[a-z]\]\+)?(?<end>"[\w._-]*.js")/i;

  for (const chunk of splitIntoChunks(content || '')) {
    Array.from(chunk.matchAll(markerPattern)).forEach((match) => {
      const modulePath = match[0].slice(5, -5);
      if (!modulePath) return;
      resultsSet?.moduleFiles?.set(modulePath, referenceUrl || window.location.href);
      if (resultsSet?.jsFiles?.has(modulePath)) {
        resultsSet.jsFiles.delete(modulePath);
      }
    });

    Array.from(chunk.matchAll(objectChunkPattern)).forEach((match) => {
      try {
        const parsed = JSON.parse(match[0]);
        Object.keys(parsed || {}).forEach((modulePath) => {
          resultsSet?.moduleFiles?.set(modulePath, referenceUrl || window.location.href);
          if (resultsSet?.jsFiles?.has(modulePath)) {
            resultsSet.jsFiles.delete(modulePath);
          }
        });
      } catch {}
    });

    const dynamicMatch = chunk.match(dynamicChunkPattern);
    if (dynamicMatch && !isUseWebpack) {
      try {
        let chunkBase = getBasePath(referenceUrl || baseHref);
        let base = dynamicMatch.groups?.base;
        let end = dynamicMatch.groups?.end;
        let nameStruct = dynamicMatch.groups?.name_struct;
        let nameMapRaw = dynamicMatch.groups?.name;
        let hashMapRaw = dynamicMatch.groups?.hash;
        let add = dynamicMatch.groups?.add || '';

        if (base !== undefined) {
          base = base.replaceAll('"', '');
          if (!base.startsWith('/')) base = `/${base}`;
          if (!base.endsWith('/')) base = `${base}/`;
          if (chunkBase.includes(base)) base = chunkBase;
        } else {
          base = chunkBase;
        }
        if (end !== undefined) {
          end = end.replaceAll('"', '');
        }
        if (add) {
          add = add.replaceAll(/["+]/g, '');
        }
        const nameMap = new Map();
        const hashMap = new Map();
        if (nameMapRaw) {
          nameMapRaw.split(',').forEach((item) => {
            const [k, v] = item.split(':');
            if (!k || !v) return;
            nameMap.set(k.replaceAll('"', ''), v.replaceAll('"', ''));
          });
        }
        if (hashMapRaw) {
          hashMapRaw.split(',').forEach((item) => {
            const [k, v] = item.split(':');
            if (!k || !v) return;
            hashMap.set(k.replaceAll('"', ''), v.replaceAll('"', ''));
          });
        }
        if (hashMap.size > 0) {
          hashMap.forEach((hash, key) => {
            const name = nameMap.get(key) || key;
            const candidatePath = `${base}${name}${add}${hash}${end || ''}`;
            try {
              jsUrls.add(new URL(candidatePath, baseHref).href);
            } catch {}
          });
        } else if (nameStruct && nameMap.size > 0) {
          nameMap.forEach((name) => {
            const candidatePath = `${base}${name}${add}${end || ''}`;
            try {
              jsUrls.add(new URL(candidatePath, baseHref).href);
            } catch {}
          });
        }
        isUseWebpack = true;
      } catch (error) {
        window.logger.warn('Webpack chunk parse error:', error?.message || error);
      }
    }

    const hasPreloadHint = /(?:__vitePreload|modulepreload|static\/js\/[^'"\s]+-[a-f0-9]{6,}\.js)/i.test(chunk);
    if (deepScanEnabled || isHtmlContent || hasPreloadHint) {
      Array.from(chunk.matchAll(quotedJsPattern)).forEach((match) => {
        let rawPath = match[0].slice(1, -1);
        try {
          rawPath = decodeURIComponent(rawPath);
        } catch {}
        if (!rawPath || rawPath.includes(' ')) return;
        if (rawPath.includes('/dist/') || rawPath.includes('/node_modules/')) {
          resultsSet?.moduleFiles?.set(rawPath, referenceUrl || window.location.href);
          return;
        }
        if (resultsSet?.moduleFiles?.has(rawPath)) return;

        let resolved = '';
        if (rawPath.startsWith('http')) {
          resolved = rawPath;
        } else if (rawPath.startsWith('//')) {
          resolved = `${window.location.protocol}${rawPath}`;
        } else if (rawPath.startsWith('/')) {
          resolved = `${baseOrigin}${rawPath}`;
        } else {
          try {
            const normalizedStaticPath = rawPath.replace(/^\.\/+/, '').replace(/^\/+/, '');
            if (/^static\/js\//i.test(normalizedStaticPath)) {
              const prefix = appBasePath.endsWith('/') ? appBasePath : `${appBasePath}/`;
              const mergedPath = `${prefix}${normalizedStaticPath}`.replace(/\/{2,}/g, '/');
              resolved = `${baseOrigin}${mergedPath.startsWith('/') ? '' : '/'}${mergedPath}`;
            }
            const pathParts = rawPath.split('/').filter(Boolean);
            const firstValidIdx = pathParts.findIndex((p) => p !== '.' && p !== '..');
            if (!resolved && firstValidIdx !== -1 && firstValidIdx < pathParts.length - 1) {
              const treeKey = pathParts[firstValidIdx];
              const fullPath = findFullPath(tree, `/${treeKey}/`);
              if (fullPath) {
                const fileName = pathParts[pathParts.length - 1];
                const middleParts = pathParts.slice(firstValidIdx + 1, -1);
                let mergedPath = fullPath.endsWith('/') ? fullPath : `${fullPath}/`;
                if (middleParts.length > 0) {
                  mergedPath += `${middleParts.join('/')}/`;
                }
                resolved = `${baseOrigin}${mergedPath.startsWith('/') ? '' : '/'}${mergedPath}${fileName}`;
              }
            }
            if (!resolved) {
              resolved = new URL(rawPath, baseHref).href;
            }
          } catch {
            return;
          }
        }
        if (!resolved) return;
        try {
          const host = new URL(resolved).hostname.toLowerCase();
          if (host !== hostname) return;
        } catch {
          return;
        }
        jsUrls.add(resolved);
      });
    }
  }
  return jsUrls;
};
//扫描函数
async function scanSources(sources, isHtmlContent = false, url) {
  try {
    const resultsSet = tabResults.get(currentTabId);
    incrementDebugCounter(resultsSet, 'scan_source_batches', 1);
    for (const source of sources) {
      if (!source) continue;
      for (const chunk of splitIntoChunks(source)) {
        incrementDebugCounter(resultsSet, isHtmlContent ? 'scan_html_chunks' : 'scan_js_chunks', 1);
        let update = await matchPatterns(chunk, isHtmlContent, url);
        if (detectDomXss(chunk, isHtmlContent, url, resultsSet)) {
          update = true;
        }
        if (detectPageRoutes(chunk, isHtmlContent, url, resultsSet)) {
          update = true;
        }
        if (update) sendUpdate();
        await new Promise(r => setTimeout(r, 0));
      }
    }
  } catch (e) {
    if (e.message !== 'Extension context invalidated.') {
      window.logger.error('扫描出错:', e);
    }
  }
}
const debounceScan = () => {
  if (scanTimeout) {
    clearTimeout(scanTimeout);
  }
  scanTimeout = setTimeout(() => {
    window.logger.info('DOM变化触发重新扫描...');
    const htmlContent = document.documentElement.innerHTML;
    const resultsSet = tabResults.get(currentTabId);
    if (resultsSet && collectIframeResults(resultsSet, { replace: true })) {
      sendUpdate();
    }
    triggerVueRuntimeRouteScan();
    if (htmlContent) {
      scanSources([htmlContent], true, document.location.href);
      const jsUrls = collectJsUrls(htmlContent, true, document.baseURI || document.location.href);
      jsUrls.forEach(url => enqueueJsUrl(url, 'page', '', document.location.href));
    }
    runExternalFingerprintScan().then((changed) => {
      if (changed) sendUpdate();
    });
  }, 1000); 
};
const observer = new MutationObserver((mutations) => {
  let discoveredJs = false;
  let iframeChanged = false;
  mutations.forEach((mutation) => {
    if (mutation.type === 'childList') {
      mutation.addedNodes?.forEach((node) => {
        if (!(node instanceof Element)) return;
        const scriptNodes = [];
        if (node.tagName?.toLowerCase() === 'script') {
          scriptNodes.push(node);
        }
        node.querySelectorAll?.('script[src]').forEach(script => scriptNodes.push(script));
        scriptNodes.forEach((script) => {
          const src = script.getAttribute('src');
          if (!src) return;
          try {
            const fullUrl = new URL(src, document.baseURI || window.location.href).href;
            enqueueJsUrl(fullUrl, 'page', '', document.location.href);
            discoveredJs = true;
          } catch {}
        });
        if (node.tagName?.toLowerCase() === 'iframe' || node.querySelector?.('iframe')) {
          iframeChanged = true;
        }
      });
      mutation.removedNodes?.forEach((node) => {
        if (!(node instanceof Element)) return;
        if (node.tagName?.toLowerCase() === 'iframe' || node.querySelector?.('iframe')) {
          iframeChanged = true;
        }
      });
    }
    if (mutation.type === 'attributes' && mutation.attributeName === 'src') {
      const target = mutation.target;
      if (target instanceof HTMLScriptElement && target.src) {
        enqueueJsUrl(target.src, 'page', '', document.location.href);
        discoveredJs = true;
      }
      if (target instanceof HTMLIFrameElement) {
        iframeChanged = true;
      }
    }
  });

  if (discoveredJs) {
    sendUpdate();
  }
  if (iframeChanged) {
    const resultsSet = tabResults.get(currentTabId);
    if (resultsSet && collectIframeResults(resultsSet, { replace: true })) {
      sendUpdate();
    }
    triggerVueRuntimeRouteScan();
  }

  if (!dynamicScanEnabled) return;

  const significantChanges = mutations.filter(mutation => {
    if (mutation.type === 'attributes' && (mutation.attributeName === 'class' || mutation.attributeName === 'style')) {
      return false;
    }
    return true;
  });

  if (significantChanges.length > 0) {
    debounceScan();
  }
});
function discoverJsFromCurrentDom() {
  try {
    const htmlContent = document.documentElement.innerHTML;
    if (!htmlContent) return;
    const jsUrls = collectJsUrls(htmlContent, true, document.baseURI || document.location.href);
    jsUrls.forEach(url => enqueueJsUrl(url, 'page', '', document.location.href));
  } catch (e) {
    if (e.message !== 'Extension context invalidated.') {
      window.logger.warn('增量发现JS失败:', e);
    }
  }
}
function syncTabJsFromBackground(reason = 'sync') {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({
      type: 'REGISTER_CONTENT',
      from: 'content',
      to: 'background',
      frameId: currentFrameId
    }, (response) => {
      if (chrome.runtime.lastError || !response) {
        resolve(0);
        return;
      }
      currentFrameId = String(response?.frameId ?? currentFrameId ?? '0');
      const responseTabId = response.tabId || currentTabId;
      if (!currentTabId) {
        currentTabId = responseTabId;
      }
      if (!currentTabId) {
        resolve(0);
        return;
      }
      getTabResults(currentTabId);
      const urls = Array.isArray(response.tabJs) ? response.tabJs : [];
      let queued = 0;
      urls.forEach((url) => {
        const existed = queueSet.has(url);
        enqueueJsUrl(url, `background:${reason}`, '', 'background');
        if (!existed && queueSet.has(url)) {
          queued++;
        }
      });
      const resultsSet = tabResults.get(currentTabId);
      incrementDebugCounter(resultsSet, 'background_sync_calls', 1);
      incrementDebugCounter(resultsSet, 'background_sync_total_urls', urls.length);
      incrementDebugCounter(resultsSet, 'background_sync_new_urls', queued);
      resolve(queued);
    });
  });
}
function getTabResults(currentTabId){
  if (!tabResults.has(currentTabId)) {
    tabResults.set(currentTabId, {
      domains: new Map(),
      absoluteApis: new Map(),
      apis: new Map(),
      moduleFiles: new Map(),
      pageRoutes: new Map(),
      docFiles: new Map(),
      windowsPaths: new Map(),
      ips: new Map(),
      phones: new Map(),
      emails: new Map(),
      idcards: new Map(),
      jwts: new Map(),
      iframes: new Map(),
      imageFiles: new Map(),
      jsFiles: new Map(),
      thirdPartyLibs: new Map(),
      vueFiles: new Map(),
      urls: new Map(),
      githubUrls: new Map(),
      companies: new Map(),
      credentials: new Map(),
      cookies: new Map(),
      idKeys: new Map(),
      domxssVulns: new Map(),
      vulnReports: new Map(),
      fingers: new Map(),
      progress: new Map(),
      debugSummary: new Map(),
      debugDiscoveredJs: new Map(),
      debugFetchedJs: new Map(),
      debugFetchFailedJs: new Map(),
      debugDomxssCandidates: new Map(),
      debugDomxssTrace: new Map(),
      debugDomxssFiltered: new Map(),
      debugSourceInference: new Map()
    });
  }
}
async function initScan() {
  try {
    await waitForDependencies();
    if (!currentTabId) await getTabId();
    getTabResults(currentTabId);
    bindVueRuntimeRouteListener();
    injectVueRuntimeRouteScanner();
    // 新一轮扫描前清空全局发现队列，避免历史错误URL残留
    queueSet.clear();
    jsQueue.length = 0;
    jsFileMap.clear();
    inFlightSet.clear();
    Object.keys(tree).forEach((key) => {
      delete tree[key];
    });
    reportedVulnIds.clear();
    domXssFileStats.clear();
    window.logger.info('开始扫描...');
    Object.keys(tabResults.get(currentTabId)).forEach(key => {
      tabResults.get(currentTabId)[key].clear();
    });
    if (isWhitelisted) return;
    const htmlContent = document.documentElement.innerHTML;
    const resultsSet = tabResults.get(currentTabId);
    collectIframeResults(resultsSet, { replace: true });
    triggerVueRuntimeRouteScan();
    if (htmlContent) {
      await scanSources([htmlContent], true, document.location.href);
    }
    if (await runExternalFingerprintScan()) {
      sendUpdate();
    }

    const initialJs = collectJsUrls(htmlContent, true, document.baseURI || document.location.href);
    initialJs.forEach(url => enqueueJsUrl(url, 'page', '', document.location.href));
    syncTabJsFromBackground('init');
    // 某些 SPA（如 require/backbone）会在首屏后异步注入脚本，做一次延迟补扫
    setTimeout(() => {
      discoverJsFromCurrentDom();
      syncTabJsFromBackground('delay-1');
    }, 1800);
    setTimeout(() => {
      discoverJsFromCurrentDom();
      syncTabJsFromBackground('delay-2');
    }, 4500);
    if (!observerInitialized) {
      observer.observe(document.body, {
        childList: true,
        subtree: true,
        characterData: true,
        attributeFilter: ['src', 'href', 'data-*'],
        characterDataOldValue: false
      });
      observerInitialized = true;
    }
    window.addEventListener('hashchange', () => {
      const html = document.documentElement.innerHTML;
      if (html) {
        scanSources([html], true, document.location.href);
      }
      runExternalFingerprintScan().then((changed) => {
        if (changed) sendUpdate();
      });
      const resultsSet = tabResults.get(currentTabId);
      if (resultsSet && collectIframeResults(resultsSet, { replace: true })) {
        sendUpdate();
      }
      triggerVueRuntimeRouteScan();
      discoverJsFromCurrentDom();
      syncTabJsFromBackground('hashchange');
    });
  } catch (e) {
    if (e.message !== 'Extension context invalidated.') {
      window.logger.error('初始化扫描出错:', e);
    }
  }
}

// 发送更新
const sendUpdate = () => {
  try {
    const results = {};
    const total = queueSet.size;
    const remaining = jsQueue.length;
    const dealing = inFlightSet.size;
    const percent = total === 0 ? 100 : Math.floor(((total - remaining - dealing) / total) * 100);
    const currentResultSet = tabResults.get(currentTabId);
    if (!currentResultSet) return;
    currentResultSet.progress.set('percent', percent);
    currentResultSet.debugSummary.set('queue_total', total);
    currentResultSet.debugSummary.set('queue_pending', remaining);
    currentResultSet.debugSummary.set('queue_inflight', dealing);
    currentResultSet.debugSummary.set('queue_progress_percent', percent);
    syncVulnReportsToBackground(currentResultSet);
    for (const key in currentResultSet) {
      results[key] = Array.from(currentResultSet[key]);
    }
    if (!Array.isArray(results.routes)) {
      results.routes = Array.isArray(results.pageRoutes) ? results.pageRoutes : [];
    }
    chrome.runtime.sendMessage({
      type: 'SCAN_UPDATE',
      from: 'content',
      to: 'popup',
      results: results,
      tabId: currentTabId,
      frameId: currentFrameId,
      isInIframe,
      frameUrl: window.location.href
    }).catch(() => {
    });
    
    chrome.runtime.sendMessage({
      type: 'UPDATE_BADGE',
      from: 'content',
      to: 'background',
      results: results,
      tabId: currentTabId,
      frameId: currentFrameId
    }).catch(() => {
    });
  } catch (e) {
    if (e.message !== 'Extension context invalidated.') {
      window.logger.error('发送更新出错:', e);
    }
  }
};
async function processJsQueue() {
  while (jsQueue.length > 0 && inFlightSet.size < MAX_CONCURRENT) {
    const url = jsQueue.shift();
    inFlightSet.add(url);
    
    handleJsTask(url).finally(() => {
      inFlightSet.delete(url);
      if (inFlightSet.size === 0){
        sendUpdate();
      }
      if (jsQueue.length > 0) {
        processJsQueue();
      }
    });
    await new Promise(r => setTimeout(r, 0));
  }
}

async function handleJsTask(url) {
  const resultsSet = tabResults.get(currentTabId);
  try {
    incrementDebugCounter(resultsSet, 'js_fetch_attempts', 1);
    const response = await new Promise(resolve => {
      chrome.runtime.sendMessage({
        type: 'FETCH_JS',
        url,
        from: 'content',
        to: 'background',
        frameId: currentFrameId
      }, resolve);
    });
    if (response?.frameId && String(response.frameId) !== String(currentFrameId)) {
      setDebugInfo(resultsSet, 'debugFetchFailedJs', url, `frame mismatch: current=${currentFrameId}, response=${response.frameId}`);
      return;
    }
    const content = response?.content || '';
    const fetchMeta = response?.fetchMeta || {};
    const method = fetchMeta.method || 'unknown';
    if (content && /\.js(?:\?|$)/i.test(url) && isLikelyHtmlDocument(content)) {
      incrementDebugCounter(resultsSet, 'js_fetch_html_response', 1);
      setDebugInfo(resultsSet, 'debugFetchFailedJs', url, `${method}: html-like response`);
      return;
    }

    if (content) {
      incrementDebugCounter(resultsSet, 'js_fetch_success', 1);
      setDebugInfo(resultsSet, 'debugFetchedJs', url, `${method}, bytes=${content.length}`);
      await scanSources([content], false, url);
      const newJsUrls = collectJsUrls(content, false, url);
      if(newJsUrls){
        newJsUrls.forEach(jsUrl => enqueueJsUrl(jsUrl, 'page', getBasePath(url), url));
      }
      return;
    }
    incrementDebugCounter(resultsSet, 'js_fetch_failed', 1);
    setDebugInfo(resultsSet, 'debugFetchFailedJs', url, fetchMeta.reason || 'empty response');
  } catch (e) {
    console.error('处理 JS 出错:', url, e);
    incrementDebugCounter(resultsSet, 'js_fetch_failed', 1);
    setDebugInfo(resultsSet, 'debugFetchFailedJs', url, e?.message || 'handleJsTask exception');
  }
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  try {
    console.log('request from:', request.from);
    switch (request.type) {
      case 'GET_RESULTS': {
        const targetTabId = request.tabId || currentTabId;
        const results = tabResults.get(targetTabId);
        if (!results) {
          sendResponse(null);
          break;
        }
        let changed = false;
        if (String(targetTabId) === String(currentTabId)) {
          changed = collectIframeResults(results, { replace: true });
          triggerVueRuntimeRouteScan();
        }
        const normalizedResults = Object.fromEntries(
          Object.entries(results).map(([key, value]) => [key, Array.from(value)])
        );
        if (!Array.isArray(normalizedResults.routes)) {
          normalizedResults.routes = Array.isArray(normalizedResults.pageRoutes) ? normalizedResults.pageRoutes : [];
        }
        sendResponse(normalizedResults);
        if (changed) {
          sendUpdate();
        }
        break;
      }
      case 'UPDATE_ROUTE': {
        const route = String(request.route || '').trim();
        if (!route || /^(javascript|data|vbscript):/i.test(route)) {
          sendResponse({ success: false, message: 'invalid route' });
          break;
        }
        window.location.href = route;
        sendResponse({ success: true });
        break;
      }
      case 'UPDATE_DYNAMIC_SCAN': {
        dynamicScanEnabled = Boolean(request.enabled);
        sendResponse({ success: true });
        break;
      }
      case 'UPDATE_DEEP_SCAN': {
        deepScanEnabled = Boolean(request.enabled);
        sendResponse({ success: true });
        break;
      }
      default: {
        sendResponse(null);
      }
    }
  } catch (e) {
    if (e.message !== 'Extension context invalidated.') {
      window.logger.error('处理消息出错:', e);
    }
    sendResponse(null);
  }
  return true;
});

(async () => {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', async () => {
      await initSettings();
      await initScan();
    });
  } else {
    await initSettings();
    await initScan();
  }
})();
